"""
일일 AI 리포트 — Claude 브리핑 + 트렌드

하루 동안 쌓인 탐지·대응 데이터를 집계해 경영진/분석가용 브리핑을 만든다.
  - 각 모듈(알림/SOAR/EDR/Sigma/네트워크/인증/평판/MITRE)에서 핵심 지표 수집
  - Claude(ai_analyst.generate_text)로 자연어 브리핑 생성
  - API 키 없으면 규칙 기반 요약으로 fallback (항상 동작)
  - 정해진 시각(REPORT_HOUR)마다 자동 생성 + 온디맨드 생성
  - data/reports/*.json 로 영속화

핵심 관점: 정탐/오탐 비율, TOP 위협/공격자, 자동 대응 성과, 권고사항.
"""
import os
import json
import time
import glob
import threading
from datetime import datetime
from collections import Counter


REPORT_SYSTEM = (
    "당신은 홈서버(자동매매 봇 운영)를 지키는 SOC의 시니어 분석가입니다. "
    "하루치 보안 관제 데이터를 받아 한국어로 간결하고 실행 가능한 일일 브리핑을 작성합니다. "
    "과장 없이 사실 기반으로, 정탐/오탐 구분과 자동 대응 성과를 강조하고, "
    "가장 중요한 위협과 오늘 할 일을 명확히 제시하세요."
)


class DailyReport:
    def __init__(self, socketio, config=None, ai_analyst=None, services=None):
        self.socketio = socketio
        self.config = config or {}
        self.ai = ai_analyst
        self.services = services or {}   # {threat_detector, soar, edr, sigma, ...}
        self.running = False
        self._lock = threading.Lock()

        try:
            self.report_hour = int(self.config.get("REPORT_HOUR", 8))
        except (TypeError, ValueError):
            self.report_hour = 8
        self.report_dir = self.config.get("REPORT_DIR", "data/reports")
        self.reports = []       # 메모리 캐시 (최근순)
        self._last_gen_date = None
        self.stats = {"total_reports": 0, "last_generated": None,
                      "ai_mode": "demo"}

    # ------------------------------------------------------------------ #
    #  라이프사이클
    # ------------------------------------------------------------------ #

    def start(self, demo=True):
        if self.running:
            return
        self.running = True
        self._load_history()
        with self._lock:
            self.stats["ai_mode"] = "claude" if (self.ai and self.ai.available) else "demo"
        threading.Thread(target=self._schedule_loop, daemon=True).start()
        print(f"[Report] 일일 리포트 시작 — 매일 {self.report_hour:02d}시 자동 생성, "
              f"AI {'Claude' if self.stats['ai_mode']=='claude' else '데모(규칙기반)'}")

    def stop(self):
        self.running = False

    def _schedule_loop(self):
        # 시작 직후 최초 리포트 1회 (데모/미리보기)
        time.sleep(8)
        if self.running and not self.reports:
            try:
                self.generate(trigger="startup")
            except Exception as e:
                print(f"[Report] 최초 생성 오류: {e}")
        while self.running:
            now = datetime.now()
            today = now.strftime("%Y-%m-%d")
            if now.hour == self.report_hour and self._last_gen_date != today:
                try:
                    self.generate(trigger="scheduled")
                except Exception as e:
                    print(f"[Report] 예약 생성 오류: {e}")
            for _ in range(60):
                if not self.running:
                    return
                time.sleep(1)

    # ------------------------------------------------------------------ #
    #  스냅샷 수집
    # ------------------------------------------------------------------ #

    def _snapshot(self):
        s = self.services
        snap = {"generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

        # 알림
        td = s.get("threat_detector")
        alerts = []
        if td:
            try:
                alerts = td.get_alerts(limit=500)
                snap["alert_stats"] = td.get_stats()
            except Exception:
                pass
        snap["alerts_total"] = len(alerts)
        snap["by_severity"] = dict(Counter(a.get("severity") for a in alerts))
        snap["by_threat"] = dict(Counter(a.get("threat_label") or a.get("threat_type")
                                         for a in alerts).most_common(6))
        snap["by_status"] = dict(Counter(a.get("status") for a in alerts))
        snap["top_sources"] = Counter(a.get("src_ip") for a in alerts
                                      if a.get("src_ip")).most_common(5)

        # SOAR
        soar = s.get("soar")
        if soar:
            try:
                st = soar.get_status()
                snap["soar"] = st.get("stats", {})
                snap["blocked_ips"] = [b.get("ip") for b in st.get("blocked_ips", [])][:10]
            except Exception:
                pass

        # EDR / Sigma / 네트워크 / 인증 / 평판
        for key, svc_name in [("edr", "edr"), ("sigma", "sigma"),
                              ("net", "net_monitor"), ("auth", "authlog"),
                              ("rep", "ip_reputation")]:
            svc = s.get(svc_name)
            if svc:
                try:
                    snap[key] = svc.get_status().get("stats", {})
                except Exception:
                    pass

        # MITRE 상위 기법
        mitre = s.get("mitre")
        if mitre:
            try:
                snap["mitre_top"] = self._mitre_top(mitre)
            except Exception:
                pass
        return snap

    @staticmethod
    def _mitre_top(mitre):
        for meth in ("get_top_techniques", "get_status", "get_hits"):
            fn = getattr(mitre, meth, None)
            if not fn:
                continue
            try:
                data = fn()
            except Exception:
                continue
            if isinstance(data, dict) and "hits" in data:
                items = data["hits"]
                if isinstance(items, dict):
                    return sorted(items.items(), key=lambda kv: kv[1], reverse=True)[:5]
        return []

    # ------------------------------------------------------------------ #
    #  리포트 생성
    # ------------------------------------------------------------------ #

    def generate(self, trigger="manual"):
        snap = self._snapshot()
        highlights = self._highlights(snap)
        briefing = self._ai_briefing(snap, highlights)

        with self._lock:
            rid = datetime.now().strftime("%Y%m%d_%H%M%S")
            report = {
                "id": rid,
                "generated": snap["generated"],
                "trigger": trigger,
                "ai_mode": self.stats["ai_mode"],
                "metrics": snap,
                "highlights": highlights,
                "briefing": briefing,
            }
            self.reports.insert(0, report)
            self.reports = self.reports[:60]
            self._last_gen_date = datetime.now().strftime("%Y-%m-%d")
            self.stats["total_reports"] += 1
            self.stats["last_generated"] = snap["generated"]

        self._persist(report)
        try:
            self.socketio.emit("daily_report", {"id": rid, "generated": snap["generated"]})
        except Exception:
            pass
        return report

    def _highlights(self, snap):
        soar = snap.get("soar", {})
        tp = soar.get("escalated_tp", 0)
        fp = soar.get("auto_closed_fp", 0)
        total_triage = tp + fp
        fp_rate = round(fp / total_triage * 100, 1) if total_triage else 0
        return {
            "alerts_total": snap.get("alerts_total", 0),
            "critical": snap.get("by_severity", {}).get("CRITICAL", 0),
            "high": snap.get("by_severity", {}).get("HIGH", 0),
            "true_positives": tp,
            "false_positives": fp,
            "fp_rate": fp_rate,
            "auto_blocked": soar.get("auto_blocked", 0),
            "blocks_prevented": soar.get("blocks_prevented", 0),
            "edr_detections": snap.get("edr", {}).get("detections", 0),
            "sigma_matches": snap.get("sigma", {}).get("matches", 0),
            "malicious_conns": snap.get("net", {}).get("malicious_conns", 0),
            "brute_alerts": snap.get("auth", {}).get("brute_alerts", 0),
            "top_threat": (list(snap.get("by_threat", {}).keys()) or ["없음"])[0],
            "top_source": (snap.get("top_sources") or [["없음"]])[0][0],
        }

    def _ai_briefing(self, snap, hl):
        prompt = self._build_prompt(snap, hl)
        if self.ai:
            text = self.ai.generate_text(prompt, system=REPORT_SYSTEM, max_tokens=1200)
            if text:
                return text
        return self._fallback_briefing(hl)

    @staticmethod
    def _build_prompt(snap, hl):
        return (
            "다음은 오늘 하루 SOC 관제 요약 데이터입니다. 이를 바탕으로 "
            "① 오늘의 핵심 요약(2~3문장) ② 가장 중요한 위협 ③ 자동 대응 성과(정탐/오탐) "
            "④ 내일까지 할 일 3가지를 한국어로 작성하세요.\n\n"
            f"- 총 알림: {hl['alerts_total']} (CRITICAL {hl['critical']}, HIGH {hl['high']})\n"
            f"- AI 트리아지: 정탐 {hl['true_positives']} / 오탐 {hl['false_positives']} "
            f"(오탐율 {hl['fp_rate']}%)\n"
            f"- 자동 차단: {hl['auto_blocked']} (안전장치로 방지 {hl['blocks_prevented']})\n"
            f"- EDR 탐지: {hl['edr_detections']}, Sigma 매치: {hl['sigma_matches']}, "
            f"악성 연결: {hl['malicious_conns']}, SSH 브루트포스: {hl['brute_alerts']}\n"
            f"- 위협 유형 분포: {snap.get('by_threat', {})}\n"
            f"- TOP 공격 출발지: {snap.get('top_sources', [])}\n"
            f"- 차단된 IP: {snap.get('blocked_ips', [])}\n"
        )

    @staticmethod
    def _fallback_briefing(hl):
        risk = "높음" if hl["critical"] else ("주의" if hl["high"] or hl["true_positives"] else "안정")
        lines = [
            "■ 오늘의 요약 (자동 생성 · 규칙 기반)",
            f"보안 상태: {risk}. 총 {hl['alerts_total']}건의 알림 중 CRITICAL {hl['critical']}건, "
            f"HIGH {hl['high']}건이 발생했습니다.",
            "",
            "■ 자동 대응 성과",
            f"AI 트리아지가 정탐 {hl['true_positives']}건을 확정하고 오탐 {hl['false_positives']}건을 "
            f"자동 종결했습니다(오탐율 {hl['fp_rate']}%). 자동 차단 {hl['auto_blocked']}건, "
            f"안전장치로 오차단 방지 {hl['blocks_prevented']}건.",
            "",
            "■ 주요 위협",
            f"가장 많은 위협 유형은 '{hl['top_threat']}', 최다 공격 출발지는 {hl['top_source']} 입니다. "
            f"EDR {hl['edr_detections']}건 · Sigma {hl['sigma_matches']}건 · 악성연결 "
            f"{hl['malicious_conns']}건 · SSH 브루트포스 {hl['brute_alerts']}건 탐지.",
            "",
            "■ 권고 (내일까지)",
            "1) 정탐으로 확정된 인시던트의 후속 조치(차단 유지/근본원인) 확인",
            "2) 오탐율이 높으면 탐지 임계값·화이트리스트 조정",
            "3) 차단된 IP의 평판(AbuseIPDB)·재접속 여부 모니터링",
            "",
            "※ ANTHROPIC_API_KEY를 설정하면 Claude가 더 정교한 브리핑을 작성합니다.",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    #  조회 / 영속화
    # ------------------------------------------------------------------ #

    def get_status(self):
        with self._lock:
            latest = self.reports[0] if self.reports else None
            history = [{"id": r["id"], "generated": r["generated"],
                        "trigger": r["trigger"], "ai_mode": r["ai_mode"],
                        "highlights": r["highlights"]} for r in self.reports[:30]]
            return {"stats": dict(self.stats), "latest": latest, "history": history}

    def get_report(self, rid):
        with self._lock:
            for r in self.reports:
                if r["id"] == rid:
                    return r
        return None

    def _persist(self, report):
        try:
            os.makedirs(self.report_dir, exist_ok=True)
            with open(os.path.join(self.report_dir, f"report_{report['id']}.json"),
                      "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[Report] 저장 실패: {e}")

    def _load_history(self):
        try:
            files = sorted(glob.glob(os.path.join(self.report_dir, "report_*.json")),
                           reverse=True)[:60]
            loaded = []
            for path in files:
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        loaded.append(json.load(f))
                except Exception:
                    continue
            with self._lock:
                self.reports = loaded
                self.stats["total_reports"] = len(loaded)
                if loaded:
                    self.stats["last_generated"] = loaded[0].get("generated")
        except Exception:
            pass
