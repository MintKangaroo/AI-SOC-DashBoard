"""
SOAR (Security Orchestration, Automation and Response) 엔진

홈서버 관제 목적의 자동 대응 플레이북:
  PB-AI-TRIAGE   : HIGH/CRITICAL 알림 → Claude AI 트리아지 → 오탐 자동 종결 / 정탐 에스컬레이션
  PB-AUTO-BLOCK  : AI 정탐 판정 + CRITICAL + 외부 IP → 자동 차단
  PB-SIEM-SCANNER: 접근 로그에서 동일 IP 프로브 반복(3회+) → 자동 차단
  PB-IOC-BLOCK   : 위협 인텔 IoC 매칭 IP → 즉시 차단
  PB-BRUTE-BLOCK : 무차별 대입(BRUTE_FORCE) 외부 IP → 자동 차단

차단 모드 (SOAR_BLOCK_MODE):
  simulate (기본) — 차단 명령을 실행하지 않고 기록만 (학습/데모 안전)
  ufw / iptables  — 실제 방화벽 명령 실행 (sudo -n 필요, 실패 시 시뮬레이션 기록)

모든 대응은 data/blocklist.txt 에 영속화되고 SocketIO "soar_action" 으로 스트리밍된다.
"""
import os
import time
import socket
import threading
import subprocess
import ipaddress
from datetime import datetime, timedelta
from collections import deque, Counter

from modules.playbooks import steps_for
from modules.soar_execution_store import SOARExecutionStore

from modules.logging_setup import get_logger

_log = get_logger(__name__)


class SOAREngine:
    AI_TRIAGE_BUDGET = 6          # 5분당 AI 트리아지 최대 횟수 (비용 보호)
    AI_TRIAGE_WINDOW = 300.0

    def __init__(self, socketio, config=None, ai_analyst=None, ml_analyst=None,
                 threat_detector=None, blocklist_path="data/blocklist.txt",
                 execution_db_path=None):
        self.socketio = socketio
        self.config = config or {}
        self.ai = ai_analyst
        self.ml = ml_analyst
        self.threat_detector = threat_detector
        self.decision = None    # app.py 에서 주입 (판정 결과를 클러스터에 학습)
        self.incidents = None   # app.py 에서 주입 (정탐 → 인시던트 승격)
        self.notifier = None    # app.py 에서 주입 (정탐/차단 → 폰 푸시)
        self.virustotal = None  # wiring 에서 주입 (악성코드 해시 평판)
        self.running = False
        self._lock = threading.Lock()
        self._queue = deque(maxlen=500)

        self.block_mode = str(self.config.get("SOAR_BLOCK_MODE", "simulate")).lower()
        self.firewall_helper = str(self.config.get(
            "SOAR_FIREWALL_HELPER", "/usr/local/sbin/soc-ufw"))
        self.auto_block = str(self.config.get("SOAR_AUTO_BLOCK", "True")) == "True"
        self.approval_required = bool(self.config.get("SOAR_APPROVAL_REQUIRED", False))
        self.min_block_confidence = int(self.config.get("SOAR_MIN_BLOCK_CONFIDENCE", 95))
        corroboration = self.config.get("SOAR_REQUIRE_CORROBORATION", False)
        self.require_corroboration = (corroboration is True or
                                      str(corroboration).lower() == "true")
        try:
            self.approval_timeout_minutes = max(
                1, int(self.config.get("SOAR_APPROVAL_TIMEOUT_MINUTES", 15)))
        except (TypeError, ValueError):
            self.approval_timeout_minutes = 15
        try:
            # 차단 자동 만료 TTL (시간) — 0 이면 영구 차단
            self.block_ttl_hours = float(self.config.get("SOAR_BLOCK_TTL_HOURS", 24))
        except (TypeError, ValueError):
            self.block_ttl_hours = 24.0
        self._last_expiry_check = 0.0

        # ── 안전장치: 절대 차단 금지 목록 (자가 락아웃 방지) ──
        # 사설/CGNAT(Tailscale)/자기자신은 코드 고정, 추가 IP·대역은 .env로 지정
        allow_raw = self.config.get("SOAR_BLOCK_ALLOWLIST", "") or ""
        self._allowlist = tuple(x.strip() for x in allow_raw.split(",") if x.strip())
        self._own_ips = self._detect_own_ips()

        self.blocklist_path = blocklist_path
        self.blocked_ips = {}          # ip → {reason, timestamp, mode}
        self._load_blocklist()

        self.actions = deque(maxlen=300)   # 대응 이력
        self._action_id = 0
        self._triaged_alerts = set()       # 알림별 AI 트리아지 1회 제한
        self._exfil_alerts = set()         # 자료 유출 조사 플레이북 중복 방지
        self._ai_calls = deque(maxlen=50)  # AI 호출 타임스탬프 (rate limit)
        self._siem_probe_counter = Counter()
        execution_db_path = execution_db_path or os.path.join(
            os.path.dirname(blocklist_path) or "data", "soar_executions.db")
        self.execution_store = SOARExecutionStore(execution_db_path)
        restored = self.execution_store.load_recent(100)
        self.executions = deque(restored, maxlen=100)
        self._execution_id = max((e.get("id", 0) for e in restored), default=0)

        self.stats = {
            "total_actions": 0,
            "auto_blocked": 0,
            "auto_closed_fp": 0,
            "escalated_tp": 0,
            "ai_triages": 0,
            "blocks_prevented": 0,   # 안전장치로 차단 차단된 수
        }

        self.playbooks = [
            {"id": "PB-AI-TRIAGE",    "name": "AI 트리아지 (정탐/오탐 자동 판별)",
             "description": "HIGH/CRITICAL 알림을 Claude AI가 분석 — 오탐은 자동 종결+ML 피드백, 정탐은 에스컬레이션",
             "enabled": True, "runs": 0, "last_run": None},
            {"id": "PB-AUTO-BLOCK",   "name": "정탐 CRITICAL 자동 차단",
             "description": "정탐 판정(신뢰도 95+) + CRITICAL + 독립근거 2개 + 외부 IP → 승인 후 차단",
             "enabled": True, "runs": 0, "last_run": None},
            {"id": "PB-SIEM-SCANNER", "name": "반복 스캐너 자동 차단",
             "description": "자동매매 서버 접근 로그에서 동일 IP가 프로브 3회 이상 → 차단",
             "enabled": True, "runs": 0, "last_run": None},
            {"id": "PB-IOC-BLOCK",    "name": "IoC 매칭 즉시 차단",
             "description": "위협 인텔 피드의 악성 IP와 통신 감지 → 즉시 차단",
             "enabled": True, "runs": 0, "last_run": None},
            {"id": "PB-BRUTE-BLOCK",  "name": "무차별 대입 자동 차단",
             "description": "BRUTE_FORCE 알림의 외부 출발지 IP → 차단",
             "enabled": True, "runs": 0, "last_run": None},
            {"id": "PB-HONEYPOT-BLOCK", "name": "허니팟 접촉 자동 차단",
             "description": "허니팟 유인 서비스에 접촉한 외부 IP(고신뢰 침해지표) → 즉시 차단",
             "enabled": True, "runs": 0, "last_run": None},
            {"id": "PB-CORRELATED-ESCALATE", "name": "상관관계 발동 에스컬레이션",
             "description": "SIEM 상관관계 규칙(다중벡터·스캔→침투 등) 발동 → 인시던트 승격",
             "enabled": True, "runs": 0, "last_run": None},
            {"id": "PB-DATA-EXFIL", "name": "내부 자료 유출 조사·격리",
             "description": "대량 외부 전송/DNS 터널링 → 증거 보존·범위 산정·인시던트 생성 (내부 호스트 자동 차단 금지)",
             "enabled": True, "runs": 0, "last_run": None},
            {"id": "PB-MALWARE-ENRICH", "name": "악성코드 VirusTotal 강화",
             "description": "악성코드·EDR·Sigma 알림의 해시를 추출해 VirusTotal 기존 분석 결과로 보강(파일 업로드 안 함)",
             "enabled": True, "runs": 0, "last_run": None},
        ]

    # ------------------------------------------------------------------ #
    #  라이프사이클
    # ------------------------------------------------------------------ #

    def start(self, demo=True):
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._worker_loop, daemon=True).start()
        _log.info(f"[SOAR] 엔진 시작 — 차단 모드: {self.block_mode}, 자동 차단: {self.auto_block}")
        # 실차단 모드인데 sudo 가 안 되면 명확히 경고 (조용한 폴백 방지)
        if self.block_mode in ("ufw", "iptables"):
            if (self.block_mode == "ufw" and
                    self._run_fw(["sudo", "-n", self.firewall_helper, "status"])):
                _log.warning(f"[SOAR] 실차단 활성 — {self.block_mode} 방화벽 규칙을 실제 적용합니다.")
            else:
                _log.warning(f"[SOAR] ⚠ 경고: {self.block_mode} 모드이나 passwordless sudo 불가 "
                      f"→ 실제 차단은 실패하고 simulate 로 기록됩니다. "
                      f"sudoers 설정 필요.")
        _log.info("[SOAR] 안전장치: 사설·Tailscale(100.64/10)·서버자신"
              + (f"·화이트리스트{list(self._allowlist)}" if self._allowlist else "")
              + " 절대 차단 안 함")

    def stop(self):
        self.running = False

    # ------------------------------------------------------------------ #
    #  이벤트 핸들러 (다른 모듈에서 호출)
    # ------------------------------------------------------------------ #

    def handle_alert(self, alert):
        """threat_detector 알림 (신뢰도 임계값 통과분만 들어옴)"""
        self._queue.append(("alert", alert))

    def handle_siem_event(self, event):
        """SIEM 의심 이벤트 (HIGH/CRITICAL)"""
        self._queue.append(("siem", event))

    def handle_ti_match(self, match):
        """위협 인텔 IoC 매칭"""
        self._queue.append(("ti", match))

    # ------------------------------------------------------------------ #
    #  조회 API
    # ------------------------------------------------------------------ #

    def get_status(self):
        self._expire_approvals()
        with self._lock:
            return {
                "stats": dict(self.stats),
                "block_mode": self.block_mode,
                "auto_block": self.auto_block,
                "approval_required": self.approval_required,
                "approval_timeout_minutes": self.approval_timeout_minutes,
                "min_block_confidence": self.min_block_confidence,
                "require_corroboration": self.require_corroboration,
                "block_ttl_hours": self.block_ttl_hours,
                "safety": {
                    "cgnat_protected": "100.64.0.0/10 (Tailscale)",
                    "private_protected": True,
                    "own_ips": sorted(self._own_ips),
                    "allowlist": list(self._allowlist),
                    "prevented": self.stats["blocks_prevented"],
                },
                "playbooks": [{**p, "steps": steps_for(p["id"])} for p in self.playbooks],
                "blocked_ips": [
                    {"ip": ip, **info} for ip, info in
                    sorted(self.blocked_ips.items(),
                           key=lambda kv: kv[1]["timestamp"], reverse=True)
                ],
                "actions": list(reversed(list(self.actions)))[:50],
                "executions": [dict(e) for e in list(self.executions)[:30]],
                "virustotal": self.virustotal.status() if self.virustotal else
                              {"active": False, "mode": "hash_lookup_only", "uploads": False},
            }

    def toggle_playbook(self, pb_id):
        with self._lock:
            for pb in self.playbooks:
                if pb["id"] == pb_id:
                    pb["enabled"] = not pb["enabled"]
                    return pb["enabled"]
        return None

    # ------------------------------------------------------------------ #
    #  수동 대응 (분석가 조치)
    # ------------------------------------------------------------------ #

    def manual_block(self, ip, reason="분석가 수동 차단"):
        return self._block_ip(ip, reason, playbook="MANUAL")

    def manual_block_request(self, ip, reason="분석가 수동 차단"):
        before = self._execution_id
        ok = self._block_ip(ip, reason, playbook="MANUAL")
        if ok and self.approval_required and self._execution_id > before:
            return {"success": True, "status": "waiting_approval",
                    "execution_id": self._execution_id}
        return {"success": ok, "status": "executed" if ok else "rejected"}

    def review_approval(self, execution_id, decision, actor, reason=""):
        """대기 중인 IP 차단을 승인·거절·취소한다."""
        self._expire_approvals()
        entry, context = self.execution_store.get(execution_id)
        if not entry:
            return {"ok": False, "status": "not_found"}
        if entry.get("status") != "waiting_approval":
            return {"ok": False, "status": "not_pending"}
        if decision not in ("approve", "reject", "cancel"):
            return {"ok": False, "status": "invalid_decision"}
        if not self._claim_pending_approval(execution_id):
            return {"ok": False, "status": "not_pending"}
        label = {"approve": "승인", "reject": "거절", "cancel": "취소"}[decision]
        detail = f"{actor} {label}" + (f" · {reason}" if reason else "")
        self._execution_step(execution_id, "approval",
                             "completed" if decision == "approve" else "failed", detail)
        self._set_execution_fields(execution_id, approval={
            **entry.get("approval", {}), "decision": decision, "actor": actor,
            "reason": str(reason or "")[:300],
            "decided_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
        if decision != "approve":
            self._execution_step(execution_id, "block", "skipped", f"요청 {label}")
            self._execution_step(execution_id, "log", "completed", "감사 로그 기록")
            status = "cancelled" if decision == "cancel" else "rejected"
            self._execution_finish(execution_id, status)
            return {"ok": True, "status": status}
        self._execution_step(execution_id, "block", "running", "승인된 차단 실행")
        ok = self._block_ip(context.get("ip"), context.get("reason", "승인된 차단"),
                            playbook=context.get("source_playbook", "MANUAL"),
                            ttl_hours=context.get("ttl_hours"), bypass_approval=True)
        self._execution_step(execution_id, "block", "completed" if ok else "failed",
                             "차단 완료" if ok else "차단 실패 또는 중복")
        self._execution_step(execution_id, "log", "completed", "감사 로그 기록")
        self._execution_finish(execution_id, "completed" if ok else "failed")
        return {"ok": ok, "status": "approved" if ok else "execution_failed"}

    def approve_many(self, execution_ids, actor, reason="일괄 승인"):
        """클라이언트가 확인한 스냅샷의 승인 요청만 최대 100건 처리한다."""
        results = []
        for execution_id in list(dict.fromkeys(execution_ids))[:100]:
            try:
                run_id = int(execution_id)
            except (TypeError, ValueError):
                continue
            result = self.review_approval(run_id, "approve", actor, reason)
            results.append({"id": run_id, **result})
        return {
            "ok": any(r.get("ok") for r in results),
            "requested": len(results),
            "approved": sum(1 for r in results if r.get("status") == "approved"),
            "failed": sum(1 for r in results if r.get("status") != "approved"),
            "results": results,
        }

    def manual_unblock(self, ip):
        with self._lock:
            if ip not in self.blocked_ips:
                return False
            mode = self.blocked_ips[ip].get("mode", "simulate")
            del self.blocked_ips[ip]
            self._save_blocklist()
        if mode == "ufw":
            self._run_ufw("unblock", ip)
        elif mode == "iptables":
            self._run_fw(["sudo", "-n", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        self._log_action("MANUAL", "unblock", ip, "success", "차단 해제")
        return True

    def test_virustotal(self, hash_value):
        """분석가가 제공한 해시로 강화 플레이북 전체 흐름을 안전하게 시험한다."""
        return self._process_malware_enrichment({
            "id": "VT-TEST", "threat_type": "MALWARE_BEACON",
            "severity": "HIGH", "details": {"sha256": hash_value},
        }, persist=False)

    def retry_execution(self, execution_id):
        """실패한 읽기 전용 강화 실행을 새 실행으로 재개한다."""
        entry, context = self.execution_store.get(execution_id)
        if not entry:
            return {"ok": False, "status": "not_found"}
        if entry.get("status") != "failed":
            return {"ok": False, "status": "not_failed"}
        if entry.get("playbook") != "PB-MALWARE-ENRICH" or not context.get("hash"):
            return {"ok": False, "status": "not_retryable"}
        return self._run_malware_lookup(context["hash"], alert_id=context.get("alert_id"),
                                        persist=context.get("persist", False),
                                        retry_of=execution_id)

    # ------------------------------------------------------------------ #
    #  워커 루프
    # ------------------------------------------------------------------ #

    def _worker_loop(self):
        while self.running:
            now = time.time()
            if now - self._last_expiry_check > 30:
                self._last_expiry_check = now
                try:
                    self._expire_blocks()
                    self._expire_approvals()
                except Exception as e:
                    _log.error(f"[SOAR] TTL 만료 처리 오류: {e}")
            if self._queue:
                kind, data = self._queue.popleft()
                try:
                    if kind == "alert":
                        self._process_alert(data)
                    elif kind == "siem":
                        self._process_siem(data)
                    elif kind == "ti":
                        self._process_ti(data)
                except Exception as e:
                    _log.error(f"[SOAR] 처리 오류({kind}): {e}")
            else:
                time.sleep(0.3)

    # ------------------------------------------------------------------ #
    #  플레이북 실행
    # ------------------------------------------------------------------ #

    def _process_alert(self, alert):
        alert_id = alert.get("id")
        severity = alert.get("severity")
        src_ip = alert.get("src_ip")

        threat_type = alert.get("threat_type")
        auto_block_eligible = self._eligible_auto_block(alert)

        if (self._pb_enabled("PB-MALWARE-ENRICH") and
                threat_type in ("MALWARE_BEACON", "EDR_THREAT", "SIGMA_MATCH")):
            self._process_malware_enrichment(alert)

        if (self._pb_enabled("PB-DATA-EXFIL") and
                threat_type in ("DATA_EXFIL", "DNS_TUNNELING") and
                alert_id not in self._exfil_alerts):
            self._process_data_exfil(alert)

        # PB-BRUTE-BLOCK: AI 없이도 즉시 차단 (명백한 케이스)
        if (self._pb_enabled("PB-BRUTE-BLOCK") and self.auto_block
                and threat_type == "BRUTE_FORCE"
                and auto_block_eligible
                and self._is_external(src_ip)):
            self._pb_run("PB-BRUTE-BLOCK")
            self._block_ip(src_ip, f"무차별 대입 (알림 #{alert_id})",
                           playbook="PB-BRUTE-BLOCK")

        # PB-HONEYPOT-BLOCK: 허니팟 접촉 = 고신뢰 침해지표 → 즉시 차단
        if (self._pb_enabled("PB-HONEYPOT-BLOCK") and self.auto_block
                and threat_type == "HONEYPOT"
                and auto_block_eligible
                and self._is_external(src_ip)):
            self._pb_run("PB-HONEYPOT-BLOCK")
            self._block_ip(src_ip, f"허니팟 유인 접촉 (알림 #{alert_id})",
                           playbook="PB-HONEYPOT-BLOCK")

        # PB-CORRELATED-ESCALATE: 상관관계 규칙 발동 알림 → 실행 기록(트리아지에서 인시던트 승격)
        if self._pb_enabled("PB-CORRELATED-ESCALATE") and threat_type == "CORRELATED":
            self._pb_run("PB-CORRELATED-ESCALATE")

        # PB-AI-TRIAGE
        if (not self._pb_enabled("PB-AI-TRIAGE") or severity not in ("HIGH", "CRITICAL")
                or alert_id in self._triaged_alerts or not self.ai):
            return
        self._triaged_alerts.add(alert_id)

        if not self._ai_budget_ok():
            # 예산 초과 → 규칙 기반 fallback (탐지기 신뢰도 사용)
            conf = alert.get("confidence") or 0.5
            verdict = conf >= 0.7
            detail = f"AI 예산 초과 — 규칙 기반 판정(신뢰도 {conf:.2f})"
            self._pb_counter("PB-AI-TRIAGE")
            run_id = self._execution_start("PB-AI-TRIAGE", f"알림 #{alert_id}")
            self._execution_step(run_id, "intake", "completed")
            self._execution_step(run_id, "enrich", "completed", "탐지 신뢰도·위협그룹 prior 적용")
            self._execution_step(run_id, "ai", "skipped", "AI 호출 예산 초과")
            self._apply_triage(alert, verdict, int(conf * 100), detail, ai=False,
                               execution_id=run_id)
            return

        self._pb_counter("PB-AI-TRIAGE")
        run_id = self._execution_start("PB-AI-TRIAGE", f"알림 #{alert_id}")
        self._execution_step(run_id, "intake", "completed")
        self._execution_step(run_id, "enrich", "completed", "IP 평판·위협그룹 prior 적용")
        self._execution_step(run_id, "ai", "running", "Claude 분석 요청")
        self._ai_calls.append(time.time())
        entry = self.ai.analyze_alert(alert, async_mode=False)
        result = (entry or {}).get("result", {})
        verdict = result.get("is_true_positive")
        confidence = result.get("confidence", 50)
        summary = result.get("summary", "")
        with self._lock:
            self.stats["ai_triages"] += 1
        if verdict is None:
            self._execution_step(run_id, "ai", "failed", "판정 결과 없음")
            self._execution_finish(run_id, "failed")
            self._log_action("PB-AI-TRIAGE", "triage", f"알림 #{alert_id}",
                             "inconclusive", "AI 판정 불가 — 수동 검토 필요")
            return
        self._execution_step(run_id, "ai", "completed", f"신뢰도 {confidence}%")
        self._apply_triage(alert, verdict, confidence, summary, ai=True,
                           execution_id=run_id)

    def _process_data_exfil(self, alert):
        """내부 자료 유출은 IP 차단 대신 증거 보존·케이스 기반으로 대응한다."""
        alert_id = alert.get("id")
        self._exfil_alerts.add(alert_id)
        self._pb_counter("PB-DATA-EXFIL")
        src, dst = alert.get("src_ip"), alert.get("dst_ip")
        details = alert.get("details") or {}
        amount = int(details.get("bytes_in_window") or
                     details.get("bytes_per_5min") or 0)
        target = f"알림 #{alert_id} · {src} → {dst or '외부'}"
        run_id = self._execution_start("PB-DATA-EXFIL", target, context={
            "alert_id": alert_id, "src_ip": src, "dst_ip": dst,
            "bytes_out": amount, "containment": "analyst_required"})
        self._execution_step(run_id, "intake", "completed", alert.get("description", ""))
        self._execution_step(
            run_id, "validate", "completed",
            f"전송량 {amount / 1e6:.1f}MB · 목적지 {dst or '미상'} · 허용목록 미일치")
        self._execution_step(run_id, "preserve", "completed",
                             "알림 원문·호스트·목적지·전송량 스냅샷 저장")
        self._execution_step(run_id, "scope", "completed",
                             "사용자·프로세스·파일 목록은 인시던트에서 추가 조사")
        self._execution_step(run_id, "contain", "skipped",
                             "내부 호스트 자동 차단 금지 — 분석가가 계정/세션 격리 결정")
        if self.threat_detector:
            self.threat_detector.update_alert_status(
                alert_id, "ACK", note="SOAR 자료 유출 조사 플레이북 — 증거 보존 및 수동 격리 검토",
                assignee="SOAR")
        inc_id = None
        if self.incidents:
            try:
                inc_id = self.incidents.promote_alert(
                    alert, "내부 자료 유출 의심 — 수동 범위 산정 및 격리 필요")
            except Exception:
                pass
        self._execution_step(run_id, "case", "completed",
                             f"인시던트 #{inc_id} 생성/병합" if inc_id else "인시던트 연계 없음")
        self._execution_step(run_id, "notify", "completed", "SOAR 관제 큐에 우선 표시")
        self._execution_finish(run_id, "completed")
        self._log_action("PB-DATA-EXFIL", "preserve_escalate",
                         f"알림 #{alert_id}", "success",
                         f"{src} → {dst} · {amount / 1e6:.1f}MB · 내부 자동 차단 안 함")

    def _apply_triage(self, alert, is_tp, confidence, summary, ai=True, execution_id=None):
        alert_id = alert.get("id")
        src_ip = alert.get("src_ip")
        who = "AI" if ai else "규칙"

        # 의사결정 지원: 판정 결과를 위협 그룹에 학습 (정오탐 분석 자동화)
        if self.decision:
            try:
                self.decision.record_verdict(alert_id, is_tp, source=who)
            except Exception:
                pass

        if not is_tp:
            if execution_id:
                self._execution_step(execution_id, "verdict", "running", "오탐 자동 종결")
            # 오탐 → 자동 종결 (+ AI 경로는 ML 피드백이 ai_analyst 에서 자동 반영)
            if self.threat_detector:
                self.threat_detector.update_alert_status(
                    alert_id, "CLOSED",
                    note=f"SOAR {who} 트리아지: 오탐 판정({confidence}%) — {summary}",
                    assignee="SOAR")
            if not ai and self.ml:
                self.ml.mark_alert(is_fp=True)
            with self._lock:
                self.stats["auto_closed_fp"] += 1
            self._log_action("PB-AI-TRIAGE", "auto_close", f"알림 #{alert_id}",
                             "success", f"{who} 오탐 판정({confidence}%) → 자동 종결")
            if execution_id:
                self._execution_step(execution_id, "verdict", "completed")
                self._execution_step(execution_id, "notify", "skipped", "오탐은 통보하지 않음")
                self._execution_finish(execution_id, "completed")
            return

        # 정탐 → 에스컬레이션 (ACK + 메모)
        if self.threat_detector:
            self.threat_detector.update_alert_status(
                alert_id, "ACK",
                note=f"SOAR {who} 트리아지: 정탐 판정({confidence}%) — {summary}",
                assignee="SOAR")
        if not ai and self.ml:
            self.ml.mark_alert(is_fp=False)
        with self._lock:
            self.stats["escalated_tp"] += 1
        self._log_action("PB-AI-TRIAGE", "escalate", f"알림 #{alert_id}",
                         "success", f"{who} 정탐 판정({confidence}%) → 에스컬레이션")
        if execution_id:
            self._execution_step(execution_id, "verdict", "completed", "정탐 ACK·에스컬레이션")
            self._execution_step(execution_id, "notify", "running", "인시던트 승격·통보")

        # 정탐 확정 → 폰 푸시 (오탐은 보내지 않음)
        if self.notifier:
            try:
                self.notifier.notify_true_positive(alert, confidence, who=who)
            except Exception:
                pass

        # 인시던트 자동 승격 (같은 위협그룹은 기존 케이스에 병합)
        if self.incidents:
            try:
                inc_id = self.incidents.promote_alert(
                    alert, f"{who} 정탐 판정({confidence}%)")
                self._log_action("PB-AI-TRIAGE", "incident", f"INC-{inc_id}",
                                 "success", f"알림 #{alert_id} → 인시던트 #{inc_id} 승격/병합")
            except Exception:
                pass

        # PB-AUTO-BLOCK: 정탐 + CRITICAL + 외부 IP + 고신뢰
        block_evidence = self._block_evidence(alert)
        enough_evidence = (not self.require_corroboration or len(block_evidence) >= 2)
        if (self._pb_enabled("PB-AUTO-BLOCK") and self.auto_block
                and alert.get("severity") == "CRITICAL"
                and confidence >= self.min_block_confidence and enough_evidence
                and not (alert.get("details") or {}).get("demo")
                and self._is_external(src_ip)):
            self._pb_run("PB-AUTO-BLOCK")
            self._block_ip(src_ip,
                           f"{who} 정탐 CRITICAL (알림 #{alert_id}, {confidence}%, "
                           f"근거: {', '.join(block_evidence)})",
                           playbook="PB-AUTO-BLOCK")
        if execution_id:
            self._execution_step(execution_id, "notify", "completed")
            self._execution_finish(execution_id, "completed")

    @staticmethod
    def _block_evidence(alert):
        """서로 독립적인 자동 차단 근거만 반환한다."""
        details = alert.get("details") or {}
        if details.get("block_excluded"):
            return []
        evidence = set(details.get("evidence") or [])
        if details.get("source") == "snort":
            evidence.add("snort_signature")
        rep = details.get("ip_reputation") or {}
        if rep.get("score", 0) >= 90 and rep.get("source") != "demo":
            evidence.add("abuseipdb_90")
        vt = details.get("virustotal") or {}
        if vt.get("malicious", 0) >= 5:
            evidence.add("virustotal_5plus")
        return sorted(evidence)

    def _eligible_auto_block(self, alert):
        """자동 생성 이벤트가 차단 후보 큐에 들어갈 최소 안전 조건."""
        details = alert.get("details") or {}
        if details.get("demo"):
            return False
        confidence = float(alert.get("confidence") or details.get("confidence") or 0)
        if confidence * 100 < self.min_block_confidence:
            return False
        return (not self.require_corroboration or
                len(self._block_evidence(alert)) >= 2)

    def _process_malware_enrichment(self, alert, persist=True):
        details = alert.get("details") or {}
        candidates = [alert.get("hash"), alert.get("sha256"), details.get("hash"),
                      details.get("sha256"), details.get("sha1"), details.get("md5")]
        value = next((str(v) for v in candidates if v), None)
        if not value:
            run_id = self._execution_start("PB-MALWARE-ENRICH", f"알림 #{alert.get('id')}")
            self._pb_counter("PB-MALWARE-ENRICH")
            self._execution_step(run_id, "intake", "completed")
            self._execution_step(run_id, "hash", "skipped", "알림에 해시 없음")
            self._execution_step(run_id, "vt", "skipped", "조회 대상 없음")
            self._execution_step(run_id, "verdict", "skipped")
            self._execution_step(run_id, "handoff", "completed", "기존 AI 트리아지 계속")
            self._execution_finish(run_id, "completed")
            return {"ok": False, "status": "no_hash", "execution_id": run_id}
        return self._run_malware_lookup(value, alert_id=alert.get("id"), persist=persist,
                                        alert=alert)

    def _run_malware_lookup(self, value, alert_id=None, persist=True, alert=None,
                            retry_of=None):
        target = f"알림 #{alert_id}" if alert_id is not None else "해시 조회"
        context = {"hash": value, "alert_id": alert_id, "persist": bool(persist)}
        run_id = self._execution_start("PB-MALWARE-ENRICH", target, context=context,
                                       retry_of=retry_of)
        self._pb_counter("PB-MALWARE-ENRICH")
        self._execution_step(run_id, "intake", "completed",
                             "재시도 요청 복원" if retry_of else "알림 수신")
        self._execution_step(run_id, "hash", "completed", value)
        self._execution_step(run_id, "vt", "running")
        result = self.virustotal.lookup_hash(value) if self.virustotal else {
            "ok": False, "status": "not_configured", "hash": value}
        if result.get("ok"):
            detail = (f"{result.get('verdict')} · malicious {result.get('malicious', 0)} · "
                      f"suspicious {result.get('suspicious', 0)}")
            self._execution_step(run_id, "vt", "completed", detail)
            self._execution_step(run_id, "verdict", "completed", result.get("verdict"))
            if alert is not None:
                alert.setdefault("details", {})["virustotal"] = result
            if persist and self.threat_detector and isinstance(alert_id, int):
                self.threat_detector.enrich_alert(alert_id, {"virustotal": result})
            self._log_action("PB-MALWARE-ENRICH", "vt_lookup", value,
                             "success", detail)
        else:
            status = result.get("status", "error")
            state = "skipped" if status == "not_configured" else "failed"
            self._execution_step(run_id, "vt", state, status)
            self._execution_step(run_id, "verdict", "skipped")
        if result.get("ok"):
            self._execution_step(run_id, "handoff", "completed", "AI 트리아지에 결과 전달")
            self._execution_finish(run_id, "completed")
        elif result.get("status") == "not_configured":
            self._execution_step(run_id, "handoff", "completed", "연동 설정 후 다시 실행 필요")
            self._execution_finish(run_id, "completed")
        else:
            self._execution_step(run_id, "handoff", "skipped", "조회 실패로 전달하지 않음")
            self._execution_finish(run_id, "failed")
        return {**result, "execution_id": run_id}

    def _process_siem(self, event):
        if not (self._pb_enabled("PB-SIEM-SCANNER") and self.auto_block):
            return
        if event.get("severity") not in ("HIGH", "CRITICAL"):
            return
        ip = event.get("ip")
        if not self._is_external(ip):
            return
        if self.require_corroboration:
            return  # 반복 로그 한 종류만으로는 자동 차단 후보를 만들지 않음
        self._siem_probe_counter[ip] += 1
        if self._siem_probe_counter[ip] == 3:   # 3회째에 1번만 발동
            self._pb_run("PB-SIEM-SCANNER")
            self._block_ip(ip, f"반복 프로브 3회+ ({event.get('category')}, "
                               f"소스: {event.get('source')})",
                           playbook="PB-SIEM-SCANNER")

    def _process_ti(self, match):
        if not (self._pb_enabled("PB-IOC-BLOCK") and self.auto_block):
            return
        if match.get("kind") != "ip":
            return
        if self.require_corroboration:
            return  # 단일 IoC 피드 일치만으로는 자동 차단 후보를 만들지 않음
        ip = match.get("indicator")
        self._pb_run("PB-IOC-BLOCK")
        self._block_ip(ip, f"위협 인텔 IoC 매칭 ({match.get('description', '')[:60]})",
                       playbook="PB-IOC-BLOCK")

    # ------------------------------------------------------------------ #
    #  차단 실행
    # ------------------------------------------------------------------ #

    def _block_ip(self, ip, reason, playbook, ttl_hours=None, bypass_approval=False):
        if not ip:
            return False

        # 안전장치: 사설/Tailscale/자기자신/화이트리스트는 절대 차단 금지
        blockable, why = self._is_blockable(ip)
        if not blockable:
            with self._lock:
                self.stats["blocks_prevented"] += 1
            self._log_action(playbook, "block_prevented", ip, "safe",
                             f"안전장치 발동 — {why} (차단 안 함) · 원래 사유: {reason}")
            return False

        with self._lock:
            if ip in self.blocked_ips:
                return False   # 이미 차단됨

        if self.approval_required and not bypass_approval:
            return self._queue_block_approval(ip, reason, playbook, ttl_hours)

        mode, result = self.block_mode, "simulated"
        if self.block_mode == "ufw":
            ok = self._run_ufw("block", ip)
            result = "success" if ok else "simulated (ufw 실패)"
            mode = "ufw" if ok else "simulate"
        elif self.block_mode == "iptables":
            ok = self._run_fw(["sudo", "-n", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
            result = "success" if ok else "simulated (iptables 실패)"
            mode = "iptables" if ok else "simulate"

        ttl = self.block_ttl_hours if ttl_hours is None else ttl_hours
        expires_ts = time.time() + ttl * 3600 if ttl > 0 else 0
        with self._lock:
            self.blocked_ips[ip] = {
                "reason": reason, "mode": mode,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "expires_ts": expires_ts,
                "expires": (datetime.fromtimestamp(expires_ts)
                            .strftime("%Y-%m-%d %H:%M:%S") if expires_ts else "영구"),
            }
            self.stats["auto_blocked"] += 1
            self._save_blocklist()
        self._log_action(playbook, "block_ip", ip, result,
                         f"{reason} (만료: {self.blocked_ips[ip]['expires']})")
        if self.notifier:
            try:
                self.notifier.notify_block(ip, reason)
            except Exception:
                pass
        if self.incidents:
            try:
                self.incidents.attach_block(ip, reason)
            except Exception:
                pass
        return True

    def _queue_block_approval(self, ip, reason, playbook, ttl_hours):
        with self._lock:
            duplicate = next((e for e in self.executions
                              if e.get("status") == "waiting_approval"
                              and e.get("approval", {}).get("ip") == ip), None)
        if duplicate:
            return True
        expires = datetime.now() + timedelta(minutes=self.approval_timeout_minutes)
        run_id = self._execution_start("PB-BLOCK-APPROVAL", ip, context={
            "ip": ip, "reason": reason, "source_playbook": playbook,
            "ttl_hours": ttl_hours})
        self._execution_step(run_id, "request", "completed", f"{playbook} · {reason}")
        self._execution_step(run_id, "safety", "completed", "안전 검사 통과")
        self._execution_step(run_id, "approval", "running", "분석가 결정 대기")
        self._set_execution_fields(run_id, status="waiting_approval", approval={
            "ip": ip, "requested_by": playbook,
            "expires_at": expires.strftime("%Y-%m-%d %H:%M:%S")})
        self._log_action(playbook, "approval_request", ip, "waiting",
                         f"차단 승인 대기 · {expires.strftime('%H:%M:%S')} 만료")
        return True

    def _expire_approvals(self):
        now = datetime.now()
        with self._lock:
            pending = [(e["id"], e.get("approval", {}).get("expires_at"))
                       for e in self.executions if e.get("status") == "waiting_approval"]
        for run_id, expires in pending:
            try:
                expired = datetime.strptime(expires, "%Y-%m-%d %H:%M:%S") <= now
            except (TypeError, ValueError):
                expired = False
            if expired:
                if not self._claim_pending_approval(run_id):
                    continue
                self._execution_step(run_id, "approval", "failed", "승인 시간 만료")
                self._execution_step(run_id, "block", "skipped", "미승인")
                self._execution_step(run_id, "log", "completed", "만료 기록")
                self._execution_finish(run_id, "expired")

    def _claim_pending_approval(self, run_id):
        """승인/거절/만료 중 하나만 처리하도록 메모리 상태를 원자 선점한다."""
        with self._lock:
            entry = next((e for e in self.executions if e["id"] == run_id), None)
            if not entry or entry.get("status") != "waiting_approval":
                return False
            entry["status"] = "processing_approval"
            snapshot = {**entry, "steps": [dict(s) for s in entry["steps"]]}
            self.execution_store.save(snapshot)
        self._emit_execution(snapshot)
        return True

    def _set_execution_fields(self, run_id, **fields):
        with self._lock:
            entry = next((e for e in self.executions if e["id"] == run_id), None)
            if not entry:
                return False
            entry.update(fields)
            snapshot = {**entry, "steps": [dict(s) for s in entry["steps"]]}
            self.execution_store.save(snapshot)
        self._emit_execution(snapshot)
        return True

    def _expire_blocks(self):
        """TTL 이 지난 차단을 자동 해제"""
        now = time.time()
        with self._lock:
            expired = [(ip, info) for ip, info in self.blocked_ips.items()
                       if info.get("expires_ts") and info["expires_ts"] <= now]
            for ip, _ in expired:
                del self.blocked_ips[ip]
            if expired:
                self._save_blocklist()
        for ip, info in expired:
            mode = info.get("mode", "simulate")
            if mode == "ufw":
                self._run_ufw("unblock", ip)
            elif mode == "iptables":
                self._run_fw(["sudo", "-n", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            self._log_action("TTL", "unblock", ip, "success",
                             f"차단 TTL({self.block_ttl_hours}h) 만료 — 자동 해제")

    @staticmethod
    def _run_fw(cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    def _run_ufw(self, action, ip):
        return self._run_fw(["sudo", "-n", self.firewall_helper, action, ip])

    # ------------------------------------------------------------------ #
    #  유틸
    # ------------------------------------------------------------------ #

    def _pb_enabled(self, pb_id):
        with self._lock:
            return any(p["id"] == pb_id and p["enabled"] for p in self.playbooks)

    def _pb_run(self, pb_id):
        """짧은 동기 플레이북 실행을 완료 흐름으로 기록한다."""
        self._pb_counter(pb_id)
        run_id = self._execution_start(pb_id, "자동 트리거")
        for step in steps_for(pb_id):
            self._execution_step(run_id, step["key"], "completed")
        self._execution_finish(run_id, "completed")
        return run_id

    def _pb_counter(self, pb_id):
        with self._lock:
            for p in self.playbooks:
                if p["id"] == pb_id:
                    p["runs"] += 1
                    p["last_run"] = datetime.now().strftime("%H:%M:%S")

    def _execution_start(self, pb_id, target, context=None, retry_of=None):
        steps = [{**s, "status": "pending", "detail": "", "updated": None}
                 for s in steps_for(pb_id)]
        with self._lock:
            self._execution_id += 1
            entry = {"id": self._execution_id, "playbook": pb_id, "target": target,
                     "status": "running", "started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                     "finished": None, "current_step": steps[0]["key"] if steps else None,
                     "steps": steps, "retry_of": retry_of,
                     "attempt": 1}
            if retry_of:
                previous, _ = self.execution_store.get(retry_of)
                entry["attempt"] = int((previous or {}).get("attempt", 1)) + 1
            self.executions.appendleft(entry)
            self.execution_store.save(entry, context or {})
        self._emit_execution(entry)
        return entry["id"]

    def _execution_step(self, run_id, key, status, detail=""):
        with self._lock:
            entry = next((e for e in self.executions if e["id"] == run_id), None)
            if not entry:
                return
            for step in entry["steps"]:
                if step["key"] == key:
                    step["status"] = status
                    step["detail"] = str(detail or "")[:300]
                    step["updated"] = datetime.now().strftime("%H:%M:%S")
                    break
            entry["current_step"] = key if status == "running" else next(
                (s["key"] for s in entry["steps"] if s["status"] == "pending"), None)
            snapshot = {**entry, "steps": [dict(s) for s in entry["steps"]]}
            self.execution_store.save(snapshot)
        self._emit_execution(snapshot)

    def _execution_finish(self, run_id, status):
        with self._lock:
            entry = next((e for e in self.executions if e["id"] == run_id), None)
            if not entry:
                return
            entry["status"] = status
            entry["current_step"] = None
            entry["finished"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            snapshot = {**entry, "steps": [dict(s) for s in entry["steps"]]}
            self.execution_store.save(snapshot)
        self._emit_execution(snapshot)

    def _emit_execution(self, entry):
        try:
            self.socketio.emit("soar_execution", entry)
        except Exception:
            pass

    def _ai_budget_ok(self):
        now = time.time()
        recent = [t for t in self._ai_calls if now - t < self.AI_TRIAGE_WINDOW]
        return len(recent) < self.AI_TRIAGE_BUDGET

    def _log_action(self, playbook, action, target, result, detail):
        with self._lock:
            self._action_id += 1
            entry = {
                "id": self._action_id,
                "playbook": playbook,
                "action": action,
                "target": target,
                "result": result,
                "detail": detail,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            self.actions.append(entry)
            self.stats["total_actions"] += 1
        self.socketio.emit("soar_action", entry)

    _PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "169.254.",
                         "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                         "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                         "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")

    @classmethod
    def _is_external(cls, ip):
        return bool(ip) and not ip.startswith(cls._PRIVATE_PREFIXES)

    @staticmethod
    def _is_cgnat(ip):
        """100.64.0.0/10 (CGNAT) — Tailscale 대역. 절대 차단 금지."""
        try:
            a, b = ip.split(".")[:2]
            return int(a) == 100 and 64 <= int(b) <= 127
        except (ValueError, IndexError):
            return False

    @staticmethod
    def _detect_own_ips():
        ips = set()
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None):
                addr = info[4][0]
                if "." in addr:
                    ips.add(addr)
        except Exception:
            pass
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
            s.close()
        except Exception:
            pass
        return ips

    def _is_blockable(self, ip):
        """차단 가능 여부 검사 (자가 락아웃 방지). 반환: (bool, 사유 or None)"""
        if not ip:
            return False, "빈 IP"
        try:
            addr = ipaddress.ip_address(str(ip))
        except ValueError:
            return False, "유효하지 않은 IP"
        if addr.version != 4 or not addr.is_global:
            return False, "공개 IPv4 아님"
        if ip.startswith(self._PRIVATE_PREFIXES):
            return False, "사설 IP"
        if self._is_cgnat(ip):
            return False, "Tailscale/CGNAT 대역"
        if ip in self._own_ips:
            return False, "서버 자신"
        for entry in self._allowlist:
            if ip == entry or (entry.endswith(".") and ip.startswith(entry)):
                return False, f"화이트리스트({entry})"
        return True, None

    # ------------------------------------------------------------------ #
    #  차단 목록 영속화
    # ------------------------------------------------------------------ #

    def _load_blocklist(self):
        try:
            if os.path.exists(self.blocklist_path):
                with open(self.blocklist_path, "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split("|", 4)
                        if len(parts) >= 4:
                            ip, mode, ts, reason = parts[0], parts[1], parts[2], parts[3]
                            expires_ts = float(parts[4]) if len(parts) == 5 else 0
                            self.blocked_ips[ip] = {
                                "reason": reason, "mode": mode, "timestamp": ts,
                                "expires_ts": expires_ts,
                                "expires": (datetime.fromtimestamp(expires_ts)
                                            .strftime("%Y-%m-%d %H:%M:%S")
                                            if expires_ts else "영구"),
                            }
        except Exception as e:
            _log.error(f"[SOAR] 차단 목록 로드 실패: {e}")

    def _save_blocklist(self):
        try:
            os.makedirs(os.path.dirname(self.blocklist_path) or ".", exist_ok=True)
            with open(self.blocklist_path, "w", encoding="utf-8") as f:
                for ip, info in self.blocked_ips.items():
                    f.write(f"{ip}|{info['mode']}|{info['timestamp']}|"
                            f"{info['reason']}|{info.get('expires_ts', 0)}\n")
        except Exception as e:
            _log.error(f"[SOAR] 차단 목록 저장 실패: {e}")
