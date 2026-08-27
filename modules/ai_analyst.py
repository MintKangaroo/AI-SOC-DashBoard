"""
AI 보안 분석 모듈 - Claude API 기반
- 알림 자동 분석 및 위협 판단
- 자연어 보안 질의 (SOC 챗봇)
- 패킷/로그 패턴 이상 탐지 요약
- 대응 조치 추천
"""
import os
import json
import threading
import time
from datetime import datetime
from collections import deque

from modules.logging_setup import get_logger

_log = get_logger(__name__)

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False


def _num(value, default):
    try:
        return float(value) if value is not None else float(default)
    except (TypeError, ValueError):
        return float(default)


SYSTEM_PROMPT = """당신은 숙련된 SOC(Security Operations Center) 분석가 AI입니다.
실시간 보안 이벤트, 네트워크 패킷, Sysmon 로그, 위협 알림을 분석하여 다음을 제공합니다:

1. 위협 심각도 평가 (CRITICAL / HIGH / MEDIUM / LOW)
2. 공격 유형 분류 및 상세 설명
3. 즉각적 대응 조치 권고
4. 추가 조사 포인트 제시
5. 오탐(False Positive) 여부 판단

답변은 항상 한국어로, 간결하고 실용적으로 작성하세요.
JSON 형식으로 구조화된 분석 결과를 반환하세요.
"""


class AIAnalyst:
    def __init__(self, socketio, api_key=None, ml_analyst=None, config=None):
        cfg = config or {}
        self.socketio = socketio
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.model = os.getenv("AI_MODEL", "claude-sonnet-4-6")
        self.ml_analyst = ml_analyst  # AI 판정 → RL 피드백 연동
        self.client = None
        self.available = False
        self.analysis_history = deque(maxlen=100)
        self._lock = threading.Lock()
        self._queue = deque(maxlen=50)
        self._worker_thread = None
        self.running = False

        # 호출 한계 — SDK 기본은 타임아웃 10분 × 재시도 2회 = 최대 30분이다.
        # 단일 워커 큐라 한 번 막히면 그 시간만큼 트리아지 전체가 정체된다.
        self.timeout_seconds = _num(cfg.get("AI_TIMEOUT_SECONDS"), 30.0)
        self.max_retries = int(_num(cfg.get("AI_MAX_RETRIES"), 1))

        # 서킷브레이커 — 연속 실패가 쌓이면 일정 시간 호출을 멈춘다.
        # API 가 죽었을 때 매 알림마다 타임아웃을 기다리는 것을 막는다.
        self.breaker_threshold = int(_num(cfg.get("AI_BREAKER_THRESHOLD"), 3))
        self.breaker_cooldown = _num(cfg.get("AI_BREAKER_COOLDOWN"), 300.0)
        self._fail_streak = 0
        self._breaker_until = 0.0
        self._last_error = ""
        self.call_stats = {"ok": 0, "failed": 0, "skipped_breaker": 0}

        if ANTHROPIC_AVAILABLE and self.api_key:
            try:
                self.client = anthropic.Anthropic(
                    api_key=self.api_key,
                    timeout=self.timeout_seconds,
                    max_retries=self.max_retries,
                )
                self.available = True
            except Exception as e:
                _log.error(f"[AIAnalyst] Claude API 초기화 실패: {e}")

    # ------------------------------------------------------------------ #
    #  호출 회복력 (타임아웃 · 재시도 · 서킷브레이커)
    # ------------------------------------------------------------------ #

    def _breaker_open(self):
        return time.time() < self._breaker_until

    def _record_success(self):
        with self._lock:
            self._fail_streak = 0
            self._breaker_until = 0.0
            self._last_error = ""
            self.call_stats["ok"] += 1

    def _record_failure(self, message):
        with self._lock:
            self._fail_streak += 1
            self._last_error = message
            self.call_stats["failed"] += 1
            opened = False
            if self._fail_streak >= self.breaker_threshold:
                self._breaker_until = time.time() + self.breaker_cooldown
                opened = True
        if opened:
            _log.warning(f"[AIAnalyst] 연속 실패 {self._fail_streak}회 — "
                  f"{int(self.breaker_cooldown)}초간 호출 중단 (사유: {message})")

    @staticmethod
    def _describe_error(exc):
        """SDK 예외를 사람이 읽을 사유로 바꾼다.

        하나의 광범위한 except 로 잡으면 재시도 가능한 실패(429/5xx/네트워크)와
        불가능한 실패(401/400)를 구분할 수 없다. 좁은 것부터 잡는다.
        """
        if not ANTHROPIC_AVAILABLE:
            return f"{type(exc).__name__}: {exc}"
        if isinstance(exc, anthropic.APITimeoutError):
            return "응답 시간 초과"
        if isinstance(exc, anthropic.RateLimitError):
            return "요청 한도 초과(429)"
        if isinstance(exc, anthropic.AuthenticationError):
            return "인증 실패 — ANTHROPIC_API_KEY 확인 필요"
        if isinstance(exc, anthropic.PermissionDeniedError):
            return "권한 없음 — API 키 권한 확인 필요"
        if isinstance(exc, anthropic.NotFoundError):
            return f"모델/엔드포인트 없음 — AI_MODEL={os.getenv('AI_MODEL', '')} 확인"
        if isinstance(exc, anthropic.BadRequestError):
            return f"잘못된 요청(400): {exc}"
        if isinstance(exc, anthropic.APIStatusError):
            return f"API 오류({getattr(exc, 'status_code', '?')})"
        if isinstance(exc, anthropic.APIConnectionError):
            return "네트워크 연결 실패"
        return f"{type(exc).__name__}: {exc}"

    # ------------------------------------------------------------------ #

    def start(self):
        if self.running:
            return
        self.running = True
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()

    def stop(self):
        self.running = False

    def is_available(self):
        return self.available

    # ------------------------------------------------------------------ #
    #  공개 API
    # ------------------------------------------------------------------ #

    def analyze_alert(self, alert: dict, async_mode=True):
        """알림 자동 분석 (비동기 큐 or 동기)"""
        task = {"type": "alert", "data": alert}
        if async_mode:
            self._queue.append(task)
            return {"status": "queued", "alert_id": alert.get("id")}
        return self._do_analyze_alert(alert)

    def analyze_packet_summary(self, summary: dict, async_mode=True):
        """패킷 트래픽 이상 분석"""
        task = {"type": "packet", "data": summary}
        if async_mode:
            self._queue.append(task)
            return {"status": "queued"}
        return self._do_analyze_packet(summary)

    def chat(self, user_message: str, context: dict = None):
        """SOC 챗봇 — 동기 응답.

        호출자(SocketIO 핸들러·REST 라우트)의 스레드를 잡는다. 클라이언트
        타임아웃이 걸려 있어 최대 대기가 timeout × (max_retries+1) 로 제한된다
        (기본 30s × 2 = 60s). 이전에는 SDK 기본값이라 최대 30분이었다.
        """
        if not self.available or self._breaker_open():
            return self._mock_chat(user_message)
        return self._do_chat(user_message, context or {})

    def get_history(self, limit=20):
        with self._lock:
            return list(self.analysis_history)[-limit:]

    def get_status(self):
        with self._lock:
            stats = dict(self.call_stats)
            streak = self._fail_streak
            last_error = self._last_error
        remaining = max(0, int(self._breaker_until - time.time()))
        return {
            "available": self.available,
            "model": self.model if self.available else "demo",
            "queue_size": len(self._queue),
            "total_analyses": len(self.analysis_history),
            "api_key_set": bool(self.api_key),
            "resilience": {
                "timeout_seconds": self.timeout_seconds,
                "max_retries": self.max_retries,
                "breaker_open": remaining > 0,
                "breaker_reopen_in": remaining,
                "fail_streak": streak,
                "last_error": last_error,
                "calls": stats,
            },
        }

    # ------------------------------------------------------------------ #
    #  내부 분석 로직
    # ------------------------------------------------------------------ #

    def _worker_loop(self):
        while self.running:
            if self._queue:
                task = self._queue.popleft()
                try:
                    if task["type"] == "alert":
                        result = self._do_analyze_alert(task["data"])
                    elif task["type"] == "packet":
                        result = self._do_analyze_packet(task["data"])
                    else:
                        result = None

                    if result:
                        self.socketio.emit("ai_analysis", result)
                except Exception as e:
                    _log.error(f"[AIAnalyst] 분석 오류: {e}")
            time.sleep(0.5)

    def _do_analyze_alert(self, alert: dict):
        prompt = f"""다음 보안 알림을 분석하세요:

알림 유형: {alert.get('threat_type')} ({alert.get('threat_label')})
심각도: {alert.get('severity')}
출발지 IP: {alert.get('src_ip')}
목적지 IP: {alert.get('dst_ip')}
설명: {alert.get('description')}
세부정보: {json.dumps(alert.get('details', {}), ensure_ascii=False)}
발생 시각: {alert.get('timestamp')}

다음 JSON 형식으로 분석 결과를 반환하세요:
{{
  "is_true_positive": true/false,
  "confidence": 0~100,
  "attack_vector": "공격 벡터 설명",
  "impact": "예상 피해 범위",
  "immediate_actions": ["즉시 조치 1", "즉시 조치 2"],
  "investigation_points": ["조사 항목 1", "조사 항목 2"],
  "summary": "한 줄 요약"
}}"""

        return self._call_claude(prompt, "alert_analysis", alert.get("id"))

    def _do_analyze_packet(self, summary: dict):
        prompt = f"""다음 네트워크 트래픽 현황을 분석하고 이상 징후를 탐지하세요:

초당 패킷 수: {summary.get('pps', 0)}
초당 바이트: {summary.get('bps', 0)}
상위 출발지 IP: {summary.get('top_talkers', [])}
프로토콜 분포: {summary.get('protocol_dist', {})}
총 패킷: {summary.get('total_packets', 0)}

이상 징후 탐지 결과를 JSON으로 반환하세요:
{{
  "anomaly_detected": true/false,
  "anomaly_type": "이상 유형",
  "severity": "CRITICAL/HIGH/MEDIUM/LOW/NORMAL",
  "suspicious_ips": ["의심 IP 목록"],
  "recommendation": "권고 조치",
  "summary": "트래픽 분석 요약"
}}"""

        return self._call_claude(prompt, "packet_analysis", None)

    def _do_chat(self, user_message: str, context: dict):
        ctx_str = ""
        if context:
            ctx_str = f"\n현재 시스템 상태:\n{json.dumps(context, ensure_ascii=False, indent=2)}\n"

        prompt = f"{ctx_str}\n사용자 질문: {user_message}"
        result = self._call_claude(prompt, "chat", None, system_override=SYSTEM_PROMPT)
        if result and "raw_response" in result:
            return result["raw_response"]
        return result.get("summary", "분석을 완료할 수 없습니다.") if result else "오류가 발생했습니다."

    def generate_text(self, prompt, system=None, max_tokens=1200):
        """자유 서술형 텍스트 생성 (일일 리포트 등). API 없거나 차단 중이면 None."""
        if not self.available:
            return None
        if self._breaker_open():
            with self._lock:
                self.call_stats["skipped_breaker"] += 1
            _log.warning(f"[AIAnalyst] 서킷브레이커 열림 — 리포트 생성 건너뜀 "
                  f"({self._last_error})")
            return None
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system or SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as e:
            reason = self._describe_error(e)
            self._record_failure(reason)
            _log.error(f"[AIAnalyst] 리포트 생성 오류: {reason}")
            return None
        self._record_success()
        return response.content[0].text

    def _call_claude(self, prompt, analysis_type, ref_id, system_override=None):
        if not self.available:
            return self._mock_analysis(analysis_type, ref_id)
        if self._breaker_open():
            # API 가 죽었을 때 알림마다 타임아웃을 기다리지 않는다.
            # 규칙 기반 mock 으로 즉시 응답해 파이프라인을 흐르게 한다.
            with self._lock:
                self.call_stats["skipped_breaker"] += 1
            result = self._mock_analysis(analysis_type, ref_id)
            if isinstance(result, dict):
                result["degraded"] = True
                result["degraded_reason"] = f"AI 호출 중단 중 ({self._last_error})"
            return result

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=system_override or SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            content = response.content[0].text

            try:
                start = content.find("{")
                end = content.rfind("}") + 1
                if start >= 0 and end > start:
                    parsed = json.loads(content[start:end])
                else:
                    parsed = {"raw_response": content}
            except json.JSONDecodeError:
                parsed = {"raw_response": content}

            entry = {
                "type": analysis_type,
                "ref_id": ref_id,
                "result": parsed,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "model": self.model,
            }

            with self._lock:
                self.analysis_history.append(entry)

            self._feedback_to_ml(analysis_type, parsed)
            self._record_success()
            return entry

        except Exception as e:
            reason = self._describe_error(e)
            self._record_failure(reason)
            _log.error(f"[AIAnalyst] Claude API 오류: {reason}")
            result = self._mock_analysis(analysis_type, ref_id)
            if isinstance(result, dict):
                result["degraded"] = True
                result["degraded_reason"] = reason
            return result

    def _feedback_to_ml(self, analysis_type, parsed):
        """AI가 오탐/정탐을 판정하면 Q-Learning 보상 루프에 자동 반영."""
        if analysis_type != "alert_analysis" or not self.ml_analyst:
            return
        verdict = parsed.get("is_true_positive")
        if verdict is True:
            self.ml_analyst.mark_alert(is_fp=False)
        elif verdict is False:
            self.ml_analyst.mark_alert(is_fp=True)

    # ------------------------------------------------------------------ #
    #  Mock (API 키 없을 때)
    # ------------------------------------------------------------------ #

    _MOCK_ALERT_RESPONSES = [
        {
            "is_true_positive": True,
            "confidence": 87,
            "attack_vector": "외부에서 내부 네트워크로의 대량 SYN 패킷 전송",
            "impact": "서비스 가용성 저하, 네트워크 과부하",
            "immediate_actions": ["해당 IP 방화벽 차단", "업스트림 제공자에 블랙홀 라우팅 요청"],
            "investigation_points": ["공격 IP의 ASN 확인", "공격 지속 시간 측정"],
            "summary": "DDoS 공격으로 판단됨. 즉각 차단 조치 필요",
        },
        {
            "is_true_positive": True,
            "confidence": 92,
            "attack_vector": "내부 호스트에서 다수 포트 순차 접근 (TCP SYN)",
            "impact": "내부 네트워크 취약점 노출 가능성",
            "immediate_actions": ["해당 내부 호스트 격리", "악성코드 감염 여부 확인"],
            "investigation_points": ["해당 호스트의 프로세스 목록 확인", "최근 설치된 소프트웨어 확인"],
            "summary": "내부 감염 호스트의 포트 스캔 가능성 높음",
        },
        {
            "is_true_positive": False,
            "confidence": 65,
            "attack_vector": "자동화된 서비스 상태 확인으로 추정",
            "impact": "해당 없음",
            "immediate_actions": ["모니터링 지속", "화이트리스트 등록 검토"],
            "investigation_points": ["해당 서비스의 정상 동작 패턴 확인"],
            "summary": "오탐 가능성 있음. 추가 모니터링 권고",
        },
    ]

    def _mock_analysis(self, analysis_type, ref_id):
        import random
        if analysis_type == "alert_analysis":
            result = random.choice(self._MOCK_ALERT_RESPONSES)
        elif analysis_type == "packet_analysis":
            result = {
                "anomaly_detected": random.choice([True, False]),
                "anomaly_type": random.choice(["트래픽 급증", "비정상 프로토콜 비율", "정상"]),
                "severity": random.choice(["HIGH", "MEDIUM", "LOW", "NORMAL"]),
                "suspicious_ips": [f"192.168.1.{random.randint(1, 254)}"],
                "recommendation": "지속 모니터링 및 이상 IP 추적",
                "summary": "AI 데모 모드 — 실제 분석을 위해 API 키를 설정하세요",
            }
        else:
            result = {"raw_response": "AI 데모 모드입니다. ANTHROPIC_API_KEY를 .env에 설정하면 실제 Claude AI가 분석합니다."}

        entry = {
            "type": analysis_type,
            "ref_id": ref_id,
            "result": result,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "model": "demo",
        }
        with self._lock:
            self.analysis_history.append(entry)
        self._feedback_to_ml(analysis_type, result)
        return entry

    def _mock_chat(self, message):
        responses = {
            "ddos": "DDoS 공격 탐지 시 즉시 업스트림 제공자에게 블랙홀 라우팅을 요청하고, 방화벽에서 해당 IP 대역을 차단하세요.",
            "포트스캔": "포트 스캔은 공격 전 정찰 단계입니다. 해당 출발지 IP를 차단하고 내부 취약점 점검을 진행하세요.",
            "악성코드": "악성코드 감염 시 즉시 해당 호스트를 네트워크에서 격리하고, EDR/백신으로 전체 스캔을 실시하세요.",
            "default": "SOC 대시보드 AI 분석 모드입니다. ANTHROPIC_API_KEY를 .env 파일에 설정하면 Claude AI가 실제 보안 분석을 제공합니다.",
        }
        msg_lower = message.lower()
        for key, resp in responses.items():
            if key in msg_lower:
                return resp
        return responses["default"]
