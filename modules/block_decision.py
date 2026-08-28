"""차단 결정 재현 로그 (docs/AUDIT.md 3단계 제안 C).

SOAR 가 IP 를 차단할 때 신뢰도·AI 판정·IP 평판·VirusTotal·Snort 서명·상관관계가
모두 관여하는데, 사후에 **"왜 이 IP 가 차단되었나"** 를 완전히 재구성할 수 없었다.
`soar_executions.db` 에 실행 스냅샷은 있으나 **각 입력 신호의 그 시점 값이 없다.**
자동 차단은 되돌리기 어려운 조치인데 그 근거가 휘발성이었다는 뜻이다.

여기서 두 가지를 한다.

1. **결정 시점의 모든 입력을 하나의 레코드로 고정한다.** 차단된 건만이 아니라
   **차단하지 않은 건도 남긴다** — 실무에서 더 자주 묻는 질문은 "왜 안 막았나"다.
2. **재생(replay)**: 임계값이 달랐다면 결과가 달라졌을지 같은 레코드로 다시
   계산한다. `SOAR_MIN_BLOCK_CONFIDENCE` 를 실데이터로 튜닝할 근거가 된다.

**설계 원칙: 기록된 결정이 곧 실제 결정이어야 한다.** 로그를 위해 판정을 다시
계산하면 로그와 행동이 갈라질 수 있고, 그런 로그는 없느니만 못하다. 그래서
게이트 판정을 `evaluate_gates()` 하나로 뽑고 SOAR 가 **그 결과로 차단하며**
같은 결과를 그대로 저장한다.

AI 근거 추적(제안 #6)도 여기에 포함된다 — AI 판정·모델·요약이 신호 스냅샷에
들어간다. 감사 권고대로 **프롬프트 전문은 저장하지 않는다**(알림 사본이 생긴다).
"""
import json
import os
import sqlite3
import threading
from datetime import datetime

from modules.logging_setup import get_logger

_log = get_logger(__name__)

# 게이트 정의 — 순서가 곧 UI 표시 순서다
GATE_LABELS = {
    "playbook_enabled": "플레이북 활성 (PB-AUTO-BLOCK)",
    "auto_block_on": "자동 차단 설정 켜짐",
    "severity_critical": "심각도 CRITICAL",
    "verdict_true_positive": "정탐 판정",
    "confidence": "신뢰도 임계값 충족",
    "corroboration": "독립 근거 충족",
    "not_demo": "데모 이벤트 아님",
    "external_ip": "외부 IP",
}


def evaluate_gates(*, playbook_enabled, auto_block, severity, is_true_positive,
                   confidence, min_confidence, evidence, require_corroboration,
                   is_demo, is_external):
    """차단 게이트를 평가한다. (통과여부, 게이트목록) 반환.

    **이 함수의 결과가 곧 실제 차단 여부다.** SOAR 가 이 반환값으로 행동하고
    같은 값을 결정 레코드에 남긴다 — 로그와 행동이 갈라질 여지를 없앤다.
    """
    evidence = sorted(evidence or [])
    gates = [
        {"id": "playbook_enabled", "passed": bool(playbook_enabled),
         "actual": bool(playbook_enabled), "required": True},
        {"id": "auto_block_on", "passed": bool(auto_block),
         "actual": bool(auto_block), "required": True},
        {"id": "severity_critical", "passed": severity == "CRITICAL",
         "actual": severity, "required": "CRITICAL"},
        {"id": "verdict_true_positive", "passed": bool(is_true_positive),
         "actual": bool(is_true_positive), "required": True},
        {"id": "confidence", "passed": float(confidence) >= float(min_confidence),
         "actual": float(confidence), "required": float(min_confidence)},
        {"id": "corroboration",
         "passed": (not require_corroboration) or len(evidence) >= 2,
         "actual": evidence,
         "required": 2 if require_corroboration else 0},
        {"id": "not_demo", "passed": not is_demo,
         "actual": bool(is_demo), "required": False},
        {"id": "external_ip", "passed": bool(is_external),
         "actual": bool(is_external), "required": True},
    ]
    for gate in gates:
        gate["label"] = GATE_LABELS[gate["id"]]
    return all(g["passed"] for g in gates), gates


# 게이트 통과 이후의 실제 결과 — 안전장치와 승인 큐가 여기서 갈린다
OUTCOME_LABELS = {
    "blocked": "차단됨",
    "queued_for_approval": "승인 대기 (사람 결정 필요)",
    "prevented_by_safety": "안전장치가 막음 (사설·Tailscale·화이트리스트)",
    "already_blocked": "이미 차단된 IP",
    "gates_not_met": "게이트 미충족 (차단 시도 안 함)",
    "no_ip": "출발지 IP 없음",
}


def blocking_reasons(gates):
    """차단을 막은 게이트 id 목록 — '왜 안 막았나'의 답."""
    return [g["id"] for g in gates if not g["passed"]]


class BlockDecisionLog:
    """결정 레코드 영속화 (append-only)."""

    def __init__(self, db_path="data/block_decisions.db", retention_days=365):
        directory = os.path.dirname(db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.retention_days = int(retention_days)
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=10000")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS decisions (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts         TEXT NOT NULL,
                    alert_id   INTEGER,
                    src_ip     TEXT,
                    blocked    INTEGER NOT NULL,
                    decided_by TEXT,
                    gates      TEXT NOT NULL,
                    signals    TEXT NOT NULL,
                    thresholds TEXT NOT NULL,
                    reason     TEXT DEFAULT '',
                    -- 게이트 통과 여부와 실제 결과는 다르다. 게이트를 다 통과해도
                    -- 안전장치(사설·Tailscale·화이트리스트)나 승인 큐가 차단을 막는다.
                    gates_passed INTEGER DEFAULT 0,
                    outcome      TEXT DEFAULT ''
                )""")
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_dec_ts ON decisions(ts)")
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_dec_ip ON decisions(src_ip)")
            self._conn.commit()

    # ------------------------------------------------------------------ #

    def record(self, *, alert_id, src_ip, blocked, gates, signals, thresholds,
               decided_by="AI", reason="", gates_passed=None, outcome=""):
        """결정 1건 기록. 실패해도 예외를 밖으로 내보내지 않는다.

        감사 로그를 남기지 못한다고 차단 파이프라인을 멈추는 건 본말전도다.
        """
        try:
            with self._lock:
                cur = self._conn.execute(
                    """INSERT INTO decisions
                       (ts, alert_id, src_ip, blocked, decided_by, gates, signals,
                        thresholds, reason, gates_passed, outcome)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), alert_id, src_ip,
                     1 if blocked else 0, decided_by,
                     json.dumps(gates, ensure_ascii=False),
                     json.dumps(signals, ensure_ascii=False),
                     json.dumps(thresholds, ensure_ascii=False), reason,
                     1 if (blocked if gates_passed is None else gates_passed) else 0,
                     outcome or ("blocked" if blocked else "")))
                self._conn.commit()
            return cur.lastrowid
        except Exception as e:
            _log.error(f"[BlockDecision] 결정 기록 실패: {e}")
            return None

    def _row_to_dict(self, row):
        def _load(text, default):
            try:
                return json.loads(text) if text else default
            except json.JSONDecodeError:
                return default
        gates = _load(row[6], [])
        return {
            "id": row[0], "ts": row[1], "alert_id": row[2], "src_ip": row[3],
            "blocked": bool(row[4]), "decided_by": row[5],
            "gates": gates, "signals": _load(row[7], {}),
            "thresholds": _load(row[8], {}), "reason": row[9],
            # 게이트는 통과했는데 안전장치·승인 큐에 막힌 경우를 구분한다
            "gates_passed": bool(row[10]), "outcome": row[11] or "",
            "outcome_label": OUTCOME_LABELS.get(row[11], row[11] or "-"),
            "blocked_by": blocking_reasons(gates),
        }

    _COLS = ("id, ts, alert_id, src_ip, blocked, decided_by, gates, signals, "
             "thresholds, reason, gates_passed, outcome")

    def recent(self, limit=50, blocked=None, src_ip=None):
        where, params = [], []
        if blocked is not None:
            where.append("blocked = ?"); params.append(1 if blocked else 0)
        if src_ip:
            where.append("src_ip = ?"); params.append(src_ip)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {self._COLS} FROM decisions {clause} "
                f"ORDER BY id DESC LIMIT ?", params + [int(limit)]).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get(self, decision_id):
        with self._lock:
            row = self._conn.execute(
                f"SELECT {self._COLS} FROM decisions WHERE id = ?",
                (int(decision_id),)).fetchone()
        return self._row_to_dict(row) if row else None

    def stats(self):
        with self._lock:
            total, blocked = self._conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(blocked), 0) FROM decisions").fetchone()
            rows = self._conn.execute(
                "SELECT gates FROM decisions WHERE blocked = 0").fetchall()
        # 무엇이 차단을 가장 자주 막았는가 — 임계값 튜닝의 출발점
        counts = {}
        for (gates_json,) in rows:
            try:
                gates = json.loads(gates_json)
            except json.JSONDecodeError:
                continue
            for gid in blocking_reasons(gates):
                counts[gid] = counts.get(gid, 0) + 1
        top = sorted(counts.items(), key=lambda kv: -kv[1])
        return {
            "total": total, "blocked": blocked, "skipped": total - blocked,
            "top_blockers": [{"id": gid, "label": GATE_LABELS.get(gid, gid),
                              "count": n} for gid, n in top],
        }

    # ------------------------------------------------------------------ #

    def replay(self, decision_id=None, *, record=None, min_confidence=None,
               require_corroboration=None, auto_block=None):
        """임계값을 바꿨다면 결과가 달라졌을지 같은 신호로 다시 계산한다."""
        record = record or (self.get(decision_id) if decision_id is not None else None)
        if not record:
            return None
        signals = record["signals"]
        thresholds = record["thresholds"]
        by_id = {g["id"]: g for g in record["gates"]}

        def orig(gate_id, key, default=None):
            return by_id.get(gate_id, {}).get(key, default)

        new_min = (thresholds.get("min_block_confidence") if min_confidence is None
                   else float(min_confidence))
        new_corr = (thresholds.get("require_corroboration")
                    if require_corroboration is None else bool(require_corroboration))
        new_auto = (thresholds.get("auto_block") if auto_block is None
                    else bool(auto_block))

        would_block, gates = evaluate_gates(
            playbook_enabled=orig("playbook_enabled", "actual", True),
            auto_block=new_auto,
            severity=orig("severity_critical", "actual"),
            is_true_positive=orig("verdict_true_positive", "actual", False),
            confidence=signals.get("confidence", 0),
            min_confidence=new_min,
            evidence=signals.get("evidence") or [],
            require_corroboration=new_corr,
            is_demo=signals.get("demo", False),
            is_external=orig("external_ip", "actual", False),
        )
        return {
            "decision_id": record["id"],
            "original": {"blocked": record["blocked"],
                         "thresholds": thresholds},
            "replayed": {"blocked": would_block,
                         "thresholds": {"min_block_confidence": new_min,
                                        "require_corroboration": new_corr,
                                        "auto_block": new_auto},
                         "gates": gates,
                         "blocked_by": blocking_reasons(gates)},
            "changed": would_block != record["blocked"],
        }

    def purge_older_than(self, days=None):
        days = int(self.retention_days if days is None else days)
        with self._lock:
            n = self._conn.execute(
                "SELECT COUNT(*) FROM decisions WHERE ts < datetime('now', ?, 'localtime')",
                (f"-{days} days",)).fetchone()[0]
            if n:
                self._conn.execute(
                    "DELETE FROM decisions WHERE ts < datetime('now', ?, 'localtime')",
                    (f"-{days} days",))
                self._conn.commit()
        return n

    def close(self):
        with self._lock:
            self._conn.close()
