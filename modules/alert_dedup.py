"""알림 중복제거 · 억제 레이어 — 탐지 엔진과 SOAR 사이.

## 왜 필요한가

`_add_alert` 에 이미 중복억제가 있었으나 다음 문제가 있었다.

- **조용히 drop 했다.** `return` 한 줄로 알림이 사라지고 카운트도 기록도 남지
  않았다. 나중에 "잘못 억제한 것"을 되짚을 방법이 없었다.
- `status == "OPEN"` 인 기존 알림만 억제 근거로 삼았다. SOAR 가 알림을 즉시
  자동 ACK 하므로(`soar.py:460,513`, `_add_alert` 안에서 동기 호출),
  첫 알림이 ACK 되면 이후 중복은 전부 새 알림이 됐다.
- 60초 윈도우와 `(유형, 출발지)` 키가 하드코딩이었다.
- 타임스탬프 파싱이 실패하면 `except: return` 으로 알림을 유실했다.
- 스톰 모드가 없었다.
- `stats["suppressed"]` 는 저신뢰 알림만 세어 dedup 활동이 지표에 안 보였다.

아카이브 110,748건 실측 기준, `(유형, 출발지)` 키에 5분 윈도우를 적용하면
33,616건(30.4%)이 병합된다.

## 두 개념을 분리한다

| | 대상 | 정보 손실 | CRITICAL |
|---|---|---|---|
| **dedup** | 모든 심각도 | **없음** — 알림은 남고 count 만 증가 | 적용 |
| **suppression** | 운영자가 등록한 규칙 | 실시간 표시 억제 (원문은 보관) | **제외** |

CRITICAL 을 dedup 에서까지 빼면 절감분의 대부분이 사라진다(아카이브의 55.5%가
CRITICAL). dedup 은 아무것도 잃지 않으므로 전 심각도에 적용하고, 알림을 조용하게
만드는 suppression 만 CRITICAL 을 면제한다.

## 무엇도 버리지 않는다

dedup 으로 병합된 이벤트도, suppression 으로 억제된 이벤트도 전부
`suppressed_events` 테이블에 원문째 보관한다. 조용한 누락이 가장 위험하다.
"""
import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

from modules.logging_setup import get_logger

_log = get_logger(__name__)

# 기본값 — config 로 덮어쓸 수 있다
DEFAULT_WINDOW = 300.0          # 중복 병합 윈도우(초). 실측 기준 5분에서 30.4% 병합
# 아카이브 실측상 전체 알림이 분당 최대 34건이었다. 단일 핑거프린트가 60초에
# 20건을 넘으면 명백한 스톰이다. 50 으로 두면 이 배포에서는 영원히 발동하지 않는다.
DEFAULT_STORM_THRESHOLD = 20
DEFAULT_STORM_WINDOW = 60.0     # 스톰 판정 구간(초)
DEFAULT_STORM_SUMMARY_EVERY = 300.0   # 스톰 지속 시 요약 알림 재발행 간격(초)

# 억제 규칙이 CRITICAL 을 조용하게 만들지 못하게 한다
SUPPRESSION_EXEMPT_SEVERITIES = ("CRITICAL",)

# 소스별로 details 에 흩어져 있는 룰 식별자. 앞에서부터 처음 발견되는 것을 쓴다.
_RULE_ID_KEYS = ("rule_id", "sid", "rule", "signature", "technique_id",
                 "category", "service")

# 설명 정규화: 숫자·헥스·IP·따옴표 내용을 자리표시자로 바꿔 형태만 남긴다
_RE_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_RE_HEX = re.compile(r"\b[0-9a-fA-F]{8,}\b")
_RE_NUM = re.compile(r"\d+")
_RE_WS = re.compile(r"\s+")


def normalize_description(text, limit=120):
    """설명에서 가변 값을 지우고 '형태'만 남긴다. 핑거프린트 안정화용."""
    s = str(text or "")
    s = _RE_IP.sub("<IP>", s)
    s = _RE_HEX.sub("<HEX>", s)
    s = _RE_NUM.sub("N", s)
    return _RE_WS.sub(" ", s).strip()[:limit]


def extract_rule_id(details):
    """소스마다 다른 위치에 있는 룰 식별자를 하나로 뽑는다. 없으면 빈 문자열."""
    if not isinstance(details, dict):
        return ""
    for key in _RULE_ID_KEYS:
        val = details.get(key)
        if val not in (None, "", [], {}):
            return str(val)[:80]
    return ""


def _norm_endpoint(value):
    """출발지/목적지 정규화.

    src_ip 가 항상 IP 인 것은 아니다 — SIGMA_MATCH 는 None, EDR_THREAT 는
    호스트명('mintkangaroo')을 넣는다. 실측상 이 둘이 전체의 26%를 차지하므로
    반드시 처리해야 한다.
    """
    if value in (None, "", "None"):
        return "-"
    return str(value)[:100]


def fingerprint(threat_type, src_ip, dst_ip, description, details=None):
    """중복 판정 키. 룰ID + 출발지 + 목적지 + 정규화된 설명 형태."""
    parts = (
        extract_rule_id(details),
        str(threat_type or ""),
        _norm_endpoint(src_ip),
        _norm_endpoint(dst_ip),
        normalize_description(description),
    )
    return hashlib.sha1("\x1f".join(parts).encode("utf-8")).hexdigest()


class AlertDeduplicator:
    """핑거프린트 기반 중복 병합 + 규칙 기반 억제 + 스톰 요약."""

    def __init__(self, config=None, db_path="data/alert_dedup.db"):
        cfg = config or {}
        self.window = self._num(cfg.get("DEDUP_WINDOW_SECONDS"), DEFAULT_WINDOW)
        self.storm_threshold = int(self._num(
            cfg.get("DEDUP_STORM_THRESHOLD"), DEFAULT_STORM_THRESHOLD))
        self.storm_window = self._num(
            cfg.get("DEDUP_STORM_WINDOW_SECONDS"), DEFAULT_STORM_WINDOW)
        self.storm_summary_every = self._num(
            cfg.get("DEDUP_STORM_SUMMARY_SECONDS"), DEFAULT_STORM_SUMMARY_EVERY)
        self.enabled = str(cfg.get("DEDUP_ENABLED", "True")) == "True"

        self._lock = threading.Lock()
        # fingerprint → {alert_id, first_seen, last_seen, count, storm, ...}
        self._state = {}
        # fingerprint → 최근 발생 시각 deque (스톰 판정용)
        self._recent = defaultdict(lambda: deque(maxlen=self.storm_threshold * 4))
        self.stats = {
            "seen": 0, "deduplicated": 0, "suppressed": 0,
            "storms": 0, "storm_events": 0, "passed": 0,
        }

        directory = os.path.dirname(db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
        self._init_db()
        self._seed_rules(cfg)

    @staticmethod
    def _num(value, default):
        try:
            return float(value) if value is not None else float(default)
        except (TypeError, ValueError):
            return float(default)

    # ------------------------------------------------------------------ #
    #  스키마
    # ------------------------------------------------------------------ #

    def _init_db(self):
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=10000")
            # 억제 규칙 — 하드코딩하지 않고 DB 에 둔다
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS suppression_rules (
                    id          INTEGER PRIMARY KEY,
                    name        TEXT NOT NULL,
                    threat_type TEXT DEFAULT '',
                    src_prefix  TEXT DEFAULT '',
                    rule_id     TEXT DEFAULT '',
                    desc_regex  TEXT DEFAULT '',
                    reason      TEXT DEFAULT '',
                    enabled     INTEGER DEFAULT 1,
                    created     TEXT NOT NULL,
                    hits        INTEGER DEFAULT 0
                )
            """)
            # 억제·병합된 이벤트 원문 보관 — 조용한 누락 방지
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS suppressed_events (
                    id            INTEGER PRIMARY KEY,
                    fingerprint   TEXT NOT NULL,
                    kind          TEXT NOT NULL,   -- duplicate | suppressed | storm
                    reason        TEXT DEFAULT '',
                    parent_alert  INTEGER,         -- 병합된 대상 알림 id
                    threat_type   TEXT,
                    severity      TEXT,
                    src_ip        TEXT,
                    dst_ip        TEXT,
                    description   TEXT,
                    payload       TEXT NOT NULL,   -- 알림 원문 JSON
                    ts            TEXT NOT NULL
                )
            """)
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_supp_fp ON suppressed_events(fingerprint)")
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_supp_ts ON suppressed_events(ts)")
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_supp_parent ON suppressed_events(parent_alert)")
            self._conn.commit()

    def _seed_rules(self, cfg):
        """config 의 DEDUP_SUPPRESS_RULES 를 최초 1회만 DB 에 넣는다.

        형식: "이름=유형:출발지접두:룰ID:사유; ..." (빈 칸은 와일드카드)
        이후 편집은 DB(및 API)에서 한다 — config 가 매번 덮어쓰지 않는다.
        """
        raw = str(cfg.get("DEDUP_SUPPRESS_RULES", "") or "").strip()
        if not raw:
            return
        with self._lock:
            existing = self._conn.execute(
                "SELECT COUNT(*) FROM suppression_rules").fetchone()[0]
            if existing:
                return
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for item in raw.split(";"):
                name, _, spec = item.partition("=")
                if not name.strip() or not spec.strip():
                    continue
                parts = (spec.split(":") + ["", "", "", ""])[:4]
                self._conn.execute(
                    """INSERT INTO suppression_rules
                       (name, threat_type, src_prefix, rule_id, reason, created)
                       VALUES (?,?,?,?,?,?)""",
                    (name.strip(), parts[0].strip(), parts[1].strip(),
                     parts[2].strip(), parts[3].strip() or "config 시드", now))
            self._conn.commit()

    # ------------------------------------------------------------------ #
    #  억제 규칙
    # ------------------------------------------------------------------ #

    def get_rules(self, enabled_only=False):
        sql = ("SELECT id,name,threat_type,src_prefix,rule_id,desc_regex,"
               "reason,enabled,created,hits FROM suppression_rules")
        if enabled_only:
            sql += " WHERE enabled=1"
        with self._lock:
            rows = self._conn.execute(sql + " ORDER BY id").fetchall()
        keys = ("id", "name", "threat_type", "src_prefix", "rule_id", "desc_regex",
                "reason", "enabled", "created", "hits")
        return [dict(zip(keys, r)) for r in rows]

    def add_rule(self, name, threat_type="", src_prefix="", rule_id="",
                 desc_regex="", reason=""):
        if desc_regex:
            re.compile(desc_regex)          # 잘못된 정규식은 등록 시점에 거른다
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO suppression_rules
                   (name, threat_type, src_prefix, rule_id, desc_regex, reason, created)
                   VALUES (?,?,?,?,?,?,?)""",
                (name, threat_type, src_prefix, rule_id, desc_regex, reason, now))
            self._conn.commit()
            return cur.lastrowid

    def set_rule_enabled(self, rule_id, enabled):
        with self._lock:
            self._conn.execute("UPDATE suppression_rules SET enabled=? WHERE id=?",
                               (1 if enabled else 0, int(rule_id)))
            self._conn.commit()

    def delete_rule(self, rule_id):
        with self._lock:
            self._conn.execute("DELETE FROM suppression_rules WHERE id=?", (int(rule_id),))
            self._conn.commit()

    def _match_rule(self, alert):
        """알림에 걸리는 억제 규칙을 찾는다. CRITICAL 은 규칙 억제 대상이 아니다."""
        if str(alert.get("severity", "")).upper() in SUPPRESSION_EXEMPT_SEVERITIES:
            return None
        rid = extract_rule_id(alert.get("details"))
        src = _norm_endpoint(alert.get("src_ip"))
        ttype = str(alert.get("threat_type") or "")
        desc = str(alert.get("description") or "")
        for rule in self.get_rules(enabled_only=True):
            if rule["threat_type"] and rule["threat_type"] != ttype:
                continue
            if rule["src_prefix"] and not src.startswith(rule["src_prefix"]):
                continue
            if rule["rule_id"] and rule["rule_id"] != rid:
                continue
            if rule["desc_regex"]:
                try:
                    if not re.search(rule["desc_regex"], desc):
                        continue
                except re.error:
                    continue        # 깨진 규칙이 알림을 삼키지 않게 한다
            return rule
        return None

    # ------------------------------------------------------------------ #
    #  핵심 판정
    # ------------------------------------------------------------------ #

    def evaluate(self, alert):
        """알림 1건을 판정한다.

        반환 dict:
          action      : "pass" | "duplicate" | "suppress" | "storm"
          fingerprint : 핑거프린트
          parent_id   : duplicate/storm 일 때 병합 대상 알림 id
          count       : 해당 핑거프린트의 누적 발생 수
          reason      : 사람이 읽을 사유
          storm_start : 이번 호출에서 스톰이 시작됐는지
        """
        fp = fingerprint(alert.get("threat_type"), alert.get("src_ip"),
                         alert.get("dst_ip"), alert.get("description"),
                         alert.get("details"))
        now = time.time()

        with self._lock:
            self.stats["seen"] += 1

        if not self.enabled:
            with self._lock:
                self.stats["passed"] += 1
            return {"action": "pass", "fingerprint": fp, "count": 1,
                    "reason": "dedup 비활성", "parent_id": None, "storm_start": False}

        # 1) 운영자 억제 규칙 (CRITICAL 면제)
        rule = self._match_rule(alert)
        if rule is not None:
            with self._lock:
                self.stats["suppressed"] += 1
                self._conn.execute(
                    "UPDATE suppression_rules SET hits=hits+1 WHERE id=?", (rule["id"],))
                self._conn.commit()
            reason = f"억제 규칙 '{rule['name']}'" + (f" — {rule['reason']}" if rule["reason"] else "")
            self._record(fp, "suppressed", reason, None, alert)
            return {"action": "suppress", "fingerprint": fp, "count": 0,
                    "reason": reason, "parent_id": None, "storm_start": False}

        with self._lock:
            state = self._state.get(fp)
            expired = state is None or (now - state["last_seen"]) > self.window

            # 2) 스톰 판정 — 짧은 구간에 동일 핑거프린트가 몰리는가
            recent = self._recent[fp]
            while recent and now - recent[0] > self.storm_window:
                recent.popleft()
            recent.append(now)
            storming = len(recent) > self.storm_threshold

            if expired:
                # 윈도우 밖 → 새 알림으로 통과. alert_id 는 나중에 note_alert_id 로 확정.
                self._state[fp] = {
                    "alert_id": None, "first_seen": now, "last_seen": now,
                    "count": 1, "storm": storming,
                    "last_summary": now if storming else 0.0,
                }
                self.stats["passed"] += 1
                if storming:
                    self.stats["storms"] += 1
                return {"action": "storm" if storming else "pass",
                        "fingerprint": fp, "count": 1, "parent_id": None,
                        "reason": "스톰 시작 — 요약 알림 발행" if storming else "신규",
                        "storm_start": storming}

            # 3) 윈도우 안 재발 → 병합
            state["count"] += 1
            state["last_seen"] = now
            count = state["count"]
            parent = state["alert_id"]
            was_storm = state["storm"]
            state["storm"] = storming

            if storming:
                self.stats["storm_events"] += 1
                # 스톰 지속 중 요약 알림 재발행 시점인가
                if not was_storm:
                    self.stats["storms"] += 1
                    state["last_summary"] = now
                    self.stats["passed"] += 1
                    return {"action": "storm", "fingerprint": fp, "count": count,
                            "parent_id": parent, "reason": "스톰 전환 — 요약 알림 발행",
                            "storm_start": True}
                if now - state["last_summary"] >= self.storm_summary_every:
                    state["last_summary"] = now
                    self.stats["passed"] += 1
                    return {"action": "storm", "fingerprint": fp, "count": count,
                            "parent_id": parent, "reason": "스톰 지속 — 요약 갱신",
                            "storm_start": False}

            self.stats["deduplicated"] += 1

        reason = (f"{int(self.window)}초 내 동일 핑거프린트 재발 (누적 {count}회)"
                  if not storming else f"스톰 중 병합 (누적 {count}회)")
        self._record(fp, "storm" if storming else "duplicate", reason, parent, alert)
        return {"action": "duplicate", "fingerprint": fp, "count": count,
                "parent_id": parent, "reason": reason, "storm_start": False}

    def note_alert_id(self, fingerprint_value, alert_id):
        """통과한 알림의 id 를 핑거프린트 상태에 기록한다(이후 병합 대상)."""
        with self._lock:
            state = self._state.get(fingerprint_value)
            if state is not None and state.get("alert_id") is None:
                state["alert_id"] = alert_id

    # ------------------------------------------------------------------ #
    #  보관 · 복구 조회
    # ------------------------------------------------------------------ #

    def _record(self, fp, kind, reason, parent, alert):
        """억제·병합된 이벤트를 원문째 보관한다. 실패해도 알림 처리를 막지 않는다."""
        try:
            with self._lock:
                self._conn.execute(
                    """INSERT INTO suppressed_events
                       (fingerprint, kind, reason, parent_alert, threat_type,
                        severity, src_ip, dst_ip, description, payload, ts)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (fp, kind, reason, parent, alert.get("threat_type"),
                     alert.get("severity"), alert.get("src_ip"), alert.get("dst_ip"),
                     alert.get("description"),
                     json.dumps(alert, ensure_ascii=False, default=str),
                     datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                self._conn.commit()
        except (sqlite3.Error, TypeError, ValueError) as e:
            _log.warning(f"[Dedup] 억제 이벤트 보관 실패({e}) — 핑거프린트 {fp[:12]}")

    def suppressed(self, limit=100, offset=0, kind=None, fingerprint_value=None,
                   parent_alert=None):
        """억제·병합된 이벤트 조회. 잘못 억제한 것을 되짚기 위한 경로다."""
        where, params = [], []
        if kind:
            where.append("kind = ?"); params.append(kind)
        if fingerprint_value:
            where.append("fingerprint = ?"); params.append(fingerprint_value)
        if parent_alert is not None:
            where.append("parent_alert = ?"); params.append(int(parent_alert))
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) FROM suppressed_events {clause}", params).fetchone()[0]
            rows = self._conn.execute(
                f"""SELECT id, fingerprint, kind, reason, parent_alert, threat_type,
                           severity, src_ip, dst_ip, description, payload, ts
                    FROM suppressed_events {clause}
                    ORDER BY id DESC LIMIT ? OFFSET ?""",
                params + [int(limit), int(offset)]).fetchall()
        keys = ("id", "fingerprint", "kind", "reason", "parent_alert", "threat_type",
                "severity", "src_ip", "dst_ip", "description", "payload", "ts")
        out = []
        for row in rows:
            item = dict(zip(keys, row))
            try:
                item["payload"] = json.loads(item["payload"])
            except (json.JSONDecodeError, TypeError):
                item["payload"] = {}
            out.append(item)
        return out, total

    def get_stats(self):
        with self._lock:
            s = dict(self.stats)
            active = len(self._state)
            storming = sum(1 for v in self._state.values() if v.get("storm"))
        seen = max(s["seen"], 1)
        s.update({
            "active_fingerprints": active,
            "active_storms": storming,
            "dedup_rate": round(s["deduplicated"] / seen * 100, 1),
            "suppression_rate": round(s["suppressed"] / seen * 100, 1),
            "reduction_rate": round((s["deduplicated"] + s["suppressed"]) / seen * 100, 1),
            "window_seconds": int(self.window),
            "storm_threshold": self.storm_threshold,
            "enabled": self.enabled,
        })
        return s

    def purge_older_than(self, days):
        """보관된 억제 이벤트 정리. retention 루프가 호출한다."""
        arg = f"-{int(days)} days"
        with self._lock:
            n = self._conn.execute(
                "SELECT COUNT(*) FROM suppressed_events WHERE ts < datetime('now', ?, 'localtime')",
                (arg,)).fetchone()[0]
            if n:
                self._conn.execute(
                    "DELETE FROM suppressed_events WHERE ts < datetime('now', ?, 'localtime')",
                    (arg,))
                self._conn.commit()
        return n

    def close(self):
        with self._lock:
            self._conn.close()
