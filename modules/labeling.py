"""라벨링 큐 — ML 재학습의 진짜 병목을 다룬다.

`scripts/eval_ml.py` 가 말하는 두 병목 중 하나는 **사람 라벨**이다. 정탐/오탐이
확정된 알림이 없으면 precision/recall 을 잴 수 없고, 재학습해도 좋아졌는지 알 수
없다. 그런데 알림이 11만 건이라 한 건씩 보는 건 불가능하다.

**실측이 설계를 바꿨다.** 11만 건을 (위협유형 · 룰ID · 정규화된 설명)으로 묶으니
**서로 다른 그룹이 67개**뿐이었다. 상위 15개가 전체의 61%를 덮는다. 즉 이건
"10만 건을 라벨링하는 문제"가 아니라 **"67개를 판정하는 문제"** 다.

## 두 가지를 정직하게 처리한다

**1. 아카이브는 그대로 둔다.** 알림 11만 건 중 대부분이 아카이브에 있는데 그건
설계상 조회 전용이다(`alert_store` 는 활성 테이블만 UPDATE 한다). 라벨을 거기
써넣는 대신 **별도 저장소**에 둔다. 라벨은 이벤트가 아니라 **분석가가 만든 산출물**
이므로 원본과 분리하는 편이 옳기도 하다.

**2. 그룹 라벨과 개별 라벨을 구분해 센다.** 한 번의 판정으로 수천 건에 라벨이
붙으면 편하지만, 그 라벨은 개별 검토보다 **약한 증거**다. 이걸 뭉뚱그려 세면
"측정 가능" 문턱을 낮은 품질의 라벨로 넘기게 된다 — 자기 지표를 스스로 속이는
짓이다. 그래서 `scope`(group/single)를 함께 저장하고 평가 스크립트가 나눠 센다.

**3. 합성 알림을 실측과 섞지 않는다.** 실측 결과 11만 건 중 **70.8%가 합성**
이었다 — 허니팟 데모(`details.demo=True`), 퍼플팀 하네스의 TEST-NET IP,
데모 평판(`Demo ISP`), 허니넷 SIMULATED 로그. 이걸 모르고 상위 그룹을 판정하면
**합성 데이터로 정답지를 만들게 된다.** ML 피처에서 이미 같은 실수가 있었다
(설정만 보고 합성 트래픽을 'real' 로 기록 — `ml_analyst._origin_of` 참조).
그래서 각 그룹이 무엇으로 이뤄져 있는지 큐가 먼저 말한다.

## 큐 순서

한 번의 판정이 **몇 건을 덮는가**로 정렬한다. 정보량이 큰 것부터 본다.
이미 라벨이 있는 그룹은 뒤로 민다.
"""
import json
import os
import re
import sqlite3
import threading
from datetime import datetime

from modules.logging_setup import get_logger

_log = get_logger(__name__)

VALID_VERDICTS = ("TRUE_POSITIVE", "FALSE_POSITIVE")
_DIGITS = re.compile(r"\d+")
_SPACES = re.compile(r"\s+")


def normalize_description(description):
    """설명에서 가변 부분(숫자)을 지워 같은 종류끼리 묶는다.

    "포트 4444 스캔"과 "포트 8080 스캔"은 분석가에게 같은 판단을 요구한다.
    """
    text = _DIGITS.sub("#", description or "")
    return _SPACES.sub(" ", text).strip()[:120]


# 문서용(RFC 5737) 대역 — 퍼플팀 하네스가 실제 공격 대신 쓰는 IP.
_TESTNET = re.compile(r"\b(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)")

PROVENANCE_SYNTHETIC = "synthetic"
PROVENANCE_REAL = "real"

_demo_descriptions = None


def _demo_catalog():
    """`threat_detector` 데모 생성기의 문구 카탈로그(정규화된 형태).

    아카이브의 알림은 origin 이 전부 'legacy' 라 저장값으로는 실측·합성을 가릴
    수 없다. 그런데 데모 생성기는 **고정된 목록**에서 문구를 고르고, 그 문구는
    실제 탐지 경로 어디에도 없다(확인함). 그래서 문구 일치가 확실한 표지가 된다.

    카탈로그를 여기 복사하지 않고 원본을 읽는다 — 복사하면 생성기가 바뀔 때
    조용히 어긋난다.
    """
    global _demo_descriptions
    if _demo_descriptions is None:
        try:
            from modules.threat_detector import ThreatDetector
            _demo_descriptions = {
                normalize_description(row[4]) for row in ThreatDetector._DEMO_THREATS
            }
        except Exception as e:                      # pragma: no cover - 방어
            _log.warning(f"[Labeling] 데모 카탈로그 로드 실패: {e}")
            _demo_descriptions = set()
    return _demo_descriptions


_demo_cmdlines = None


def _demo_cmdline_catalog():
    """EDR 데모가 주입하는 가짜 프로세스의 cmdline.

    EDR 이 데모로 돌던 시기의 알림이 아카이브에 1만 4천 건 넘게 있다. 그
    cmdline 은 고정 문자열이라 실제 프로세스가 만들어낼 수 없고, Sigma 도
    같은 프로세스 목록을 먹으므로 SIGMA_MATCH 쪽 알림까지 같이 걸러진다.
    """
    global _demo_cmdlines
    if _demo_cmdlines is None:
        try:
            from modules.edr import DEMO_THREAT_PROCESSES
            _demo_cmdlines = {p["cmdline"] for _, p in DEMO_THREAT_PROCESSES}
        except Exception as e:                      # pragma: no cover - 방어
            _log.warning(f"[Labeling] EDR 데모 카탈로그 로드 실패: {e}")
            _demo_cmdlines = set()
    return _demo_cmdlines


def classify_provenance(description, details_json, details=None, stored_origin=None):
    """이 알림이 실측인가 합성인가 — **라벨의 값어치를 정하는 정보**다.

    이 저장소는 실제 센서와 합성 생성기를 함께 돌린다(허니팟 데모, 퍼플팀
    하네스, 허니넷 SIMULATED 로그). 그건 탐지 파이프라인을 검증하려는
    의도적 설계이고 그 자체로 문제가 아니다. 문제는 **그걸 모른 채 정답지를
    만드는 것**이다. 합성 알림에 붙은 '정탐' 라벨은 생성기가 의도한 바를
    확인해 줄 뿐, 모델이 실제 침해를 잡는지에 대해서는 아무것도 말하지 않는다.

    보수적으로 판단한다 — 합성 표지가 하나라도 있으면 합성으로 본다.
    표지가 없다고 실측이 보장되는 건 아니므로 'real' 은 '합성 표지 없음'
    으로 읽어야 한다.

    반환: (PROVENANCE_*, 근거 문자열)
    """
    if details is None:
        try:
            details = json.loads(details_json or "{}")
        except (TypeError, ValueError):
            details = {}
    if not isinstance(details, dict):
        details = {}

    # 저장된 origin 이 신뢰할 만하면 그것부터 쓴다. 단 'legacy'/'unknown' 은
    # 소급 백필값이라 아무 의미가 없다 — 아카이브 11만 건이 전부 'legacy' 다.
    if stored_origin == "demo":
        return PROVENANCE_SYNTHETIC, "저장된 origin=demo"

    if details.get("demo") is True:
        return PROVENANCE_SYNTHETIC, "details.demo=True"

    blob = f"{details_json or ''}{description or ''}"
    if _TESTNET.search(blob):
        return PROVENANCE_SYNTHETIC, "TEST-NET IP(RFC 5737 문서용 대역)"
    if "Demo ISP" in blob:
        return PROVENANCE_SYNTHETIC, "데모 평판(Demo ISP)"
    if "soc_monitor" in blob:
        return PROVENANCE_SYNTHETIC, "허니넷 SIMULATED 로그"
    if normalize_description(description) in _demo_catalog():
        return PROVENANCE_SYNTHETIC, "threat_detector 데모 카탈로그 문구"
    cmdline = details.get("cmdline")
    if cmdline and cmdline in _demo_cmdline_catalog():
        return PROVENANCE_SYNTHETIC, "EDR 데모 주입 프로세스 cmdline"
    return PROVENANCE_REAL, "합성 표지 없음"


def group_key(threat_type, rule_id, description):
    return "|".join((str(threat_type or ""), str(rule_id or ""),
                     normalize_description(description)))


def _rule_id(details_json):
    try:
        details = json.loads(details_json) if details_json else {}
    except (json.JSONDecodeError, TypeError):
        return ""
    for key in ("rule_id", "sid", "signature_id"):
        if details.get(key):
            return str(details[key])
    return ""


class LabelStore:
    """분석가 라벨 — 알림 원본과 분리해 보관한다."""

    def __init__(self, db_path="data/labels.db"):
        directory = os.path.dirname(db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=10000")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS labels (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_key  TEXT NOT NULL,
                    verdict    TEXT NOT NULL,
                    -- group: 그룹 전체를 한 번에 판정 (약한 증거)
                    -- single: 알림 하나를 개별 검토 (강한 증거)
                    scope      TEXT NOT NULL DEFAULT 'group',
                    -- 그룹 라벨은 0 을 쓴다. **NULL 을 쓰면 안 된다** —
                    -- SQLite 는 UNIQUE 제약에서 NULL 을 서로 다른 값으로 보므로
                    -- 재판정이 덮어쓰지 않고 중복으로 쌓여 통계가 부풀려진다.
                    alert_id   INTEGER NOT NULL DEFAULT 0,
                    covers     INTEGER DEFAULT 0,
                    actor      TEXT NOT NULL,
                    reason     TEXT NOT NULL,
                    labeled_at TEXT NOT NULL,
                    UNIQUE(group_key, scope, alert_id)
                )""")
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_labels_group ON labels(group_key)")
            self._conn.commit()

    def put(self, key, verdict, actor, reason, scope="group", alert_id=None, covers=0):
        if verdict not in VALID_VERDICTS:
            raise ValueError(f"판정은 {VALID_VERDICTS} 중 하나여야 합니다")
        if len(str(reason).strip()) < 3:
            # 근거 없는 라벨은 나중에 되짚을 수 없다 — 알림 판정과 같은 기준을 쓴다
            raise ValueError("판정 근거를 3자 이상 적어야 합니다")
        with self._lock:
            self._conn.execute(
                """INSERT INTO labels
                   (group_key, verdict, scope, alert_id, covers, actor, reason, labeled_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(group_key, scope, alert_id) DO UPDATE SET
                     verdict=excluded.verdict, covers=excluded.covers,
                     actor=excluded.actor, reason=excluded.reason,
                     labeled_at=excluded.labeled_at""",
                (key, verdict, scope, int(alert_id or 0), int(covers), actor, reason,
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            self._conn.commit()
        return True

    def all_labels(self):
        with self._lock:
            rows = self._conn.execute(
                """SELECT group_key, verdict, scope, alert_id, covers, actor,
                          reason, labeled_at FROM labels ORDER BY id DESC""").fetchall()
        return [{"group_key": r[0], "verdict": r[1], "scope": r[2],
                 "alert_id": r[3] or None,
                 "covers": r[4], "actor": r[5], "reason": r[6], "labeled_at": r[7]}
                for r in rows]

    def by_group(self):
        return {row["group_key"]: row for row in self.all_labels()
                if row["scope"] == "group"}

    def stats(self):
        """그룹 라벨과 개별 라벨을 **나눠서** 센다.

        한 번의 그룹 판정으로 수천 건이 덮이지만 그건 개별 검토보다 약한 증거다.
        합쳐 세면 '측정 가능' 문턱을 낮은 품질로 넘기게 된다.
        """
        with self._lock:
            rows = self._conn.execute(
                """SELECT scope, verdict, COUNT(*), COALESCE(SUM(covers), 0)
                   FROM labels GROUP BY scope, verdict""").fetchall()
        out = {"group": {"decisions": 0, "covers": 0, "tp": 0, "fp": 0},
               "single": {"decisions": 0, "covers": 0, "tp": 0, "fp": 0}}
        for scope, verdict, n, covers in rows:
            bucket = out.setdefault(scope, {"decisions": 0, "covers": 0, "tp": 0, "fp": 0})
            bucket["decisions"] += n
            bucket["covers"] += covers if scope == "group" else n
            bucket["tp" if verdict == "TRUE_POSITIVE" else "fp"] += n
        return out

    def close(self):
        with self._lock:
            self._conn.close()


def build_queue(alert_store, label_store=None, limit=50, include_labeled=False,
                provenance=None):
    """라벨링 큐 — 한 번의 판정이 덮는 알림 수가 큰 것부터.

    `alert_store` 가 없으면 빈 큐를 준다. 조회는 아카이브를 포함한다
    (라벨 대상의 대부분이 거기 있다).

    `provenance="real"` 이면 합성 표지가 붙은 알림을 빼고 센다 — 실측만으로
    정답지를 만들고 싶을 때 쓴다. 기본은 전부 세되 그룹마다 구성을 함께
    돌려준다(`provenance` 필드). 어느 쪽이든 **분석가가 무엇을 판정하는지
    모르는 상태로 두지 않는 것**이 요점이다.
    """
    if alert_store is None:
        return {"groups": [], "summary": {"total_alerts": 0, "groups": 0,
                                          "labeled_groups": 0, "coverage_pct": 0.0}}
    reader = alert_store._reader()
    rows = reader.execute(
        "SELECT id, threat_type, severity, src_ip, description, details, timestamp, "
        "origin FROM alerts_all").fetchall()

    labeled = label_store.by_group() if label_store else {}
    groups = {}
    skipped_synthetic = 0
    for (alert_id, threat_type, severity, src_ip, description, details, ts,
         stored_origin) in rows:
        origin, why = classify_provenance(description, details,
                                          stored_origin=stored_origin)
        if provenance == PROVENANCE_REAL and origin == PROVENANCE_SYNTHETIC:
            skipped_synthetic += 1
            continue
        key = group_key(threat_type, _rule_id(details), description)
        g = groups.setdefault(key, {
            "key": key, "threat_type": threat_type, "rule_id": _rule_id(details),
            "description": normalize_description(description),
            "count": 0, "severities": {}, "sources": set(),
            "first_seen": ts, "last_seen": ts, "sample_alert_id": alert_id,
            "origins": {}, "origin_reasons": {},
        })
        g["count"] += 1
        g["origins"][origin] = g["origins"].get(origin, 0) + 1
        g["origin_reasons"].setdefault(origin, why)
        g["severities"][severity] = g["severities"].get(severity, 0) + 1
        if src_ip:
            g["sources"].add(src_ip)
        if ts and ts < (g["first_seen"] or ts):
            g["first_seen"] = ts
        if ts and ts > (g["last_seen"] or ts):
            g["last_seen"] = ts

    # 필터를 걸었으면 분모도 걸린 뒤 기준이어야 한다 — 안 그러면 coverage_pct 가
    # 실제보다 작게 나와 진행도를 과소평가한다.
    total_alerts = len(rows) - skipped_synthetic
    out = []
    for key, g in groups.items():
        label = labeled.get(key)
        # 출발지가 많다는 건 여러 주체가 같은 짓을 했다는 뜻이고, 하나뿐이면
        # 한 호스트의 반복이다. 분석가가 균질성을 가늠하는 데 필요한 정보다.
        out.append({
            "key": key, "threat_type": g["threat_type"], "rule_id": g["rule_id"],
            "description": g["description"], "count": g["count"],
            "unique_sources": len(g["sources"]),
            "severities": dict(sorted(g["severities"].items(), key=lambda kv: -kv[1])),
            "first_seen": g["first_seen"], "last_seen": g["last_seen"],
            "sample_alert_id": g["sample_alert_id"],
            # 이 그룹이 무엇으로 이뤄져 있는가. 합성이 섞였으면 그 라벨은
            # 실제 침해 탐지력에 대한 증거가 되지 못한다.
            "provenance": {
                "real": g["origins"].get(PROVENANCE_REAL, 0),
                "synthetic": g["origins"].get(PROVENANCE_SYNTHETIC, 0),
                "reason": g["origin_reasons"].get(PROVENANCE_SYNTHETIC, ""),
            },
            "label": label,
            "coverage_pct": round(g["count"] / total_alerts * 100, 2) if total_alerts else 0.0,
        })
    if not include_labeled:
        out = [g for g in out if not g["label"]]
    out.sort(key=lambda g: -g["count"])

    covered = sum(g["count"] for g in groups.values()
                  if labeled.get(g["key"]))
    return {
        "groups": out[:int(limit)],
        "summary": {
            "total_alerts": total_alerts,
            "groups": len(groups),
            "labeled_groups": len(labeled),
            "covered_alerts": covered,
            "coverage_pct": round(covered / total_alerts * 100, 1) if total_alerts else 0.0,
            "provenance_filter": provenance,
            "excluded_synthetic": skipped_synthetic,
            "synthetic_alerts": sum(
                g["origins"].get(PROVENANCE_SYNTHETIC, 0) for g in groups.values()),
        },
    }
