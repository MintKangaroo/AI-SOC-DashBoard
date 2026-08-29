"""위협 헌팅 콘솔 — 저장된 쿼리 (docs/AUDIT.md 3단계 제안 #7).

`alert_store.search()` 가 8개 조건(심각도·상태·유형·판정·출처·IP·본문·기간)을
지원하고 `/api/alerts/history` 로 노출되어 있다. 하지만 **분석가가 매번 조건을
다시 입력해야 했다.** 헌팅은 반복 행위다 — "지난주에 봤던 그 패턴을 다시 본다"가
핵심인데, 그 '그 패턴'을 어디에도 적어둘 수 없었다.

여기서 세 가지를 한다.

1. **쿼리를 저장한다.** 분석가의 지식(무엇을 왜 찾는가)이 코드나 머릿속이 아니라
   실행 가능한 형태로 남는다.
2. **지난번 이후 새로 걸린 것만 알려준다.** 헌팅에서 실제로 궁금한 건 전체
   결과가 아니라 **델타**다. 매번 같은 100건을 다시 보면 사람은 곧 안 본다.
3. **찾은 지표를 워치리스트로 승격한다.** 헌팅 결과가 행동으로 이어지지 않으면
   그건 조회일 뿐이다.

감사는 이 기능에 선행 조건을 달았다 — `search()` 가 아카이브를 못 보면 헌팅
콘솔은 껍데기라는 것. 그건 `scope` 파라미터로 해소됐고(#13), 여기서는 기본값을
`all` 로 두어 **전체 이력 위에서** 사냥한다.
"""
import json
import os
import sqlite3
import threading
from datetime import datetime

from modules.logging_setup import get_logger

_log = get_logger(__name__)

# search() 가 받는 필터만 허용한다. 임의 키를 그대로 넘기면 TypeError 가 나거나
# 더 나쁘게는 의도치 않은 인자에 바인딩된다.
ALLOWED_FILTERS = {
    "severity", "status", "threat_type", "verdict", "origin",
    "ip", "text", "date_from", "date_to", "scope",
}

# 분석가가 처음부터 빈 화면을 보지 않도록 하는 시작 쿼리.
# 각각 "무엇을 왜 찾는가"가 설명에 들어 있다 — 헌팅 쿼리의 값어치는 조건이
# 아니라 그 이유에 있다.
STARTER_HUNTS = [
    {
        "name": "미판정 CRITICAL",
        "description": "아무도 정탐/오탐을 확정하지 않은 CRITICAL. 쌓이면 그 자체가 위험이다.",
        "filters": {"severity": "CRITICAL", "verdict": "UNREVIEWED"},
    },
    {
        "name": "재오픈된 알림",
        "description": "종료했다가 다시 열린 건. 대응이 먹히지 않았다는 신호다.",
        "filters": {"status": "OPEN", "verdict": "TRUE_POSITIVE"},
    },
    {
        "name": "웹 공격 시도",
        "description": "웹 계층 공격. 공개 서비스가 있으면 가장 먼저 두드려지는 곳이다.",
        "filters": {"threat_type": "WEB_ATTACK"},
    },
    {
        "name": "허니팟 접촉",
        "description": "유인 서비스에 닿은 건 오탐일 수 없다 — 정상 사용자는 갈 이유가 없다.",
        "filters": {"threat_type": "HONEYPOT"},
    },
    {
        "name": "YARA 악성 파일",
        "description": "파일 내용 기반 탐지. 해시로는 못 잡는 변종이 여기 걸린다.",
        "filters": {"threat_type": "MALWARE_FILE"},
    },
    {
        "name": "오탐 확정 이력",
        "description": "왜 오탐이었는지 되짚어 룰을 고치는 출발점. 튜닝의 재료다.",
        "filters": {"verdict": "FALSE_POSITIVE"},
    },
]


class HuntStore:
    """저장된 헌팅 쿼리와 실행 이력."""

    def __init__(self, db_path="data/hunts.db", alert_store=None, watchlist=None):
        directory = os.path.dirname(db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.alert_store = alert_store
        self.watchlist = watchlist
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=10000")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS hunts (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    name         TEXT NOT NULL UNIQUE,
                    description  TEXT DEFAULT '',
                    filters      TEXT NOT NULL,
                    created_at   TEXT NOT NULL,
                    created_by   TEXT DEFAULT 'system',
                    last_run_at  TEXT,
                    last_total   INTEGER DEFAULT 0,
                    -- 지난 실행에서 가장 큰 알림 id. 다음 실행의 '새로 걸린 것'
                    -- 기준선이 된다. 헌팅에서 궁금한 건 전체가 아니라 델타다.
                    last_max_id  INTEGER DEFAULT 0,
                    run_count    INTEGER DEFAULT 0
                )""")
            self._conn.commit()
        self._seed()

    # ------------------------------------------------------------------ #

    def _seed(self):
        """비어 있을 때만 시작 쿼리를 넣는다. 사용자가 지운 것을 되살리지 않는다."""
        with self._lock:
            existing = self._conn.execute("SELECT COUNT(*) FROM hunts").fetchone()[0]
        if existing:
            return
        for hunt in STARTER_HUNTS:
            self.create(hunt["name"], hunt["filters"],
                        description=hunt["description"], created_by="system")

    @staticmethod
    def sanitize_filters(filters):
        """`search()` 가 아는 키만 남긴다. (정리된 필터, 버려진 키) 반환."""
        filters = filters or {}
        clean, dropped = {}, []
        for key, value in filters.items():
            if key not in ALLOWED_FILTERS:
                dropped.append(key)
                continue
            if value in (None, ""):
                continue
            clean[key] = value
        # 헌팅은 전체 이력 위에서 한다 — 아카이브를 빼면 껍데기가 된다
        clean.setdefault("scope", "all")
        return clean, dropped

    def create(self, name, filters, description="", created_by="system"):
        name = (name or "").strip()
        if not name:
            raise ValueError("헌팅 이름이 필요합니다")
        clean, dropped = self.sanitize_filters(filters)
        if not clean or set(clean) == {"scope"}:
            raise ValueError("검색 조건이 최소 하나는 필요합니다")
        with self._lock:
            try:
                cur = self._conn.execute(
                    """INSERT INTO hunts (name, description, filters, created_at, created_by)
                       VALUES (?, ?, ?, ?, ?)""",
                    (name, description, json.dumps(clean, ensure_ascii=False),
                     datetime.now().strftime("%Y-%m-%d %H:%M:%S"), created_by))
                self._conn.commit()
            except sqlite3.IntegrityError:
                raise ValueError(f"같은 이름의 헌팅이 이미 있습니다: {name}") from None
        return {"id": cur.lastrowid, "name": name, "filters": clean, "dropped": dropped}

    def update(self, hunt_id, name=None, filters=None, description=None):
        sets, params = [], []
        if name is not None:
            sets.append("name = ?"); params.append(name.strip())
        if description is not None:
            sets.append("description = ?"); params.append(description)
        if filters is not None:
            clean, _ = self.sanitize_filters(filters)
            sets.append("filters = ?")
            params.append(json.dumps(clean, ensure_ascii=False))
        if not sets:
            return False
        params.append(int(hunt_id))
        with self._lock:
            cur = self._conn.execute(
                f"UPDATE hunts SET {', '.join(sets)} WHERE id = ?", params)
            self._conn.commit()
        return cur.rowcount == 1

    def delete(self, hunt_id):
        with self._lock:
            cur = self._conn.execute("DELETE FROM hunts WHERE id = ?", (int(hunt_id),))
            self._conn.commit()
        return cur.rowcount == 1

    def _row(self, row):
        try:
            filters = json.loads(row[3]) if row[3] else {}
        except json.JSONDecodeError:
            filters = {}
        return {"id": row[0], "name": row[1], "description": row[2],
                "filters": filters, "created_at": row[4], "created_by": row[5],
                "last_run_at": row[6], "last_total": row[7],
                "last_max_id": row[8], "run_count": row[9]}

    _COLS = ("id, name, description, filters, created_at, created_by, "
             "last_run_at, last_total, last_max_id, run_count")

    def list_all(self):
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {self._COLS} FROM hunts ORDER BY name").fetchall()
        return [self._row(r) for r in rows]

    def get(self, hunt_id):
        with self._lock:
            row = self._conn.execute(
                f"SELECT {self._COLS} FROM hunts WHERE id = ?", (int(hunt_id),)).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------ #

    def run(self, hunt_id, limit=100, mark=True):
        """헌팅 실행. 전체 결과와 **지난 실행 이후 새로 걸린 건**을 함께 준다.

        `mark=False` 면 기준선을 갱신하지 않는다 — 미리보기로 돌려볼 때 델타가
        소진되면 안 되기 때문이다.
        """
        hunt = self.get(hunt_id)
        if not hunt:
            return None
        if self.alert_store is None:
            return {**hunt, "error": "알림 저장소가 없습니다", "results": [], "total": 0}

        filters = dict(hunt["filters"])
        filters["limit"] = int(limit)
        try:
            rows, total = self.alert_store.search(**filters)
        except (TypeError, ValueError) as e:
            _log.error(f"[Hunt] '{hunt['name']}' 실행 실패: {e}")
            return {**hunt, "error": f"검색 조건 오류: {e}", "results": [], "total": 0}

        baseline = int(hunt["last_max_id"] or 0)
        new_rows = [r for r in rows if int(r.get("id") or 0) > baseline]
        max_id = max([int(r.get("id") or 0) for r in rows], default=baseline)
        ran_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if mark:
            with self._lock:
                self._conn.execute(
                    """UPDATE hunts SET last_run_at = ?, last_total = ?,
                              last_max_id = ?, run_count = run_count + 1
                       WHERE id = ?""",
                    (ran_at, total, max(max_id, baseline), int(hunt_id)))
                self._conn.commit()
        return {
            **hunt, "ran_at": ran_at, "total": total, "results": rows,
            "new_count": len(new_rows), "new_ids": [r["id"] for r in new_rows],
            "baseline_id": baseline,
            # 처음 실행이면 전부가 '새것'이라 델타가 의미 없다 — 그걸 알려준다
            "first_run": hunt["run_count"] == 0,
            "top_sources": self._top_sources(rows),
        }

    @staticmethod
    def _top_sources(rows):
        """결과에서 반복되는 출발지 — 워치리스트 승격 후보."""
        counts = {}
        for row in rows:
            ip = (row.get("src_ip") or "").strip()
            if ip and ip.count(".") == 3:
                counts[ip] = counts.get(ip, 0) + 1
        return [{"ip": ip, "count": n}
                for ip, n in sorted(counts.items(), key=lambda kv: -kv[1])[:10]]

    def promote_to_watchlist(self, value, ioc_type="ip", note="", actor="analyst"):
        """헌팅에서 찾은 지표를 워치리스트로 올린다.

        결과가 행동으로 이어지지 않으면 헌팅은 조회일 뿐이다.
        """
        if self.watchlist is None:
            return {"ok": False, "error": "워치리스트가 없습니다"}
        try:
            added = self.watchlist.add(ioc_type, value,
                                       note=note or "헌팅에서 승격", added_by=actor)
            return {"ok": bool(added), "ioc": value, "type": ioc_type}
        except Exception as e:
            _log.error(f"[Hunt] 워치리스트 승격 실패({value}): {e}")
            return {"ok": False, "error": str(e)}

    def close(self):
        with self._lock:
            self._conn.close()
