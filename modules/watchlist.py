"""IOC 워치리스트 — 분석가가 능동적으로 주시할 지표(IP/도메인/해시)를 등록하고
관제 파이프라인에서 매칭 시 히트를 집계한다.

SOAR 차단이 '사후 반응'이라면 워치리스트는 '능동 헌팅' — 아직 차단까진 아니지만
계속 지켜볼 지표를 올려두고, 등장하면 알림·집계한다.
"""
import os
import sqlite3
import threading
from datetime import datetime

VALID_TYPES = ("ip", "domain", "hash")


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Watchlist:
    def __init__(self, socketio=None, db_path="data/watchlist.db"):
        self.socketio = socketio
        directory = os.path.dirname(db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
        self._lock = threading.Lock()
        with self._lock:
            # 히트 카운터가 탐지 경로(_add_alert 대조훅)에서 갱신된다.
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=10000")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS watchlist (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type  TEXT,
                    value     TEXT UNIQUE,
                    note      TEXT DEFAULT '',
                    added_by  TEXT DEFAULT '',
                    added_at  TEXT,
                    hits      INTEGER DEFAULT 0,
                    last_hit  TEXT
                )
            """)
            self._conn.commit()
        self._cache = None      # {(type,value)} 빠른 매칭용
        self._reload_cache()

    # ---------------- 내부 캐시 ---------------- #
    def _reload_cache(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT ioc_type, value FROM watchlist").fetchall()
        # 값 → 타입 (매칭 시 타입 무관 빠른 조회)
        self._cache = {v: t for t, v in rows}

    # ---------------- CRUD ---------------- #
    def add(self, ioc_type, value, note="", added_by="system"):
        ioc_type = (ioc_type or "").strip().lower()
        value = (value or "").strip()
        if ioc_type not in VALID_TYPES or not value:
            return {"ok": False, "error": "유형(ip/domain/hash)과 값이 필요합니다"}
        try:
            with self._lock:
                self._conn.execute(
                    """INSERT INTO watchlist (ioc_type, value, note, added_by, added_at)
                       VALUES (?,?,?,?,?)""",
                    (ioc_type, value, note, added_by, _now()))
                self._conn.commit()
        except sqlite3.IntegrityError:
            return {"ok": False, "error": "이미 등록된 IOC 입니다"}
        self._reload_cache()
        return {"ok": True}

    def remove(self, ioc_id):
        with self._lock:
            cur = self._conn.execute("DELETE FROM watchlist WHERE id=?", (ioc_id,))
            self._conn.commit()
            removed = cur.rowcount > 0
        if removed:
            self._reload_cache()
        return removed

    def get(self, ioc_id):
        with self._lock:
            r = self._conn.execute(
                "SELECT value FROM watchlist WHERE id=?", (ioc_id,)).fetchone()
        return r[0] if r else None

    def list_all(self):
        with self._lock:
            rows = self._conn.execute(
                """SELECT id, ioc_type, value, note, added_by, added_at, hits, last_hit
                   FROM watchlist ORDER BY hits DESC, id DESC""").fetchall()
        items = [{"id": r[0], "type": r[1], "value": r[2], "note": r[3],
                  "added_by": r[4], "added_at": r[5], "hits": r[6], "last_hit": r[7]}
                 for r in rows]
        stats = {
            "total": len(items),
            "by_type": {t: sum(1 for i in items if i["type"] == t) for t in VALID_TYPES},
            "hit_total": sum(i["hits"] for i in items),
            "active_hits": sum(1 for i in items if i["hits"] > 0),
        }
        return items, stats

    # ---------------- 매칭 ---------------- #
    def match(self, value):
        """단일 값이 워치리스트에 있으면 타입 반환, 없으면 None."""
        if not value:
            return None
        return (self._cache or {}).get(value)

    def match_alert(self, src_ip, dst_ip):
        """알림의 src/dst 를 워치리스트와 대조. 매칭된 항목 리스트 반환 + 히트 기록."""
        hits = []
        for role, val in (("src", src_ip), ("dst", dst_ip)):
            t = self.match(val)
            if t:
                hits.append({"role": role, "type": t, "value": val})
                self._record_hit(val)
        return hits

    def _record_hit(self, value):
        with self._lock:
            self._conn.execute(
                "UPDATE watchlist SET hits = hits + 1, last_hit = ? WHERE value = ?",
                (_now(), value))
            self._conn.commit()
        if self.socketio:
            try:
                self.socketio.emit("watchlist_hit", {"value": value, "ts": _now()})
            except Exception:
                pass

    def close(self):
        with self._lock:
            self._conn.close()
