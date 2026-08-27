"""트래픽 피처 영속화 — ML 재학습·평가의 전제 조건.

## 왜 필요한가

`MLAnalyst` 가 소비하는 입력은 3초 주기 트래픽 피처 8개다. 그런데 이 피처는
`deque(maxlen=60)` 로 메모리에만 존재했고(최대 3분 분량), 파일이나 DB로 저장하는
코드가 없었다. 반면 모든 정탐/오탐 라벨은 `alerts` 테이블(알림 단위)에 있다.

**즉 ML 모델의 입력 공간에는 라벨은커녕 데이터 자체가 한 건도 기록된 적이 없었다.**
이 상태에서는 실트래픽 재학습도, 홀드아웃 평가도, 룰 베이스라인 비교도 불가능하다.

이 모듈은 그 공백을 메운다. append-only 로 피처를 쌓고, 나중에 알림 시각과
조인해 약한 라벨을 만들 수 있도록 타임스탬프를 함께 저장한다.

## 설계

- SQLite WAL + busy_timeout. 단일 커넥션 + 락으로 프로세스 내 직렬화.
- 쓰기는 배치. 3초마다 한 건씩 커밋하면 fsync 가 과도하므로 버퍼에 모아
  `FLUSH_EVERY` 건마다 한 번 커밋한다.
- 보존정책은 `modules/retention.py` 가 아니라 자체 `purge_older_than()` 으로
  제공하고, retention 루프가 호출한다.
"""
import os
import sqlite3
import threading
import time
from datetime import datetime

# 저장 컬럼 순서 = MLAnalyst.FEATURE_NAMES 순서
FEATURE_COLUMNS = [
    "pps", "bps", "tcp_ratio", "udp_ratio", "icmp_ratio",
    "unique_src", "unique_dst_port", "avg_pkt_size",
]

FLUSH_EVERY = 20        # 버퍼가 이 크기가 되면 커밋 (3초 주기 → 약 1분)
FLUSH_INTERVAL = 60.0   # 버퍼가 덜 찼어도 이 시간이 지나면 커밋


class MLFeatureStore:
    def __init__(self, db_path="data/ml_features.db", flush_every=FLUSH_EVERY):
        directory = os.path.dirname(db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.db_path = db_path
        self._flush_every = max(1, int(flush_every))
        self._buffer = []
        self._last_flush = time.time()
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=10000")
            cols = ", ".join(f"{c} REAL" for c in FEATURE_COLUMNS)
            self._conn.execute(f"""
                CREATE TABLE IF NOT EXISTS features (
                    id        INTEGER PRIMARY KEY,
                    ts        TEXT NOT NULL,
                    origin    TEXT NOT NULL DEFAULT 'real',
                    {cols}
                )
            """)
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_features_ts ON features(ts)")
            self._conn.commit()

    # ------------------------------------------------------------------ #
    #  쓰기
    # ------------------------------------------------------------------ #

    def record(self, feat, origin="real", ts=None):
        """피처 벡터 1건을 버퍼에 넣고, 조건이 되면 커밋한다.

        origin: 'real'(실트래픽) | 'demo'(합성 트래픽). 재학습 시 demo 를 제외할 수
        있어야 하므로 반드시 구분해 저장한다.
        """
        if feat is None or len(feat) != len(FEATURE_COLUMNS):
            return False
        row = (ts or datetime.now().strftime("%Y-%m-%d %H:%M:%S"), origin,
               *(float(v) for v in feat))
        with self._lock:
            self._buffer.append(row)
            due = (len(self._buffer) >= self._flush_every
                   or time.time() - self._last_flush >= FLUSH_INTERVAL)
            if due:
                self._flush_locked()
        return True

    def flush(self):
        with self._lock:
            self._flush_locked()

    def _flush_locked(self):
        if not self._buffer:
            self._last_flush = time.time()
            return 0
        placeholders = ", ".join("?" for _ in range(len(FEATURE_COLUMNS) + 2))
        cols = ", ".join(["ts", "origin"] + FEATURE_COLUMNS)
        try:
            self._conn.executemany(
                f"INSERT INTO features({cols}) VALUES ({placeholders})", self._buffer)
            self._conn.commit()
            n = len(self._buffer)
        except sqlite3.Error as e:
            print(f"[MLFeatureStore] 저장 실패({e}) — 버퍼 {len(self._buffer)}건 폐기")
            n = 0
        self._buffer.clear()
        self._last_flush = time.time()
        return n

    # ------------------------------------------------------------------ #
    #  읽기
    # ------------------------------------------------------------------ #

    def count(self, origin=None):
        with self._lock:
            if origin:
                return self._conn.execute(
                    "SELECT COUNT(*) FROM features WHERE origin = ?",
                    (origin,)).fetchone()[0]
            return self._conn.execute("SELECT COUNT(*) FROM features").fetchone()[0]

    def load(self, origin=None, limit=None, since=None):
        """(ts, origin, feat...) 행을 시간 오름차순으로 반환한다."""
        where, params = [], []
        if origin:
            where.append("origin = ?"); params.append(origin)
        if since:
            where.append("ts >= ?"); params.append(since)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        sql = (f"SELECT ts, origin, {', '.join(FEATURE_COLUMNS)} FROM features "
               f"{clause} ORDER BY id ASC")
        if limit:
            sql += f" LIMIT {int(limit)}"
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def stats(self):
        """수집 현황 — 재학습 가능 여부 판단용."""
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM features").fetchone()[0]
            real = self._conn.execute(
                "SELECT COUNT(*) FROM features WHERE origin='real'").fetchone()[0]
            oldest, newest = self._conn.execute(
                "SELECT MIN(ts), MAX(ts) FROM features").fetchone()
            pending = len(self._buffer)
        return {
            "total": total, "real": real, "demo": total - real,
            "pending": pending, "oldest": oldest, "newest": newest,
        }

    # ------------------------------------------------------------------ #
    #  보존
    # ------------------------------------------------------------------ #

    def purge_older_than(self, days):
        """N일 이전 피처를 삭제한다. 반환: 삭제 건수."""
        arg = f"-{int(days)} days"
        with self._lock:
            n = self._conn.execute(
                "SELECT COUNT(*) FROM features WHERE ts < datetime('now', ?, 'localtime')",
                (arg,)).fetchone()[0]
            if n:
                self._conn.execute(
                    "DELETE FROM features WHERE ts < datetime('now', ?, 'localtime')",
                    (arg,))
                self._conn.commit()
        return n

    def close(self):
        self.flush()
        with self._lock:
            self._conn.close()
