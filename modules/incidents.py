"""
인시던트(케이스) 관리 모듈

SOC 실무의 케이스 관리 워크플로:
  알림(Alert)은 개별 이벤트, 인시던트(Incident)는 대응 단위.
  SOAR가 정탐으로 판정한 알림은 (위협유형 × 출발지 /24) 단위 인시던트로
  자동 승격·병합되고, 차단 등 대응 조치가 타임라인에 기록된다.

상태 흐름: OPEN → INVESTIGATING → CONTAINED → RESOLVED
data/incidents.json 에 원자적으로 영속화하고 직전 정상본을 .bak 으로 보존한다.
"""
import os
import json
import shutil
import sqlite3
import tempfile
import threading
from datetime import datetime, timedelta

from modules.logging_setup import get_logger
from modules.telemetry import telemetry

_log = get_logger(__name__)


VALID_STATUS = ("OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED")
# 자동 종료 대상 상태 — RESOLVED 는 이미 종료된 것이므로 제외한다
_AUTO_RESOLVABLE = ("OPEN", "INVESTIGATING", "CONTAINED")
_SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _src_net(ip):
    if not ip:
        return "unknown"
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else ip


class IncidentManager:
    def __init__(self, socketio=None, store_path="data/incidents.json",
                 save_debounce_seconds=0):
        self.socketio = socketio
        self.store_path = store_path
        self._lock = threading.Lock()
        self.incidents = {}     # id → incident dict
        self._next_id = 1
        # 저장 대기 중인 인시던트 id. 매 저장마다 전량을 재직렬화하지 않기 위함.
        # 이전 구현은 self.incidents 전체를 json.dumps + upsert 했고, 실측으로
        # 23,299건 기준 저장 1회에 0.63초가 걸렸다. 그 시간 동안 self._lock 을
        # 잡고 있어 promote_alert/attach_block(= SOAR 정탐 승격 경로)이 막혔다.
        # (docs/AUDIT.md B-1)
        self._dirty = set()
        self._meta_dirty = True
        self._save_debounce_seconds = max(0, float(save_debounce_seconds or 0))
        self._save_timer = None
        self._load()

    # ------------------------------------------------------------------ #
    #  자동 승격 (SOAR 에서 호출)
    # ------------------------------------------------------------------ #

    def promote_alert(self, alert, reason="정탐 판정"):
        """정탐 알림 → 인시던트 생성 또는 기존 활성 인시던트에 병합"""
        threat_type = alert.get("threat_type", "UNKNOWN")
        net = _src_net(alert.get("src_ip"))
        severity = alert.get("severity", "MEDIUM")

        with self._lock:
            inc = self._find_active(threat_type, net)
            if inc is None:
                inc_id = self._next_id
                self._next_id += 1
                inc = {
                    "id": inc_id,
                    "title": f"{alert.get('threat_label', threat_type)} — {net}",
                    "threat_type": threat_type,
                    "src_net": net,
                    "severity": severity,
                    "status": "OPEN",
                    "assignee": "",
                    "alert_ids": [],
                    "created": _now(),
                    "updated": _now(),
                    "timeline": [{"ts": _now(), "kind": "open",
                                  "text": f"인시던트 생성 — {reason}"}],
                }
                self.incidents[inc_id] = inc
                self._meta_dirty = True      # _next_id 가 증가했다

            aid = alert.get("id")
            if aid is not None and aid not in inc["alert_ids"]:
                inc["alert_ids"].append(aid)
            # 심각도 상향만 허용
            if _SEV_ORDER.get(severity, 0) > _SEV_ORDER.get(inc["severity"], 0):
                inc["severity"] = severity
            inc["timeline"].append({
                "ts": _now(), "kind": "alert",
                "text": f"알림 #{aid} 연결 ({severity}, {alert.get('src_ip')}) — {reason}",
            })
            vt = (alert.get("details") or {}).get("virustotal") or {}
            if vt:
                inc["timeline"].append({
                    "ts": _now(), "kind": "enrich",
                    "text": (f"VirusTotal {vt.get('verdict', 'UNKNOWN')} — 악성 "
                             f"{vt.get('malicious', 0)} · 의심 {vt.get('suspicious', 0)} "
                             f"· SHA256 {str(vt.get('sha256') or vt.get('hash') or '')[:16]}…"),
                })
            inc["updated"] = _now()
            inc_id = inc["id"]
            self._dirty.add(inc_id)
            self._schedule_save()

        self._emit()
        return inc_id

    def attach_block(self, ip, reason):
        """차단 조치를 해당 대역의 활성 인시던트 타임라인에 기록"""
        net = _src_net(ip)
        changed = False
        with self._lock:
            for inc in self.incidents.values():
                if inc["src_net"] == net and inc["status"] in ("OPEN", "INVESTIGATING"):
                    inc["timeline"].append({
                        "ts": _now(), "kind": "block",
                        "text": f"IP {ip} 차단 — {reason}",
                    })
                    if inc["status"] == "OPEN":
                        inc["status"] = "INVESTIGATING"
                    inc["updated"] = _now()
                    self._dirty.add(inc["id"])
                    changed = True
            if changed:
                self._schedule_save()
        if changed:
            self._emit()
        return changed

    # ------------------------------------------------------------------ #
    #  분석가 조치
    # ------------------------------------------------------------------ #

    def update(self, inc_id, status=None, assignee=None, note=None):
        with self._lock:
            inc = self.incidents.get(inc_id)
            if not inc:
                return False
            if status:
                if status not in VALID_STATUS:
                    return False
                if status != inc["status"]:
                    inc["timeline"].append({
                        "ts": _now(), "kind": "status",
                        "text": f"상태 변경: {inc['status']} → {status}",
                    })
                    inc["status"] = status
            if assignee is not None:
                inc["assignee"] = assignee
                inc["timeline"].append({
                    "ts": _now(), "kind": "assign",
                    "text": f"담당자 지정: {assignee or '(해제)'}",
                })
            if note:
                inc["timeline"].append({"ts": _now(), "kind": "note", "text": note})
            inc["updated"] = _now()
            self._dirty.add(inc_id)
            self._save()
        self._emit()
        return True

    # ------------------------------------------------------------------ #
    #  조회
    # ------------------------------------------------------------------ #

    def get_all(self, limit=100, status=None):
        with self._lock:
            items = sorted(self.incidents.values(),
                           key=lambda i: i["updated"], reverse=True)
        if status:
            items = [i for i in items if i["status"] == status]
        return [self._summary(i) for i in items[:limit]]

    def get(self, inc_id):
        with self._lock:
            inc = self.incidents.get(inc_id)
            return dict(inc) if inc else None

    def get_stats(self):
        with self._lock:
            counts = {"total": len(self.incidents)}
            for st in VALID_STATUS:
                counts[st.lower()] = sum(
                    1 for i in self.incidents.values() if i["status"] == st)
        counts["active"] = counts["open"] + counts["investigating"]
        return counts

    @staticmethod
    def _summary(inc):
        d = {k: inc[k] for k in ("id", "title", "threat_type", "src_net",
                                 "severity", "status", "assignee",
                                 "created", "updated")}
        d["alert_count"] = len(inc["alert_ids"])
        d["timeline_count"] = len(inc["timeline"])
        return d

    # ------------------------------------------------------------------ #
    #  내부
    # ------------------------------------------------------------------ #

    def _find_active(self, threat_type, net):
        for inc in self.incidents.values():
            if (inc["threat_type"] == threat_type and inc["src_net"] == net
                    and inc["status"] in ("OPEN", "INVESTIGATING")):
                return inc
        return None

    def _emit(self):
        if self.socketio:
            try:
                self.socketio.emit("incident_update", {
                    "stats": self.get_stats(),
                    "incidents": self.get_all(30),
                })
            except Exception:
                pass

    def _load(self):
        if not self.store_path:
            return
        if self.store_path.endswith(".db"):
            return self._load_sqlite()
        candidates = (self.store_path, self.store_path + ".bak")
        last_error = None
        for path in candidates:
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                loaded = {int(k): v for k, v in data.get("incidents", {}).items()}
                self.incidents = loaded
                self._next_id = max(
                    int(data.get("next_id", 1)),
                    max(loaded.keys(), default=0) + 1,
                )
                if path.endswith(".bak"):
                    _log.warning("[Incidents] 기본 저장본 손상 — 백업에서 복구")
                    self._save(create_backup=False)
                return
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as e:
                last_error = e
        if last_error:
            _log.error(f"[Incidents] 로드 실패(백업 포함): {last_error}")

    def _save(self, create_backup=True):
        """완성된 임시 파일만 원본과 교체해 중단 시 JSON 절단을 방지한다."""
        if self.store_path.endswith(".db"):
            return self._save_sqlite()
        tmp_path = None
        try:
            directory = os.path.dirname(self.store_path) or "."
            os.makedirs(directory, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(prefix=".incidents-", suffix=".tmp",
                                            dir=directory, text=True)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"next_id": self._next_id,
                           "incidents": {str(k): v for k, v in self.incidents.items()}},
                          f, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            if create_backup and os.path.exists(self.store_path):
                try:
                    shutil.copy2(self.store_path, self.store_path + ".bak")
                except OSError:
                    pass
            os.replace(tmp_path, self.store_path)
            tmp_path = None
            if create_backup and not os.path.exists(self.store_path + ".bak"):
                try:
                    shutil.copy2(self.store_path, self.store_path + ".bak")
                except OSError:
                    pass
        except Exception as e:
            _log.error(f"[Incidents] 저장 실패: {e}")
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def _load_sqlite(self):
        """SQLite 저장소 초기화 및 기존 incidents.json 무손실 1회 이관."""
        directory = os.path.dirname(self.store_path) or "."
        os.makedirs(directory, exist_ok=True)
        self._db = sqlite3.connect(self.store_path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("""CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY, payload TEXT NOT NULL, updated TEXT NOT NULL)""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS incident_meta (
            key TEXT PRIMARY KEY, value TEXT NOT NULL)""")
        rows = self._db.execute("SELECT id, payload FROM incidents").fetchall()
        if rows:
            for inc_id, payload in rows:
                try:
                    self.incidents[int(inc_id)] = json.loads(payload)
                except (ValueError, TypeError, json.JSONDecodeError):
                    continue
            meta = self._db.execute(
                "SELECT value FROM incident_meta WHERE key='next_id'").fetchone()
            self._next_id = max(int(meta[0]) if meta else 1,
                                max(self.incidents.keys(), default=0) + 1)
            # 방금 DB 에서 읽은 것이므로 저장할 변경분이 없다
            self._dirty.clear()
            self._meta_dirty = False
            return

        legacy = os.path.splitext(self.store_path)[0] + ".json"
        if os.path.exists(legacy):
            original = self.store_path
            self.store_path = legacy
            self._load()
            self.store_path = original
            if self.incidents:
                self._mark_all_dirty()
                self._save_sqlite()
                _log.info(f"[Incidents] JSON → SQLite 무손실 이관: {len(self.incidents)}건")

    # ------------------------------------------------------------------ #
    #  보존 정리
    # ------------------------------------------------------------------ #

    def count_auto_resolvable(self, days):
        """자동 종료 대상(마지막 활동 후 N일 경과) 건수. 변경 없이 조회만."""
        cutoff = (datetime.now() - timedelta(days=int(days))).strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            return sum(1 for inc in self.incidents.values()
                       if inc.get("status") in _AUTO_RESOLVABLE
                       and str(inc.get("updated", "")) < cutoff)

    def auto_resolve_stale(self, days, limit=None):
        """마지막 활동 후 N일간 조용한 인시던트를 자동 종료한다.

        인시던트를 닫는 자동 경로가 없어 생성만 되고 절대 닫히지 않았다
        (실측 23,299건 중 RESOLVED 0건, CONTAINED 0건 — docs/AUDIT.md B-3a).
        그 결과 보존정책이 영원히 아무것도 지우지 못했고 MTTR 지표도 산출되지
        않았다. 실무 SOC 의 stale case auto-close 관행을 따른다.

        조용한 종료가 아니다 — 각 인시던트의 타임라인에 사유와 **이전 상태**를
        남기므로 나중에 되짚을 수 있다. 새 알림이 오면 `_find_active` 가
        RESOLVED 를 제외하므로 새 인시던트로 다시 열린다.

        반환: 종료 건수.
        """
        cutoff = (datetime.now() - timedelta(days=int(days))).strftime("%Y-%m-%d %H:%M:%S")
        now = _now()
        with self._lock:
            targets = [inc for inc in self.incidents.values()
                       if inc.get("status") in _AUTO_RESOLVABLE
                       and str(inc.get("updated", "")) < cutoff]
            if limit:
                targets = targets[:int(limit)]
            for inc in targets:
                previous = inc["status"]
                inc["status"] = "RESOLVED"
                inc["updated"] = now
                inc["timeline"].append({
                    "ts": now, "kind": "auto_resolve",
                    "text": (f"자동 종료 — {int(days)}일간 신규 활동 없음 "
                             f"(이전 상태: {previous})"),
                })
                self._dirty.add(inc["id"])
            if targets:
                self._save()
        if targets:
            self._emit()
        return len(targets)

    def count_purgeable(self, days):
        """정리 대상(종료된 지 N일 지난 RESOLVED) 건수. 변경 없이 조회만."""
        cutoff = (datetime.now() - timedelta(days=int(days))).strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            return sum(1 for inc in self.incidents.values()
                       if inc.get("status") == "RESOLVED"
                       and str(inc.get("updated", "")) < cutoff)

    def purge_resolved_older_than(self, days):
        """종료(RESOLVED)된 지 N일 지난 인시던트만 삭제한다.

        OPEN/INVESTIGATING/CONTAINED 는 **절대 지우지 않는다.** 진행 중인 케이스를
        지우는 것은 분석가의 작업을 소리 없이 없애는 일이다.

        메모리와 DB 양쪽에서 제거한다. 반환: 삭제 건수.
        """
        cutoff = (datetime.now() - timedelta(days=int(days))).strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            victims = [inc_id for inc_id, inc in self.incidents.items()
                       if inc.get("status") == "RESOLVED"
                       and str(inc.get("updated", "")) < cutoff]
            if not victims:
                return 0
            for inc_id in victims:
                self.incidents.pop(inc_id, None)
                self._dirty.discard(inc_id)
            if self.store_path.endswith(".db") and getattr(self, "_db", None):
                try:
                    with self._db:
                        self._db.executemany(
                            "DELETE FROM incidents WHERE id=?",
                            [(i,) for i in victims])
                except (OSError, sqlite3.Error) as e:
                    _log.error(f"[Incidents] 정리 실패({e}) — 메모리만 반영됨")
            else:
                self._save()
        self._emit()
        return len(victims)

    def _mark_all_dirty(self):
        """전량 저장이 필요할 때(최초 이관 등) 호출한다."""
        self._dirty.update(self.incidents.keys())
        self._meta_dirty = True

    def _save_sqlite(self):
        # AUDIT B-1 이 숨었던 지점 — 저장 지연을 재서 다시 숨지 않게 한다
        with telemetry.timed("incidents.save"):
            return self._save_sqlite_inner()

    def _save_sqlite_inner(self):
        """변경된 인시던트만 저장한다.

        이전 구현은 매 저장마다 self.incidents 전체를 재직렬화하고
        `DELETE ... WHERE id NOT IN (?,?,...)` 로 재조정했다. 두 가지 문제가 있었다.

        1. 실측 23,299건 기준 저장 1회 0.63초. 디바운스가 5초라 알림이 몰리면
           코어 하나의 ~13%를 변경 없는 데이터 재작성에 쓰면서, 그 시간 동안
           self._lock 을 잡아 SOAR 정탐 승격 경로를 막았다. (AUDIT B-1)
        2. `NOT IN` 의 바인드 변수가 인시던트 수만큼 늘어 SQLite 상한
           32,766(3.32+)에 걸리면 `too many SQL variables` 로 저장이 실패하는데,
           예외를 잡아 print 만 하므로 **영속화가 조용히 멈춘다**. (AUDIT B-2)

        재조정 쿼리는 제거했다. 인시던트는 프로세스 내에서 삭제되지 않으므로
        (self.incidents 에 del/pop/clear 가 0건) DB 에만 있고 메모리에 없는
        행이 생길 수 없다. 삭제 기능이 생기면 그때 삭제 목록을 따로 추적한다.
        """
        if not self._dirty and not self._meta_dirty:
            return
        pending = set(self._dirty)
        rows = [(inc_id, json.dumps(inc, ensure_ascii=False),
                 inc.get("updated", _now()))
                for inc_id in pending
                if (inc := self.incidents.get(inc_id)) is not None]
        try:
            with self._db:
                if rows:
                    self._db.executemany(
                        """INSERT INTO incidents(id,payload,updated) VALUES(?,?,?)
                           ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,
                           updated=excluded.updated""", rows)
                if self._meta_dirty:
                    self._db.execute(
                        """INSERT INTO incident_meta(key,value) VALUES('next_id',?)
                           ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                        (str(self._next_id),))
        except (OSError, sqlite3.Error, ValueError, TypeError) as e:
            # dirty 를 비우지 않는다 — 다음 저장에서 재시도한다.
            _log.error(f"[Incidents] SQLite 저장 실패: {e}")
            return
        self._dirty -= pending
        self._meta_dirty = False

    def _schedule_save(self):
        """고빈도 자동 병합은 묶어서 저장해 대형 JSON의 반복 fsync를 줄인다."""
        if not self._save_debounce_seconds:
            self._save()
            return
        if self._save_timer and self._save_timer.is_alive():
            return

        def flush():
            with self._lock:
                self._save_timer = None
                self._save()

        self._save_timer = threading.Timer(self._save_debounce_seconds, flush)
        self._save_timer.daemon = True
        self._save_timer.start()
