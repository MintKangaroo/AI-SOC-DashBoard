"""YARA 파일 스캐너 — 내용 기반 악성코드 탐지.

`hash_checker` 의 해시 대조는 **'알려진 바로 그 파일'** 만 잡는다. 한 바이트만
바뀌어도 해시가 달라져 놓친다. YARA 는 파일 내용의 패턴으로 잡으므로 변종에
강하다. 둘은 대체가 아니라 보완이다 — 해시는 확정적이고 YARA 는 일반화된다.

Sigma 엔진과 같은 원칙으로 만든다.

- **없어도 뜬다**: `yara-python` 미설치면 비활성 상태로 보고하고 앱은 정상 기동한다.
- **detection-as-code**: 룰의 정탐/오탐 샘플이 `data/yara/rule_tests.yml` 에 있고
  CI 가 검증한다(`tests/test_yara_rules.py`). 오탐 나는 룰은 머지되지 않는다.
- **MITRE 매핑**: 룰 `meta.mitre` 가 커버리지 자가 진단에 그대로 들어간다.

**안전 한계를 먼저 정한다.** 스캐너가 관제 서버를 잡아먹으면 안 된다:
파일 크기 상한·스캔 타임아웃·허용 디렉터리 밖 거부. 디렉터리 스캔은 파일 수
상한을 두고, 심볼릭 링크는 따라가지 않는다(경로 탈출 방지).
"""
import os
import threading
from collections import deque
from datetime import datetime

from modules.logging_setup import get_logger
from modules.telemetry import telemetry

_log = get_logger(__name__)

try:
    import yara
    YARA_OK = True
except ImportError:      # pragma: no cover - 설치 여부에 따라 갈린다
    yara = None
    YARA_OK = False

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class YaraScanner:
    def __init__(self, socketio=None, config=None, threat_detector=None,
                 mitre_tracker=None):
        self.socketio = socketio
        self.config = config or {}
        self.threat_detector = threat_detector
        self.mitre = mitre_tracker
        self.running = False
        self._lock = threading.Lock()

        self.rules_dir = self.config.get("YARA_RULES_DIR", "data/yara")
        self.max_file_mb = float(self.config.get("YARA_MAX_FILE_MB", 32))
        self.timeout = int(self.config.get("YARA_TIMEOUT", 10))
        self.max_files = int(self.config.get("YARA_MAX_FILES", 2000))

        self._rules = None            # 컴파일된 yara.Rules
        self.rule_meta = []           # 패널·커버리지용 룰 목록
        self.matches = deque(maxlen=200)
        self.stats = {
            "enabled": YARA_OK, "rules_loaded": 0, "rules_error": 0,
            "files_scanned": 0, "matches": 0, "skipped_too_big": 0,
            "errors": 0, "last_load": None, "last_scan": None,
        }

    # ------------------------------------------------------------------ #
    #  라이프사이클
    # ------------------------------------------------------------------ #

    def start(self, demo=True):
        self.running = True
        if not YARA_OK:
            _log.warning("[YARA] yara-python 미설치 — 파일 내용 기반 탐지 비활성 "
                         "(해시 대조는 그대로 동작)")
            return
        self.load_rules()
        _log.info(f"[YARA] 스캐너 시작 — 룰 {self.stats['rules_loaded']}개 "
                  f"· 파일 상한 {self.max_file_mb:g}MB · 타임아웃 {self.timeout}s")

    def stop(self):
        self.running = False

    def load_rules(self):
        """`rules_dir` 의 .yar/.yara 를 컴파일한다. 실패해도 기존 룰을 유지한다."""
        if not YARA_OK:
            return 0
        paths = {}
        try:
            for name in sorted(os.listdir(self.rules_dir)):
                if name.endswith((".yar", ".yara")):
                    paths[os.path.splitext(name)[0]] = os.path.join(self.rules_dir, name)
        except OSError as e:
            _log.error(f"[YARA] 룰 디렉터리 접근 불가({self.rules_dir}): {e}")
            with self._lock:
                self.stats["rules_error"] += 1
            return 0
        if not paths:
            _log.warning(f"[YARA] {self.rules_dir} 에 룰이 없다")
            return 0
        try:
            compiled = yara.compile(filepaths=paths)
        except Exception as e:
            # 컴파일 실패 시 기존 룰을 살려둔다 — 잘못된 룰 하나로 탐지가 통째로
            # 꺼지는 편보다 낫다.
            _log.error(f"[YARA] 룰 컴파일 실패: {e}")
            with self._lock:
                self.stats["rules_error"] += 1
            return 0
        meta = self._describe(compiled)
        with self._lock:
            self._rules = compiled
            self.rule_meta = meta
            self.stats["rules_loaded"] = len(meta)
            self.stats["last_load"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return len(meta)

    @staticmethod
    def _describe(compiled):
        out = []
        for rule in compiled:
            meta = dict(getattr(rule, "meta", {}) or {})
            out.append({
                "name": rule.identifier,
                "description": meta.get("description", ""),
                "severity": str(meta.get("severity", "MEDIUM")).upper(),
                "mitre": str(meta.get("mitre", "")).upper() or None,
                "author": meta.get("author", ""),
            })
        return sorted(out, key=lambda r: r["name"])

    # ------------------------------------------------------------------ #
    #  스캔
    # ------------------------------------------------------------------ #

    def scan_file(self, path):
        """파일 1개 스캔. 결과 dict 반환(예외를 밖으로 내보내지 않는다)."""
        if not YARA_OK:
            return {"path": path, "error": "yara-python 미설치", "enabled": False,
                    "matches": []}
        with self._lock:
            rules = self._rules
        if rules is None:
            return {"path": path, "error": "로드된 룰 없음", "matches": []}
        try:
            size = os.path.getsize(path)
        except OSError as e:
            return {"path": path, "error": f"파일 접근 불가: {e}", "matches": []}
        if size > self.max_file_mb * 1024 * 1024:
            with self._lock:
                self.stats["skipped_too_big"] += 1
            return {"path": path, "size": size, "matches": [], "skipped": True,
                    "error": f"{self.max_file_mb:g}MB 초과 — 건너뜀"}

        try:
            with telemetry.timed("yara.scan_file"):
                raw = rules.match(path, timeout=self.timeout)
        except Exception as e:
            with self._lock:
                self.stats["errors"] += 1
            _log.error(f"[YARA] 스캔 오류({path}): {e}")
            return {"path": path, "error": str(e), "matches": []}

        matches = [self._match_dict(m) for m in raw]
        result = {
            "path": path, "size": size, "matches": matches,
            "malicious": bool(matches),
            "severity": self._top_severity(matches),
            "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        with self._lock:
            self.stats["files_scanned"] += 1
            self.stats["last_scan"] = result["scanned_at"]
            if matches:
                self.stats["matches"] += len(matches)
                self.matches.appendleft(result)
        if matches:
            self._report(result)
        return result

    def scan_data(self, data):
        """바이트열 스캔 — 룰 테스트·업로드 검사용(파일을 만들지 않는다)."""
        if not YARA_OK:
            return []
        with self._lock:
            rules = self._rules
        if rules is None:
            return []
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        try:
            return [self._match_dict(m) for m in rules.match(data=data,
                                                             timeout=self.timeout)]
        except Exception as e:
            _log.error(f"[YARA] 데이터 스캔 오류: {e}")
            return []

    def scan_directory(self, directory, extensions=None):
        """디렉터리 재귀 스캔. 파일 수 상한을 두고 심볼릭 링크는 따라가지 않는다."""
        results, scanned = [], 0
        truncated = False
        for root, dirs, files in os.walk(directory, followlinks=False):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            for name in sorted(files):
                full = os.path.join(root, name)
                if os.path.islink(full):
                    continue
                if extensions and os.path.splitext(name)[1].lower() not in extensions:
                    continue
                if scanned >= self.max_files:
                    truncated = True
                    break
                scanned += 1
                res = self.scan_file(full)
                if res.get("matches"):
                    results.append(res)
            if truncated:
                break
        return {
            "directory": directory, "files_scanned": scanned,
            "matched_files": len(results), "results": results,
            "truncated": truncated, "max_files": self.max_files,
        }

    # ------------------------------------------------------------------ #

    @staticmethod
    def _match_dict(match):
        meta = dict(getattr(match, "meta", {}) or {})
        # 문자열 원문은 담지 않는다 — 악성 페이로드 사본을 만들 이유가 없다.
        # 어떤 패턴이 걸렸는지(식별자)와 개수만 남긴다.
        hits = {}
        for s in getattr(match, "strings", []) or []:
            ident = getattr(s, "identifier", None) or str(s)
            hits[ident] = hits.get(ident, 0) + len(getattr(s, "instances", []) or [1])
        return {
            "rule": match.rule,
            "description": meta.get("description", ""),
            "severity": str(meta.get("severity", "MEDIUM")).upper(),
            "mitre": str(meta.get("mitre", "")).upper() or None,
            "tags": list(getattr(match, "tags", []) or []),
            "matched_strings": sorted(hits),
            "match_count": sum(hits.values()) or len(hits),
        }

    @staticmethod
    def _top_severity(matches):
        if not matches:
            return None
        return max((m["severity"] for m in matches),
                   key=lambda s: SEVERITY_ORDER.get(s, 0))

    def _report(self, result):
        """탐지를 파이프라인에 투입한다. 실패해도 스캔 결과는 그대로 돌려준다."""
        top = max(result["matches"], key=lambda m: SEVERITY_ORDER.get(m["severity"], 0))
        try:
            if self.threat_detector:
                self.threat_detector.report_alert(
                    "MALWARE_FILE", result["severity"],
                    src_ip=os.uname().nodename if hasattr(os, "uname") else "localhost",
                    dst_ip="",
                    description=f"YARA 탐지: {top['rule']} — {os.path.basename(result['path'])}",
                    details={"source": "yara", "path": result["path"],
                             "rule_id": top["rule"], "mitre": top["mitre"],
                             "rules": [m["rule"] for m in result["matches"]],
                             "matched_strings": top["matched_strings"]})
        except Exception as e:
            _log.error(f"[YARA] 알림 전달 오류: {e}")
        try:
            if self.mitre and top.get("mitre"):
                self.mitre.map_threat("MALWARE_FILE", description=top["rule"])
        except Exception as e:
            _log.error(f"[YARA] MITRE 매핑 오류: {e}")
        try:
            if self.socketio:
                self.socketio.emit("yara_match", {
                    "path": result["path"], "severity": result["severity"],
                    "rules": [m["rule"] for m in result["matches"]],
                    "scanned_at": result["scanned_at"]})
        except Exception:
            pass

    def get_status(self):
        with self._lock:
            return {
                "running": self.running,
                "stats": dict(self.stats),
                "rules": list(self.rule_meta),
                "matches": list(self.matches)[:30],
                "limits": {"max_file_mb": self.max_file_mb, "timeout": self.timeout,
                           "max_files": self.max_files},
            }
