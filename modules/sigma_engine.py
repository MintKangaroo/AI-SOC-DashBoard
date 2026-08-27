"""
Sigma 룰 엔진 — 업계 표준 탐지룰 포맷

Sigma(https://sigmahq.io)는 SIEM 중립적인 YAML 탐지룰 표준이다.
이 모듈은 data/sigma/*.yml 의 Sigma 룰을 로드해 이벤트(주로 프로세스 생성)에
매칭하고, 매치되면 threat_detector 파이프라인(AI 트리아지→SOAR)에 투입한다.

지원 범위(실전 룰 대부분 커버하는 실용적 subset):
  - detection: 이름있는 selection 맵 + condition 문자열
  - 필드 수정자: |contains |startswith |endswith |re |all
  - 값: 스칼라(=), 리스트(OR, |all이면 AND)
  - condition: and / or / not / 괄호 / "1 of them" / "all of them" / "1 of sel*"

PyYAML 없으면 비활성(데모 fallback: 내장 룰 로드도 YAML 필요하므로 graceful off).
"""
import os
import re
import glob
import threading
from datetime import datetime
from collections import deque

from modules.logging_setup import get_logger

_log = get_logger(__name__)

try:
    import yaml
    YAML_OK = True
except ImportError:
    YAML_OK = False


# 첫 실행 시 data/sigma 에 심어줄 샘플 룰 (EDR 데모 프로세스와 매칭되도록 구성)
BUNDLED_RULES = {
"lnx_reverse_shell.yml": """
title: Linux Reverse Shell via /dev/tcp
id: 7c2e2b6a-1f3a-4c11-9d21-aa11bb22cc01
status: stable
description: bash/sh 가 /dev/tcp 로 리버스 셸을 여는 패턴
level: critical
logsource:
  product: linux
  category: process_creation
tags:
  - attack.execution
  - attack.t1059.004
detection:
  selection:
    CommandLine|contains:
      - '/dev/tcp/'
      - 'bash -i'
      - 'sh -i'
  condition: selection
""",
"lnx_download_exec.yml": """
title: Linux Download and Execute (curl/wget pipe to shell)
id: 7c2e2b6a-1f3a-4c11-9d21-aa11bb22cc02
status: stable
description: curl/wget 로 받아 바로 셸로 파이프하는 다운로드-실행
level: high
logsource:
  product: linux
  category: process_creation
tags:
  - attack.command_and_control
  - attack.t1105
detection:
  selection_tool:
    CommandLine|contains:
      - 'curl '
      - 'wget '
  selection_pipe:
    CommandLine|contains:
      - '| bash'
      - '| sh'
      - '|bash'
      - '|sh'
  condition: selection_tool and selection_pipe
""",
"lnx_webshell_spawn.yml": """
title: Web Server Spawning Shell (Webshell)
id: 7c2e2b6a-1f3a-4c11-9d21-aa11bb22cc03
status: stable
description: nginx/apache/php 가 셸을 자식으로 실행 — 웹셸/RCE 의심
level: critical
logsource:
  product: linux
  category: process_creation
tags:
  - attack.persistence
  - attack.t1505.003
detection:
  selection_parent:
    ParentImage|endswith:
      - 'nginx'
      - 'apache2'
      - 'httpd'
      - 'php-fpm'
  selection_shell:
    Image|endswith:
      - '/bash'
      - '/sh'
      - '/dash'
  condition: selection_parent and selection_shell
""",
"lnx_cryptominer.yml": """
title: Cryptominer Execution
id: 7c2e2b6a-1f3a-4c11-9d21-aa11bb22cc04
status: stable
description: xmrig/minerd 등 크립토 마이너 실행 또는 마이닝 풀 접속
level: high
logsource:
  product: linux
  category: process_creation
tags:
  - attack.impact
  - attack.t1496
detection:
  selection_bin:
    Image|contains:
      - 'xmrig'
      - 'minerd'
  selection_pool:
    CommandLine|contains:
      - 'pool'
      - 'stratum+tcp'
      - 'minexmr'
  condition: selection_bin or selection_pool
""",
"lnx_scanner.yml": """
title: Network Scanner Execution
id: 7c2e2b6a-1f3a-4c11-9d21-aa11bb22cc05
status: experimental
description: nmap/masscan 등 스캐너 실행
level: medium
logsource:
  product: linux
  category: process_creation
tags:
  - attack.discovery
  - attack.t1046
detection:
  selection:
    Image|endswith:
      - '/nmap'
      - '/masscan'
  condition: selection
""",
}


class SigmaEngine:
    def __init__(self, socketio, config=None, threat_detector=None, mitre_tracker=None):
        self.socketio = socketio
        self.config = config or {}
        self.threat_detector = threat_detector
        self.mitre = mitre_tracker
        self.running = False
        self._lock = threading.Lock()

        self.rules_dir = self.config.get("SIGMA_RULES_DIR", "data/sigma")
        self.rules = []            # 파싱된 룰
        self.matches = deque(maxlen=300)
        self._match_id = 0
        self._seen = set()         # (rule_id, dedup) 중복 억제
        self.stats = {
            "enabled": YAML_OK,
            "rules_loaded": 0,
            "rules_error": 0,
            "evaluations": 0,
            "matches": 0,
            "last_load": None,
        }

    # ------------------------------------------------------------------ #
    #  라이프사이클
    # ------------------------------------------------------------------ #

    def start(self, demo=True):
        self.running = True
        if not YAML_OK:
            _log.warning("[Sigma] PyYAML 미설치 — Sigma 엔진 비활성(룰 파싱 불가)")
            return
        self._bundle_default_rules()
        self.load_rules()
        _log.info(f"[Sigma] 룰 엔진 시작 — {self.stats['rules_loaded']}개 룰 로드")

    def stop(self):
        self.running = False

    def _bundle_default_rules(self):
        try:
            os.makedirs(self.rules_dir, exist_ok=True)
            existing = glob.glob(os.path.join(self.rules_dir, "*.yml"))
            if existing:
                return
            for fname, content in BUNDLED_RULES.items():
                with open(os.path.join(self.rules_dir, fname), "w", encoding="utf-8") as f:
                    f.write(content.lstrip())
        except Exception as e:
            _log.error(f"[Sigma] 기본 룰 생성 실패: {e}")

    # ------------------------------------------------------------------ #
    #  룰 로드
    # ------------------------------------------------------------------ #

    def load_rules(self):
        if not YAML_OK:
            return
        rules, errors = [], 0
        for path in sorted(glob.glob(os.path.join(self.rules_dir, "*.yml"))
                           + glob.glob(os.path.join(self.rules_dir, "*.yaml"))):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    doc = yaml.safe_load(f)
                if not doc or "detection" not in doc:
                    continue
                rules.append(self._normalize_rule(doc, path))
            except Exception as e:
                errors += 1
                _log.error(f"[Sigma] 룰 파싱 오류 {os.path.basename(path)}: {e}")
        with self._lock:
            self.rules = rules
            self.stats["rules_loaded"] = len(rules)
            self.stats["rules_error"] = errors
            self.stats["last_load"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._emit_status()
        return rules

    @staticmethod
    def _normalize_rule(doc, path):
        det = doc.get("detection", {})
        tags = doc.get("tags", []) or []
        mitre = [t.replace("attack.", "").upper() for t in tags if isinstance(t, str)
                 and t.lower().startswith("attack.t")]
        return {
            "id": doc.get("id", os.path.basename(path)),
            "file": os.path.basename(path),
            "title": doc.get("title", "(제목 없음)"),
            "level": (doc.get("level") or "medium").lower(),
            "status": doc.get("status", "unknown"),
            "description": doc.get("description", ""),
            "logsource": doc.get("logsource", {}),
            "tags": tags,
            "mitre": mitre,
            "detection": det,
            "condition": det.get("condition", ""),
            "enabled": True,
        }

    # ------------------------------------------------------------------ #
    #  조회
    # ------------------------------------------------------------------ #

    def get_status(self):
        with self._lock:
            return {
                "stats": dict(self.stats),
                "rules": [{k: r[k] for k in
                           ("id", "file", "title", "level", "status", "mitre", "enabled")}
                          for r in self.rules],
                "matches": list(reversed(list(self.matches)))[:50],
            }

    def toggle_rule(self, rule_id):
        with self._lock:
            for r in self.rules:
                if r["id"] == rule_id:
                    r["enabled"] = not r["enabled"]
                    return r["enabled"]
        return None

    # ------------------------------------------------------------------ #
    #  매칭 진입점
    # ------------------------------------------------------------------ #

    def evaluate(self, event):
        """정규화된 이벤트(dict)를 모든 활성 룰에 평가. 매치된 룰 리스트 반환."""
        if not YAML_OK:
            return []
        with self._lock:
            rules = [r for r in self.rules if r["enabled"]]
            self.stats["evaluations"] += 1
        matched = []
        for rule in rules:
            try:
                if self._match_rule(rule, event):
                    matched.append(rule)
            except Exception as e:
                _log.error(f"[Sigma] 평가 오류({rule.get('file')}): {e}")
        for rule in matched:
            self._record_match(rule, event)
        return matched

    def feed_process(self, proc):
        """EDR 프로세스 스냅샷을 process_creation 이벤트로 정규화 후 평가."""
        cmd = proc.get("cmdline") or ""
        name = proc.get("name") or ""
        exe = proc.get("exe_path") or name
        parent = proc.get("parent") or ""
        event = {
            "category": "process_creation",
            "Image": exe,
            "OriginalFileName": name,
            "CommandLine": cmd,
            "ParentImage": parent,
            "User": proc.get("user") or "",
            "_pid": proc.get("pid"),
        }
        return self.evaluate(event)

    def test_event(self, fields):
        """UI 수동 테스트: 임의 필드 dict 를 룰에 평가(파이프라인 투입 없이 결과만)."""
        if not YAML_OK:
            return []
        with self._lock:
            rules = [r for r in self.rules if r["enabled"]]
        out = []
        for rule in rules:
            try:
                if self._match_rule(rule, fields):
                    out.append({"id": rule["id"], "title": rule["title"],
                                "level": rule["level"], "mitre": rule["mitre"]})
            except Exception:
                pass
        return out

    # ------------------------------------------------------------------ #
    #  매칭 엔진
    # ------------------------------------------------------------------ #

    def _match_rule(self, rule, event):
        det = rule["detection"]
        sel_results = {}
        for name, spec in det.items():
            if name == "condition":
                continue
            sel_results[name] = self._match_selection(spec, event)
        return self._eval_condition(rule["condition"], sel_results)

    def _match_selection(self, spec, event):
        # spec 이 리스트면 각 항목(맵) 중 하나라도 참이면 참(OR)
        if isinstance(spec, list):
            return any(self._match_selection(s, event) for s in spec)
        if not isinstance(spec, dict):
            return False
        # 맵의 모든 (필드:값) 이 참이어야 함(AND)
        for key, want in spec.items():
            field, mods = self._split_key(key)
            have = event.get(field)
            if not self._match_field(have, want, mods):
                return False
        return True

    @staticmethod
    def _split_key(key):
        parts = key.split("|")
        return parts[0], [m.lower() for m in parts[1:]]

    def _match_field(self, have, want, mods):
        if have is None:
            return False
        have_s = str(have)
        # 리스트 값: |all 이면 모두(AND), 아니면 하나라도(OR)
        if isinstance(want, list):
            checks = [self._match_scalar(have_s, str(w), mods) for w in want]
            return all(checks) if "all" in mods else any(checks)
        return self._match_scalar(have_s, str(want), mods)

    @staticmethod
    def _match_scalar(have_s, want_s, mods):
        h, w = have_s.lower(), want_s.lower()
        if "contains" in mods:
            return w in h
        if "startswith" in mods:
            return h.startswith(w)
        if "endswith" in mods:
            return h.endswith(w)
        if "re" in mods:
            try:
                return re.search(want_s, have_s) is not None
            except re.error:
                return False
        return h == w   # 기본: 완전 일치(대소문자 무시)

    def _eval_condition(self, condition, sel_results):
        cond = (condition or "").strip()
        if not cond:
            return any(sel_results.values())
        names = list(sel_results.keys())

        # "all of them" / "1 of them"
        m = re.match(r"^(all|1|\d+)\s+of\s+them$", cond, re.I)
        if m:
            vals = list(sel_results.values())
            if m.group(1).lower() == "all":
                return all(vals)
            need = 1 if m.group(1) == "1" else int(m.group(1))
            return sum(1 for v in vals if v) >= need

        # "all of sel*" / "1 of sel*"
        m = re.match(r"^(all|1|\d+)\s+of\s+(\S+)$", cond, re.I)
        if m and m.group(2) != "them":
            pat = m.group(2).replace("*", ".*")
            sub = [v for n, v in sel_results.items() if re.fullmatch(pat, n)]
            if m.group(1).lower() == "all":
                return bool(sub) and all(sub)
            need = 1 if m.group(1) == "1" else int(m.group(1))
            return sum(1 for v in sub if v) >= need

        # 일반 boolean 식: 이름을 True/False 로 치환 후 안전 eval
        expr = cond
        # 긴 이름부터 치환(부분 일치 방지)
        for n in sorted(names, key=len, reverse=True):
            expr = re.sub(rf"\b{re.escape(n)}\b",
                          "True" if sel_results[n] else "False", expr)
        # 남은 토큰이 안전한지 검사(and/or/not/괄호/True/False/공백만)
        safe = re.sub(r"\b(and|or|not|True|False)\b", "", expr)
        safe = safe.replace("(", "").replace(")", "").strip()
        if safe:   # 미해석 토큰(정의 안 된 selection 등) → 안전하게 False
            return False
        try:
            return bool(eval(expr, {"__builtins__": {}}, {}))
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    #  매치 기록 + 파이프라인 투입
    # ------------------------------------------------------------------ #

    _LEVEL_TO_SEV = {"critical": "CRITICAL", "high": "HIGH",
                     "medium": "MEDIUM", "low": "LOW", "informational": "INFO"}

    def _record_match(self, rule, event):
        dedup = f"{rule['id']}:{event.get('_pid') or event.get('CommandLine','')[:40]}"
        with self._lock:
            if dedup in self._seen:
                return
            self._seen.add(dedup)
            if len(self._seen) > 2000:
                self._seen.clear()
            self._match_id += 1
            sev = self._LEVEL_TO_SEV.get(rule["level"], "MEDIUM")
            match = {
                "id": self._match_id,
                "rule_id": rule["id"],
                "rule": rule["title"],
                "level": rule["level"],
                "severity": sev,
                "mitre": rule["mitre"],
                "image": event.get("Image"),
                "cmdline": event.get("CommandLine"),
                "parent": event.get("ParentImage"),
                "pid": event.get("_pid"),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            self.matches.append(match)
            self.stats["matches"] += 1

        try:
            self.socketio.emit("sigma_match", match)
        except Exception:
            pass

        if self.mitre:
            for tech in rule["mitre"]:
                try:
                    self.mitre.map_threat("SIGMA_MATCH", src_ip=None, dst_ip=None,
                                          description=f"{rule['title']} ({tech})")
                except Exception:
                    pass

        # HIGH/CRITICAL 은 AI 트리아지 파이프라인에 투입
        if self.threat_detector and match["severity"] in ("HIGH", "CRITICAL"):
            try:
                self.threat_detector.report_alert(
                    "SIGMA_MATCH", match["severity"],
                    src_ip=None, dst_ip=None,
                    description=f"[Sigma] {rule['title']} — {event.get('Image') or event.get('CommandLine','')[:60]}",
                    details={"sigma": True, "rule_id": rule["id"], "rule": rule["title"],
                             "level": rule["level"], "mitre": rule["mitre"],
                             "cmdline": event.get("CommandLine"), "pid": event.get("_pid")})
            except Exception as e:
                _log.error(f"[Sigma] 파이프라인 투입 오류: {e}")

    def _emit_status(self):
        try:
            with self._lock:
                self.socketio.emit("sigma_status", {"stats": dict(self.stats)})
        except Exception:
            pass
