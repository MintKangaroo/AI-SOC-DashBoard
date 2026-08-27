"""
자동화 취약점 패치 관리 (Ansible 기반)

홈서버의 미적용 보안 업데이트를 스캔하고, Ansible 플레이북으로 패치를 자동화한다.

설계 원칙 (운영 중 자동매매 서버 보호):
  - 스캔은 읽기 전용(apt list --upgradable) — sudo 불필요, 안전
  - 실제 패치는 절대 자동 실행하지 않음 — 분석가가 명시적으로 트리거
  - 기본 실행은 dry-run(--check) — 무엇이 바뀌는지만 확인
  - 실제 적용(apply)은 PATCH_APPLY_ENABLED=True + ansible + passwordless sudo 필요
  - Ansible 플레이북 파일을 생성해 사용자가 직접 검토/실행할 수도 있음

ansible 미설치/실패 시 데모 모드로 동작(가상 취약 패키지 + 시뮬레이션 로그).
"""
import os
import re
import sys
import time
import shutil
import tempfile
import threading
import shlex
import subprocess
from datetime import datetime
from collections import deque

from modules.logging_setup import get_logger

_log = get_logger(__name__)


# ────────────────────────────────────────────────────────────────────
#  원격 명령 안전장치 — allowlist 방식
# ────────────────────────────────────────────────────────────────────
#
# 이전에는 파괴적 명령을 **부분 문자열 blocklist** 로 걸렀는데, 실제로 새고 있었다
# (docs/AUDIT.md C-3). 통과 사례:
#     rm -fr /                    (옵션 순서만 바꿈)
#     rm  -rf /                   (공백 하나 추가)
#     rm -rf --no-preserve-root / (옵션 추가)
#     find / -delete              (다른 명령으로 같은 결과)
#
# 이 게이트는 운영 중인 자동매매 서버로 나가는 `ansible -m shell` 앞의 마지막
# 방어선이므로 blocklist 로는 부족하다. 세 겹으로 바꾼다.
#   1) 셸 메타문자 차단 — 명령 연결·리다이렉션·치환 자체를 막는다
#   2) 명령 allowlist   — 첫 토큰이 허용 목록에 있어야 한다
#   3) 기존 blocklist   — 위 둘을 통과해도 파괴적 패턴이면 거부(중복 방어)

# 명령 연결·리다이렉션·치환을 가능하게 하는 문자. 하나라도 있으면 거부한다.
_SHELL_METACHARS = (";", "&", "|", "`", "$(", "${", ">", "<", "\n", "\r")

# 허용 명령 (조회 전용). UI 플레이스홀더가 안내하는 용도와 일치한다:
#   "예: uptime · df -h · systemctl status trader"
_DEFAULT_ALLOWED_CMDS = (
    "uptime", "df", "free", "ps", "uname", "hostname", "id", "whoami", "date",
    "lsblk", "du", "ss", "ip", "lscpu", "nproc", "getent",
    "systemctl", "journalctl", "apt", "dpkg-query", "dpkg", "pip", "python3",
    "tail", "head", "wc", "stat", "ls", "which", "sha256sum", "md5sum",
)

# systemctl / journalctl 은 조회 하위명령만 허용 (start/stop/restart 금지 —
# 자동매매 프로세스를 원격에서 내리는 사고를 막는다)
_READONLY_SUBCMDS = {
    "systemctl": {"status", "is-active", "is-enabled", "is-failed",
                  "list-units", "list-timers", "show", "cat"},
    "apt": {"list", "show", "policy"},
    "dpkg": {"-l", "-s", "-L", "--list", "--status"},
    "pip": {"list", "show", "freeze"},
}

# 실제 실행(apply) 시 무조건 차단하는 파괴적 명령 패턴 (중복 방어)
_DANGEROUS_CMD = (
    "rm -rf /", "rm -rf /*", "mkfs", "dd if=", "> /dev/sd", "of=/dev/sd",
    ":(){", "shutdown", "reboot", "halt", "poweroff", "init 0", "init 6",
    "chmod -R 000", "chown -R", "> /etc/", "userdel", "kill -9 -1",
)


def check_command(command, allowed=None):
    """원격 실행 허용 여부. 반환: (ok, 거부사유 or None).

    거부 사유를 문자열로 돌려주므로 UI 가 왜 막혔는지 그대로 보여줄 수 있다.
    """
    cmd = (command or "").strip()
    if not cmd:
        return False, "빈 명령"

    for meta in _SHELL_METACHARS:
        if meta in cmd:
            return False, (f"셸 메타문자 '{meta}' 는 허용되지 않습니다 "
                           "(명령 연결·리다이렉션 차단)")

    try:
        tokens = shlex.split(cmd)
    except ValueError as e:
        return False, f"명령 구문 오류: {e}"
    if not tokens:
        return False, "빈 명령"

    base = os.path.basename(tokens[0])
    allow = tuple(allowed) if allowed else _DEFAULT_ALLOWED_CMDS
    if base not in allow:
        return False, (f"'{base}' 는 허용 목록에 없습니다. 조회 명령만 실행할 수 "
                       f"있습니다 (허용: {', '.join(sorted(allow)[:8])} …). "
                       "그 외 명령은 서버에서 직접 실행하세요.")

    sub_allowed = _READONLY_SUBCMDS.get(base)
    if sub_allowed:
        sub = tokens[1] if len(tokens) > 1 else ""
        if sub not in sub_allowed:
            return False, (f"'{base} {sub}' 는 허용되지 않습니다. "
                           f"조회 하위명령만 가능합니다: {', '.join(sorted(sub_allowed))}")

    low = cmd.lower()
    if any(d in low for d in _DANGEROUS_CMD):
        return False, "파괴적 명령으로 판단되어 차단했습니다."
    return True, None


# 데모/샘플 취약 패키지 (CVE 예시 — 학습·데모용)
DEMO_PACKAGES = [
    {"package": "openssl", "current": "3.0.2-0ubuntu1.15", "candidate": "3.0.2-0ubuntu1.18",
     "suite": "jammy-security", "security": True, "cve": "CVE-2024-6119"},
    {"package": "openssh-server", "current": "1:8.9p1-3ubuntu0.7", "candidate": "1:8.9p1-3ubuntu0.10",
     "suite": "jammy-security", "security": True, "cve": "CVE-2024-6387 (regreSSHion)"},
    {"package": "sudo", "current": "1.9.9-1ubuntu2.4", "candidate": "1.9.9-1ubuntu2.5",
     "suite": "jammy-security", "security": True, "cve": "CVE-2023-22809"},
    {"package": "curl", "current": "7.81.0-1ubuntu1.15", "candidate": "7.81.0-1ubuntu1.20",
     "suite": "jammy-security", "security": True, "cve": "CVE-2024-2398"},
    {"package": "vim", "current": "2:8.2.3995-1ubuntu2.15", "candidate": "2:8.2.3995-1ubuntu2.21",
     "suite": "jammy-updates", "security": False, "cve": None},
]

_LINE_RE = re.compile(r"^(\S+?)/(\S+?)\s+(\S+)\s+\S+\s+\[upgradable from:\s*([^\]]+)\]")


class PatchManager:
    def __init__(self, socketio, config=None):
        self.socketio = socketio
        self.config = config or {}
        self.running = False
        self._demo = True
        self._lock = threading.Lock()

        self.apply_enabled = str(self.config.get("PATCH_APPLY_ENABLED", "False")) == "True"
        # 원격 실행 허용 명령 — 비우면 조회 전용 기본 목록
        raw_allow = str(self.config.get("PATCH_COMMAND_ALLOWLIST", "") or "")
        self.command_allowlist = tuple(
            c.strip() for c in raw_allow.split(",") if c.strip()) or None
        self.playbook_dir = self.config.get("PATCH_PLAYBOOK_DIR", "data/ansible")
        # 플레이북용(ansible-playbook)·ad-hoc용(ansible) 각각 — venv/bin 도 탐색
        self.ansible_bin = self._find_bin("ansible-playbook")
        self.ansible_adhoc = self._find_bin("ansible")

        self.hosts = self._load_hosts()   # 일괄 명령/패치 대상 호스트 인벤토리
        self.inventory = []          # [{package, current, candidate, suite, security, cve}]
        self.jobs = deque(maxlen=50)  # 패치/명령 작업 이력
        self._job_id = 0
        self.last_scan = None
        self.stats = {
            "mode": "off",
            "upgradable": 0,
            "security": 0,
            "jobs_run": 0,
            "last_scan": None,
            "ansible": bool(self.ansible_bin),
            "apply_enabled": self.apply_enabled,
        }

    # ------------------------------------------------------------------ #
    #  호스트 인벤토리 (일괄 대상)
    # ------------------------------------------------------------------ #

    def _find_bin(self, name):
        """PATH + venv bin 에서 실행파일 탐색 (./venv/bin/python 실행 시 PATH 누락 대비)."""
        found = shutil.which(name)
        if found:
            return found
        cand = os.path.join(os.path.dirname(sys.executable), name)
        return cand if os.path.exists(cand) else None

    def _load_hosts(self):
        """localhost 는 항상 포함. .env ANSIBLE_TARGETS="이름=user@host;이름2=host2" 로 원격 추가."""
        hosts = [{"id": "localhost", "name": "이 서버(localhost)", "addr": "localhost",
                  "conn": "local"}]
        raw = self.config.get("ANSIBLE_TARGETS", "") or ""
        for part in raw.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name, addr = part.split("=", 1)
            name, addr = name.strip(), addr.strip()
            if not addr:
                continue
            hosts.append({"id": addr, "name": name, "addr": addr, "conn": "ssh"})
        return hosts

    def _hosts_by_id(self, ids):
        if not ids:
            return [self.hosts[0]]           # 기본: localhost
        idset = set(ids)
        sel = [h for h in self.hosts if h["id"] in idset]
        return sel or [self.hosts[0]]

    def _write_inventory(self, sel):
        """선택 호스트로 임시 Ansible 인벤토리(INI) 파일 생성 → 경로 반환."""
        lines = ["[targets]"]
        for h in sel:
            if h["conn"] == "local":
                lines.append("localhost ansible_connection=local")
            elif "@" in h["addr"]:
                user, host = h["addr"].split("@", 1)
                lines.append(f"{host} ansible_user={user}")
            else:
                lines.append(h["addr"])
        fd, path = tempfile.mkstemp(prefix="soc_inv_", suffix=".ini")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return path

    # ------------------------------------------------------------------ #
    #  라이프사이클
    # ------------------------------------------------------------------ #

    def start(self, demo=True):
        if self.running:
            return
        self.running = True
        self._demo = demo
        with self._lock:
            self.stats["mode"] = "demo" if demo else "real"
        # 시작 시 1회 스캔 + 6시간 주기 재스캔
        threading.Thread(target=self._scan_loop, daemon=True).start()
        mode = "실측(apt)" if not demo else "데모"
        ans = "ansible 있음" if self.ansible_bin else "ansible 미설치(플레이북 생성만)"
        _log.info(f"[Patch] 취약점 패치 관리 시작 — {mode}, {ans}, "
              f"실제적용 {'허용' if self.apply_enabled else '금지(dry-run만)'}")

    def stop(self):
        self.running = False

    def _scan_loop(self):
        while self.running:
            try:
                self.scan()
            except Exception as e:
                _log.error(f"[Patch] 스캔 오류: {e}")
            for _ in range(6 * 60 * 60):
                if not self.running:
                    return
                time.sleep(1)

    # ------------------------------------------------------------------ #
    #  스캔
    # ------------------------------------------------------------------ #

    def scan(self):
        inv = None
        if not getattr(self, "_demo", True):
            inv = self._scan_apt()
        if inv is None:
            inv = [dict(p) for p in DEMO_PACKAGES]
        with self._lock:
            self.inventory = inv
            self.last_scan = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.stats["upgradable"] = len(inv)
            self.stats["security"] = sum(1 for p in inv if p.get("security"))
            self.stats["last_scan"] = self.last_scan
        self._emit_status()
        return inv

    def _scan_apt(self):
        try:
            r = subprocess.run(["apt", "list", "--upgradable"],
                               capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                return None
            inv = []
            for line in r.stdout.splitlines():
                m = _LINE_RE.match(line.strip())
                if not m:
                    continue
                pkg, suite, cand, cur = m.groups()
                inv.append({
                    "package": pkg, "current": cur.strip(), "candidate": cand,
                    "suite": suite, "security": "security" in suite.lower(),
                    "cve": None,
                })
            return inv
        except Exception as e:
            _log.error(f"[Patch] apt 스캔 실패: {e}")
            return None

    # ------------------------------------------------------------------ #
    #  조회
    # ------------------------------------------------------------------ #

    def get_status(self):
        with self._lock:
            return {
                "stats": dict(self.stats),
                "ansible_path": self.ansible_bin,
                "hosts": list(self.hosts),
                "inventory": list(self.inventory),
                "jobs": list(reversed(list(self.jobs)))[:20],
            }

    # ------------------------------------------------------------------ #
    #  Ansible 플레이북 생성
    # ------------------------------------------------------------------ #

    def generate_playbook(self, security_only=True):
        with self._lock:
            pkgs = [p["package"] for p in self.inventory
                    if (p.get("security") or not security_only)]
        content = self._render_playbook(pkgs, security_only)
        os.makedirs(self.playbook_dir, exist_ok=True)
        fname = f"patch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yml"
        path = os.path.join(self.playbook_dir, fname)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            _log.error(f"[Patch] 플레이북 저장 실패: {e}")
        return path, content

    def _render_playbook(self, pkgs, security_only):
        title = "보안 업데이트만" if security_only else "전체 업데이트"
        lines = [
            "---",
            f"# SOC 대시보드 자동 생성 — {title} 패치 플레이북",
            f"# 생성: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "# 실행 전 반드시 검토하세요. 자동매매 서버는 점검 시간대에 적용 권장.",
            "- name: 서버 취약점 패치",
            "  hosts: targets",
            "  become: true",
            "  tasks:",
            "    - name: apt 캐시 갱신",
            "      apt:",
            "        update_cache: true",
        ]
        if security_only:
            lines += [
                "    - name: 보안 업데이트만 적용 (unattended-upgrades 정책)",
                "      apt:",
                "        upgrade: dist",
                "        only_upgrade: true",
            ]
            if pkgs:
                lines += [
                    "    - name: 대상 보안 패키지 명시 업그레이드",
                    "      apt:",
                    "        name:",
                ] + [f"          - {p}" for p in pkgs] + [
                    "        state: latest",
                ]
        else:
            lines += [
                "    - name: 전체 패키지 업그레이드",
                "      apt:",
                "        upgrade: dist",
            ]
        lines += [
            "    - name: 재부팅 필요 여부 확인",
            "      stat:",
            "        path: /var/run/reboot-required",
            "      register: reboot_required",
            "    - name: 재부팅 필요 알림",
            "      debug:",
            "        msg: '재부팅이 필요합니다 (/var/run/reboot-required 존재)'",
            "      when: reboot_required.stat.exists",
        ]
        return "\n".join(lines) + "\n"

    # ------------------------------------------------------------------ #
    #  패치 작업 실행
    # ------------------------------------------------------------------ #

    def run_job(self, mode="check", security_only=True, host_ids=None):
        """mode: 'check'(dry-run, 기본) | 'apply'(실제 적용). apply 는 안전장치 통과 필요.
        host_ids: 대상 호스트 id 목록(없으면 localhost)."""
        path, content = self.generate_playbook(security_only)
        sel = self._hosts_by_id(host_ids)
        with self._lock:
            self._job_id += 1
            job = {
                "id": self._job_id, "kind": "patch", "mode": mode,
                "security_only": security_only, "playbook": path,
                "hosts": [h["name"] for h in sel],
                "started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "running", "result": "", "log": "",
            }
            self.jobs.append(job)
            self.stats["jobs_run"] += 1

        # 안전장치: 실제 적용은 명시 허용 + ansible 필요
        if mode == "apply" and not self.apply_enabled:
            self._finish_job(job, "blocked",
                             "실제 적용 금지 상태 — PATCH_APPLY_ENABLED=True 필요 "
                             "(운영 중 자동매매 서버 보호). 생성된 플레이북을 점검 시간대에 수동 실행하세요.")
            return job

        threading.Thread(target=self._execute_job, args=(job, path, mode, sel), daemon=True).start()
        return job

    def _execute_job(self, job, path, mode, sel):
        inv_path = None
        try:
            # 데모 모드는 실제 ansible 을 호출하지 않는다. --check 가 읽기 전용이라도
            # 데모에서 운영 서버로 나가는 subprocess 는 프로젝트의 데모 fallback
            # 규칙(CLAUDE.md)에 어긋나고, 테스트를 실행 환경에 의존하게 만든다.
            if self.ansible_bin and not self._demo:
                inv_path = self._write_inventory(sel)
                cmd = [self.ansible_bin, "-i", inv_path, path]
                if mode == "check":
                    cmd.append("--check")
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                log = (r.stdout or "") + (r.stderr or "")
                ok = r.returncode == 0
                self._finish_job(job, "success" if ok else "failed",
                                 f"ansible-playbook {'(dry-run)' if mode=='check' else '적용'} "
                                 f"· 대상 {len(sel)}대 · 종료코드 {r.returncode}", log[-4000:])
            else:
                reason = ("데모 모드 — 실제 ansible 호출 안 함"
                          if self._demo else "ansible 미설치")
                self._finish_job(job, "simulated",
                                 f"{reason} — 시뮬레이션(대상 {len(sel)}대). 아래 플레이북을 "
                                 "검토 후 점검 시간대에 수동 실행하세요.",
                                 self._simulated_log(mode, sel))
        except subprocess.TimeoutExpired:
            self._finish_job(job, "failed", "시간 초과(600s)", "")
        except Exception as e:
            self._finish_job(job, "failed", f"실행 오류: {type(e).__name__}", str(e))
        finally:
            if inv_path:
                try:
                    os.remove(inv_path)
                except OSError:
                    pass

    def _simulated_log(self, mode, sel=None):
        with self._lock:
            secs = [p for p in self.inventory if p.get("security")]
        sel = sel or [self.hosts[0]]
        head = "DRY-RUN (실제 변경 없음)" if mode == "check" else "APPLY (시뮬레이션)"
        lines = [f"PLAY [서버 취약점 패치] — {head}",
                 f"대상 호스트: {', '.join(h['name'] for h in sel)}", ""]
        recap = []
        for h in sel:
            lines.append(f"── {h['name']} ({h['addr']}) ──")
            lines.append("TASK [apt 캐시 갱신] ......... ok")
            for p in secs:
                lines.append(f"TASK [업그레이드 {p['package']}] {p['current']} -> {p['candidate']}  "
                             f"changed{(' ('+p['cve']+')') if p.get('cve') else ''}")
            recap.append(f"{h['addr']:<24} changed={len(secs)}  failed=0")
        lines += ["", "PLAY RECAP", *recap]
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    #  일괄 ad-hoc 명령 실행
    # ------------------------------------------------------------------ #

    def run_command(self, command, host_ids=None, mode="check"):
        """선택 호스트에 shell 명령을 일괄 실행.
        mode: 'check'(미리보기만, 기본) | 'apply'(실제 실행 — 안전장치 통과 필요)."""
        command = (command or "").strip()
        sel = self._hosts_by_id(host_ids)
        with self._lock:
            self._job_id += 1
            job = {
                "id": self._job_id, "kind": "command", "mode": mode,
                "command": command, "hosts": [h["name"] for h in sel],
                "started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "running", "result": "", "log": "",
            }
            self.jobs.append(job)
            self.stats["jobs_run"] += 1

        if not command:
            self._finish_job(job, "blocked", "명령이 비어 있습니다.")
            return job

        # dry-run(check): 실제 실행하지 않고 무엇이 실행될지 미리보기만.
        # 안전장치 판정도 함께 보여줘 '실행'을 누르기 전에 막힐 것을 알 수 있게 한다.
        if mode != "apply":
            ok, reason = check_command(command, self.command_allowlist)
            verdict = ("실행 가능" if ok else f"실행 시 차단됨 — {reason}")
            preview = "\n".join(
                f"[{h['name']}] $ {command}" for h in sel
            ) + f"\n\n[안전장치 판정] {verdict}" \
              + "\n(미리보기 — 실제 실행 안 함. 실행하려면 '실행' 버튼)"
            self._finish_job(job, "simulated",
                             f"미리보기 — 대상 {len(sel)}대", preview)
            return job

        # apply: 안전장치 3중 (명시 허용 + 명령 allowlist + ansible 필요)
        if not self.apply_enabled:
            self._finish_job(job, "blocked",
                             "실제 실행 금지 상태 — PATCH_APPLY_ENABLED=True 필요 "
                             "(운영 중 자동매매 서버 보호).")
            return job
        ok, reason = check_command(command, self.command_allowlist)
        if not ok:
            self._finish_job(job, "blocked", reason)
            return job
        if not self.ansible_adhoc:
            self._finish_job(job, "simulated",
                             "ansible 미설치 — 실제 실행 불가. 시뮬레이션만.",
                             "\n".join(f"[{h['name']}] $ {command}  (ansible 필요)" for h in sel))
            return job

        threading.Thread(target=self._execute_command,
                         args=(job, command, sel), daemon=True).start()
        return job

    def _execute_command(self, job, command, sel):
        inv_path = None
        try:
            inv_path = self._write_inventory(sel)
            cmd = [self.ansible_adhoc, "targets", "-i", inv_path, "-m", "shell", "-a", command]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            log = (r.stdout or "") + (r.stderr or "")
            ok = r.returncode == 0
            self._finish_job(job, "success" if ok else "failed",
                             f"명령 실행 · 대상 {len(sel)}대 · 종료코드 {r.returncode}",
                             log[-4000:])
        except subprocess.TimeoutExpired:
            self._finish_job(job, "failed", "시간 초과(300s)", "")
        except Exception as e:
            self._finish_job(job, "failed", f"실행 오류: {type(e).__name__}", str(e))
        finally:
            if inv_path:
                try:
                    os.remove(inv_path)
                except OSError:
                    pass

    def _finish_job(self, job, status, result, log=""):
        with self._lock:
            job["status"] = status
            job["result"] = result
            job["log"] = log
            job["finished"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.socketio.emit("patch_job", {k: job.get(k) for k in
                               ("id", "kind", "mode", "status", "result", "playbook",
                                "command", "hosts", "finished")})
        except Exception:
            pass
        self._emit_status()

    def _emit_status(self):
        try:
            with self._lock:
                self.socketio.emit("patch_status", {"stats": dict(self.stats)})
        except Exception:
            pass
