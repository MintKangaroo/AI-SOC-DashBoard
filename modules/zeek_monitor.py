"""Zeek notice.log 를 SOC 알림 파이프라인으로 전달한다.

Zeek 는 시그니처 IDS 가 아니라 **프로토콜 분석기**다. conn/dns/http/ssl 로그는
"무슨 일이 있었나"의 기록이고, 판단이 담긴 것은 notice.log 뿐이다(Scan::Port_Scan,
SSH::Password_Guessing, HTTP::SQL_Injection_Attacker, Intel::Notice …). 그래서
여기서는 **notice.log 만** 알림으로 올린다 — Suricata 에서 alert 만 올리는 것과 같은
원칙이다. conn.log 를 알림으로 올리면 알림 파이프라인이 곧 트래픽 로그가 된다.

형식은 둘 다 받는다: JSON(`LogAscii::use_json=T`, 한 줄에 객체 하나)과 기본
TSV(`#fields` 헤더 뒤 탭 구분). TSV 는 헤더가 파일마다 다르므로 헤더를 먼저 읽는다.

IDS 와 같은 원칙: Zeek 는 근거 하나를 줄 뿐 차단하지 않는다. 차단은 SOAR 게이트가
결정한다. MITRE 는 note 종류를 IDS 분류(classtype)와 같은 어휘로 옮겨 검증된
`IDS_CATEGORY_MAPPING` 을 그대로 쓴다 — 근거 약한 note 는 비워 둔다.
"""
import json
import os
import subprocess
import threading
import time
from collections import Counter, deque
from datetime import datetime

from modules.logging_setup import get_logger

_log = get_logger(__name__)

# note → (심각도, IDS 분류 어휘 — mitre_attack.IDS_CATEGORY_MAPPING 의 키. 없으면 매핑 없음)
_NOTE_RULES = {
    "Scan::Port_Scan":                ("HIGH",     "network-scan"),
    "Scan::Address_Scan":             ("HIGH",     "network-scan"),
    "SSH::Password_Guessing":         ("HIGH",     "unsuccessful-user"),
    "FTP::Bruteforcing":              ("HIGH",     "unsuccessful-user"),
    "HTTP::SQL_Injection_Attacker":   ("CRITICAL", "web-application-attack"),
    "HTTP::SQL_Injection_Victim":     ("HIGH",     "web-application-attack"),
    "Signatures::Sensitive_Signature": ("HIGH",    ""),
    "Signatures::Multiple_Signatures": ("HIGH",    ""),
    "Intel::Notice":                  ("HIGH",     ""),
    "SSL::Invalid_Server_Cert":       ("LOW",      ""),
    "Weird::Activity":                ("LOW",      ""),
    "Conn::Content_Gap":              ("LOW",      ""),
    "TeamCymruMalwareHashRegistry::Match": ("CRITICAL", "malicious file transfer"),
}
_DEFAULT_SEVERITY = "MEDIUM"


def _ts(value):
    """Zeek ts(epoch float) → 'YYYY-MM-DD HH:MM:SS'. 이미 문자열이면 그대로."""
    try:
        return datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OverflowError, OSError):
        return str(value or "")


def _clean(v):
    return None if v in (None, "-", "(empty)", "") else v


class ZeekNoticeParser:
    """줄 단위 파서. TSV 는 #fields 헤더를 기억해야 하므로 상태를 가진다."""

    def __init__(self):
        self.fields = None      # TSV 헤더
        self.separator = "\t"

    def parse(self, line):
        """반환: notice dict / ("skip", 이유) / None(파싱 불가)."""
        line = (line or "").rstrip("\n")
        if not line.strip():
            return None
        if line.startswith("#"):
            if line.startswith("#fields"):
                self.fields = line.split(self.separator)[1:]
                return ("skip", "header")
            if line.startswith("#separator"):
                try:
                    self.separator = bytes(line.split(" ", 1)[1].strip(), "utf-8").decode("unicode_escape")
                except (IndexError, UnicodeDecodeError):
                    self.separator = "\t"
                return ("skip", "header")
            return ("skip", "header")
        if line.startswith("{"):
            try:
                rec = json.loads(line)
            except ValueError:
                return None
            if not isinstance(rec, dict):
                return None
        else:
            if not self.fields:
                return None            # 헤더를 못 봤으면 열 이름을 모른다
            parts = line.split(self.separator)
            if len(parts) < len(self.fields):
                return None
            rec = dict(zip(self.fields, parts))
        note = _clean(rec.get("note"))
        if not note:
            return ("skip", "no_note")
        sev, category = _NOTE_RULES.get(note, (_DEFAULT_SEVERITY, ""))
        actions = rec.get("actions")
        if isinstance(actions, str):
            actions = [a for a in actions.split(",") if a]
        return {
            "timestamp": _ts(rec.get("ts")), "uid": _clean(rec.get("uid")),
            "note": note, "msg": str(_clean(rec.get("msg")) or "")[:300],
            "sub": str(_clean(rec.get("sub")) or "")[:200],
            "src_ip": _clean(rec.get("src")) or _clean(rec.get("id.orig_h")),
            "dst_ip": _clean(rec.get("dst")) or _clean(rec.get("id.resp_h")),
            "src_port": _clean(rec.get("id.orig_p")), "dst_port": _clean(rec.get("p")) or _clean(rec.get("id.resp_p")),
            "proto": str(_clean(rec.get("proto")) or ""),
            "actions": actions or [], "severity": sev, "category": category,
        }


class ZeekMonitor:
    def __init__(self, socketio, config=None, threat_detector=None):
        config = config or {}
        self.socketio = socketio
        self.threat_detector = threat_detector
        self.enabled = str(config.get("ZEEK_ENABLED", "True")) == "True"
        self.notice_path = str(config.get("ZEEK_NOTICE_PATH", "/opt/zeek/logs/current/notice.log"))
        self.poll_interval = max(0.1, float(config.get("ZEEK_POLL_INTERVAL", 1.0)))
        self.running = False
        self.parser = ZeekNoticeParser()
        self.events = deque(maxlen=200)
        self.by_note = Counter()
        self.stats = {"parsed": 0, "invalid": 0, "alerts": 0, "status": "stopped"}
        self._system_cache = ({}, 0.0)

    def start(self, demo=False):
        # Zeek 도 합성 이벤트를 만들지 않는다 — 없으면 waiting
        if self.running or not self.enabled:
            if not self.enabled:
                self.stats["status"] = "disabled"
            return
        self.running = True
        self.stats["status"] = "active" if os.path.exists(self.notice_path) else "waiting"
        threading.Thread(target=self._tail_loop, daemon=True, name="zeek-tail").start()
        _log.info(f"[Zeek] notice.log 감시: {self.notice_path} ({self.stats['status']})")

    def stop(self):
        self.running = False

    def get_status(self):
        system, cached_at = self._system_cache
        now = time.time()
        if now - cached_at >= 5:
            system = {"zeek_service": self._service_state("zeek")}
            self._system_cache = (system, now)
        return {**self.stats, "enabled": self.enabled, "notice_path": self.notice_path,
                "mode": "real" if self.stats["status"] == "active" else "off",
                "recent": list(self.events)[:20], "system": system,
                "by_note": dict(self.by_note.most_common(10)),
                "note_rules": {k: v[0] for k, v in _NOTE_RULES.items()}}

    @staticmethod
    def _service_state(name):
        def run(action):
            try:
                out = subprocess.run(["systemctl", action, name], capture_output=True,
                                     text=True, timeout=2, check=False)
                return (out.stdout or out.stderr).strip().splitlines()[0]
            except (OSError, subprocess.TimeoutExpired, IndexError):
                return "unknown"
        return {"active": run("is-active"), "enabled": run("is-enabled")}

    def ingest_line(self, line):
        parsed = self.parser.parse(line)
        if parsed is None:
            if (line or "").strip():
                self.stats["invalid"] += 1
            return None
        if isinstance(parsed, tuple):
            return None
        ev = parsed
        self.stats["parsed"] += 1
        self.by_note[ev["note"]] += 1
        self.events.appendleft(ev)
        self.socketio.emit("zeek_notice", ev)
        if self.threat_detector:
            details = {
                "source": "zeek", "sensor": "zeek", "note": ev["note"], "uid": ev["uid"],
                "category": ev["category"], "protocol": ev["proto"],
                "src_port": ev["src_port"], "dst_port": ev["dst_port"],
                "sub": ev["sub"], "actions": ev["actions"],
                "evidence": ["zeek_notice"], "demo": False,
            }
            self.threat_detector.report_alert(
                "ZEEK_NOTICE", ev["severity"], ev["src_ip"], ev["dst_ip"],
                f"[Zeek {ev['note']}] {ev['msg'] or ev['sub'] or ev['note']}", details)
            self.stats["alerts"] += 1
        return ev

    def _tail_loop(self):
        handle = None
        inode = None
        while self.running:
            try:
                stat = os.stat(self.notice_path)
                if handle is None or inode != stat.st_ino:   # 최초 열기·로테이션(Zeek 는 매시간 회전)
                    if handle:
                        handle.close()
                    handle = open(self.notice_path, "r", encoding="utf-8", errors="replace")
                    # 새 파일이면 헤더를 읽어야 TSV 열 이름을 안다 — 헤더만 소비하고 끝으로
                    self.parser = ZeekNoticeParser()
                    for l in handle:
                        if l.startswith("#"):
                            self.parser.parse(l)
                        else:
                            break
                    handle.seek(0, os.SEEK_END)
                    inode = stat.st_ino
                    self.stats["status"] = "active"
                line = handle.readline()
                if line:
                    if line.endswith("\n"):
                        self.ingest_line(line)
                    else:
                        handle.seek(handle.tell() - len(line.encode("utf-8", "replace")))
                        time.sleep(self.poll_interval)
                    continue
            except (FileNotFoundError, PermissionError):
                self.stats["status"] = "waiting"
                if handle:
                    handle.close()
                    handle = None
            except OSError:
                self.stats["status"] = "error"
            time.sleep(self.poll_interval)
        if handle:
            handle.close()
