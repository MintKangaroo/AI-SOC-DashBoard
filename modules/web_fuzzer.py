"""
웹 엔드포인트 퍼저 — 견고성(robustness) 점검

본인 소유 서버(자동매매 대시보드 등)의 HTTP 엔드포인트에 비정상 입력
(경계값·특수문자·오버플로·인젝션 표면 마커)을 보내 서버가 안전하게
처리하는지 점검한다. 목적은 공격이 아니라 **방어 관점의 결함 발견**:
  - 5xx / 미처리 예외 (입력 검증 부재)
  - 응답 없음(timeout) / 연결 리셋 (행·크래시 가능)
  - 입력 반사(reflection) — XSS/인젝션 표면
  - 비정상 지연 / 응답 크기 이상

안전 설계 (운영 중 자동매매 봇 보호):
  - 대상은 **사설/loopback/Tailscale 호스트만** 허용 (공인 IP 거부 → 오남용 방지)
  - 기본 **GET 전용** — 매매 트리거(POST) 없음. POST는 FUZZ_ALLOW_WRITE=True 필요
  - **rate limit**(기본 5 req/s) + 최대 요청 수 상한으로 부하 최소화
  - 순차 전송(동시성 없음) — 대상 서버 부담 억제
  - requests 미설치 시 urllib fallback
"""
import time
import socket
import threading
import ipaddress
import urllib.parse
from datetime import datetime
from collections import deque

try:
    import requests
except ImportError:
    requests = None
import urllib.request
import urllib.error

from modules.logging_setup import get_logger

_log = get_logger(__name__)


# 퍼징 페이로드 (익스플로잇 아님 — 입력 검증/견고성 점검용 마커)
PAYLOADS = [
    ("empty", ""), ("zero", "0"), ("negative", "-1"), ("bigint", "9" * 18),
    ("overflow", "A" * 8000), ("whitespace", "    "),
    ("sql_marker", "' OR '1'='1"), ("sql_comment", "admin'--"),
    ("xss", "<script>alert(1)</script>"), ("xss_attr", "\"><img src=x onerror=1>"),
    ("path_traversal", "../../../../etc/passwd"), ("path_trav_enc", "..%2f..%2f..%2fetc%2fpasswd"),
    ("null_byte", "abc%00def"), ("crlf", "a%0d%0aX-Injected:1"),
    ("format_str", "%n%n%s%s%x"), ("template", "{{7*7}}"), ("template_el", "${7*7}"),
    ("json_broken", '{"a":'), ("array", "[]"), ("nan", "NaN"),
    ("neg_overflow", "-1e309"), ("unicode_rtl", "‮abc"), ("bool", "true"),
]


class WebFuzzer:
    def __init__(self, socketio, config=None):
        self.socketio = socketio
        self.config = config or {}
        self.running = False
        self._lock = threading.Lock()
        self._fuzzing = False
        self._stop_flag = False

        self.rate = float(self.config.get("FUZZ_RATE", 5))            # req/s
        self.max_requests = int(self.config.get("FUZZ_MAX_REQUESTS", 300))
        self.timeout = float(self.config.get("FUZZ_TIMEOUT", 5))
        self.allow_write = str(self.config.get("FUZZ_ALLOW_WRITE", "False")) == "True"
        self.targets = self._load_targets()

        self.findings = deque(maxlen=200)
        self.history = deque(maxlen=20)
        self.stats = {
            "mode": "off",
            "targets": len(self.targets),
            "requests": 0,
            "findings": 0,
            "errors_5xx": 0,
            "timeouts": 0,
            "reflections": 0,
            "last_run": None,
            "fuzzing": False,
            "allow_write": self.allow_write,
            "engine": "requests" if requests else "urllib",
        }

    # ------------------------------------------------------------------ #
    #  대상 인벤토리 (본인 소유 서버만)
    # ------------------------------------------------------------------ #

    def _load_targets(self):
        """self(SOC 대시보드) + FUZZ_TARGETS(없으면 NET_MONITOR_TARGETS) "이름=host:port"."""
        port = self.config.get("PORT", 8080)
        targets = [{"id": "self", "name": "이 SOC 대시보드",
                    "base": f"http://127.0.0.1:{port}", "hostport": f"127.0.0.1:{port}"}]
        raw = (self.config.get("FUZZ_TARGETS", "")
               or self.config.get("NET_MONITOR_TARGETS", "") or "")
        for part in raw.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name, hp = part.split("=", 1)
            hp = hp.strip()
            if not hp:
                continue
            base = hp if hp.startswith("http") else f"http://{hp}"
            targets.append({"id": hp, "name": name.strip(), "base": base, "hostport": hp})
        return targets

    def _target_by_id(self, tid):
        for t in self.targets:
            if t["id"] == tid:
                return t
        return None

    def _is_private_host(self, base):
        """대상이 본인 소유(사설/loopback/CGNAT·Tailscale) 인지 검증. 공인 IP 거부."""
        try:
            host = urllib.parse.urlparse(base).hostname or ""
        except Exception:
            return False
        if host in ("localhost",):
            return True
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except (OSError, ValueError):
            return False
        # 사설/loopback/링크로컬 + Tailscale/CGNAT 100.64/10
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
        try:
            return ip in ipaddress.ip_network("100.64.0.0/10")
        except ValueError:
            return False

    # ------------------------------------------------------------------ #
    #  라이프사이클
    # ------------------------------------------------------------------ #

    def start(self, demo=True):
        if self.running:
            return
        self.running = True
        with self._lock:
            self.stats["mode"] = "ready"
        eng = "requests" if requests else "urllib"
        _log.info(f"[Fuzzer] 웹 퍼저 준비 — 대상 {len(self.targets)}개 · {self.rate}req/s "
              f"· 최대 {self.max_requests}건 · {eng} · POST {'허용' if self.allow_write else '금지(GET만)'}")

    def stop(self):
        self.running = False
        self._stop_flag = True

    def stop_run(self):
        """진행 중 퍼징 중단 요청."""
        self._stop_flag = True

    # ------------------------------------------------------------------ #
    #  퍼징 실행
    # ------------------------------------------------------------------ #

    def run(self, target_id="self", paths=None, params=None, method="GET"):
        with self._lock:
            if self._fuzzing:
                return {"status": "busy", "msg": "이미 퍼징 중입니다."}
        t = self._target_by_id(target_id)
        if not t:
            return {"status": "error", "msg": "알 수 없는 대상입니다."}
        if not self._is_private_host(t["base"]):
            return {"status": "blocked",
                    "msg": "공인 IP 대상은 거부합니다 — 본인 소유(사설/Tailscale) 서버만 퍼징 가능."}
        method = (method or "GET").upper()
        if method != "GET" and not self.allow_write:
            return {"status": "blocked",
                    "msg": "POST/쓰기 메서드는 FUZZ_ALLOW_WRITE=True 필요 (자동매매 트리거 보호)."}
        paths = [p.strip() for p in (paths or ["/", "/login", "/api/whoami"]) if p.strip()]
        params = [p.strip() for p in (params or ["q"]) if p.strip()] or ["q"]

        with self._lock:
            self._fuzzing = True
            self._stop_flag = False
            self.stats["fuzzing"] = True
        threading.Thread(target=self._run_fuzz,
                         args=(t, paths, params, method), daemon=True).start()
        self._emit_status()
        return {"status": "started", "target": t["name"],
                "paths": len(paths), "method": method}

    def _run_fuzz(self, target, paths, params, method):
        sent = found = e5 = to = refl = 0
        try:
            for path in paths:
                base_url = target["base"].rstrip("/") + "/" + path.lstrip("/")
                baseline = self._request(base_url, method)   # 정상 응답 기준선
                for param in params:
                    for label, payload in PAYLOADS:
                        if self._stop_flag or sent >= self.max_requests:
                            break
                        url = self._build_url(base_url, param, payload)
                        r = self._request(url, method)
                        sent += 1
                        fnd = self._classify(target, path, param, label, payload,
                                             url, r, baseline)
                        if fnd:
                            found += 1
                            if fnd["type"] == "server_error":
                                e5 += 1
                            elif fnd["type"] == "timeout":
                                to += 1
                            elif fnd["type"] == "reflection":
                                refl += 1
                            self._record(fnd)
                        time.sleep(1.0 / max(0.5, self.rate))
                    if self._stop_flag or sent >= self.max_requests:
                        break
                if self._stop_flag or sent >= self.max_requests:
                    break
        except Exception as e:
            _log.error(f"[Fuzzer] 퍼징 오류: {e}")
        finally:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with self._lock:
                self._fuzzing = False
                self.stats["fuzzing"] = False
                self.stats["requests"] += sent
                self.stats["findings"] += found
                self.stats["errors_5xx"] += e5
                self.stats["timeouts"] += to
                self.stats["reflections"] += refl
                self.stats["last_run"] = ts
                self.history.appendleft({
                    "ts": ts, "target": target["name"], "method": method,
                    "requests": sent, "findings": found,
                    "stopped": self._stop_flag,
                })
            self._emit_status()

    def _build_url(self, base_url, param, payload):
        sep = "&" if "?" in base_url else "?"
        return f"{base_url}{sep}{urllib.parse.quote(param)}={urllib.parse.quote(payload, safe='')}"

    def _request(self, url, method):
        """단일 요청 → {status, elapsed, length, text, error}."""
        t0 = time.time()
        try:
            if requests is not None:
                resp = requests.request(method, url, timeout=self.timeout,
                                        allow_redirects=False)
                body = resp.text[:20000]
                return {"status": resp.status_code, "elapsed": time.time() - t0,
                        "length": len(resp.content), "text": body, "error": None}
            req = urllib.request.Request(url, method=method)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = resp.read(20000)
                return {"status": resp.status, "elapsed": time.time() - t0,
                        "length": len(data), "text": data.decode("latin-1", "ignore"),
                        "error": None}
        except urllib.error.HTTPError as e:
            body = b""
            try:
                body = e.read(20000)
            except Exception:
                pass
            return {"status": e.code, "elapsed": time.time() - t0,
                    "length": len(body), "text": body.decode("latin-1", "ignore"),
                    "error": None}
        except (TimeoutError, socket.timeout):
            return {"status": None, "elapsed": time.time() - t0, "length": 0,
                    "text": "", "error": "timeout"}
        except Exception as e:
            # requests.Timeout 등도 여기서 처리
            name = type(e).__name__.lower()
            err = "timeout" if "timeout" in name else "conn_reset" if "conn" in name else name
            return {"status": None, "elapsed": time.time() - t0, "length": 0,
                    "text": "", "error": err}

    def _classify(self, target, path, param, label, payload, url, r, baseline):
        base = {"target": target["name"], "path": path, "param": param,
                "payload_label": label,
                "payload": payload[:60] + ("…" if len(payload) > 60 else ""),
                "url": url, "status": r.get("status"),
                "elapsed_ms": int(r.get("elapsed", 0) * 1000),
                "time": datetime.now().strftime("%H:%M:%S")}
        st = r.get("status")
        if r.get("error") == "timeout":
            return {**base, "type": "timeout", "severity": "high",
                    "desc": "응답 없음(timeout) — 입력이 서버를 멈추게 함(행/크래시 가능)"}
        if r.get("error") in ("conn_reset", "connectionreseterror", "connectionerror"):
            return {**base, "type": "timeout", "severity": "high",
                    "desc": "연결 리셋/오류 — 비정상 입력에 프로세스가 끊김"}
        if st is not None and st >= 500:
            return {**base, "type": "server_error", "severity": "high",
                    "desc": f"HTTP {st} — 미처리 예외(입력 검증 부재 가능)"}
        # 입력 반사 (XSS/인젝션 표면) — HTML스러운 페이로드가 원문 그대로 반사
        if payload and label in ("xss", "xss_attr", "template", "template_el", "sql_marker") \
                and payload in (r.get("text") or ""):
            sev = "medium" if label in ("xss", "xss_attr") else "low"
            return {**base, "type": "reflection", "severity": sev,
                    "desc": f"입력이 응답에 원문 반사됨 — {label} 인젝션 표면 가능(출력 인코딩 확인)"}
        # 비정상 지연 (기준선 대비 급증)
        b_el = (baseline or {}).get("elapsed", 0) or 0
        if r.get("elapsed", 0) > max(2.0, b_el * 5) and r.get("error") is None:
            return {**base, "type": "latency", "severity": "low",
                    "desc": f"지연 급증 {base['elapsed_ms']}ms (기준선 {int(b_el*1000)}ms) — DoS 표면 가능"}
        return None

    def _record(self, fnd):
        with self._lock:
            self.findings.appendleft(fnd)
        try:
            self.socketio.emit("fuzz_finding", fnd)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  조회 / emit
    # ------------------------------------------------------------------ #

    def get_status(self):
        with self._lock:
            return {
                "stats": dict(self.stats),
                "targets": [{"id": t["id"], "name": t["name"], "base": t["base"],
                             "private": self._is_private_host(t["base"])}
                            for t in self.targets],
                "findings": list(self.findings)[:80],
                "history": list(self.history)[:15],
                "payload_count": len(PAYLOADS),
            }

    def _emit_status(self):
        try:
            with self._lock:
                self.socketio.emit("fuzz_status", {"stats": dict(self.stats)})
        except Exception:
            pass
