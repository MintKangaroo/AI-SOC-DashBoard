"""자기 관측성 (docs/AUDIT.md 3단계 제안 B).

이 감사에서 발견한 문제 대부분은 **관측성이 있었다면 스스로 드러났을 것들**이다.

- B-1: 인시던트 저장이 매번 0.63초씩 락을 잡았다 — 저장 지연을 아무도 재지 않았다.
- B-2: `id NOT IN (?×23,299)` 가 32,766건에서 조용히 실패한다 — 에러 카운터가 없었다.
- B-4: Claude 호출이 최대 30분 스레드를 잡았다 — 외부 호출 지연을 재지 않았다.
- B-7: 집계가 쓰기를 34초 막았다 — 큐 대기를 재지 않았다.

`system_health.py` 는 모듈이 real/demo/off 중 무엇인지는 보여주지만 **얼마나
느린지, 얼마나 실패하는지, 얼마나 밀렸는지**는 답하지 못한다. 여기서 그것을 잰다.

**40개 모듈을 고치지 않는다.** `system_health` 와 같은 원칙으로,
(1) 문제가 실제로 숨었던 경로에만 `timed()` 를 넣고,
(2) 큐 깊이 같은 건 기존 객체에서 방어적으로 꺼낸다(probe).

계측이 관측 대상을 망가뜨리면 안 되므로 기록 경로는 예외를 밖으로 내보내지
않고, 메모리에만 둔다(롤링 윈도우). 영속화가 필요해지면 그때 붙인다.
"""
import threading
import time
from collections import deque
from datetime import datetime

# 지점별 최근 표본 수. 200개면 3초 주기 루프 기준 약 10분치다.
WINDOW = 200

# 이 값을 넘으면 '느림'으로 표시한다. 근거는 감사에서 실측한 값들이다.
SLOW_MS = {
    "incidents.save": 200.0,       # B-1 실측 630ms — 탐지 경로를 막았다
    "alert_store.write": 50.0,
    "alert_store.search": 1500.0,  # 11만 행 통합 조회 실측 1.1초
    "ai.analyze": 30000.0,         # AI_TIMEOUT_SECONDS 기본 30초
    "ip_reputation.lookup": 3000.0,
    "virustotal.lookup": 8000.0,
}
DEFAULT_SLOW_MS = 1000.0

# 표본이 이보다 적으면 '느림'으로 표시하지 않는다.
# 기동 직후 한 건(DB 초기화·연결 수립 포함)이 p95 를 지배해 실제로 오탐이 났다.
# 경보가 늑대소년이 되면 사람이 화면을 안 본다 — 오탐을 줄이는 쪽이 낫다.
MIN_SAMPLES_FOR_SLOW = 10


def _percentile(values, pct):
    if not values:
        return None
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((pct / 100.0) * len(ordered) + 0.5)) - 1))
    return ordered[idx]


class Telemetry:
    """지점별 지연·에러·처리량 집계. 프로세스 메모리에만 둔다."""

    def __init__(self, window=WINDOW):
        self._lock = threading.Lock()
        self._window = int(window)
        self._points = {}
        self._probes = {}

    # ------------------------------------------------------------------ #
    #  기록
    # ------------------------------------------------------------------ #

    def _point(self, name):
        point = self._points.get(name)
        if point is None:
            point = {
                "samples": deque(maxlen=self._window),
                "calls": 0, "errors": 0,
                "last_success": None, "last_error": None, "last_error_at": None,
            }
            self._points[name] = point
        return point

    def record(self, name, ms, ok=True, error=None):
        """지점 1회 관측. 계측이 관측 대상을 죽이면 안 되므로 절대 던지지 않는다."""
        try:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with self._lock:
                point = self._point(name)
                point["samples"].append(float(ms))
                point["calls"] += 1
                if ok:
                    point["last_success"] = now
                else:
                    point["errors"] += 1
                    point["last_error"] = str(error)[:200] if error else "unknown"
                    point["last_error_at"] = now
        except Exception:
            pass

    def incr_error(self, name, error=None):
        """지연 없이 실패만 세는 경우 (B-2 의 무성 실패 같은 것)."""
        self.record(name, 0.0, ok=False, error=error)

    def timed(self, name):
        return _Timer(self, name)

    # ------------------------------------------------------------------ #
    #  프로브 — 모듈을 고치지 않고 현재 값을 꺼내온다
    # ------------------------------------------------------------------ #

    def register_probe(self, name, fn, label=None, unit="", warn_above=None):
        """호출 시점의 값을 돌려주는 함수를 등록한다(큐 깊이 등)."""
        with self._lock:
            self._probes[name] = {"fn": fn, "label": label or name,
                                  "unit": unit, "warn_above": warn_above}

    def _read_probes(self):
        out = []
        with self._lock:
            probes = list(self._probes.items())
        for name, spec in probes:
            try:
                value = spec["fn"]()
            except Exception as e:
                out.append({"name": name, "label": spec["label"], "value": None,
                            "unit": spec["unit"], "error": str(e)[:120], "warn": True})
                continue
            warn_above = spec["warn_above"]
            warn = warn_above is not None and value is not None and value > warn_above
            out.append({"name": name, "label": spec["label"], "value": value,
                        "unit": spec["unit"], "warn": bool(warn),
                        "warn_above": warn_above})
        return sorted(out, key=lambda p: p["name"])

    # ------------------------------------------------------------------ #
    #  조회
    # ------------------------------------------------------------------ #

    def snapshot(self):
        with self._lock:
            points = {name: {**p, "samples": list(p["samples"])}
                      for name, p in self._points.items()}
        rows = []
        for name, p in points.items():
            samples = p["samples"]
            slow_ms = SLOW_MS.get(name, DEFAULT_SLOW_MS)
            p95 = _percentile(samples, 95)
            rows.append({
                "name": name,
                "calls": p["calls"],
                "errors": p["errors"],
                "error_rate": round(p["errors"] / p["calls"] * 100, 1) if p["calls"] else 0.0,
                "p50": round(_percentile(samples, 50), 1) if samples else None,
                "p95": round(p95, 1) if p95 is not None else None,
                "max": round(max(samples), 1) if samples else None,
                "samples": len(samples),
                # 최근 표본을 그대로 넘겨 스파크라인으로 그린다. 별도 시계열
                # 저장소를 두지 않고도 '언제부터 느려졌나'가 보인다.
                "spark": [round(v, 1) for v in samples[-40:]],
                "slow_threshold_ms": slow_ms,
                # '느리다'와 '실패한다'는 다른 문제다 — 따로 표시한다
                "slow": bool(p95 is not None and p95 > slow_ms
                             and len(samples) >= MIN_SAMPLES_FOR_SLOW),
                "warming_up": len(samples) < MIN_SAMPLES_FOR_SLOW,
                "last_success": p["last_success"],
                "last_error": p["last_error"],
                "last_error_at": p["last_error_at"],
            })
        rows.sort(key=lambda r: r["name"])
        probes = self._read_probes()
        return {
            "points": rows,
            "probes": probes,
            "summary": {
                "points": len(rows),
                "slow": sum(1 for r in rows if r["slow"]),
                "failing": sum(1 for r in rows if r["errors"]),
                "probe_warnings": sum(1 for p in probes if p["warn"]),
            },
        }

    def reset(self):
        with self._lock:
            self._points.clear()


class _Timer:
    """`with telemetry.timed("x"):` — 예외가 나면 실패로 기록하고 그대로 올려보낸다."""

    __slots__ = ("_tel", "_name", "_start")

    def __init__(self, telemetry, name):
        self._tel, self._name, self._start = telemetry, name, None

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb):
        elapsed_ms = (time.perf_counter() - self._start) * 1000.0
        self._tel.record(self._name, elapsed_ms, ok=exc_type is None, error=exc)
        return False    # 예외를 삼키지 않는다 — 계측이 흐름을 바꾸면 안 된다


# 전역 인스턴스. 모듈들이 import 해서 바로 쓴다(주입 배선을 40곳에 넣지 않으려고).
telemetry = Telemetry()
