#!/usr/bin/env python3
"""부하 시험 — 실제 서버를 띄워 응답 지연과 자기 관측성 지표를 잰다.

## 왜 필요한가

pytest 는 `test_client` 로 돈다. 그건 **프로세스도, 소켓도, 스레드 경합도 없는**
환경이다. 실제로 이 스크립트의 초판이 테스트 700여 개가 전부 놓친 것들을 찾아냈다:

- YARA 룰 디렉터리가 없으면 탐지가 통째로 죽는 문제 (작업 디렉터리가 저장소 밖일 때)
- 조회 커넥션을 락으로 공유해 **동시 조회가 66배 느려지던** 문제
- 같은 집계를 동시 요청마다 중복 계산하던 문제 (thundering herd)

## 설계 원칙

**사용자의 실데이터를 건드리지 않는다.** 격리된 임시 디렉터리에서 돌고, 실데이터가
필요하면 `sqlite3 .backup` 으로 **사본**을 뜬다(WAL 이라 파일 복사는 -wal 을 놓친다).
차단 경로는 simulate 고정, 외부 수집기는 전부 끈다.

## 사용법

    python scripts/loadtest.py                 # 빈 DB 로 (빠름)
    python scripts/loadtest.py --with-real-data  # 실데이터 사본으로 (의미 있는 수치)
    python scripts/loadtest.py --workers 16 --rounds 3

결과 해석: `alert_store.search` 의 p95 가 단독 실행 대비 크게 벌어지면 조회끼리
막고 있다는 뜻이다. 텔레메트리 요약의 `slow` 가 0 이 아니면 그 지점을 먼저 본다.
"""
import argparse
import concurrent.futures as cf
import json
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 실서버에서만 드러나는 것을 보려는 것이므로, 무거운 조회와 가벼운 조회를 섞는다.
DEFAULT_MIX = [
    ("/api/alerts/history?limit=50", 12),
    ("/api/alerts/history?ip=185.220&limit=50", 6),
    ("/api/metrics/soc?days=90", 4),
    ("/api/alerts/history/export.ocsf.json?limit=2000", 3),
    ("/api/mitre/coverage", 4),
    ("/api/system/health", 4),
    ("/api/telemetry", 2),
    ("/api/hunts", 2),
]

ENV = {
    "AUTH_ENABLED": "False", "DEMO_MODE": "True", "DEBUG": "False",
    "SOAR_BLOCK_MODE": "simulate", "SOAR_AUTO_BLOCK": "False",
    "PATCH_APPLY_ENABLED": "False", "SYSLOG_ENABLED": "False",
    "HONEYPOT_ENABLED": "False", "SNORT_ENABLED": "False", "NTFY_ENABLED": "False",
    "SIEM_ACCESS_LOGS": "none=/nonexistent/a.log",
    "AUTH_LOG_PATH": "/nonexistent/a.log",
    "ANSIBLE_TARGETS": "", "NET_MONITOR_TARGETS": "", "FUZZ_TARGETS": "",
    "SECRET_KEY": "loadtest-only",
}


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def copy_real_data(workdir):
    """실데이터 사본. WAL 이므로 파일 복사가 아니라 .backup 을 쓴다."""
    copied = {}
    for name, table in (("alerts.db", "alerts"), ("alerts_archive.db", "alerts_archive")):
        src_path = os.path.join(REPO, "data", name)
        if not os.path.exists(src_path):
            continue
        dst_path = os.path.join(workdir, "data", name)
        src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True)
        dst = sqlite3.connect(dst_path)
        src.backup(dst)
        try:
            copied[name] = dst.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except sqlite3.Error:
            copied[name] = 0
        dst.close()
        src.close()
    return copied


def start_server(workdir, port):
    env = {**os.environ, **ENV, "PYTHONPATH": REPO,
           "HOST": "127.0.0.1", "PORT": str(port),
           "YARA_WATCH_DIRS": os.path.join(workdir, "watch")}
    log = open(os.path.join(workdir, "server.log"), "w", encoding="utf-8")
    proc = subprocess.Popen([sys.executable, os.path.join(REPO, "app.py")],
                            cwd=workdir, env=env, stdout=log, stderr=subprocess.STDOUT,
                            start_new_session=True)
    base = f"http://127.0.0.1:{port}"
    for _ in range(60):
        if proc.poll() is not None:
            raise RuntimeError("서버가 기동 중에 죽었다 — server.log 확인")
        try:
            urllib.request.urlopen(base + "/api/telemetry", timeout=3).read()
            return proc, base
        except (urllib.error.URLError, OSError):
            time.sleep(1)
    raise RuntimeError("서버 기동 시간 초과")


def stop_server(proc):
    """프로세스 그룹째 정리한다. pgrep 패턴 매칭은 쓰지 않는다 —
    호출한 셸의 명령줄까지 매칭해 자기 자신을 죽이는 사고가 난다."""
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except OSError:
        proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            proc.kill()


def run_round(base, mix, workers):
    paths = [p for path, n in mix for p in [path] * n]

    def hit(path):
        started = time.time()
        try:
            with urllib.request.urlopen(base + path, timeout=180) as r:
                r.read()
            ok = True
        except Exception:
            ok = False
        return path.split("?")[0], (time.time() - started) * 1000, ok

    stats, failures = {}, 0
    started = time.time()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for name, ms, ok in ex.map(hit, paths):
            stats.setdefault(name, []).append(ms)
            failures += 0 if ok else 1
    return stats, time.time() - started, failures, len(paths)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--with-real-data", action="store_true",
                    help="data/alerts*.db 의 사본을 물려 의미 있는 규모로 잰다")
    ap.add_argument("--workers", type=int, default=8, help="동시 요청 수 (기본 8)")
    ap.add_argument("--rounds", type=int, default=2,
                    help="라운드 수. 1회차는 캐시가 비어 있어 느리다 (기본 2)")
    ap.add_argument("--keep", action="store_true", help="작업 디렉터리를 지우지 않는다")
    args = ap.parse_args()

    workdir = tempfile.mkdtemp(prefix="soc-loadtest-")
    os.makedirs(os.path.join(workdir, "data"), exist_ok=True)
    os.makedirs(os.path.join(workdir, "watch"), exist_ok=True)
    port = _free_port()
    print(f"작업 디렉터리: {workdir}\n포트: {port}")

    if args.with_real_data:
        copied = copy_real_data(workdir)
        if copied:
            print("실데이터 사본: " + " · ".join(f"{k} {v:,}건" for k, v in copied.items()))
        else:
            print("실데이터 없음 — 빈 DB 로 진행")

    proc = None
    try:
        proc = start_server(workdir, port)
        proc, base = proc
        total = json.load(urllib.request.urlopen(base + "/api/alerts/history?limit=1"))["total"]
        print(f"적재: {total:,}건\n")
        for rnd in range(1, args.rounds + 1):
            stats, elapsed, failures, n = run_round(base, DEFAULT_MIX, args.workers)
            label = " (캐시 비어 있음)" if rnd == 1 else ""
            print(f"── 라운드 {rnd}{label}: {n}요청 · {elapsed:.1f}초 "
                  f"· 동시 {args.workers}" + (f" · 실패 {failures}" if failures else ""))
            for name, xs in sorted(stats.items(), key=lambda kv: -max(kv[1])):
                xs.sort()
                print(f"   {name:<44} n={len(xs):>2} "
                      f"p50 {xs[len(xs) // 2]:>7.0f}ms  최대 {xs[-1]:>8.0f}ms")

        tel = json.load(urllib.request.urlopen(base + "/api/telemetry"))
        print(f"\n텔레메트리: {tel['summary']}")
        for p in sorted(tel["points"], key=lambda p: -(p["p95"] or 0)):
            mark = " ⚠느림" if p["slow"] else (" (표본부족)" if p["warming_up"] else "")
            print(f"   {p['name']:<24} 호출 {p['calls']:>5} p50 {p['p50']:>8} "
                  f"p95 {p['p95']:>9} 실패 {p['errors']}{mark}")
        for probe in tel["probes"]:
            if probe["warn"] or probe.get("error"):
                print(f"   ⚠ {probe['label']}: {probe['value']} {probe.get('error', '')}")

        slow = tel["summary"]["slow"]
        if slow:
            print(f"\n느린 지점 {slow}개 — 위 목록의 ⚠ 부터 볼 것.")
        return 1 if slow else 0
    finally:
        if proc is not None:
            stop_server(proc)
        if args.keep:
            print(f"\n작업 디렉터리 유지: {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
