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
import http.cookiejar
import math
import platform
import secrets
import urllib.parse
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

CONSOLE_MIX = [
    ('/api/console/alerts?limit=50&hours=168',12),
    ('/api/console/alerts?q=CVE&hours=168',8),
    ('/api/console/entities?q=185.220&hours=168',8),
    ('/api/console/quality?hours=168',4),
    ('/api/console/summary?hours=168',4),
    ('/api/console/mitre?hours=168',4),
    ('/api/whoami',4),
]
ENV = {
    'AUTH_ENABLED':'False','AUTH_USERS_DB':'','DEMO_MODE':'True','DEBUG':'False',
    'SOAR_BLOCK_MODE':'simulate','SOAR_AUTO_BLOCK':'False','SOAR_APPROVAL_REQUIRED':'True',
    'PATCH_APPLY_ENABLED':'False','SYSLOG_ENABLED':'False','SNORT_ENABLED':'False',
    'SURICATA_ENABLED':'False','ZEEK_ENABLED':'False','NTFY_ENABLED':'False',
    'SIEM_ACCESS_LOGS':'none=/nonexistent/a.log','AUTH_LOG_PATH':'/nonexistent/a.log',
    'ANSIBLE_TARGETS':'','NET_MONITOR_TARGETS':'','FUZZ_TARGETS':'',
    'ANTHROPIC_API_KEY':'','ABUSEIPDB_API_KEY':'','VIRUSTOTAL_API_KEY':'',
    'VULNERS_API_KEY':'','ML_AUTO_RETRAIN':'False','YARA_SCAN_PROCESSES':'False',
    'DASH_PASSWORD':'','DASH_PASSWORD_HASH':'','SECRET_KEY':'loadtest-only',
}
# Runs the real app/services in a temporary process, with controlled ingestion.


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[max(0,math.ceil(len(ordered)*fraction)-1)], 2)


def summarize(values):
    return {'samples':len(values),'p50_ms':percentile(values,.5),
            'p95_ms':percentile(values,.95),'max_ms':round(max(values),2) if values else None}


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


def start_server(workdir, port, credentials=None, ingest_rate=0):
    env = {**os.environ, **ENV, 'PYTHONPATH':REPO, 'HOST':'127.0.0.1', 'PORT':str(port),
           'TRACE_ISOLATED_WORKDIR':os.path.abspath(workdir),
           'TRACE_TEST_INGEST_RATE':str(ingest_rate),
           'YARA_WATCH_DIRS':os.path.join(workdir,'watch')}
    for key,name in [('AUDIT_DB','audit.db'),('WATCHLIST_DB','watchlist.db'),
                     ('HUNT_DB','hunts.db'),('LABEL_DB','labels.db'),('BLOCK_DECISION_DB','decisions.db')]:
        env[key] = os.path.join(workdir,'data',name)
    env['LOG_DIR'] = os.path.join(workdir,'logs')
    if credentials:
        env.update(AUTH_ENABLED='True',AUTH_USERS_DB=os.path.join(workdir,'data','users.db'),
                   DASH_USERNAME=credentials['username'],DASH_PASSWORD=credentials['password'])
    with open(os.path.join(workdir,'server.log'),'w',encoding='utf-8') as log:
        proc = subprocess.Popen([sys.executable,os.path.join(REPO,'scripts','loadtest_server.py')],cwd=workdir,env=env,
                                stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    base = f'http://127.0.0.1:{port}'
    try:
        for _ in range(60):
            if proc.poll() is not None:
                raise RuntimeError('Server exited during startup; inspect temporary server.log.')
            try:
                urllib.request.urlopen(base+'/login',timeout=3).read()
                return proc,base
            except (urllib.error.URLError,OSError):
                time.sleep(1)
        raise RuntimeError('Server startup timed out.')
    except Exception:
        stop_server(proc)
        raise


def authenticated_opener(base, credentials):
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    data = urllib.parse.urlencode(credentials).encode()
    opener.open(urllib.request.Request(base+'/login',data=data,headers={'Origin':base}),timeout=30).read()
    who = json.load(opener.open(base+'/api/whoami'))
    if who.get('role') != 'admin':
        raise RuntimeError('Load-test authentication failed.')
    return opener


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


def run_round(base, mix, workers, opener=None):
    paths = [p for path, n in mix for p in [path] * n]
    opener = opener or urllib.request.build_opener()

    def hit(path):
        started = time.monotonic()
        try:
            with opener.open(base + path, timeout=90) as r:
                r.read()
            ok = True
        except Exception:
            ok = False
        return path, (time.monotonic() - started) * 1000, ok

    stats, failures = {}, 0
    started = time.monotonic()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for name, ms, ok in ex.map(hit, paths):
            stats.setdefault(name, []).append(ms)
            failures += 0 if ok else 1
    return stats, time.monotonic() - started, failures, len(paths)


def main():
    ap = argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--with-real-data',action='store_true',help='Read-only SQLite backup to temporary storage')
    ap.add_argument('--workers',type=int,default=8)
    ap.add_argument('--rounds',type=int,default=2)
    ap.add_argument('--profile',choices=['legacy','console','both'],default='both')
    ap.add_argument('--authenticated',action='store_true',help='Exercise managed identity/session checks')
    ap.add_argument('--ingest-rate',type=float,default=0,help='Synthetic detector inputs/sec (0–100)')
    ap.add_argument('--p95-budget-ms',type=float,default=2000,help='Declared HTTP p95 acceptance budget, not an industry SLA')
    ap.add_argument('--json-output',help='Write aggregate results only; no alert evidence or credentials')
    ap.add_argument('--keep',action='store_true')
    args = ap.parse_args()
    if not 1 <= args.workers <= 64 or not 1 <= args.rounds <= 20 or not math.isfinite(args.ingest_rate) or not 0 <= args.ingest_rate <= 100 or not math.isfinite(args.p95_budget_ms) or args.p95_budget_ms <= 0:
        ap.error('Invalid workers, rounds, ingestion rate or latency budget.')
    workdir = tempfile.mkdtemp(prefix='soc-loadtest-')
    os.makedirs(os.path.join(workdir,'data'),exist_ok=True)
    os.makedirs(os.path.join(workdir,'watch'),exist_ok=True)
    proc = None
    report = {'scope':'Isolated HTTP read workload; collectors and response workers disabled.',
              'data':'COPY OF STORED EVIDENCE' if args.with_real_data else 'EMPTY DATABASE',
              'workers':args.workers,'profile':args.profile,'authenticated':args.authenticated,
              'target_ingest_per_second':args.ingest_rate,'p95_budget_ms':args.p95_budget_ms,
              'python':platform.python_version(),'cpu_count':os.cpu_count(),'rounds':[]}
    try:
        report['copied'] = copy_real_data(workdir) if args.with_real_data else {}
        credentials = {'username':'loadtest-admin','password':secrets.token_urlsafe(32)} if args.authenticated else None
        proc,base = start_server(workdir,_free_port(),credentials,args.ingest_rate)
        opener = authenticated_opener(base,credentials) if credentials else urllib.request.build_opener()
        mix = DEFAULT_MIX if args.profile == 'legacy' else CONSOLE_MIX if args.profile == 'console' else DEFAULT_MIX+CONSOLE_MIX
        report['stored_alerts_at_start'] = json.load(opener.open(base+'/api/alerts/history?limit=1'))['total']
        open(os.path.join(workdir,'start-ingest'),'w').close()
        combined = {}
        for rnd in range(1,args.rounds+1):
            stats,elapsed,failures,n = run_round(base,mix,args.workers,opener)
            for path, values in stats.items():
                combined.setdefault(path, []).extend(values)
            paths = {path:summarize(values) for path,values in stats.items()}
            exceeded = [path for path,values in paths.items() if values['p95_ms'] > args.p95_budget_ms]
            report['rounds'].append({'round':rnd,'cache':'initial' if rnd == 1 else 'subsequent',
                'requests':n,'elapsed_seconds':round(elapsed,3),'requests_per_second':round(n/elapsed,2),
                'http_failures':failures,'budget_exceeded':exceeded,'paths':paths})
            print(f'Round {rnd}: {n} requests, {failures} failures, {len(exceeded)} paths over declared p95 budget')
        report['aggregate_paths'] = {path:summarize(values) for path,values in combined.items()}
        if args.ingest_rate:
            open(os.path.join(workdir,'stop-ingest'),'w').close()
            ingestion_path = os.path.join(workdir,'ingestion.json')
            for _ in range(200):
                if os.path.exists(ingestion_path):
                    break
                time.sleep(.1)
            with open(ingestion_path) as result:
                ingestion = json.load(result)
            ingestion['latency'] = summarize(ingestion.pop('durations_ms'))
            ingestion['observed_per_second'] = round(ingestion['attempted']/ingestion['elapsed_seconds'],2)
            report['ingestion'] = ingestion
        telemetry = json.load(opener.open(base+'/api/telemetry'))
        report['telemetry'] = {'summary':telemetry['summary'], 'points':[{k:p[k] for k in ('name','calls','p50','p95','max','errors','slow')} for p in telemetry['points']]}
        ingestion = report.get('ingestion',{})
        report['passed'] = not (any(r['http_failures'] or r['budget_exceeded'] for r in report['rounds']) or ingestion.get('errors') or ingestion.get('attempted') != ingestion.get('persisted'))
        if args.json_output:
            with open(args.json_output,'w') as output:
                json.dump(report,output,indent=2)
        print(json.dumps(report,indent=2))
        return 0 if report['passed'] else 1
    finally:
        if proc is not None:
            stop_server(proc)
        if args.keep:
            print('Temporary evidence copy retained: '+workdir)
        else:
            shutil.rmtree(workdir,ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
