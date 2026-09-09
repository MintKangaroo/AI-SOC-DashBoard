"""Isolated load/browser validation server. Run through scripts/loadtest.py only."""
import json
import os
from pathlib import Path
import threading
import time


def main():
    work = Path.cwd()
    if os.environ.get('TRACE_ISOLATED_WORKDIR') != str(work) or work == Path(__file__).resolve().parent.parent:
        raise SystemExit('Use scripts/loadtest.py; an isolated working directory is required.')
    import wiring
    # Repeatable validation: collectors and response workers never start.
    wiring.start_services = lambda *args: None
    import app
    from modules.threat_detector import Alert
    rate = float(os.environ.get('TRACE_TEST_INGEST_RATE', '0'))

    def ingest():
        while not (work/'start-ingest').exists():
            time.sleep(.05)
        durations, errors, count = [], 0, 0
        started = time.monotonic()
        while not (work/'stop-ingest').exists() and count < 100000:
            before = time.monotonic()
            try:
                alert = Alert('PORT_SCAN', 'LOW', '10.250.0.7', '10.250.0.8',
                              'SYNTHETIC load validation',
                              {'demo':True, 'provenance':'SYNTHETIC', 'source':'trace-loadtest',
                               'rule_id':'load-'+str(count)})
                app.app.threat_detector._add_alert(alert)
            except Exception:
                errors += 1
            count += 1
            durations.append((time.monotonic()-before)*1000)
            time.sleep(max(0, 1/rate-(time.monotonic()-before)))
        elapsed = time.monotonic()-started
        persisted = app.app.threat_detector.store.console_search(source_name='trace-loadtest', hours=0, limit=1)['total']
        # Publish atomically; the parent must not read a partially written report.
        pending = work/'ingestion.tmp'
        pending.write_text(json.dumps({'attempted':count, 'persisted':persisted,
            'errors':errors, 'durations_ms':durations, 'elapsed_seconds':elapsed,
            'provenance':'SYNTHETIC',
            'scope':'Low-severity private-address detector inputs; no response workers.'}))
        pending.replace(work/'ingestion.json')

    if rate:
        threading.Thread(target=ingest, daemon=True).start()
    app.socketio.run(app.app, host='127.0.0.1', port=int(os.environ['PORT']),
                     allow_unsafe_werkzeug=True, use_reloader=False)


if __name__ == '__main__':
    main()
