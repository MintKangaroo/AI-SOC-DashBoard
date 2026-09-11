# TRACE load validation · 2026-09-09

This is a bounded local HTTP/concurrent-ingestion benchmark, **not** a production
capacity certification or an end-to-end sensor test. The same Flask/Jinja application,
Blueprints, authentication and SQLite stores run in a temporary process. No operational
server is restarted, no original database is written and no response action is executed.

## 2026-09-11 재측정 (한국어 요약)

조사 콘솔·권한 검사가 들어온 뒤 처음 다시 쟀다. **회귀는 없다.**

| 프로파일 | `alert_store.search` p95 | 가장 느린 경로 | 예산(2초) 초과 |
|---|---|---|---|
| `legacy` | 444ms (09-06 약 400ms) | `/api/metrics/soc?days=90` 1회차 2,291ms | 1건(1회차만, 캐시 뒤 수 ms) |
| `both` | 1,078ms | `/api/alerts/history/export.ocsf.json?limit=2000` 2,306ms | 1건 |

- 데이터: 알림 111,378건(활성 630 + 아카이브 110,748), 인시던트 23,303건, 동시 8.
- HTTP 실패 0 · 텔레메트리 `failing` 0 · `slow` 0 · 캐시 재사용 정상.
- **같은 조건에서는 안 느려졌다.** `both` 에서 두 배가 되는 것은 콘솔 질의가 같은
  저장소를 함께 때리기 때문이며, 새 기능이 쓰는 값이지 회귀가 아니다.
- `/api/metrics/soc` 1회차가 1.1초→2.3초로 는 원인은 인덱스가 아니라 **인시던트
  23,303건을 파이썬으로 훑는 집계**다(`soc_metrics._incident_times`). 캐시가 받아
  주므로 사용자는 패널을 처음 열 때 한 번 겪는다. 줄이려면 그 집계를 미리 계산하거나
  인시던트 보존을 조이는 두 길이 있고, 아직 어느 쪽도 하지 않았다.
- OCSF 내보내기 2,000건 2.3초는 다운로드 경로라 화면을 막지 않는다.

## Reproduce

```bash
./venv/bin/python scripts/loadtest.py --profile console --with-real-data \
  --authenticated --workers 8 --rounds 20 --ingest-rate 20 \
  --json-output /tmp/trace-load-results.json
```

`--profile legacy` exercises the original history/export/metrics/health workload;
`both` includes both profiles. Without `--with-real-data`, stores start empty.
The script opens source databases read-only and uses SQLite backup (including WAL)
to temporary copies. Temporary artifacts are deleted by default. `--keep` deliberately
retains the evidence copy, which must receive the same protection as the source data.

Authentication uses a random temporary administrator and temporary identity database.
Collectors, background response workers and external integrations are disabled. The
optional producer calls the actual `ThreatDetector._add_alert` path with unique low
severity, private-address inputs explicitly tagged **SYNTHETIC**. It verifies persisted
count separately; a swallowed storage error therefore cannot count as success.
Neither this test nor `DEMO_MODE` should be interpreted as proof of real sensor coverage.

The declared HTTP p95 budget is **2,000 ms** per route per round, a chosen engineering
acceptance threshold. Percentiles use nearest rank. Reports retain p50/p95/max, sample
counts, failures, initial/subsequent rounds, aggregate distributions and ingestion
attempts/persistence/errors. A nonzero exit reports HTTP/budget/storage failures.
The offered ingestion rate is reported separately from achieved rate: `passed` checks
HTTP latency and persistence, **not** an ingestion-throughput SLA.

## Measured duplicate-aggregate bottleneck

The first run contained 587 current + 110,748 archived alerts; the next backup contained
588 + 110,748. Both used 8 concurrent HTTP workers, 2 rounds / 88 requests and an offered
20 synthetic inputs/s. The selected console range was 168 hours. Its quality, campaign
and MITRE compositions retain their existing latest-5,000-record sample limits; the
benchmark does not claim to correlate all 111,000+ records in memory.

| Initial-round endpoint | Before p95, ms | After p95, ms |
| --- | ---: | ---: |
| Command Center summary | 3195.63 | 424.31 |
| Detection Quality | 2400.64 | 284.01 |
| Stored MITRE observations | 1527.98 | 137.04 |

Four overlapping first requests previously calculated the same aggregates independently.
`CoalescedReads` now shares only overlapping, identical reads, with a bounded in-flight
registry. Different filters remain independent; errors propagate to all waiters and
completed entries are discarded. Quality/MITRE do not acquire a stale-result TTL cache.
The summary keeps its pre-existing explicit 10-second snapshot cache. Each HTTP request
still authenticates independently and receives its own response object. The alert decoder
also avoids applying provenance twice to every returned record.

Raw aggregates: [before](validation/2026-09-09-access/initial-before.json),
[after](validation/2026-09-09-access/initial-after.json). Each heavy endpoint has only four
samples in an initial round, so these are diagnostic timings rather than statistical
service guarantees. Source snapshots and host scheduling differ slightly between runs.

## Expanded verification

Final run: **111,338 stored alerts**, **880 HTTP requests** over 20 rounds, 8 workers,
**0 HTTP failures**, no per-round p95 budget exceedance. Total HTTP test time was
15.857 seconds. Python 3.10.12 on a shared local host exposing 12 logical CPUs.

| Endpoint | Samples | p50 ms | p95 ms | Max ms |
| --- | ---: | ---: | ---: | ---: |
| `/api/console/alerts?limit=50&hours=168` | 240 | 188.15 | 352.8 | 1413.5 |
| `/api/console/alerts?q=CVE&hours=168` | 160 | 50.07 | 97.62 | 148.64 |
| `/api/console/entities?q=185.220&hours=168` | 160 | 148.91 | 270.21 | 381.48 |
| `/api/console/quality?hours=168` | 80 | 142.03 | 283.3 | 304.51 |
| `/api/console/summary?hours=168` | 80 | 12.57 | 363.36 | 385.3 |
| `/api/console/mitre?hours=168` | 80 | 120.68 | 279.73 | 499.94 |
| `/api/whoami` | 80 | 13.16 | 28.12 | 54.86 |

The producer persisted **265/265 SYNTHETIC inputs**, with 0 observed errors. The offered
rate was 20/s and achieved rate **16.72/s**, over 15.847 seconds. Detector input latency
was p50 6.39 ms, p95 30.96 ms, maximum **1431.44 ms**. The generator applies backpressure
when processing stalls; these results do **not** establish sustained 20 inputs/s capacity.

An earlier expanded run exceeded the per-round 2-second budget in its final round
(queue max 2462.90 ms, CVE search max 2412.58 ms), although its aggregate p95 stayed
below the budget and all 302 inputs persisted. That run is retained rather than removed.
The final repeat scheduled no other validation process concurrently, but this is still a
shared host; scheduler/I/O contention has not been independently attributed or eliminated.

Raw aggregates: [earlier expanded run](validation/2026-09-09-access/expanded-first.json),
[final expanded run](validation/2026-09-09-access/expanded-final.json).

## Remaining validation

- Run hours-long ingestion/retention/queries on deployment hardware with representative
  severity, evidence sizes, sensor rates and disk pressure; measure backlogs and drops.
- Benchmark authenticated WebSocket fan-out with many distinct users. Current browser
  regressions verify actual connection/revocation behavior, not high-volume fan-out capacity.
- Test collector/network failures, restart recovery, archive growth and backup restoration.
- Define a deployment-specific throughput objective and failure budget. The short local
  run, private low-severity inputs and bounded samples cannot substitute for those checks.
