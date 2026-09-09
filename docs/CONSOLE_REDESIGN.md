# TRACE · AI SOC command center

## Repository and UX audit — 2026-09-09

Starting revision: `21e93b3`. The workspace was an existing clean clone of
MintKangaroo/AI-SOC-DashBoard. No runtime databases, credentials, sensor settings,
or protected servers are part of this change.

Baseline: **860 passed, 2 warnings, 246.16 seconds**. This includes the existing
Playwright desktop/mobile panel sweep, real-server tests, security regressions,
and frontend namespace/lazy-panel/contrast checks. Baseline XML and screenshot
were captured under `/tmp/soc-baseline.xml` and `/tmp/soc-before.png`.

### System map

| Capability | Existing implementation and constraints |
| --- | --- |
| Collection | Packet capture, psutil network/EDR, Sysmon, access/auth logs, syslog, Snort, Suricata, Zeek. Sensor availability differs from global DEMO_MODE. |
| Detection | ThreatDetector, Sigma and YARA feed alerts; confidence, deduplication and suppression precede response. Original suppressed events have a separate durable store. |
| Realtime | Flask-SocketIO threading; new_alert, packet_update, AI/ML results, SIEM, IDS, SOAR executions and incident updates. Browser tables/charts are bounded and specialist panels materialize lazily. |
| Alert lifecycle | SQLite WAL live + archive union, OPEN/ACK/CLOSED, assignment and separate reasoned analyst verdicts. Archive is read-only. |
| Incidents | Persistent cases, alert IDs, assignee, status transitions and timeline. Existing correlation by network/type is not attribution. |
| SIEM/hunting | Recent raw access event buffer with fields/histogram; durable alert history; persisted hunt definitions, deltas and IOC promotion. SIEM is not a full SPL interpreter. |
| AI | Anthropic worker, timeouts and circuit breaker; fallback output is DEMO. AI verdict is separate from analyst verdict and is not ground truth. |
| ML | Isolation Forest advisory with stored real/demo features and retraining. RF/LSTM/Q-learning are isolated experiments. Accuracy is unavailable without valid evaluation data. |
| Response | SOAR playbooks, approvals, TTL, allowlists, private/self-IP protections, simulated firewall mode; patch dry-run and command allowlist; EDR system-process protections. |
| Replay | Immutable decision inputs and pure gate evaluation. Gate eligibility is not proof of a firewall operation. |
| ATT&CK | Local tactic/technique catalog, rule inventory, purple validation and observed hit counts. Hits can include simulation; rule presence does not establish live sensor visibility. |
| Campaigns | Same source + time-window grouping and tactic ordering; bounded historical query. Hypothesis, not attacker identity or proof of sequence. |
| Intelligence | IOC feeds/watchlist, IP reputation with demo fallback, optional VirusTotal hash enrichment. |
| Exposure | Port/service/CVE scanner, apt/backport cross-validation, Ansible patch state. Scanner matches alone are unverified. |
| Operations | Incident timeline MTTA/MTTR, automated FP closure ratio (not analyst FP rate), append-only audit, health aggregation, measured p50/p95/max/errors/queue probes. No measured MTTD or coverage-change history. |
| Provenance | Existing labeling classifier recognizes demo catalogs, TEST-NET, simulator logs and legacy contaminated sources. Absence of a synthetic marker does not prove real origin. |

Reviewed README, HANDOFF, CLAUDE, docs (including portfolio, case studies, current
handover, audit, architecture and module references), app/config/wiring, all API
domains, module inventory and relevant pipeline implementations, all 37 panel
templates and dashboard JS boundaries, styles/vendor assets, tests/CI,
pyproject, compose and env example. Older documents are historical evidence,
not reliable descriptions of the current code: CORS/CSRF, command allowlists,
and retention have already been hardened.

### Findings driving the redesign

- First viewport puts large infrastructure sections ahead of analyst decisions;
  the header asserts normal system health without measured evidence.
- Demo and real evidence need per-record labels. Closed alerts must not be
  called blocked IPs. AI fallback content must never look like factual analysis.
- Alert actions are crowded and supporting context is scattered across panels.
- Realtime insertion can move reading positions; there is no shared pause state.
- SIEM time filtering estimates recency from array length rather than timestamps.
- There is no unified durable search across normalized alert/entity fields.
- No reason exists for a framework rewrite: Jinja, Blueprints, self-hosted assets,
  IIFEs and existing lazy materialization provide a safe incremental boundary.

## Implementation plan

1. Shared semantic tokens and components; task navigation and persistent command bar.
2. Measured Command Center, bounded stable queue, explicit provenance and freshness.
3. Alert/entity investigation, contextual facts/inferences/recommendations/unknowns,
   reasoned analyst actions, suppression preview and traceable related evidence.
4. Refine SIEM, ATT&CK/campaigns, response/replay, exposure/health workflows in place.
5. Responsive and keyboard review, new regression tests, unchanged full-suite gates.

Production safety is invariant: no new destructive AI tools, no sensor installation,
firewall changes, patch application, real-server scans, or deployment.

## Implemented outcome

TRACE adds a task-oriented shell and command bar to the real Jinja dashboard.
The first viewport prioritizes open evidence, current critical cases, source
visibility and response policy. All original lazy panels remain connected to
existing APIs and Socket.IO handlers; Detection Quality is the only new panel.

The main investigation path is Command Center/queue/search → exact stored alert →
evidence/timeline/copilot/response and audit → reasoned analyst action. Queue rows
stay in place on incoming events. Shared pause state coalesces snapshots and caps
display buffering; missed display items do not delete backend evidence.

The API additions compose the existing stores. They do not introduce a second
backend, new response engine, database migration, framework or frontend dependency.
Durable queries bind parameters and expose sample/time limits. Alert changes commit
to SQLite before reporting success or mutating memory; records outside the memory
deque can now be acknowledged. Archive evidence remains read-only.

### Changed file map

| Responsibility | Files |
| --- | --- |
| Shell and tokens | `templates/dashboard.html`, `static/css/style.css`, new `static/css/console.css`, `static/js/dash/01-core.js` |
| Core workspaces | `templates/panels/{overview,alerts,siem,mitre,soar,vulnscan}.html`, new `templates/panels/quality.html` |
| Reusable dialogs | new `templates/components/console-dialogs.html` |
| Console boundaries | new `static/js/dash/{00-console-runtime,24-console,25-investigation,26-quality,27-alert-queue}.js` |
| Existing panel integration | `static/js/dash/{02-overview,03-detection,04-ml-mitre,06-sources,07-ops,08-response-init,09-alert-history,14-campaigns}.js` |
| Evidence query/composition | new `modules/{console,console_store,provenance}.py`, `modules/alert_store.py`, new `api/console_routes.py`, `api/routes.py` |
| Durable action integrity | `modules/threat_detector.py`, `api/detection_routes.py`, `modules/audit_log.py` |
| Response and correlation | `modules/{block_decision,correlation,incidents}.py`, `api/response_routes.py` |
| Collector truthfulness | `modules/{access_log_parser,sysmon_parser,system_health,geoip}.py` |
| Identity | `templates/login.html`, new `static/css/login.css`, `static/identity/telemetry-field.webp` |
| Regression coverage | new `tests/test_console.py`, `tests/test_console_browser.py`; obsolete unsafe-render exemption removed from `tests/test_frontend_counters.py`; `.github/workflows/ci.yml` runs both browser suites |
| Documentation | `README.md`, `CLAUDE.md`, `docs/{HANDOVER,PORTFOLIO}.md`, new `docs/{CONSOLE_REDESIGN,TRACE_CONSOLE,IDENTITY_ASSET}.md`, three actual demo screenshots in `docs/portfolio_img/trace-*.png` |

### Security and product review

- Existing app authentication, server session identity, Origin/Referer CSRF checks,
  CSP and self-hosted assets apply to the new Blueprint routes. The copilot accepts
  a stored alert ID and allowlisted intent, not an arbitrary command or target URL.
- Model output is constrained to advisory sections. Recorded FACTS cannot be
  overwritten and known missing-data statements cannot be erased by the model.
  Rendered source/model strings are escaped. The browser regression includes an
  HTML injection payload in a stored demo alert.
- Analyst verdict attribution now comes from the server actor; the unsigned
  `user` cookie is no longer an alternate identity source for this route.
- Replay uses immutable original inputs, explicitly reports eligibility rather
  than execution, validates numeric/boolean/source overrides and never writes
  production response state. Suppression preview only writes its audit entry.
- Existing destructive command, patch, process termination and firewall controls
  are preserved. No new automation or AI execution permission was introduced.
- REAL is source provenance, not proof of compromise. Current incident inventories,
  process counters, sampled history and the display-only map anchor are labeled
  according to their actual meaning. Missing metrics never become measured zeros.

### Intentional limits and next iteration

The new experience is not a claim of enterprise certification or complete SOC
visibility. SSO/RBAC, multi-tenancy, a dedicated asset inventory, durable raw-event
search/SPL, shared saved views, a separate notifications inbox, MTTD and historical
coverage changes were not added. Existing hunts, metrics and specialist controls
remain reachable. No accuracy, attack attribution or remediation-success metric
was fabricated. See [the scope table](TRACE_CONSOLE.md) for exact limits.

The next iteration should establish identity/role boundaries, source-authenticated
provenance in every collector, durable raw-event identifiers and lifecycle clocks,
and production-scale ingestion/query tests. Synchronous advisory requests and
SQLite concurrency need workload validation. Historical provenance can remain
ambiguous; append-only application audit usage is not cryptographic tamper evidence.
Deploy/restart and any real-server validation are separate operational actions;
this change was developed and reviewed in temporary isolated environments.

## Verification results — 2026-09-09

| Check | Result |
| --- | --- |
| Baseline before changes | **860 passed**, 2 existing dependency warnings, 246.16s |
| Full suite with coverage | **902 passed**, 2 existing dependency warnings, 208.12s |
| Coverage | **7,968 / 10,263 executable lines (77.64%, displayed as 78%)**; existing 70% gate passes |
| Lint and patch hygiene | `ruff check .` and `git diff --check` pass |
| Existing browser regression | All **38** lazy panels open on desktop and 390px mobile; no console errors, failed HTTP responses or page overflow |
| New browser workflows | Exact alert evidence, escaped hostile markup, deterministic copilot fallback, durable ACK/audit and focus return, bounded/coalesced Socket.IO display buffering, selection stability, keyboard palette/column resizing, timestamp-based SIEM query/export and mobile review |
| Responsive review | Command Center, queue, MITRE, SOAR, quality, vulnerability and health at **390, 768, 1920, 2560 and 3440px**; no document overflow or JavaScript errors |
| Identity asset | Higgsfield account rechecked; generation completed. Local **56,136-byte WebP** is used only on login; actual rendered login inspected |
| Documentation screenshots | Actual Jinja application, isolated temporary DEMO environment; three screenshots committed, not generated UI mockups |

Full run command:

```sh
coverage run --source=modules,api,experimental --omit='*/tests/*' -m pytest
coverage report --fail-under=70
ruff check .
```

There are **42 additional test cases** (35 API/domain cases and 7 browser workflows).
Existing meaningful assertions remain intact. The sole removed test entry is a
stale unsafe-render exemption for the removed fictional destination label. The
self-hosted-asset assertion remains unchanged. The existing CI now includes the
new browser workflows alongside the original panel sweep.

The two warnings are Scapy's existing cryptography TripleDES deprecations. No
production data, external scans, firewall operations, patch application, model
retraining or operational service restart was used to validate this change.
A production load test, independent accessibility/security audit and deployment
validation were not performed. Test duration is an observation, not a performance
improvement claim.
