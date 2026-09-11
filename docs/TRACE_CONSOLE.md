# SOC console: analyst and maintainer guide

The classic Korean SOC shell is restored as the default presentation.
The evidence workflows added during TRACE remain in the existing Flask/Jinja application. All 37 original specialist
panels remain available; Detection Quality and Access & roles bring the total to 39. There is no
React application, separate demo backend, new frontend build system or CDN.

See [Classic restoration and deployment](CLASSIC_RESTORE.md) for the current layout.

See [Access control](ACCESS_CONTROL.md) for opt-in managed users and permission boundaries,
and [Load validation](LOAD_VALIDATION.md) for measured query performance.

## Investigate an alert

1. Choose SOAR · 대응 → 위협 알림, press Cmd/Ctrl + K, or expand 저장 증거 요약 at the bottom of AI 관제 센터 and open a priority row.
2. Review severity, source provenance, the detection score and recorded evidence.
3. Use Evidence, Timeline, Analyst copilot, and Response & audit without losing the queue.
4. Record ACK, closure or an independent TP/FP analyst verdict with a reason.
5. Pivot to linked incidents, MITRE, entities or immutable response decisions.

Arrow keys move between queue rows; Enter opens an alert. Native dialogs trap
focus and support Escape. Entity buttons open the command palette. Column edge
handles support pointer resizing and Left/Right keys. Saved queue views and SIEM
query history are scoped to the browser, not shared team configuration.

The copilot offers evidence summary, investigation steps, response explanation and
handoff. Its FACTS section comes from stored records. Model-generated text is only
advisory; it cannot replace those facts or remove known missing-data statements.
An unavailable/invalid model response retains the deterministic evidence summary.
There are no conversational execution tools.

## Understand scope before interpreting a number

| Surface | Actual scope and limit |
| --- | --- |
| Header range | Command Center alerts/activity, queue, entity alert search and Detection Quality. Specialist panels expose independent ranges. |
| Critical cases | Current active cases of all ages; case provenance is shown. Older cases with no origin remain UNAVAILABLE. |
| Priority queue | OPEN alerts in selected range, live and archive union. Count is a database query; the home table displays up to six. |
| Analyst queue | 50 records/page, server filters and sorting; current/newest/priority order changes only on explicit refresh or analyst action. Archive rows cannot be edited. |
| Activity chart | Hourly counts over the selected range, server clock. No fabricated empty-period measurements. |
| Campaign count | Latest 5,000 alert sample; same source + time window, partitioned by provenance. A campaign is correlation, not attribution or proof of causation. |
| Detection Quality | Latest 5,000 records; sampling is explicit. FP rate = analyst FP / (analyst FP + analyst TP). Unreviewed records are excluded. Dates group current verdicts by detection date. |
| Suppression preview | Latest 5,000 stored alerts within 24h; exact rule/type and literal source prefix. CRITICAL is exempt. Only the request is audited; no rule/evidence writes. This estimates candidate-alert matches, not the full ingestion/suppression pipeline. |
| MITRE matrix | Stored alert mappings within its selected range, max 5,000; recorded fields and existing threat-type mappings. Cells expose provenance. Rule inventory and purple validation are separate. Original aggregate counters/detail history remain process-scoped and labeled. |
| Related alerts | Latest 30 textual entity matches in seven days; same provenance. Shared entities are leads, not exact correlation links. |
| Investigation links | Incidents include the exact alert ID; decisions and audit records use exact IDs/targets, not a shared-IP guess. Audit and decision views cap at 100 per alert; AI history is process-local. |
| SIEM | Retained event buffer, up to 200 rendered rows. AND text and exact `field=value`, quoted values supported; not a full SPL engine. Unknown timestamps are excluded from time filters. Timezone-less source timestamps use the server timezone. |
| SIEM exports | JSON contains query, time scope and the exact retained result snapshot. Explicit query execution is audited; history is local to this browser. Source log retention is unchanged. |
| Map | Up to 2,000 browser-session events, 80 source groups and 40 verified-destination arcs. Current backend has no verified asset geolocation, so it shows source observations without inferred destination arcs. The historical Seoul coordinate is a display anchor, not an asset location. |
| Pipeline health | Actual telemetry p50/p95/max, calls/errors and registered probes. Demo workload can generate real performance measurements. No invented normal baseline, event-loss rate, latency or sensor SLA. |
| CVE match | Scanner evidence, package validation and installed/candidate version where recorded. Package evidence alone does not establish exploitability of every CVE banner match. |
| Decision replay | Gate eligibility, immutable original snapshot and simulated difference. Does not execute or predict firewall success, re-run allowlists or change approvals. |

REAL means the source recorded real origin, not that an attack was proven. DEMO,
SYNTHETIC, SIMULATED, EXPERIMENTAL, UNAVAILABLE and MIXED are visible interpretations
with reasons. The existing stored `origin` is preserved; presentation classification
does not become a new SOAR input. Newly collected SIEM demo records explicitly
propagate their demo flag so they cannot lose provenance on alert promotion.

## Realtime behavior

The shared `SOCRealtime` adapter buffers display events while PAUSED. Collection,
durable storage, server AI work and response policy continue. Connection state is
never buffered. Frequent state snapshots are coalesced; the buffer holds at most
500 display items. The UI reports overflow and can refresh from durable evidence.
Backend history is not removed by the browser buffer cap. The alert queue does not
reorder on arrivals, keeping selection and reading position stable. Charts retain
the existing batching. High-volume screen reader messages are bounded.

Pause is a presentation tool, not a response kill switch. The SOAR panel contains
the existing automation and approval controls.

## API additions

All endpoints use the existing `/api` Blueprint and the application's authentication,
Origin/Referer CSRF enforcement, session policy and error handlers.

| Method / route | Purpose |
| --- | --- |
| GET `/console/summary` | Cached measured situation snapshot; 10-second cache. |
| GET `/console/alerts` | Bound/validated durable filters, counts and pagination. |
| GET `/console/alerts/<id>` | Evidence, exact links, chronology and deterministic briefing. |
| GET `/console/entities` | Grouped alert, incident and IOC matches. |
| GET `/console/quality` | Rule/analyst quality, dated verdict counts and noisy sources. |
| GET `/console/mitre` | Time-scoped stored technique observations with provenance. |
| POST `/console/suppression-preview` | Read-only what-if calculation plus audit record. |
| POST `/console/copilot` | Allowlisted context-bound advisory request, audited. |
| POST `/console/siem-query` | Audit explicit retained-buffer query execution. |

GET `/soar/decisions/<id>/replay` retains the original contract and adds validated
`without_evidence` and `is_true_positive` overrides. `replayed.gates_passed` and
`gates_changed` are the unambiguous UI fields. Legacy `blocked`/`changed` remain for
API compatibility; they must not be interpreted as simulated execution success.

Durable alert edits now commit before changing memory and work after records leave
the detector's in-memory deque. Archived/missing records return failure. A failed
write is not reported as successful. Analyst verdict attribution uses the server
session actor rather than a client-supplied cookie.

## Design system and architecture

- `static/css/style.css`: shared semantic surface, border, text, spacing, radius,
  severity, status, confidence, provenance and focus tokens; existing typography roles.
- `static/css/console.css`: evidence tables, filters, drawers, native action dialogs,
  timelines, empty/loading states and palette. The former `.trace-console` shell overrides
  are inactive; the page uses `.classic-console`.
- `static/css/classic.css`: compact header integration and evidence-component adaptations
  for the original SOC layout; specialist panels retain their original styles.
- `static/css/login.css`: the original standalone login styling, extracted from its template.
- `templates/components/classic-navbar.html` and `evidence-summary.html`: reusable
  Korean header and the expandable stored-evidence summary.
- `templates/components/console-dialogs.html`: reusable investigation and action surfaces.
- `00-console-runtime.js`: centralized display state, formatting, provenance and entity pivots.
- `24-console.js` through `27-alert-queue.js`: shell/search, investigation/copilot,
  quality and queue boundaries. Existing IIFE exports and lazy `onPanelReady` stay intact.
- `modules/console*.py`, `modules/provenance.py`: parameterized WAL reader queries and
  read composition. No new response engine, database or migration of historical evidence.

The globe libraries remain lazy and optional. The previously generated login bitmap
(Higgsfield, 2026-09-09) is no longer displayed and was removed from the repository on
2026-09-11 (git history before that date keeps it).

## Preserved safety and intentional limits

SOAR simulate-first, manual approval policy, allowlists, self/private-network guards,
TTL, patch dry-run/command allowlist and EDR system-process protection remain in
place. CSP continues to exclude inline handlers, unsafe-eval and remote script CDNs.
No secrets, operational databases or generated credentials belong in frontend files.

Not added: SSO/MFA, multi-tenancy, a dedicated asset inventory, guaranteed incident
attribution, full SPL, shared saved SIEM queries, a new notification inbox, MTTD,
historical coverage-change tracking, ML/AI accuracy claims, autonomous copilot
execution, generated operational artwork, or a frontend framework migration.
Existing saved hunts, case metrics and response history remain available.

For an enterprise rollout, the next iteration should integrate an identity provider/MFA,
source-authenticated provenance at every collector, durable event identifiers and
transition timestamps, ingestion retention/scale tests and an operational deployment
review. Current audit stores are append-only in application usage, not cryptographically
tamper-proof. Current SQLite/WSGI deployment limits and synchronous copilot request
capacity must be evaluated against the intended workload.
