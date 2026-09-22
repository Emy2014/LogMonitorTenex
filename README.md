# LogMonitor — SOC Log Analyzer

Upload a web proxy log, get back a triaged summary: **findings ranked by
severity and urgency** with plain-English explanations and confidence scores, a
**timeline**, **analytics dashboards** over the traffic itself, and a searchable
table of every parsed entry with the flagged rows highlighted.

Multi-tenant: organizations, roles, and access grants that separate the
narrative from the raw log lines — because raw proxy logs are employee
browsing history.

```
 browser
    │
    ▼
 web/      Next.js 15          login, dashboards, uploads, org admin
    │ /api/*  (server-side proxy, first-party cookie)
    ▼
 gateway/  Go                  auth · orgs · grants · audit
    │                          streaming ingest: parse → COPY → rollups
    │                          every dashboard read query
    ├──────────────► object store    raw uploads, retained compressed
    ├──────────────► Redis           durable job queue, rate limits
    └──────────────► PostgreSQL 16 + pgvector
                          ▲          partitioned events · rollups · findings
                          │
 worker/   Python ×N ─────┘         map → reduce → score → Claude
                                    six statistical detectors
```

The AI does not find the anomalies and it does not compute the confidence
scores. Six deterministic detectors do that, from the data itself; Claude is
given the ranked findings and writes the narrative. That boundary is the design.

---

## Running it locally

### Prerequisites

- **Docker Desktop** (or Docker Engine with the Compose plugin). This is all
  you need for the default path.
- Optional, only for running services outside Docker or running the tests:
  **Go 1.23+**, **Python 3.12**, **Node 22**.

### 1. Configure

```bash
git clone <this-repo> && cd logmonitor
cp .env.example .env
```

Every value in `.env.example` has a working local default. The one you may
want to set is `ANTHROPIC_API_KEY` — it is optional, see
[About the API key](#about-the-api-key). Leave `COOKIE_SECURE=false` and
`EDGE_AUTH_ENABLED=false` for local http.

### 2. Start the stack

```bash
docker compose up --build        # first build takes a few minutes
```

Compose starts the services below. `migrate` and `minio-init` run once and exit; the
rest stay up.

| Service | What it is | Port on your machine |
|---|---|---|
| `web` | Next.js UI | **http://localhost:3000** |
| `gateway` | Go API (auth, ingest, dashboards) | http://localhost:8000 |
| `worker` ×2 | Python detection + Claude stage, no HTTP surface | — |
| `db` | PostgreSQL 16 with pgvector | 5432 |
| `redis` | job queue, rate limits | 6379 |
| `minio` / `minio-init` | S3-compatible store for raw uploads (stands in for GCS) | 9000, console on 9001 |
| `migrate` | applies the 9 SQL migrations, then exits | — |

The stack is healthy when `web` reports `Ready` and
`curl http://localhost:8000/api/health` returns `{"status":"ok"}`.

### 3. Use it

1. Open **http://localhost:3000** and **register an organization**. The first
   user becomes its owner. There is no seeded account.
2. Go to **Uploads**, pick an analysis scope, and upload
   **`samples/zscaler_suspicious.log`**. Ingest and analysis start together:
   the row shows *Analysing…* and then its overall risk, and the
   **Dashboard**'s findings and action plan fill in. It contains six
   deliberately seeded attacks; every one is found, and the overall risk comes
   back **critical**.
3. Upload **`samples/zscaler_benign.log`** to see the other side: ordinary
   traffic produces **zero** findings.

Analysis runs in the workers and the uploads page polls, because detection
plus a model call takes longer than an HTTP request should stay open. Without
an API key an analysis finishes in seconds; with one, expect roughly a minute.
**Analyse** / **Re-analyse** on an upload row re-runs it, for example against
a different scope.

More sample files, including a tiny one for smoke tests, are described under
[Example logs](#example-logs).

### Useful variations

```bash
docker compose up --scale worker=4        # more detection parallelism
docker compose logs -f worker             # watch an analysis run
docker compose down                       # stop; data volumes are kept
docker compose down -v                    # stop and wipe database, queue and uploads
```

### About the API key

`ANTHROPIC_API_KEY` is optional. Without it the app still runs: parsing,
detection and confidence scores are unaffected, and the UI says the AI
narrative is unavailable. With it you additionally get the summary, the event
timeline and the written explanations. Get one at
[console.anthropic.com](https://console.anthropic.com/settings/keys). The
model defaults to `claude-opus-5`; override with `ANTHROPIC_MODEL`.

### Running services outside Docker

For a faster edit–run loop on one component, keep the infrastructure in Docker
and run that component natively. Each one reads the same environment variables
`docker-compose.yml` sets, and the defaults point at `localhost`.

```bash
docker compose up db redis minio minio-init      # infrastructure only

# Gateway (Go). JWT_SECRET is the one variable with no default.
cd gateway
export JWT_SECRET=dev-secret-change-me COOKIE_SECURE=false \
       S3_ENDPOINT=http://localhost:9000 S3_FORCE_PATH_STYLE=true \
       S3_ACCESS_KEY=logmonitor S3_SECRET_KEY=logmonitor-secret
go run ./cmd/gateway -migrate            # apply migrations, exit
go run ./cmd/gateway                     # serve on :8000

# Worker (Python)
cd worker
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
ANTHROPIC_API_KEY=sk-ant-... .venv/bin/python -m worker.main

# Web (Next.js). API_URL is read per request, so no rebuild when it changes.
cd web
npm ci && API_URL=http://localhost:8000 npm run dev     # :3000
```

### Running the tests

```bash
# Worker: parser fixtures, every detector, sharding, observability.
cd worker
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt -r requirements-dev.txt
.venv/bin/python -m pytest tests/ -v                     # 61 tests, no DB or network

# Detector accuracy against the labelled samples (also a CI gate).
python3 scripts/measure_accuracy.py                      # recall 6/6, 0 false positives

# Gateway: parser and unit tests run anywhere; the authz and handler
# integration tests skip themselves unless a database is available.
cd gateway && go test ./...
TEST_DATABASE_URL=postgres://logmonitor:logmonitor@localhost:5432/logmonitor?sslmode=disable \
TEST_REDIS_URL=redis://localhost:6379/0 go test ./...   # with the compose db and redis up

# Web
cd web && npx tsc --noEmit && npm run build
```

CI (`.github/workflows/ci.yml`) runs all of the above on every push.

---

## How AI is used

**Short version: the AI does not find the anomalies, and it does not compute the
confidence scores. It explains and prioritises what the statistics already
found.**

Full write-up in **[docs/AI.md](docs/AI.md)**. The essentials:

### Two stages

```
parsed entries (Go gateway, streamed into Postgres)
   │
   ├─ 1. worker/detection/stats.py   six statistical detectors  →  candidates + confidence scores
   │                                 deterministic, reproducible, no LLM
   │
   ├─    worker/ai/evidence.py       candidates + aggregates  →  evidence packet (≤14,000 chars)
   │
   └─ 2. worker/ai/analyze.py        evidence packet  →  Claude  →  summary + timeline + explanations
```

Stage 1 is a map/reduce: each worker aggregates one shard of the upload
(`map_shard`), the partials are merged, and scoring runs once over the merged
whole. Three of the six detectors compare against a file-wide baseline that no
single shard can see, which is why scores are never computed on a shard.

### Why split it this way

A 50MB proxy log is several million tokens. It would not fit in any context
window, and if it did it would cost roughly $25 per upload. Stage 1 reduces the
file to a ranked list of candidates with supporting statistics; only that
crosses the boundary. For `samples/zscaler_suspicious.log` that is a ~1.3MB
file (~300k tokens) reduced to a packet of a few thousand tokens — roughly two
orders of magnitude — and the packet is hard-capped regardless of how large the
upload is.

### Where the confidence score comes from

Every score is a reproducible statistic computed from the uploaded file —
never a number the model invented.

| Detector | Signal | Score derived from |
|---|---|---|
| `volume_spike` | Requests/IP/minute far above the file's norm | robust z-score over per-minute buckets |
| `data_exfil` | Upload volume far above the norm | robust z-score on log10(bytes) |
| `beaconing` | Near-constant request interval (C2 check-in) | `1 − stdev/mean` of intervals |
| `rare_destination` | Host seen by one user, a handful of times | inverse frequency |
| `blocked_threat` | Proxy-identified malware/phishing | deterministic → 0.95 |
| `off_hours` | Sustained activity in a dead hour | distance below the median hour |

Baselines are computed **from the file being analysed**, not from fixed
thresholds — so "unusual" means unusual for that environment. Scoring uses
median and MAD rather than mean and standard deviation, because proxy traffic
is heavy-tailed and a single 200MB upload would otherwise drag the baseline up
far enough to hide itself. There is no model to train and no artifact to ship.

### What Claude actually does

Receives the evidence packet and returns a schema-validated `Report`: a
summary, an `overall_risk`, a chronological timeline, and for each candidate a
severity, a plain-English explanation, and a recommendation. The schema is a
Pydantic model passed as the call's `output_format`, so the response is parsed
and validated by the SDK rather than by hand; a response that fails validation,
a refusal, or any API error degrades to a deterministic fallback report built
from the detector evidence. An upload always produces a result.

It refers to candidates by opaque id (`c0`, `c1`, …) and never sees database row
ids, so **it is structurally incapable of citing a log row that does not
exist** — the server maps ids back to rows itself. Only aggregates and a couple
of sample lines per candidate leave the worker; no other user's log lines reach
the model.

Model: `claude-opus-5` by default (`ANTHROPIC_MODEL` to change), with adaptive
thinking, because severity is a judgement call. Measured per analysis on the
suspicious sample: about 7,600 input and 3,700 output tokens, ~46 s, ~$0.13.
The latency is why analysis runs as a background job and the frontend polls.

---

## Example logs

All files in `samples/` are Zscaler NSS web proxy logs generated by
`scripts/generate_samples.py` with a fixed seed, so they are reproducible and
every seeded attack is known ground truth. Regenerate with
`python3 scripts/generate_samples.py`.

| File | Rows | Contents | What you should see |
|---|---|---|---|
| `zscaler_benign.log` | 1,200 | Ordinary corporate browsing across six users, working hours only | **No findings.** The control. |
| `zscaler_suspicious.log` | 2,964 | The same baseline plus six seeded attacks and two non-attack incidents | All six detectors fire; overall risk **critical** |
| `zscaler_quick.log` | 204 | A small file with two seeded attacks | Analyses in seconds. `blocked_threat` ×2 at 0.95 and the three rarely-visited hosts as `rare_destination` |
| `zscaler_beacon_only.log` | 520 | One attack class only: C2 beaconing | Exactly one finding, `beaconing` at 1.00, with the interval statistics in its evidence. Five detectors stay quiet |
| `zscaler_nss_tsv.log` | 312 + 4 bad lines | A differently-configured NSS feed: tab-delimited, different field names and order, ISO timestamps, malformed lines; one seeded exfiltration | Ingests like the others. 314 of 316 rows parse; the two collector-restart markers are kept as raw rows. One finding, `data_exfil` at 1.00 |

The first two are the labelled dataset that `scripts/measure_accuracy.py`
scores against, so they must not change; the generator writes them first and
draws the small files from the RNG afterwards, which keeps them byte-identical
across regenerations.

Seeded attacks in `zscaler_suspicious.log`:

1. **Data exfiltration** — `m.chen` uploads ~240MB to `files.dropzone-sync.ru` in 12 chunks
2. **C2 beaconing** — `j.okafor`'s host checks in to `cdn-telemetry-sync.net` every 60s for 5 hours
3. **Volume spike** — 600 requests in 3 minutes from `10.12.4.102` (enumeration)
4. **Blocked threats** — Emotet and an O365 phishing page, blocked by the proxy
5. **Off-hours activity** — `d.kim` exporting CRM records at 03:00
6. **Rare destination** — a single visit to `paste-anon-share.onion.ly`

It also carries two things that are *not* attacks — a burst of 401s against
one SSO host and a sustained 5xx episode from a slow origin — so the error and
latency panels have something an analyst would triage differently from a
threat.

`zscaler_nss_tsv.log` exists because NSS feeds are operator-configured: another
tenant's export will name and order its fields differently. The parser keys off
the header row through a table of aliases (`cip` → client IP, `sentbytes` →
request size, and so on) rather than fixed column positions, and that file is
the proof. It also shows what happens to lines a collector mangles: they become
rows with only the raw text, never silently dropped.

---

## API

Every route is served by the Go gateway on `:8000` and proxied by the web app
under the same `/api/*` path, so the browser only ever talks to one origin.
All routes except `health`, `register`, `login`, `logout` and `mfa/verify` require the
session cookie.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | Liveness |
| `POST` | `/api/auth/register` | Create an organization and its owner |
| `POST` | `/api/auth/login` | Sets an httpOnly session cookie |
| `POST` | `/api/auth/logout` | Clears it |
| `GET` | `/api/auth/me` | Current user |
| `POST` | `/api/auth/mfa/{enroll,activate,verify,disable}` | TOTP |
| `GET` `POST` | `/api/org/users`, `/api/org/invite` | Members and invitations |
| `POST` | `/api/org/mfa-policy`, `/api/org/users/{id}/mfa/reset` | Org admin |
| `GET` `POST` `DELETE` | `/api/grants`, `/api/grants/{id}` | Access grants to raw log lines |
| `GET` `POST` | `/api/uploads` | List uploads with their latest analysis · multipart upload → parse → store → analysis queued |
| `POST` | `/api/uploads/{id}/analyze` | Re-run an analysis (optionally with a different scope), returns immediately |
| `GET` | `/api/analyses/{id}` | Summary, timeline, findings (poll until `done`) |
| `GET` | `/api/dashboard/{summary,series,top,status,actions}` | Dashboard panels, scoped to the caller |
| `GET` | `/api/search` | Full-text over findings; similarity search with `VOYAGE_API_KEY` |
| `GET` | `/api/audit` | Audit trail |
| `GET` | `/api/metrics` | Process metrics, operator-only via `X-Metrics-Token` |

---

## Design decisions worth knowing

**Unparseable lines are kept, not dropped.** A line that fails to parse still
becomes a row with `raw` populated. A parser that silently discards what it
does not understand would hide exactly the malformed lines an analyst needs.
`samples/zscaler_nss_tsv.log` demonstrates it.

**`inet` for IP addresses, not `text`.** Sorts correctly and supports subnet
containment (`WHERE client_ip << '10.12.0.0/16'`).

**Column order is read from the header row.** Zscaler NSS feeds are
operator-configured — tenants emit different field subsets in different orders —
so fixed column positions would be wrong on someone else's export. The parser
maps Zscaler's real NSS Web Log field names (`ClientIP`, `login`, `respcode`,
`urlsupercategory`, `pagerisk`, ...) and prefers `ClientIP` over
`clientpublicIP`, since detection should group by the host that made the
request rather than the egress NAT address.

**The browser only ever talks to one origin.** `/api/*` is proxied to the Go
gateway by a Next.js route handler, so there is no CORS setup and the session
cookie is first-party. It is a route handler rather than a `next.config.ts`
rewrite because rewrite destinations are baked in at build time, which cannot
work when the API address is only known at runtime.

**Authorization is enforced in every query**, scoped by the authenticated user —
never in the frontend.

**Log content is never rendered as HTML.** A URL or user agent can contain
markup; React escapes by default and nothing here uses
`dangerouslySetInnerHTML`.

---

## Observability

Structured JSON logging, metrics and threshold alerting — added beyond the
brief, because a SOC product that cannot explain its own behaviour is a hard
sell. Full write-up in [docs/OBSERVABILITY.md](docs/OBSERVABILITY.md).

**Logs** — one JSON object per line, carrying `event` (a machine-readable type
like `analysis.completed`), `request_id`, hashed `user_id`, provenance
(`module`/`func`/`line`) and `duration_ms`. The request id is carried into the
analysis job, so one grep follows an upload through to its findings:

```bash
docker compose logs worker | jq 'select(.request_id == "9d4c73266b514102")'
```

**Metrics** — `GET /api/metrics`, gated by `METRICS_TOKEN` in the
`X-Metrics-Token` header rather than a user session, because the numbers are
process-wide and a tenant must not see them. Counters, histograms with true
p50/p95/p99, gauges, and derived rates. Per-stage timing is the useful part:

```
pipeline.stage_ms:  load p50=22.6   detect p50=19.0   evidence p50=1.3
                    persist p50=0.2   llm p50=0.2
```

"Analysis took 3s" does not tell you whether to optimise the detectors or the
model call. These do.

**Customer data never enters logs.** LogMonitor ingests proxy logs full of
usernames, internal IPs and full URLs. Logging that content would make the
observability pipeline a second, less-guarded copy of the customer's data, so
the rule is: log identifiers and counts, never content. Where a value must be
correlatable it is logged as a salted hash. Enforced by test
(`test_no_customer_data_in_logs`), not by discipline.

**Model accuracy is measured offline, not online.** Nothing tells a running
system whether a flagged anomaly was real, so accuracy cannot be a live metric.
The sample generator seeds known attacks, which makes the samples a labelled
dataset:

```bash
python3 scripts/measure_accuracy.py
#   recall 100% (6/6 attack classes)   precision 100%   F1 1.00
```

It exits non-zero on regression, so it runs in CI. Online, the proxy signals
that move when accuracy breaks — LLM fallback rate, refusal rate, schema
failures — are in `/api/metrics`.

## Deploying to GCP

Two deployment paths: a **$0 always-free VM** running the whole stack behind
Caddy with automatic HTTPS, and a managed Cloud Run + Cloud SQL + Memorystore
setup at ~$50/month. Start with the free one.

```bash
gcloud auth login && gcloud config set project YOUR_PROJECT   # once
./scripts/deploy_gce_free.sh                                  # free VM
./scripts/deploy_gcp.sh                                       # or: managed, ~10-15 min
./scripts/verify.sh                                           # end-to-end check
./scripts/teardown_gce_free.sh  /  ./scripts/teardown_gcp.sh  # delete everything billable
```

Full walkthrough, cost breakdown and troubleshooting in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

`--no-cpu-throttling` is no longer needed on the gateway. v1 required it
because analysis ran in FastAPI `BackgroundTasks` *after* the response was
sent, exactly when Cloud Run throttles CPU — every analysis would stick on
`running` with no error. Analysis now runs in a separate worker consuming a
durable queue, so the failure mode is gone rather than worked around.

## What shipped since, and what is still out

Most of v1's deliberate omissions were the point of v2:

| v1 left out | now |
|---|---|
| Database migrations (`create_all()`) | 9 SQL migrations, embedded in the gateway binary |
| A job queue | Redis, durable across restarts, with a reaper for stale jobs |
| User registration | organizations, roles, invitations, access grants |
| Object storage | raw uploads archived compressed, GCS or S3-compatible |
| Rate limiting, CSRF | both, plus TOTP MFA and an edge gate |
| Centralised metrics | per-stage timings persisted; percentiles survive a restart |

Still deliberately out:

- **Semantic search needs an embedding provider.** Findings are searchable by
  full text with no configuration; similarity search lights up when
  `VOYAGE_API_KEY` is set. Anthropic serves no embeddings API, and a search
  feature that is dark until someone buys a key is not a feature.
- **More log formats** — only Zscaler NSS. The parser is a registry with a
  `Sniff`/`Parse` seam, so another format is an implementation, not a rewrite.
- **Distributed tracing** — `request_id` correlation covers most of the
  practical need; OpenTelemetry is the proper answer.
- **Backups and failover on the free tier** — one VM, no replicas. That is what
  the managed path is for.

## Project layout

```
gateway/        Go: auth, orgs, grants, ingest, dashboard queries
  internal/parser/      format registry + Zscaler NSS
  internal/authz/       one resolver, every upload-scoped read
  internal/migrations/  9 SQL migrations, embedded via go:embed
worker/         Python: detection and the Claude stage
  worker/detection/     six detectors, map/reduce so they can shard
  worker/ai/            evidence packet + Claude call
  tests/                61 tests; pure functions, no database
web/            Next.js 15: dashboards, uploads, org admin, security
scripts/        sample generator, accuracy gate, deploy/verify/teardown
samples/        five example logs: a labelled pair plus three for hand testing
docs/           AI.md · OBSERVABILITY.md · DEPLOYMENT.md
```
