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
 frontend/web/     Next.js 15    login, dashboards, uploads, org admin
    │ /api/*  (server-side proxy, first-party cookie)
    ▼
 backend/gateway/  Go            auth · orgs · grants · audit
    │                            streaming ingest: parse → COPY → rollups
    │                            every dashboard read query
    ├──────────────► object store    raw uploads, retained compressed
    ├──────────────► Redis           durable job queue, rate limits
    └──────────────► PostgreSQL 16 + pgvector
                              ▲      partitioned events · rollups · findings
                              │
 backend/worker/ Python ×N ───┘      map → reduce → score → Claude
                                     six statistical detectors
```

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

The compose files live in `deploy/`. Point Compose at one for the session and
every command below works as written, from anywhere in the repo:

```bash
export COMPOSE_FILE=deploy/docker-compose.yml   # or pass -f each time
docker compose up --build                       # first build takes a few minutes
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

### Signing in

There is no seeded account and no default password: a shipped credential is the
one that never gets changed. The first user to **Register** becomes the
organization's owner; everyone after is added by an admin under
**Organization → Members → Add member**. Roles are `owner`, `admin`, `member` —
an admin sees org-wide figures, a member only their own.

Two things that look like bugs and are not: a second registration creates a
*separate* organization rather than a second user in yours, and a new
organization's dashboard is empty until something is uploaded.

TOTP enrolment is under **Security**, per user. Requiring it org-wide exists in
the gateway (`POST /api/org/mfa-policy`) but has no UI yet.

A **deployed** instance asks twice: `EDGE_AUTH_*` puts HTTP Basic auth in front
of the whole site, so the browser prompts before the app's own login page. It
gates crawlers, not data — the session, roles and grants behind it do that.
`deploy/deploy_gce_free.sh` prints the credentials once on a first deploy;
`scripts/gen_edge_auth.sh` sets or rotates them. Off by default locally.

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
`deploy/docker-compose.yml` sets, and the defaults point at `localhost`.

```bash
docker compose up db redis minio minio-init      # infrastructure only

# Gateway (Go). JWT_SECRET is the one variable with no default.
cd backend/gateway
export JWT_SECRET=dev-secret-change-me COOKIE_SECURE=false \
       S3_ENDPOINT=http://localhost:9000 S3_FORCE_PATH_STYLE=true \
       S3_ACCESS_KEY=logmonitor S3_SECRET_KEY=logmonitor-secret
go run ./cmd/gateway -migrate            # apply migrations, exit
go run ./cmd/gateway                     # serve on :8000

# Worker (Python)
cd backend/worker
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
ANTHROPIC_API_KEY=sk-ant-... .venv/bin/python -m worker.main

# Web (Next.js). API_URL is read per request, so no rebuild when it changes.
cd frontend/web
npm ci && API_URL=http://localhost:8000 npm run dev     # :3000
```

### Running the tests

```bash
# Worker: parser fixtures, every detector, sharding, observability.
cd backend/worker
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt -r requirements-dev.txt
.venv/bin/python -m pytest tests/ -v                     # 61 tests, no DB or network

# Detector accuracy against the labelled samples (also a CI gate).
python3 scripts/measure_accuracy.py                      # recall 6/6, 0 false positives

# Gateway: parser and unit tests run anywhere; the authz and handler
# integration tests skip themselves unless a database is available.
cd backend/gateway && go test ./...
TEST_DATABASE_URL=postgres://logmonitor:logmonitor@localhost:5432/logmonitor?sslmode=disable \
TEST_REDIS_URL=redis://localhost:6379/0 go test ./...   # with the compose db and redis up

# Web
cd frontend/web && npx tsc --noEmit && npm run build
```

CI (`.github/workflows/ci.yml`) runs all of the above on every push.

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

The first two are the labelled dataset `scripts/measure_accuracy.py` scores
against, so they must not change; the generator writes them first and draws the
small files from the RNG afterwards, keeping them byte-identical across
regenerations.

Seeded attacks in `zscaler_suspicious.log`:

1. **Data exfiltration** — `m.chen` uploads ~240MB to `files.dropzone-sync.ru` in 12 chunks
2. **C2 beaconing** — `j.okafor`'s host checks in to `cdn-telemetry-sync.net` every 60s for 5 hours
3. **Volume spike** — 600 requests in 3 minutes from `10.12.4.102` (enumeration)
4. **Blocked threats** — Emotet and an O365 phishing page, blocked by the proxy
5. **Off-hours activity** — `d.kim` exporting CRM records at 03:00
6. **Rare destination** — a single visit to `paste-anon-share.onion.ly`

It also carries two things that are *not* attacks — a burst of 401s against one
SSO host and a sustained 5xx episode from a slow origin — so the error and
latency panels have something an analyst would triage differently from a threat.

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

**Column order is read from the header row.** NSS feeds are
operator-configured, so fixed column positions would be wrong on someone else's
export. The parser maps Zscaler's real field names and prefers `ClientIP` over
`clientpublicIP`, since detection should group by the host that made the
request, not the egress NAT address. `samples/zscaler_nss_tsv.log` is the
proof: different delimiter, names and order, plus lines a collector mangled.

**The browser only ever talks to one origin.** `/api/*` is proxied to the
gateway by a Next.js route handler, so there is no CORS and the session cookie
is first-party. A route handler rather than a `next.config.ts` rewrite, because
rewrite destinations are baked in at build time and the API address is only
known at runtime.

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

**Logs** — one JSON object per line with `event`, `request_id`, hashed
`user_id`, provenance and `duration_ms`. The request id follows an upload into
its analysis job, so one grep covers the whole path:

```bash
docker compose logs worker | jq 'select(.request_id == "9d4c73266b514102")'
```

**Metrics** — `GET /api/metrics`, gated by `METRICS_TOKEN` in a header rather
than a session, because the numbers are process-wide and no tenant should see
them. The useful part is per-stage timing: "analysis took 3s" does not tell you
whether to optimise the detectors or the model call.

**Customer data never enters logs.** Proxy logs are full of usernames, internal
IPs and URLs; logging that content would make the observability pipeline a
second, less-guarded copy of it. Identifiers and counts only, salted hashes
where a value must be correlatable — enforced by `test_no_customer_data_in_logs`,
not by discipline.

**Accuracy is measured offline.** Nothing tells a running system whether a
flagged anomaly was real, so it cannot be a live metric. The seeded samples are
a labelled dataset instead:

```bash
python3 scripts/measure_accuracy.py
#   recall 100% (6/6 attack classes)   precision 100%   F1 1.00
```

Non-zero exit on regression, so it gates CI. The online proxies that move when
accuracy breaks — fallback rate, refusal rate, schema failures — are in
`/api/metrics`.

## Deploying to GCP

Two deployment paths: a single always-free VM running the whole stack behind
Caddy with automatic HTTPS, and a managed Cloud Run + Cloud SQL + Memorystore
setup. Start with the free one.

```bash
gcloud auth login && gcloud config set project YOUR_PROJECT   # once
./deploy/deploy_gce_free.sh                                 # free VM
./deploy/deploy_gcp.sh                                      # or: managed, ~10-15 min
./deploy/verify.sh                                          # end-to-end check
./deploy/teardown_gce_free.sh  /  ./deploy/teardown_gcp.sh  # delete every deployed resource
```

Full walkthrough and troubleshooting in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Deliberately out of scope

- **Semantic search needs an embedding provider.** Findings are full-text
  searchable with no configuration; similarity search lights up when
  `VOYAGE_API_KEY` is set. Anthropic serves no embeddings API, and a feature
  that is dark until someone buys a key is not a feature.
- **One log format** — Zscaler NSS. The parser is a registry with a
  `Sniff`/`Parse` seam, so another format is an implementation, not a rewrite.
- **Distributed tracing** — `request_id` correlation covers most of the need;
  OpenTelemetry is the proper answer.
- **Backups and failover on the free tier** — one VM, no replicas. That is what
  the managed path is for.

## Project layout

Three top-level groups: what runs on a server, what runs in a browser, and
what puts them somewhere.

```
backend/
  gateway/      Go: auth, orgs, grants, ingest, dashboard queries
    internal/parser/      format registry + Zscaler NSS
    internal/authz/       one resolver, every upload-scoped read
    internal/migrations/  9 SQL migrations, embedded via go:embed
  worker/       Python: detection and the Claude stage
    worker/detection/     six detectors, map/reduce so they can shard
    worker/ai/            evidence packet + Claude call
    tests/                61 tests; pure functions, no database

frontend/
  web/          Next.js 15: dashboards, uploads, org admin, security

deploy/         how it runs anywhere
  docker-compose.yml      the local stack
  docker-compose.vm.yml   the free-tier VM stack (images pulled, no MinIO)
  Caddyfile               TLS termination on the VM
  deploy_*.sh             free tier / managed
  teardown_*.sh           delete every deployed resource
  verify.sh               end-to-end check against a running deployment

scripts/        sample generator, accuracy gate, edge-auth hashes
samples/        five example logs: a labelled pair plus three for hand testing
docs/           OBSERVABILITY.md · DEPLOYMENT.md
```
