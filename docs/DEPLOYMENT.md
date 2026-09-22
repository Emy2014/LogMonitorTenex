# Deployment

Two options. Start with the free one.

| | Free tier | Managed |
|---|---|---|
| Script | `deploy_gce_free.sh` | `deploy_gcp.sh` |
| Cost | **$0** | ~$50/month |
| Shape | one e2-micro running everything | Cloud Run + Cloud SQL + Memorystore |
| Scales | no | yes |
| Backups, failover | none — yours to arrange | managed |
| Good for | a prototype, a demo, a portfolio link | anything real |

---

# Free tier: one always-free VM

```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
./scripts/deploy_gce_free.sh
```

Roughly 10 minutes, most of it Cloud Build. It prints an HTTPS URL when done.

## What it uses, and why it is free

| Resource | Free allowance | What we use |
|---|---|---|
| Compute Engine e2-micro | 1 instance, always-free in `us-west1`, `us-central1`, `us-east1` | the whole stack |
| Standard persistent disk | 30 GB always-free | the 30 GB boot disk |
| Cloud Storage | 5 GB always-free | archived raw uploads |
| Cloud Build | 120 build-minutes/day | builds the two images |
| Artifact Registry | 0.5 GB | the images total ~200 MB |
| Network egress | 1 GB/month to most destinations | light browsing |

The free e2-micro allowance is **one instance across the project**, so this
script assumes it is the only one. Verify against Google's own list before
relying on it: <https://cloud.google.com/free/docs/free-cloud-features#compute>

## Fitting in 1 GB

Measured running `docker-compose.vm.yml` with its real limits, after ingesting
the 2,735-line sample:

| Container | Idle | Under load | Cap |
|---|---|---|---|
| gateway | 13 MB | 142 MB | 256 MB |
| web | 46 MB | 60 MB | 192 MB |
| db | 28 MB | 34 MB | 320 MB |
| redis | 9 MB | 9 MB | 80 MB |
| caddy | 16 MB | 16 MB | 64 MB |
| **Total** | **113 MB** | **262 MB** | |

Three things make that fit:

**No MinIO.** Blob storage is native GCS through the VM's service account.
That is a container's worth of memory saved, no credentials on the machine,
and durable storage from the free 5 GB.

**`GOMEMLIMIT=192MiB`** rather than the 640MiB used in development. Ingest
streams, so this bounds memory rather than capability — a 128 MB upload still
works, it just collects more often.

**A 2 GB swapfile**, created by the deploy script. Container-Optimised OS has
none by default, and 1 GB with no swap is where an otherwise-fine stack gets
OOM-killed under a burst.

## HTTPS without owning a domain

Caddy gets a Let's Encrypt certificate for a `nip.io` hostname —
`logmonitor.<your-ip>.nip.io` resolves to that IP with no DNS to configure. That
matters beyond the padlock: without TLS the session cookie cannot carry
`Secure`, and this application holds employee browsing history.

**The IP is ephemeral.** Stopping and starting the VM changes it, and the
hostname with it. Re-run the deploy script to pick up the new address, or
reserve a static IP (free while attached to a running instance).

## Re-running is safe

Secrets already on the VM are reused, never regenerated. This is load-bearing:

- `POSTGRES_PASSWORD` is only applied when the data directory is first
  initialised, so a new value simply fails to authenticate
- `TOTP_ENCRYPTION_KEY` decrypts enrolled second factors — rotating it forces
  every user to re-enrol
- `JWT_SECRET` invalidates every live session

Rotate deliberately with `FORCE_SECRETS=1`, understanding the above.

## Limits worth knowing

- **One shared-core vCPU (0.25 baseline).** Ingest of the 2,735-line sample is
  instant; a 100 MB upload will take noticeably longer than the 6 seconds it
  takes on a laptop.
- **No backups.** `gcloud compute disks snapshot` is the manual answer.
- **No failover.** If the VM stops, the service is down.
- **Uploads capped at 128 MB** rather than 512 MB, to stay within the disk and
  memory the machine has.

## Verify and tear down

```bash
./scripts/verify.sh https://logmonitor.<ip>.nip.io
./scripts/teardown_gce_free.sh
```

`verify.sh` runs the same 14 checks against local development, the free VM, or
the managed deployment — a verification script that only ever runs in one
environment tends to be wrong in the other.

---

# Managed: Cloud Run + Cloud SQL + Memorystore

Two Cloud Run services over four managed resources.

```
            ┌──────────────────┐
  browser ─►│ logmonitor-web      │  Next.js, proxies /api/* server-side
            └────────┬─────────┘
                     │ API_URL
            ┌────────▼─────────┐
            │ logmonitor-gateway  │  Go: auth, ingest, dashboard queries
            └──┬────┬───────┬──┘
    VPC        │    │       │  unix socket
    connector  │    │       │
        ┌──────▼─┐ ┌▼──────┐ ┌▼──────────────────┐
        │ Redis  │ │ GCS   │ │ Cloud SQL         │
        │ Memory-│ │bucket │ │ PostgreSQL 16     │
        │ store  │ │       │ │ + pgvector        │
        └────────┘ └───────┘ └───────────────────┘
```

## Deploy

```bash
brew install --cask google-cloud-sdk
gcloud auth login
gcloud config set project YOUR_PROJECT_ID     # billing must be enabled

./scripts/deploy_gcp.sh
```

Re-runnable: every resource is created only if absent, so a failed run can be
repeated. First run takes 15–20 minutes, most of it waiting for Cloud SQL and
Memorystore to provision.

Then check it:

```bash
export EDGE_AUTH_USER=ops EDGE_AUTH_PASS='...'   # only if the edge gate is on
./scripts/verify.sh https://logmonitor-web-xxxxx.run.app
```

`verify.sh` takes a base URL and runs the same 14 checks against local
development or a deployment — a verification script that only ever runs in one
environment tends to be wrong in the other.

## Cost

| Resource | Approx. monthly |
|---|---|
| Cloud SQL `db-f1-micro` | $8–10 |
| Memorystore Redis Basic, 1 GB | ~$35 |
| Serverless VPC Access connector | ~$8 |
| Cloud Run (both services, scale to zero) | ~$0 idle |
| Cloud Storage | pennies; uploads compress ~13× |
| **Total** | **~$50** |

Neither Cloud SQL nor Memorystore scales to zero, so the bill runs whether or
not anyone signs in. `./scripts/teardown_gcp.sh` deletes everything.

**Redis is not optional.** It backs login rate limiting and TOTP replay
protection. The limiter fails open by design — an unreachable cache must not
become an authentication outage — so without Redis the service still runs, but
password guessing is unthrottled and a TOTP code can be replayed inside its
30-second window. That is the price of the controls, stated plainly.

## Things that are load-bearing

**The database URL is pgx-format, not asyncpg.** v1 stored
`postgresql+asyncpg://…`; the Go gateway uses pgx, which rejects that scheme.
The secret now holds `postgres://user:pass@/logmonitor?host=/cloudsql/CONN`.

**Migrations run as a Cloud Run Job, not at startup.** The job runs the
*gateway image* with `-migrate`; the SQL is embedded in the binary via
`go:embed`, so the artifact that migrates and the artifact that serves are the
same one. Running them at service startup would let several instances race for
the schema and would turn a bad migration into an outage instead of a failed
job. The deploy script executes the job with `--wait` and aborts if it fails.

**pgvector needs a database flag.** The instance is created with
`--database-flags=cloudsql.enable_pgvector=on`; migration 6 then runs
`CREATE EXTENSION vector`. On an instance created without the flag, patch it
and restart before deploying.

**Memorystore has no public IP.** Cloud Run reaches it through a Serverless
VPC Access connector, which is why `--vpc-connector` is on the gateway. Without
it the gateway cannot see Redis at all, and — because the limiter fails open —
this degrades *silently*. The gateway logs `ratelimit.unavailable` when that
happens; alert on it.

**`GOMEMLIMIT=640MiB`.** Measured, not guessed. Without a limit the Go heap
settles around 600 MB of GC headroom after the first upload, which is
uncomfortably close to the 1Gi the service is given. At 640MiB the heap holds
at 66 MB and RSS around 155 MB, with no throughput cost — 400 MB of log still
ingests in about 22 seconds.

**GCS uses the runtime service account, not HMAC keys.** `S3_ENDPOINT` is left
unset in cloud, which selects the native GCS client and Application Default
Credentials. Locally, `S3_ENDPOINT` points at MinIO and static credentials are
used. One interface, two implementations, no key material in cloud.

**`--no-cpu-throttling` is gone.** v1 needed it because analysis ran in FastAPI
`BackgroundTasks` *after* the response was sent, exactly when Cloud Run
throttles CPU. The gateway does its ingest work inside the request, so it no
longer applies. It will be needed again for the Phase 4 worker.

**Object storage is scoped to one bucket.** The runtime service account gets
`roles/storage.objectAdmin` on `gs://PROJECT-logmonitor-raw` specifically, not
project-wide storage admin.

## No seeded account

v1 created `analyst@logmonitor.dev` on startup. v2 does not: open the deployed URL
and register an organization, and the first user becomes its owner. Additional
members are added by an admin from the Organization page.

## Not yet deployed by these scripts

The Phase 4 Python worker (`worker/`) does not exist yet, so nothing consumes
the Redis job queue and no analyses run. Redis is still deployed because rate
limiting and TOTP replay protection use it today.

## Troubleshooting

**`Migrations failed`** — inspect the job:
`gcloud run jobs executions list --job=logmonitor-migrate --region=REGION`, then
`gcloud run jobs executions describe EXECUTION --region=REGION`. A schema left
`dirty` needs manual resolution; the gateway refuses to start migrations
against it rather than compounding the damage.

**Uploads return 503 "Object storage is not configured"** — `S3_BUCKET` is
unset on the gateway, or the service account lacks `objectAdmin` on it. Check
the startup log for `blob.ready` or `blob.unreachable`.

**Login never rate-limits** — the gateway cannot reach Redis. Look for
`ratelimit.unavailable` in the logs and confirm `--vpc-connector` is attached.

**`CREATE EXTENSION vector` fails** — the instance lacks
`cloudsql.enable_pgvector`. Patch it:
`gcloud sql instances patch logmonitor-db --database-flags=cloudsql.enable_pgvector=on`
(this restarts the instance), then re-run the deploy script.
