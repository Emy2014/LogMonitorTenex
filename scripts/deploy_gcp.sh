#!/usr/bin/env bash
#
# Deploy LogMonitor v2 to Google Cloud.
#
#   Cloud SQL (PostgreSQL 16 + pgvector)   schema and vectors
#   Cloud Storage                          raw uploads, retained compressed
#   Memorystore (Redis) + VPC connector    login rate limiting, TOTP replay
#   Cloud Run Job                          schema migrations
#   Cloud Run  logmonitor-gateway (Go)        API, ingest, dashboard queries
#   Cloud Run  logmonitor-web (Next.js)       frontend
#
# Safe to re-run: every resource is created only if absent, so a failed run
# can simply be repeated.
#
# Prerequisites (interactive, run these yourself first):
#   brew install --cask google-cloud-sdk
#   gcloud auth login
#   gcloud config set project YOUR_PROJECT_ID
#   ...and billing enabled on that project.
#
# Usage:  ./scripts/deploy_gcp.sh
#
set -euo pipefail

REGION="${REGION:-us-west1}"
SQL_INSTANCE="${SQL_INSTANCE:-logmonitor-db}"
SQL_TIER="${SQL_TIER:-db-f1-micro}"
DB_NAME="logmonitor"
DB_USER="logmonitor"
REDIS_INSTANCE="${REDIS_INSTANCE:-logmonitor-redis}"
REDIS_SIZE_GB="${REDIS_SIZE_GB:-1}"
VPC_CONNECTOR="${VPC_CONNECTOR:-logmonitor-connector}"
CONNECTOR_RANGE="${CONNECTOR_RANGE:-10.8.0.0/28}"
GATEWAY_SERVICE="logmonitor-gateway"
WEB_SERVICE="logmonitor-web"
MIGRATE_JOB="logmonitor-migrate"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
warn() { printf '  \033[33m%s\033[0m\n' "$*"; }
die()  { printf '\n\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# --- preflight --------------------------------------------------------------

command -v gcloud >/dev/null 2>&1 \
  || die "gcloud not found. Install it: brew install --cask google-cloud-sdk"

gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | grep -q . \
  || die "Not authenticated. Run: gcloud auth login"

PROJECT_ID="$(gcloud config get-value project 2>/dev/null)"
[ -n "$PROJECT_ID" ] && [ "$PROJECT_ID" != "(unset)" ] \
  || die "No project set. Run: gcloud config set project YOUR_PROJECT_ID"

BUCKET="${BUCKET:-${PROJECT_ID}-logmonitor-raw}"

bold "Deploying LogMonitor v2"
info "project : $PROJECT_ID"
info "region  : $REGION"
info "bucket  : gs://$BUCKET"
warn "Memorystore + the VPC connector cost roughly \$43/month on top of Cloud SQL."
warn "Tear everything down with ./scripts/teardown_gcp.sh when you are done."

# --- 1. APIs ----------------------------------------------------------------

bold "1/8  Enabling APIs (first run takes a minute)"
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  sqladmin.googleapis.com \
  secretmanager.googleapis.com \
  artifactregistry.googleapis.com \
  storage.googleapis.com \
  redis.googleapis.com \
  vpcaccess.googleapis.com \
  --quiet
info "done"

# --- 2. Cloud SQL -----------------------------------------------------------

bold "2/8  Cloud SQL (PostgreSQL 16)"
if gcloud sql instances describe "$SQL_INSTANCE" --quiet >/dev/null 2>&1; then
  info "instance '$SQL_INSTANCE' already exists, reusing"
else
  info "creating '$SQL_INSTANCE' -- this takes 5-10 minutes..."
  # cloudsql.enable_pgvector lets migration 000006 run CREATE EXTENSION vector.
  gcloud sql instances create "$SQL_INSTANCE" \
    --database-version=POSTGRES_16 \
    --tier="$SQL_TIER" \
    --region="$REGION" \
    --storage-size=10GB \
    --storage-auto-increase \
    --database-flags=cloudsql.enable_pgvector=on \
    --quiet
fi

CONN_NAME="$(gcloud sql instances describe "$SQL_INSTANCE" --format='value(connectionName)')"
info "connection name: $CONN_NAME"

gcloud sql databases describe "$DB_NAME" --instance="$SQL_INSTANCE" --quiet >/dev/null 2>&1 \
  || gcloud sql databases create "$DB_NAME" --instance="$SQL_INSTANCE" --quiet
info "database '$DB_NAME' ready"

# --- 3. Cloud Storage -------------------------------------------------------

bold "3/8  Cloud Storage bucket"
if gcloud storage buckets describe "gs://$BUCKET" --quiet >/dev/null 2>&1; then
  info "gs://$BUCKET already exists, reusing"
else
  # Uniform access: per-object ACLs are a footgun when the objects are
  # customer log data. Public access is prevented outright.
  gcloud storage buckets create "gs://$BUCKET" \
    --location="$REGION" \
    --uniform-bucket-level-access \
    --public-access-prevention \
    --quiet
  info "gs://$BUCKET created"
fi

# --- 4. Memorystore + VPC connector -----------------------------------------

bold "4/8  Memorystore (Redis) and the VPC connector"
info "Redis backs login rate limiting and TOTP replay protection."

if gcloud redis instances describe "$REDIS_INSTANCE" --region="$REGION" --quiet >/dev/null 2>&1; then
  info "'$REDIS_INSTANCE' already exists, reusing"
else
  info "creating '$REDIS_INSTANCE' -- this takes several minutes..."
  gcloud redis instances create "$REDIS_INSTANCE" \
    --size="$REDIS_SIZE_GB" \
    --region="$REGION" \
    --redis-version=redis_7_0 \
    --tier=basic \
    --quiet
fi

REDIS_HOST="$(gcloud redis instances describe "$REDIS_INSTANCE" --region="$REGION" --format='value(host)')"
REDIS_PORT="$(gcloud redis instances describe "$REDIS_INSTANCE" --region="$REGION" --format='value(port)')"
info "redis: ${REDIS_HOST}:${REDIS_PORT}"

# Memorystore has only a private IP, so Cloud Run reaches it through a
# Serverless VPC Access connector. Without this the gateway cannot see Redis
# at all and the limiter silently fails open.
if gcloud compute networks vpc-access connectors describe "$VPC_CONNECTOR" \
     --region="$REGION" --quiet >/dev/null 2>&1; then
  info "connector '$VPC_CONNECTOR' already exists, reusing"
else
  info "creating connector '$VPC_CONNECTOR'..."
  gcloud compute networks vpc-access connectors create "$VPC_CONNECTOR" \
    --region="$REGION" \
    --range="$CONNECTOR_RANGE" \
    --quiet
fi

# --- 5. secrets -------------------------------------------------------------

bold "5/8  Secret Manager"

secret_exists() { gcloud secrets describe "$1" --quiet >/dev/null 2>&1; }
put_secret() { printf '%s' "$2" | gcloud secrets create "$1" --data-file=- --quiet; }

# Alphanumeric only: some of these are embedded in URLs, where metacharacters
# would need escaping.
random_token() { LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "${1:-32}"; }
random_hex()   { LC_ALL=C tr -dc 'a-f0-9'    < /dev/urandom | head -c "${1:-64}"; }

if secret_exists logmonitor-db-url; then
  info "logmonitor-db-url exists, reusing (password unchanged)"
else
  DB_PASSWORD="$(random_token 32)"
  gcloud sql users create "$DB_USER" --instance="$SQL_INSTANCE" \
    --password="$DB_PASSWORD" --quiet 2>/dev/null \
    || gcloud sql users set-password "$DB_USER" --instance="$SQL_INSTANCE" \
         --password="$DB_PASSWORD" --quiet
  # pgx over the unix socket Cloud Run mounts at /cloudsql/<conn>. Note this
  # is the Go driver's URL form -- v1 stored asyncpg's, which pgx rejects.
  put_secret logmonitor-db-url \
    "postgres://${DB_USER}:${DB_PASSWORD}@/${DB_NAME}?host=/cloudsql/${CONN_NAME}"
  info "logmonitor-db-url created"
fi

secret_exists logmonitor-jwt-secret \
  && info "logmonitor-jwt-secret exists, reusing" \
  || { put_secret logmonitor-jwt-secret "$(random_token 48)"; info "logmonitor-jwt-secret created"; }

# Losing this key means every enrolled user must re-enrol their second factor,
# so it is generated once and never rotated by this script.
secret_exists logmonitor-totp-key \
  && info "logmonitor-totp-key exists, reusing" \
  || { put_secret logmonitor-totp-key "$(random_hex 64)"; info "logmonitor-totp-key created"; }

secret_exists logmonitor-metrics-token \
  && info "logmonitor-metrics-token exists, reusing" \
  || { put_secret logmonitor-metrics-token "$(random_token 32)"; info "logmonitor-metrics-token created"; }

# Optional keys, read from .env when present.
env_value() { [ -f .env ] && grep -E "^$1=.+" .env | head -1 | cut -d= -f2- || true; }

HAVE_AI=0
if secret_exists logmonitor-anthropic-key; then
  info "logmonitor-anthropic-key exists, reusing"; HAVE_AI=1
elif [ -n "$(env_value ANTHROPIC_API_KEY)" ]; then
  put_secret logmonitor-anthropic-key "$(env_value ANTHROPIC_API_KEY)"
  info "logmonitor-anthropic-key created from .env"; HAVE_AI=1
else
  info "no ANTHROPIC_API_KEY -- the AI narrative falls back to statistical findings"
fi

# --- 6. IAM -----------------------------------------------------------------

bold "6/8  Granting the runtime service account access"
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
RUNTIME_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

for role in roles/secretmanager.secretAccessor roles/cloudsql.client; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${RUNTIME_SA}" --role="$role" \
    --condition=None --quiet >/dev/null
  info "$role"
done

# Scoped to the one bucket rather than project-wide storage admin: the gateway
# has no business reading any other bucket in the project.
gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" \
  --member="serviceAccount:${RUNTIME_SA}" \
  --role=roles/storage.objectAdmin --quiet >/dev/null
info "roles/storage.objectAdmin on gs://$BUCKET"

# --- 7. migrations ----------------------------------------------------------

bold "7/8  Schema migrations (Cloud Run Job)"
info "A job, not gateway startup: several instances would race for the schema,"
info "and a bad migration should fail a job rather than take the API down."

# The job runs the GATEWAY image with -migrate. The SQL is embedded in that
# binary, so the artifact that migrates and the one that serves are identical
# -- no second image to keep in step, and no mounted directory to go stale.
# `jobs deploy`, not `jobs create`: only deploy accepts --source. create takes
# --image and would need the image built and pushed separately. deploy is also
# create-or-update, so there is no describe-then-branch needed.
gcloud run jobs deploy "$MIGRATE_JOB" \
  --source ./gateway \
  --region="$REGION" \
  --set-cloudsql-instances="$CONN_NAME" \
  --set-secrets="DATABASE_URL=logmonitor-db-url:latest,JWT_SECRET=logmonitor-jwt-secret:latest" \
  --args="-migrate" \
  --max-retries=1 \
  --task-timeout=600 \
  --quiet

info "executing migrations..."
gcloud run jobs execute "$MIGRATE_JOB" --region="$REGION" --wait --quiet \
  || die "Migrations failed. Inspect: gcloud run jobs executions list --job=$MIGRATE_JOB --region=$REGION"
info "schema is up to date"

# --- 8. deploy --------------------------------------------------------------

bold "8/8  Deploying services (Cloud Build, ~3 min each)"

GATEWAY_SECRETS="DATABASE_URL=logmonitor-db-url:latest"
GATEWAY_SECRETS="${GATEWAY_SECRETS},JWT_SECRET=logmonitor-jwt-secret:latest"
GATEWAY_SECRETS="${GATEWAY_SECRETS},TOTP_ENCRYPTION_KEY=logmonitor-totp-key:latest"
GATEWAY_SECRETS="${GATEWAY_SECRETS},METRICS_TOKEN=logmonitor-metrics-token:latest"

GATEWAY_ENV="REDIS_URL=redis://${REDIS_HOST}:${REDIS_PORT}/0"
GATEWAY_ENV="${GATEWAY_ENV},S3_BUCKET=${BUCKET}"          # no S3_ENDPOINT => native GCS
GATEWAY_ENV="${GATEWAY_ENV},COOKIE_SECURE=true"           # Cloud Run is https
GATEWAY_ENV="${GATEWAY_ENV},MAX_UPLOAD_BYTES=536870912"
GATEWAY_ENV="${GATEWAY_ENV},GOMEMLIMIT=640MiB"            # measured: keeps RSS ~155MB under 1Gi

gcloud run deploy "$GATEWAY_SERVICE" \
  --source ./gateway \
  --region "$REGION" \
  --allow-unauthenticated \
  --min-instances=0 \
  --max-instances=3 \
  --memory=1Gi \
  --timeout=900 \
  --vpc-connector="$VPC_CONNECTOR" \
  --add-cloudsql-instances "$CONN_NAME" \
  --set-secrets "$GATEWAY_SECRETS" \
  --set-env-vars "$GATEWAY_ENV" \
  --quiet

GATEWAY_URL="$(gcloud run services describe "$GATEWAY_SERVICE" --region "$REGION" --format='value(status.url)')"
info "gateway: $GATEWAY_URL"

# API_URL is read per request by web/src/app/api/[...path]/route.ts, so this is
# a plain env var -- the image does not need rebuilding if the URL changes.
gcloud run deploy "$WEB_SERVICE" \
  --source ./web \
  --region "$REGION" \
  --allow-unauthenticated \
  --min-instances=0 \
  --max-instances=3 \
  --memory=512Mi \
  --set-env-vars "API_URL=${GATEWAY_URL}" \
  --quiet

WEB_URL="$(gcloud run services describe "$WEB_SERVICE" --region "$REGION" --format='value(status.url)')"

# --- done -------------------------------------------------------------------

bold "Deployed"
printf '\n  \033[1;32m%s\033[0m\n\n' "$WEB_URL"
info "There is no seeded account. Open the URL and register an organization;"
info "the first user becomes its owner."
info ""
info "gateway : $GATEWAY_URL"
info "bucket  : gs://$BUCKET"
[ "$HAVE_AI" = "1" ] || info "NOTE: no Anthropic key -- the AI narrative is disabled."
info ""
info "Verify:    ./scripts/verify_gcp.sh"
info "Tear down: ./scripts/teardown_gcp.sh   <-- Cloud SQL + Memorystore bill ~\$50/mo until you do"
