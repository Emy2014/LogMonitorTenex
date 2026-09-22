#!/usr/bin/env bash
#
# Deploy LogMonitor to a single always-free Compute Engine VM.
#
#   e2-micro          always-free in us-west1, us-central1 and us-east1
#   30 GB standard PD always-free (the whole free allowance, so use one VM)
#   Cloud Storage     5 GB always-free, for archived raw uploads
#   Cloud Build       120 build-minutes/day free; builds the two images
#   Artifact Registry 0.5 GB free; the images total roughly 200 MB
#
# Expected cost: $0, provided this is the only always-free VM in the project
# and egress stays under 1 GB/month. Check before assuming:
#   https://cloud.google.com/free/docs/free-cloud-features#compute
#
# Safe to re-run: existing resources are reused, and re-running redeploys.
#
# Usage:  ./scripts/deploy_gce_free.sh
#
set -euo pipefail

# Only these three regions carry the always-free e2-micro.
ZONE="${ZONE:-us-west1-b}"
REGION="${ZONE%-*}"
VM_NAME="${VM_NAME:-logmonitor}"
REPO_NAME="${REPO_NAME:-logmonitor}"
# COS mounts $HOME noexec, so Compose lives somewhere that is not.
COMPOSE_BIN="/var/lib/google/docker-compose"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
warn() { printf '  \033[33m%s\033[0m\n' "$*"; }
die()  { printf '\n\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

case "$REGION" in
  us-west1|us-central1|us-east1) ;;
  *) die "ZONE must be in us-west1, us-central1 or us-east1 for the free tier (got $REGION)" ;;
esac

command -v gcloud >/dev/null 2>&1 || die "gcloud not found. brew install --cask google-cloud-sdk"
gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | grep -q . \
  || die "Not authenticated. Run: gcloud auth login"

PROJECT_ID="$(gcloud config get-value project 2>/dev/null)"
[ -n "$PROJECT_ID" ] && [ "$PROJECT_ID" != "(unset)" ] || die "No project set."
BUCKET="${BUCKET:-${PROJECT_ID}-logmonitor-raw}"
IMAGE_BASE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}"

bold "LogMonitor — free-tier deployment"
info "project : $PROJECT_ID"
info "zone    : $ZONE  (always-free region)"
info "vm      : $VM_NAME  (e2-micro, 30 GB)"
info "bucket  : gs://$BUCKET"

bold "1/7  Enabling APIs"
gcloud services enable compute.googleapis.com cloudbuild.googleapis.com \
  artifactregistry.googleapis.com storage.googleapis.com --quiet
info "done"

bold "2/7  Artifact Registry"
gcloud artifacts repositories describe "$REPO_NAME" --location="$REGION" --quiet >/dev/null 2>&1 \
  || gcloud artifacts repositories create "$REPO_NAME" \
       --repository-format=docker --location="$REGION" --quiet
info "$IMAGE_BASE"

bold "3/7  Cloud Storage"
if gcloud storage buckets describe "gs://$BUCKET" --quiet >/dev/null 2>&1; then
  info "gs://$BUCKET exists, reusing"
else
  gcloud storage buckets create "gs://$BUCKET" --location="$REGION" \
    --uniform-bucket-level-access --public-access-prevention --quiet
  info "gs://$BUCKET created"
fi

bold "4/7  Building images (Cloud Build, ~5 min)"
# Built here rather than on the VM: an e2-micro is 0.25 vCPU, and compiling the
# gateway plus a Next.js production build would take ~20 minutes and probably
# exhaust its memory.
#
# Three things are needed that used to be automatic, and are not any more.
# Since 2024 Cloud Build no longer creates the legacy
# <project>@cloudbuild.gserviceaccount.com account, so a build with no
# --service-account fails with a bare PERMISSION_DENIED that names nothing:
#
#   1. name a service account explicitly (the compute default will do)
#   2. give it the roles a build needs -- write logs, push images, read source
#   3. let the human act as it, or the build is refused before it starts
#
# And naming a service account makes the log destination ambiguous, which is
# why --default-buckets-behavior is required alongside it.
BUILD_SA_EMAIL="${PROJECT_NUMBER:-$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')}-compute@developer.gserviceaccount.com"
BUILD_SA="projects/${PROJECT_ID}/serviceAccounts/${BUILD_SA_EMAIL}"

for role in roles/logging.logWriter roles/artifactregistry.writer roles/storage.objectAdmin; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${BUILD_SA_EMAIL}" --role="$role" \
    --condition=None --quiet >/dev/null 2>&1 || true
done

ACTIVE_ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -1)"
gcloud iam service-accounts add-iam-policy-binding "$BUILD_SA_EMAIL" \
  --member="user:${ACTIVE_ACCOUNT}" --role=roles/iam.serviceAccountUser \
  --quiet >/dev/null 2>&1 || true

build() {
  gcloud builds submit "$1" --tag "$2" \
    --service-account="$BUILD_SA" \
    --default-buckets-behavior=REGIONAL_USER_OWNED_BUCKET \
    --quiet
}

build ./gateway "${IMAGE_BASE}/gateway:latest"
build ./web     "${IMAGE_BASE}/web:latest"
info "images pushed"

bold "5/7  Compute Engine VM"
if gcloud compute instances describe "$VM_NAME" --zone="$ZONE" --quiet >/dev/null 2>&1; then
  info "'$VM_NAME' exists, reusing"
else
  # --scopes=cloud-platform lets the gateway reach GCS as the VM's service
  # account, so no key material is written to the machine.
  gcloud compute instances create "$VM_NAME" \
    --zone="$ZONE" \
    --machine-type=e2-micro \
    --image-family=cos-stable \
    --image-project=cos-cloud \
    --boot-disk-size=30GB \
    --boot-disk-type=pd-standard \
    --scopes=cloud-platform \
    --tags=logmonitor-web \
    --quiet
  info "created"
fi

gcloud compute firewall-rules describe logmonitor-allow-web --quiet >/dev/null 2>&1 \
  || gcloud compute firewall-rules create logmonitor-allow-web \
       --allow=tcp:80,tcp:443 --target-tags=logmonitor-web \
       --description="LogMonitor HTTP/HTTPS" --quiet
info "firewall: 80, 443"

IP="$(gcloud compute instances describe "$VM_NAME" --zone="$ZONE" \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)')"
SITE="logmonitor.${IP}.nip.io"
info "address: $SITE"

gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" \
  --member="serviceAccount:$(gcloud compute instances describe "$VM_NAME" --zone="$ZONE" \
      --format='get(serviceAccounts[0].email)')" \
  --role=roles/storage.objectAdmin --quiet >/dev/null
info "bucket access granted to the VM"

bold "6/7  Secrets"
# Re-reads what the VM already has rather than minting new values.
#
# Regenerating these on a re-deploy breaks the installation in three separate
# ways, and two of them are unrecoverable:
#
#   POSTGRES_PASSWORD    Postgres only applies it when the data directory is
#                        first initialised, so a new value simply fails to
#                        authenticate against the existing volume.
#   TOTP_ENCRYPTION_KEY  decrypts enrolled second factors. A new key means
#                        every user must re-enrol, and recovery codes are the
#                        only way back in.
#   JWT_SECRET           invalidates every live session.
#
# Rotate deliberately with FORCE_SECRETS=1, not by accident on every deploy.
random_token() { LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "${1:-32}"; }
random_hex()   { LC_ALL=C tr -dc 'a-f0-9'    < /dev/urandom | head -c "${1:-64}"; }

EXISTING=""
if [ "${FORCE_SECRETS:-0}" != "1" ]; then
  EXISTING="$(gcloud compute ssh "$VM_NAME" --zone="$ZONE" --quiet \
    --command 'cat ~/.env 2>/dev/null || true' 2>/dev/null || true)"
fi

# keep <NAME> <fallback> -- reuse the deployed value when there is one.
keep() {
  local found
  found="$(printf '%s\n' "$EXISTING" | grep -E "^$1=" | head -1 | cut -d= -f2- || true)"
  if [ -n "$found" ]; then printf '%s' "$found"; else printf '%s' "$2"; fi
}

if [ -n "$EXISTING" ]; then
  info "reusing the secrets already on the VM"
else
  info "generating new secrets (first deployment)"
fi
[ "${FORCE_SECRETS:-0}" = "1" ] && warn "FORCE_SECRETS=1 -- rotating; every MFA enrolment and session is invalidated"

DB_PASSWORD="$(keep POSTGRES_PASSWORD "$(random_token 32)")"
JWT_VALUE="$(keep JWT_SECRET "$(random_token 48)")"
TOTP_VALUE="$(keep TOTP_ENCRYPTION_KEY "$(random_hex 64)")"
METRICS_VALUE="$(keep METRICS_TOKEN "$(random_token 32)")"

# Edge gate. Two derivations of one password, because they run in different
# places: the Go gateway verifies argon2id, while Next.js middleware runs on
# the edge runtime where only Web Crypto exists and compares a SHA-256 digest.
EDGE_USER="$(keep EDGE_AUTH_USER "ops")"
EDGE_HASH="$(keep EDGE_AUTH_PASS_HASH "")"
EDGE_SHA="$(keep EDGE_AUTH_PASS_SHA256 "")"
EDGE_PLAINTEXT=""

if [ -z "$EDGE_HASH" ] || [ -z "$EDGE_SHA" ]; then
  EDGE_PLAINTEXT="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 20)"
  EDGE_SHA="$(printf '%s' "$EDGE_PLAINTEXT" | openssl dgst -sha256 -hex | awk '{print $NF}')"
  # Hashed by the gateway's own code, so the parameters cannot drift from what
  # the server verifies against.
  EDGE_HASH="$(cd gateway && go run ./cmd/hashpass "$EDGE_PLAINTEXT")"
  # Docker Compose expands $VAR inside .env values, which shreds an argon2 PHC
  # string ($argon2id$v=19$...) into fragments. Doubling the dollars makes
  # Compose emit literal ones. Without this the gateway receives a mangled
  # hash and rejects the correct password -- silently, since a wrong password
  # and a wrong hash look identical from outside.
  EDGE_HASH="$(printf '%s' "$EDGE_HASH" | sed 's/\$/$$/g')"
  info "generated a new edge-gate password (shown at the end)"
else
  info "reusing the edge-gate password already on the VM"
fi

ANTHROPIC_KEY="$(keep ANTHROPIC_API_KEY "")"
if [ -z "$ANTHROPIC_KEY" ] && [ -f .env ]; then
  ANTHROPIC_KEY="$(grep -E '^ANTHROPIC_API_KEY=.+' .env | head -1 | cut -d= -f2- || true)"
fi

ENV_FILE="$(mktemp)"
trap 'rm -f "$ENV_FILE"' EXIT
cat > "$ENV_FILE" <<ENV
SITE_ADDRESS=${SITE}
GATEWAY_IMAGE=${IMAGE_BASE}/gateway:latest
WEB_IMAGE=${IMAGE_BASE}/web:latest
POSTGRES_USER=logmonitor
POSTGRES_PASSWORD=${DB_PASSWORD}
POSTGRES_DB=logmonitor
JWT_SECRET=${JWT_VALUE}
TOTP_ENCRYPTION_KEY=${TOTP_VALUE}
METRICS_TOKEN=${METRICS_VALUE}
S3_BUCKET=${BUCKET}
ANTHROPIC_API_KEY=${ANTHROPIC_KEY}
EDGE_AUTH_ENABLED=true
EDGE_AUTH_USER=${EDGE_USER}
EDGE_AUTH_PASS_HASH=${EDGE_HASH}
EDGE_AUTH_PASS_SHA256=${EDGE_SHA}
GOMEMLIMIT=192MiB
MAX_UPLOAD_BYTES=134217728
ENV

bold "7/7  Starting the stack on the VM"
gcloud compute scp --zone="$ZONE" --quiet \
  docker-compose.vm.yml Caddyfile "$ENV_FILE" "${VM_NAME}:~/" >/dev/null
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --quiet --command "
  set -e
  mv -f \"\$(basename $ENV_FILE)\" .env
  chmod 600 .env

  # Container-Optimised OS has no swap, and 1 GB with none is where an
  # otherwise-fine stack gets OOM-killed under load.
  if ! swapon --show | grep -q .; then
    sudo fallocate -l 2G /var/swapfile
    sudo chmod 600 /var/swapfile
    sudo mkswap /var/swapfile >/dev/null
    sudo swapon /var/swapfile
  fi

  # COS ships Docker but not Compose, and mounts /home, /tmp and
  # /mnt/stateful_partition noexec -- so the plugin cannot simply be dropped in
  # \\$HOME/.docker/cli-plugins: Docker finds it there and then cannot execute
  # it. /var/lib/google is writable with sudo and is not noexec, and the
  # Compose v2 binary runs standalone, so the plugin mechanism is skipped
  # entirely.
  if [ ! -x $COMPOSE_BIN ]; then
    curl -fsSL -o /tmp/docker-compose \
      https://github.com/docker/compose/releases/download/v2.32.4/docker-compose-linux-x86_64
    sudo install -m 0755 /tmp/docker-compose $COMPOSE_BIN
    rm -f /tmp/docker-compose
  fi

  # No --quiet: docker-credential-gcr does not accept it, and with the error
  # hidden the pull then fails as an unauthenticated request with no clue why.
  docker-credential-gcr configure-docker --registries=${REGION}-docker.pkg.dev
  $COMPOSE_BIN -f docker-compose.vm.yml pull --quiet
  $COMPOSE_BIN -f docker-compose.vm.yml up -d --remove-orphans
" >/dev/null

bold "Deployed"
printf '\n  \033[1;32mhttps://%s\033[0m\n\n' "$SITE"
warn "The first load waits on a Let's Encrypt certificate — give it a minute."
if [ -n "$EDGE_PLAINTEXT" ]; then
  printf '  \033[1mBrowser will prompt for a password first:\033[0m\n'
  info "  username : ${EDGE_USER}"
  info "  password : ${EDGE_PLAINTEXT}"
  warn "  Only shown now -- the VM stores a hash, which cannot be reversed."
  info ""
fi
info "Past that prompt there is no seeded account: register an organization."
info ""
info "Verify:  ./scripts/verify.sh https://${SITE}"
info "Logs:    gcloud compute ssh $VM_NAME --zone=$ZONE --command '/var/lib/google/docker-compose -f docker-compose.vm.yml logs -f'"
info "Stop:    gcloud compute instances stop $VM_NAME --zone=$ZONE"
info "Delete:  ./scripts/teardown_gce_free.sh"
info ""
warn "The IP is ephemeral: stopping and starting the VM changes it, and the"
warn "nip.io hostname with it. Re-run this script to pick up the new address."
