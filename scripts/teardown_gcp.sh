#!/usr/bin/env bash
#
# Delete every LogMonitor resource in the current project.
#
# Cloud SQL and Memorystore bill continuously (~$50/month together), so this
# exists to make stopping that a single command.
#
# Usage:  ./scripts/teardown_gcp.sh
#
set -euo pipefail

REGION="${REGION:-us-west1}"
SQL_INSTANCE="${SQL_INSTANCE:-logmonitor-db}"
REDIS_INSTANCE="${REDIS_INSTANCE:-logmonitor-redis}"
VPC_CONNECTOR="${VPC_CONNECTOR:-logmonitor-connector}"
GATEWAY_SERVICE="logmonitor-gateway"
WEB_SERVICE="logmonitor-web"
MIGRATE_JOB="logmonitor-migrate"

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
die()  { printf '\n\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

command -v gcloud >/dev/null 2>&1 || die "gcloud not found."
PROJECT_ID="$(gcloud config get-value project 2>/dev/null)"
[ -n "$PROJECT_ID" ] && [ "$PROJECT_ID" != "(unset)" ] || die "No project set."

BUCKET="${BUCKET:-${PROJECT_ID}-logmonitor-raw}"

bold "This permanently deletes LogMonitor from project: $PROJECT_ID"
info "Cloud Run   : $GATEWAY_SERVICE, $WEB_SERVICE, job $MIGRATE_JOB"
info "Cloud SQL   : $SQL_INSTANCE          <-- all analyses and log data"
info "Memorystore : $REDIS_INSTANCE"
info "VPC         : $VPC_CONNECTOR"
info "Storage     : gs://$BUCKET           <-- every archived raw upload"
info "Secrets     : logmonitor-db-url, logmonitor-jwt-secret, logmonitor-totp-key,"
info "              logmonitor-metrics-token, logmonitor-anthropic-key"
printf '\n  Type DELETE to confirm: '
read -r CONFIRM
[ "$CONFIRM" = "DELETE" ] || die "Aborted."

# Deleted in dependency order, and each step tolerates an already-absent
# resource so a partial teardown can simply be re-run.
bold "Deleting Cloud Run services and jobs"
for svc in "$GATEWAY_SERVICE" "$WEB_SERVICE"; do
  gcloud run services delete "$svc" --region="$REGION" --quiet 2>/dev/null \
    && info "deleted $svc" || info "$svc not present"
done
gcloud run jobs delete "$MIGRATE_JOB" --region="$REGION" --quiet 2>/dev/null \
  && info "deleted job $MIGRATE_JOB" || info "job $MIGRATE_JOB not present"

bold "Deleting the storage bucket"
# Raw uploads are customer log data; --recursive is required because the
# bucket is never empty if anything was ever ingested.
gcloud storage rm --recursive "gs://$BUCKET" --quiet 2>/dev/null \
  && info "deleted gs://$BUCKET" || info "gs://$BUCKET not present"

bold "Deleting Memorystore and the VPC connector"
gcloud redis instances delete "$REDIS_INSTANCE" --region="$REGION" --quiet 2>/dev/null \
  && info "deleted $REDIS_INSTANCE" || info "$REDIS_INSTANCE not present"
# The connector must go after anything using it, or the delete is refused.
gcloud compute networks vpc-access connectors delete "$VPC_CONNECTOR" \
  --region="$REGION" --quiet 2>/dev/null \
  && info "deleted $VPC_CONNECTOR" || info "$VPC_CONNECTOR not present"

bold "Deleting Cloud SQL"
gcloud sql instances delete "$SQL_INSTANCE" --quiet 2>/dev/null \
  && info "deleted $SQL_INSTANCE" || info "$SQL_INSTANCE not present"

bold "Deleting secrets"
for s in logmonitor-db-url logmonitor-jwt-secret logmonitor-totp-key \
         logmonitor-metrics-token logmonitor-anthropic-key; do
  gcloud secrets delete "$s" --quiet 2>/dev/null && info "deleted $s" || info "$s not present"
done

bold "Done"
info "Artifact Registry images from Cloud Build are left in place."
info "Remove them with: gcloud artifacts repositories delete cloud-run-source-deploy --location=$REGION"
