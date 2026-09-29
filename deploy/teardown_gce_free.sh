#!/usr/bin/env bash
# Delete the free-tier deployment.
set -euo pipefail

ZONE="${ZONE:-us-west1-b}"
REGION="${ZONE%-*}"
VM_NAME="${VM_NAME:-logmonitor}"
REPO_NAME="${REPO_NAME:-logmonitor}"

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
die()  { printf '\n\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

PROJECT_ID="$(gcloud config get-value project 2>/dev/null)"
[ -n "$PROJECT_ID" ] && [ "$PROJECT_ID" != "(unset)" ] || die "No project set."
BUCKET="${BUCKET:-${PROJECT_ID}-logmonitor-raw}"

bold "This permanently deletes LogMonitor from $PROJECT_ID"
info "VM       : $VM_NAME ($ZONE)  <-- includes the database volume"
info "Storage  : gs://$BUCKET      <-- every archived raw upload"
info "Registry : $REGION-docker.pkg.dev/$PROJECT_ID/$REPO_NAME"
info "Firewall : logmonitor-allow-web"
printf '\n  Type DELETE to confirm: '
read -r CONFIRM
[ "$CONFIRM" = "DELETE" ] || die "Aborted."

gcloud compute instances delete "$VM_NAME" --zone="$ZONE" --quiet 2>/dev/null \
  && info "deleted VM" || info "VM not present"
gcloud compute firewall-rules delete logmonitor-allow-web --quiet 2>/dev/null \
  && info "deleted firewall rule" || info "firewall rule not present"
gcloud storage rm --recursive "gs://$BUCKET" --quiet 2>/dev/null \
  && info "deleted bucket" || info "bucket not present"
gcloud artifacts repositories delete "$REPO_NAME" --location="$REGION" --quiet 2>/dev/null \
  && info "deleted registry" || info "registry not present"

bold "Done"
