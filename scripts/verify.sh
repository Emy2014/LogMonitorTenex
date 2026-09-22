#!/usr/bin/env bash
#
# End-to-end check of a running LogMonitor deployment.
#
# Takes a base URL so the same script verifies local development and a real
# Cloud Run deployment -- a verification script that only ever runs in one
# environment tends to be wrong in the other.
#
# Usage:
#   ./scripts/verify.sh                          # local, http://localhost:3000
#   ./scripts/verify.sh https://logmonitor-web-...  # a deployment
#
# With the edge gate enabled, export EDGE_AUTH_USER and EDGE_AUTH_PASS first.
#
set -uo pipefail

BASE="${1:-http://localhost:3000}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAMPLE="$REPO_ROOT/samples/zscaler_suspicious.log"

JAR="$(mktemp)"; JAR_B="$(mktemp)"
trap 'rm -f "$JAR" "$JAR_B"' EXIT

PASS=0; FAIL=0
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# The edge gate sits in front of everything, so every request carries it.
AUTH=()
if [ -n "${EDGE_AUTH_USER:-}" ] && [ -n "${EDGE_AUTH_PASS:-}" ]; then
  AUTH=(-u "${EDGE_AUTH_USER}:${EDGE_AUTH_PASS}")
fi

req() { curl -sS --max-time 120 "${AUTH[@]}" "$@"; }
code() { req -o /dev/null -w '%{http_code}' "$@"; }

bold "Verifying $BASE"

# --- reachability -----------------------------------------------------------
[ "$(code "$BASE/api/health")" = "200" ] \
  && ok "health responds" || bad "health did not return 200"

# --- the session cookie is not optional -------------------------------------
[ "$(code -b "$JAR" "$BASE/api/auth/me")" = "401" ] \
  && ok "unauthenticated /me is refused" || bad "/me should be 401 when signed out"

# A CSRF token is issued on a safe request and required on unsafe ones.
req -c "$JAR" "$BASE/api/health" >/dev/null
CSRF="$(grep logmonitor_csrf "$JAR" | awk '{print $7}')"
[ -n "$CSRF" ] && ok "CSRF token issued" || bad "no CSRF cookie was set"

[ "$(code -b "$JAR" -X POST -H 'Content-Type: application/json' \
      -d '{}' "$BASE/api/auth/login")" = "403" ] \
  && ok "state-changing request without a CSRF token is refused" \
  || bad "login without a CSRF token should be 403"

post() {
  req -b "$JAR" -c "$JAR" -X POST -H 'Content-Type: application/json' \
      -H "X-CSRF-Token: $CSRF" -d "$2" "$BASE$1"
}

# --- registration and isolation ---------------------------------------------
SUFFIX="$RANDOM$RANDOM"
EMAIL_A="verify-a-${SUFFIX}@example.test"
EMAIL_B="verify-b-${SUFFIX}@example.test"

ROLE="$(post /api/auth/register \
  "{\"org_name\":\"Verify A $SUFFIX\",\"email\":\"$EMAIL_A\",\"password\":\"verify-pass-1234\"}" \
  | sed -n 's/.*"role":"\([a-z]*\)".*/\1/p')"
[ "$ROLE" = "owner" ] && ok "registering an organization makes the first user its owner" \
  || bad "register returned role='$ROLE', expected 'owner'"

[ "$(req -b "$JAR" "$BASE/api/auth/me" | grep -c "$EMAIL_A")" = "1" ] \
  && ok "session works after registering" || bad "/me did not return the new user"

# --- ingest -----------------------------------------------------------------
if [ -f "$SAMPLE" ]; then
  UPLOAD="$(req -b "$JAR" -H "X-CSRF-Token: $CSRF" \
    -F "file=@$SAMPLE" -F "scope=file" "$BASE/api/uploads")"
  LINES="$(printf '%s' "$UPLOAD" | sed -n 's/.*"line_count":\([0-9]*\).*/\1/p')"
  PARSED="$(printf '%s' "$UPLOAD" | sed -n 's/.*"parsed_count":\([0-9]*\).*/\1/p')"

  [ "$LINES" = "2735" ] && ok "ingested the sample: $LINES lines" \
    || bad "line_count=$LINES, expected 2735"
  # One line is the header; every data row must parse.
  [ "$PARSED" = "2734" ] && ok "every data row parsed: $PARSED" \
    || bad "parsed_count=$PARSED, expected 2734"

  SUMMARY="$(req -b "$JAR" "$BASE/api/dashboard/summary?from=2024-01-01T00:00:00Z")"
  REQUESTS="$(printf '%s' "$SUMMARY" | sed -n 's/.*"requests":\([0-9]*\).*/\1/p')"
  [ "$REQUESTS" = "2734" ] && ok "dashboard reflects the ingest: $REQUESTS requests" \
    || bad "dashboard requests=$REQUESTS, expected 2734"

  printf '%s' "$SUMMARY" | grep -q '"empty":false' \
    && ok "summary no longer reports empty" || bad "summary still reports empty"

  TOP="$(req -b "$JAR" "$BASE/api/dashboard/top?dimension=host&from=2024-01-01T00:00:00Z&limit=3")"
  printf '%s' "$TOP" | grep -q 'cdn-telemetry-sync.net' \
    && ok "rollups surface the seeded beaconing host" \
    || bad "expected cdn-telemetry-sync.net among the top hosts"
else
  printf '  \033[33m-\033[0m sample not found at %s, skipping ingest checks\n' "$SAMPLE"
fi

# --- cross-tenant isolation -------------------------------------------------
req -c "$JAR_B" "$BASE/api/health" >/dev/null
CSRF_B="$(grep logmonitor_csrf "$JAR_B" | awk '{print $7}')"
req -b "$JAR_B" -c "$JAR_B" -X POST -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF_B" \
  -d "{\"org_name\":\"Verify B $SUFFIX\",\"email\":\"$EMAIL_B\",\"password\":\"verify-pass-1234\"}" \
  "$BASE/api/auth/register" >/dev/null

COUNT_B="$(req -b "$JAR_B" "$BASE/api/uploads" | grep -o '"id"' | wc -l | tr -d ' ')"
[ "$COUNT_B" = "0" ] \
  && ok "a second organization sees none of the first's uploads" \
  || bad "cross-tenant leak: organization B sees $COUNT_B uploads"

# A member may not widen the dashboard to the whole organization; the owner may.
[ "$(code -b "$JAR" "$BASE/api/dashboard/summary?scope=org")" = "200" ] \
  && ok "an admin may request organization-wide figures" \
  || bad "owner was refused scope=org"

# --- operator surface -------------------------------------------------------
[ "$(code -b "$JAR" "$BASE/api/metrics")" = "401" ] \
  && ok "metrics are closed to a user session" \
  || bad "metrics should not open to a normal user cookie"

# --- result -----------------------------------------------------------------
bold "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
