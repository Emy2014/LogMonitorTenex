#!/usr/bin/env bash
# Generate the three edge-gate values for .env from one password.
#
# Two hashes of the same credential: the Go gateway verifies with argon2id,
# while Next.js middleware runs on the edge runtime where only Web Crypto is
# available and so compares a SHA-256 digest. Both gate the same secret.
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: $0 <password> [username]" >&2
  echo "  e.g. $0 \"\$(openssl rand -base64 24)\" ops" >&2
  exit 2
fi

password="$1"
username="${2:-ops}"

sha256=$(printf '%s' "$password" | openssl dgst -sha256 -hex | awk '{print $NF}')

# argon2id via the gateway's own implementation, so the parameters cannot
# drift apart from what the server verifies against.
argon=$(cd "$(dirname "$0")/../gateway" && \
  go run ./cmd/hashpass "$password" 2>/dev/null)

cat <<OUT
EDGE_AUTH_ENABLED=true
EDGE_AUTH_USER=$username
EDGE_AUTH_PASS_HASH=$argon
EDGE_AUTH_PASS_SHA256=$sha256
OUT
