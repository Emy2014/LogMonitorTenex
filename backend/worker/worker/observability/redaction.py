"""The PII boundary.

LogMonitor ingests customer proxy logs: usernames, internal IP addresses, and full
URLs with query strings. If that content reaches application logs, the
observability pipeline becomes a second, less-guarded copy of the customer's
data -- for a security product, the thing a reviewer will probe hardest.

**The rule: log identifiers and counts, never content.**

Where a value genuinely needs to be correlatable across log lines (which user
ran this analysis?), log a salted hash instead of the value. Hashes are stable
within a deployment, so they support correlation, and are useless outside it.
"""

from __future__ import annotations

import hashlib
import os

# Per-deployment salt. Without it, hashes of a small domain (usernames,
# RFC1918 addresses) are trivially reversible with a rainbow table.
_SALT = os.getenv("LOG_HASH_SALT") or os.getenv("JWT_SECRET") or "logmonitor-dev-salt"

# Fields that must never be logged verbatim, whatever the call site intends.
FORBIDDEN_FIELDS = frozenset({
    "raw", "url", "username", "user_agent", "client_ip", "host", "password",
    "password_hash", "referer", "query",
})


def hash_identifier(value: object, prefix: str = "") -> str:
    """Stable, salted, truncated hash of an identifier.

    >>> hash_identifier("m.chen", "u_")   # doctest: +SKIP
    'u_9f2c1a7b3e4d'

    16 hex chars is ample: these are correlation handles, not cryptographic
    commitments, and collisions only cost a confusing log line.
    """
    digest = hashlib.sha256(f"{_SALT}:{value}".encode()).hexdigest()[:12]
    return f"{prefix}{digest}"


def safe_extra(fields: dict) -> dict:
    """Strip anything that could carry customer log content.

    A backstop, not the primary defence -- call sites are expected not to pass
    these in the first place. It exists so a careless future edit fails safe.
    """
    return {
        key: value
        for key, value in fields.items()
        if key not in FORBIDDEN_FIELDS
    }
