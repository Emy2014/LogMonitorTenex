"""The row shape detection works on.

Deliberately a plain dataclass, not an ORM model, so the detectors stay pure
and unit-testable without a database -- the same reason the v1 parser defined
``ParsedEntry`` rather than reusing the SQLAlchemy class.

One change from v1: entries carry their **database id**. v1 detectors returned
positional indices into the in-memory list, which the pipeline then mapped back
through a parallel ``db_ids`` array. That mapping only holds while every entry
is in one list in one process. Sharding breaks it, so ids travel with the row.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class LogEntry:
    id: int
    line_no: int
    ts: datetime | None = None
    client_ip: str | None = None
    username: str | None = None
    host: str | None = None
    url: str | None = None
    category: str | None = None
    action: str | None = None
    req_bytes: int | None = None
    resp_bytes: int | None = None
    user_agent: str | None = None
    threat_name: str | None = None
    resp_code: int | None = None
    method: str | None = None
    latency_ms: int | None = None
    cache_status: str | None = None
    raw: str = ""

    @property
    def parsed(self) -> bool:
        """True when at least a timestamp or a source IP was recovered."""
        return self.ts is not None or self.client_ip is not None

    @property
    def actor(self) -> str:
        """Who this entry is attributable to, for grouping and reporting."""
        return self.username or self.client_ip or "unknown"
