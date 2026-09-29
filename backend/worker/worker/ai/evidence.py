"""Build the compact evidence packet sent to the LLM.

This is the boundary that makes the whole design affordable. A 50MB proxy log
is millions of tokens -- it would not fit in any context window and would cost
roughly $25 per upload. Stage 1 has already reduced the file to a ranked list
of candidates with supporting statistics, so what crosses this boundary is a
few KB of aggregates, never raw log lines in bulk.

Each candidate is given a short id (``c0``, ``c1``, ...). The model refers to
those ids rather than emitting row numbers, so it is structurally incapable of
inventing a row that does not exist -- the server maps ids back to rows itself.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Mapping, Sequence

from worker.detection import Candidate, Partial
from worker.entry import LogEntry

# Hard ceiling on the packet. Well under the model's context window; the point
# is to keep cost predictable regardless of how pathological the upload is.
MAX_PACKET_CHARS = 14_000
MAX_SAMPLE_ROWS = 3


def _overview(partial: Partial) -> dict:
    """Describe the whole upload, from the merged aggregates.

    v1 computed this by walking every entry, which the reduce step no longer
    holds -- it has the merged Partial and only the rows a candidate cites.
    Every figure below is already an aggregate, so nothing is lost.
    """
    hours = sorted(partial.hour_counts)
    return {
        "total_entries": partial.entries_seen,
        "distinct_users": len({u for g in partial.hosts.values() for u in g.users}),
        "distinct_client_ips": len({ip for ip, _ in partial.ip_minute}),
        "distinct_hosts": len(partial.hosts),
        "hours_covered": hours,
        "busiest_hour": max(partial.hour_counts, key=partial.hour_counts.get) if hours else None,
        "requests_per_hour": {str(h): partial.hour_counts[h] for h in hours},
        "total_bytes_sent": sum(g.total_bytes for g in partial.user_host.values()),
        "threat_names": sorted({t for t, _ in partial.threats})[:10],
    }


def _sample_rows(by_id: Mapping[int, LogEntry], ids: Sequence[int]) -> list[str]:
    """A couple of raw lines per candidate, so the model can see real context.

    Looked up by database id rather than list position: after sharding there
    is no single ordered list to index into, and a positional lookup would
    quietly return somebody else's row.
    """
    rows = []
    for entry_id in list(ids)[:MAX_SAMPLE_ROWS]:
        entry = by_id.get(entry_id)
        if entry is not None and entry.raw:
            rows.append(entry.raw[:300])
    return rows


def build_evidence_packet(
    partial: Partial,
    candidates: Sequence[Candidate],
    by_id: Mapping[int, LogEntry] | None = None,
    baseline: dict | None = None,
) -> str:
    """Render overview + ranked candidates as JSON for the model."""
    by_id = by_id or {}
    packet: dict = {
        "overview": _overview(partial),
        "candidates": [
            {
                "id": f"c{n}",
                "kind": c.kind,
                "title": c.title,
                "statistical_confidence": round(c.score, 3),
                "affected_entry_count": len(c.entry_ids),
                "evidence": c.evidence,
                "sample_log_lines": _sample_rows(by_id, c.entry_ids),
            }
            for n, c in enumerate(candidates)
        ],
    }

    # Organization-wide context, when the upload was analysed against history.
    # Aggregates only -- no other user's log lines reach the model.
    if baseline:
        packet["organization_baseline"] = baseline

    text = json.dumps(packet, indent=2, default=str)

    # Shed sample lines first, then whole candidates, until it fits.
    while len(text) > MAX_PACKET_CHARS and packet["candidates"]:
        if any(c["sample_log_lines"] for c in packet["candidates"]):
            for c in packet["candidates"]:
                c["sample_log_lines"] = []
        else:
            packet["candidates"].pop()
        text = json.dumps(packet, indent=2, default=str)

    return text
