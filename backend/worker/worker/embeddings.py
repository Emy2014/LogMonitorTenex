"""Embedding provider, with a working fallback.

Anthropic does not serve an embeddings API, so vectors come from elsewhere.
The provider is a seam rather than a hard dependency because of what happens
when it is absent: findings are still detected, scored, explained and
searchable by text. Only "find incidents like this one" goes dark.

A security tool whose search does not work until someone buys an API key is a
security tool with no search, so the absence has to degrade rather than fail.

    VOYAGE_API_KEY set    -> voyage-3, 1024 dimensions, matching the schema
    unset                 -> no vectors written; search falls back to Postgres
                             full-text, which needs nothing
"""

from __future__ import annotations

import logging
import os
from typing import Protocol, Sequence

log = logging.getLogger("logmonitor.embeddings")

# Must match vector(1024) in migration 6. Changing the model means changing
# the column, and re-embedding everything already stored.
DIMENSIONS = 1024
MODEL = "voyage-3"
# Findings are short; this bounds a pathological explanation rather than
# trimming anything real.
MAX_CHARS = 8000


class Embedder(Protocol):
    def available(self) -> bool: ...
    async def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


class NullEmbedder:
    """Writes no vectors. Everything except similarity search still works."""

    def available(self) -> bool:
        return False

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        return []


class VoyageEmbedder:
    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def available(self) -> bool:
        return bool(self._api_key)

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        import httpx

        payload = {
            "input": [t[:MAX_CHARS] for t in texts],
            "model": MODEL,
            # Documents at write time, queries at read time -- Voyage embeds
            # the two asymmetrically and mixing them degrades recall.
            "input_type": "document",
        }
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                "https://api.voyageai.com/v1/embeddings",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json=payload)
            response.raise_for_status()
            data = response.json()["data"]
        return [item["embedding"] for item in sorted(data, key=lambda d: d["index"])]


def get_embedder() -> Embedder:
    key = os.getenv("VOYAGE_API_KEY", "").strip()
    if not key:
        log.info("no embedding provider configured; similarity search is disabled",
                 extra={"event": "embeddings.disabled"})
        return NullEmbedder()
    return VoyageEmbedder(key)


def finding_text(kind: str, explanation: str, recommendation: str | None,
                 evidence: dict | None = None) -> str:
    """What gets embedded for one finding.

    The entities matter as much as the prose: an analyst searching for
    "exfiltration to a Russian host" is reaching for the hostname as much as
    the wording, so identifying values are folded in.
    """
    parts = [kind.replace("_", " "), explanation]
    if recommendation:
        parts.append(recommendation)
    for field in ("host", "client_ip", "username", "actor", "threat_name"):
        value = (evidence or {}).get(field)
        if value:
            parts.append(f"{field}: {value}")
    return "\n".join(str(p) for p in parts)
