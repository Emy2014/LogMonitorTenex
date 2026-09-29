"""Worker settings, from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    database_url: str
    redis_url: str
    anthropic_api_key: str
    anthropic_model: str
    log_level: str
    log_json: bool
    log_hash_salt: str
    # How many entries one shard carries. Large enough that per-shard overhead
    # is negligible, small enough that a worker's memory does not track the
    # size of the upload.
    shard_size: int
    # A job whose heartbeat is older than this is presumed dead and requeued.
    stale_after_seconds: int


@lru_cache
def get_settings() -> Settings:
    return Settings(
        database_url=os.getenv(
            "DATABASE_URL",
            "postgresql+asyncpg://logmonitor:logmonitor@localhost:5432/logmonitor"),
        redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        # Absent key is not an error: detection and every confidence score are
        # unaffected, only the narrative falls back.
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
        anthropic_model=os.getenv("ANTHROPIC_MODEL", "claude-opus-5"),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        log_json=os.getenv("LOG_JSON", "true").lower() != "false",
        log_hash_salt=os.getenv("LOG_HASH_SALT") or os.getenv("JWT_SECRET", ""),
        shard_size=int(os.getenv("SHARD_SIZE", "25000")),
        stale_after_seconds=int(os.getenv("STALE_AFTER_SECONDS", "300")),
    )
