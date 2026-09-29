"""The Redis job protocol.

Two job kinds, and a counter that decides when the second may run:

    map     one per shard, consumed in parallel
    reduce  one per analysis, enqueued by whichever worker finishes the last
            map job

The counter is what makes fan-in safe. Each map worker decrements it after
writing its partial; the one that takes it to zero enqueues the reduce. Redis
DECR is atomic, so exactly one worker sees zero no matter how they interleave.

v1 scheduled analysis with FastAPI BackgroundTasks, which meant a restart
orphaned every running analysis with nothing to notice. Here the queue is
durable and a reaper requeues anything whose heartbeat goes stale.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

import redis.asyncio as redis

QUEUE_KEY = "logmonitor:jobs"
# Partials are handed between workers through Redis rather than the database:
# they are large, short-lived and of interest to nobody afterwards.
PARTIAL_TTL_SECONDS = 3600


@dataclass(frozen=True)
class Job:
    kind: str                 # "map" | "reduce"
    analysis_id: str
    upload_id: str
    org_id: str
    user_id: str
    shard: int = 0
    shard_count: int = 1
    offset: int = 0
    limit: int = 0
    scope: str = "file"
    baseline_window_days: int | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @staticmethod
    def from_json(raw: str) -> "Job":
        return Job(**json.loads(raw))


def pending_key(analysis_id: str) -> str:
    return f"logmonitor:pending:{analysis_id}"


def partial_key(analysis_id: str, shard: int) -> str:
    return f"logmonitor:partial:{analysis_id}:{shard}"


class Queue:
    def __init__(self, url: str) -> None:
        self._redis = redis.from_url(url, decode_responses=True)

    async def close(self) -> None:
        await self._redis.aclose()

    async def ping(self) -> None:
        await self._redis.ping()

    async def enqueue(self, job: Job) -> None:
        await self._redis.lpush(QUEUE_KEY, job.to_json())

    async def enqueue_map_jobs(self, jobs: list[Job]) -> None:
        """Publish a whole fan-out, and the counter that closes it.

        The counter is set before any job is pushed. Setting it afterwards
        would let a fast worker finish a shard, find no counter, and never
        trigger the reduce.
        """
        if not jobs:
            return
        analysis_id = jobs[0].analysis_id
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.set(pending_key(analysis_id), len(jobs), ex=PARTIAL_TTL_SECONDS)
            for job in jobs:
                pipe.lpush(QUEUE_KEY, job.to_json())
            await pipe.execute()

    async def reserve(self, timeout: int = 5) -> Job | None:
        """Block for the next job. Returns None when the wait expires."""
        item = await self._redis.brpop(QUEUE_KEY, timeout=timeout)
        return Job.from_json(item[1]) if item else None

    async def put_partial(self, analysis_id: str, shard: int, payload: str) -> None:
        await self._redis.set(partial_key(analysis_id, shard), payload,
                              ex=PARTIAL_TTL_SECONDS)

    async def get_partials(self, analysis_id: str, shard_count: int) -> list[str]:
        keys = [partial_key(analysis_id, s) for s in range(shard_count)]
        values = await self._redis.mget(keys)
        return [v for v in values if v is not None]

    async def drop_partials(self, analysis_id: str, shard_count: int) -> None:
        keys = [partial_key(analysis_id, s) for s in range(shard_count)]
        keys.append(pending_key(analysis_id))
        await self._redis.delete(*keys)

    async def complete_shard(self, analysis_id: str) -> bool:
        """Mark one shard done; True for the worker that closed the group.

        DECR is atomic, so exactly one caller observes zero however the
        workers interleave.
        """
        remaining = await self._redis.decr(pending_key(analysis_id))
        return remaining <= 0

    async def depth(self) -> int:
        return await self._redis.llen(QUEUE_KEY)
