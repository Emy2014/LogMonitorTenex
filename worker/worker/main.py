"""Worker entrypoint.

    python -m worker.main

Consumes map and reduce jobs from Redis. Scale by running more processes:
`docker compose up --scale worker=4`. Sharding is by (owner, time slice), so
the parallelism is real rather than nominal.

One process in the pool also reaps: an analysis whose worker died stops
heartbeating and is put back on the queue. v1 had no equivalent -- a restart
left rows in 'running' for ever, with nothing to notice or retry them.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys

from worker.config import get_settings
from worker.db import Database
from worker.observability.logging import setup_logging
from worker.pipeline import run_map, run_reduce
from worker.queue import Job, Queue

log = logging.getLogger("logmonitor.worker")

REAP_INTERVAL_SECONDS = 60


async def handle(job: Job, db: Database, queue: Queue) -> None:
    """Run one job, recording failure on the analysis rather than crashing."""
    if not await db.claim(job.analysis_id):
        log.info("analysis is no longer claimable, skipping",
                 extra={"event": "job.skipped", "analysis_id": job.analysis_id})
        return
    try:
        if job.kind == "map":
            await run_map(job, db, queue)
        elif job.kind == "reduce":
            await run_reduce(job, db, queue)
        else:
            raise ValueError(f"unknown job kind {job.kind!r}")
    except Exception as exc:  # noqa: BLE001
        # The UI needs a terminal state with a reason; a job that vanishes
        # leaves an analysis spinning for ever.
        log.exception("job failed", extra={
            "event": "job.failed", "kind": job.kind,
            "analysis_id": job.analysis_id, "error_type": type(exc).__name__})
        await db.fail(job.analysis_id, f"{type(exc).__name__}: {exc}")


async def reaper(db: Database, queue: Queue, stop: asyncio.Event) -> None:
    """Requeue analyses whose worker stopped reporting in."""
    settings = get_settings()
    while not stop.is_set():
        try:
            for row in await db.requeue_stale(settings.stale_after_seconds):
                await queue.enqueue(Job(
                    kind="map", analysis_id=str(row["id"]),
                    upload_id=str(row["upload_id"]), org_id=str(row["org_id"]),
                    user_id=str(row["user_id"]), shard=0, shard_count=1,
                    offset=0, limit=10_000_000,
                    scope=row["scope"] or "file",
                    baseline_window_days=row["baseline_window_days"]))
                log.warning("requeued a stale analysis", extra={
                    "event": "reaper.requeued", "analysis_id": str(row["id"])})
        except Exception:  # noqa: BLE001
            # A reaper that dies quietly is worse than one that logs and
            # retries: nothing else notices orphaned work.
            log.exception("reaper pass failed", extra={"event": "reaper.failed"})
        try:
            await asyncio.wait_for(stop.wait(), timeout=REAP_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            pass


async def main() -> int:
    settings = get_settings()
    setup_logging(settings.log_level, settings.log_json)

    db = Database(settings.database_url)
    queue = Queue(settings.redis_url)

    # Wait rather than crash-loop: compose gates on healthchecks, but a
    # healthy database is not the same as one accepting connections yet.
    for attempt in range(1, 11):
        try:
            await db.ping()
            await queue.ping()
            break
        except Exception as exc:  # noqa: BLE001
            log.warning("dependencies not ready, retrying", extra={
                "event": "startup.retry", "attempt": attempt, "error": str(exc)})
            await asyncio.sleep(min(attempt, 5))
    else:
        log.error("could not reach the database or Redis",
                  extra={"event": "startup.failed"})
        return 1

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    reap_task = asyncio.create_task(reaper(db, queue, stop))
    log.info("worker ready", extra={
        "event": "worker.start", "pid": os.getpid(),
        "shard_size": settings.shard_size})

    try:
        while not stop.is_set():
            job = await queue.reserve(timeout=5)
            if job is None:
                continue
            await handle(job, db, queue)
    finally:
        stop.set()
        reap_task.cancel()
        await asyncio.gather(reap_task, return_exceptions=True)
        await queue.close()
        await db.close()
        log.info("worker stopped", extra={"event": "worker.stop"})
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
