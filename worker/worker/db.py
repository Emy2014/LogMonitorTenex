"""Database access for the worker.

Raw asyncpg through SQLAlchemy Core rather than an ORM: the worker reads log
rows in bulk and writes findings, and there is no object graph worth mapping.
The schema is owned by the gateway's migrations.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Sequence

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

from worker.entry import LogEntry

ENTRY_COLUMNS = """
    id, line_no, ts, host(client_ip) AS client_ip, username, host, url,
    category, action, req_bytes, resp_bytes, user_agent, threat_name,
    resp_code, method, latency_ms, cache_status
"""


class Database:
    def __init__(self, url: str) -> None:
        # Modest pool: several worker processes share one Postgres, and each
        # does one thing at a time.
        self._engine = create_async_engine(url, pool_size=4, max_overflow=2,
                                           pool_pre_ping=True)

    async def close(self) -> None:
        await self._engine.dispose()

    @asynccontextmanager
    async def connect(self) -> AsyncIterator[AsyncConnection]:
        async with self._engine.begin() as conn:
            yield conn

    async def ping(self) -> None:
        async with self.connect() as conn:
            await conn.execute(text("SELECT 1"))

    # --- reads --------------------------------------------------------------

    async def count_entries(self, upload_id: str) -> int:
        async with self.connect() as conn:
            result = await conn.execute(
                text("SELECT count(*) FROM log_entries WHERE upload_id = :u"),
                {"u": upload_id})
            return int(result.scalar_one())

    async def load_shard(self, upload_id: str, offset: int, limit: int) -> list[LogEntry]:
        """One contiguous slice of an upload, ordered by line number.

        Ordering by line_no rather than id keeps shard boundaries stable if the
        same upload is ever re-analysed.
        """
        async with self.connect() as conn:
            result = await conn.execute(
                text(f"""
                    SELECT {ENTRY_COLUMNS}
                      FROM log_entries
                     WHERE upload_id = :u
                     ORDER BY line_no
                     LIMIT :lim OFFSET :off
                """),
                {"u": upload_id, "lim": limit, "off": offset})
            return [LogEntry(**row._mapping) for row in result]

    async def load_entries_by_id(self, ids: Sequence[int]) -> dict[int, LogEntry]:
        """Fetch specific rows, for building evidence after scoring.

        Only the rows a candidate actually implicates are loaded, which is why
        the reduce step does not need the whole upload in memory.
        """
        if not ids:
            return {}
        async with self.connect() as conn:
            result = await conn.execute(
                text(f"SELECT {ENTRY_COLUMNS} FROM log_entries WHERE id = ANY(:ids)"),
                {"ids": list(ids)})
            return {row._mapping["id"]: LogEntry(**row._mapping) for row in result}

    async def historical_baseline(
        self, org_id: str, window_days: int, exclude_upload: str
    ) -> dict[str, Any]:
        """Organization-wide context for scope='history'.

        Read from entry_rollups only, never raw rows. That is what reconciles
        an organization-wide baseline with the rule that a user may only access
        their own log lines: aggregate statistics cross users, individual log
        lines never do.
        """
        since = datetime.now(timezone.utc) - timedelta(days=window_days)
        async with self.connect() as conn:
            result = await conn.execute(
                text("""
                    SELECT COALESCE(SUM(requests), 0)  AS requests,
                           COALESCE(SUM(errors), 0)    AS errors,
                           COUNT(DISTINCT host)        AS hosts,
                           percentile_disc(0.5) WITHIN GROUP (ORDER BY requests)
                                                       AS median_bucket_requests
                      FROM entry_rollups
                     WHERE org_id = :org
                       AND grain = 'hour'
                       AND bucket_start >= :since
                       AND upload_id <> :exclude
                """),
                {"org": org_id, "since": since, "exclude": exclude_upload})
            row = result.one()._mapping
            return {
                "window_days": window_days,
                "requests": int(row["requests"] or 0),
                "errors": int(row["errors"] or 0),
                "hosts": int(row["hosts"] or 0),
                "median_hourly_requests": float(row["median_bucket_requests"] or 0),
            }

    # --- analysis lifecycle -------------------------------------------------

    async def claim(self, analysis_id: str) -> bool:
        """Move an analysis to running. False if it is not claimable."""
        async with self.connect() as conn:
            result = await conn.execute(
                text("""
                    UPDATE analyses
                       SET status = 'running',
                           started_at = COALESCE(started_at, now()),
                           heartbeat_at = now()
                     WHERE id = :id AND status IN ('queued', 'running')
                 RETURNING id
                """), {"id": analysis_id})
            return result.first() is not None

    async def heartbeat(self, analysis_id: str) -> None:
        """Say the job is still alive, so the reaper leaves it alone."""
        async with self.connect() as conn:
            await conn.execute(
                text("UPDATE analyses SET heartbeat_at = now() WHERE id = :id"),
                {"id": analysis_id})

    async def fail(self, analysis_id: str, message: str) -> None:
        async with self.connect() as conn:
            await conn.execute(
                text("""
                    UPDATE analyses
                       SET status = 'failed', error = :err, finished_at = now()
                     WHERE id = :id
                """), {"id": analysis_id, "err": message[:2000]})

    async def finish(self, analysis_id: str, *, summary: str | None,
                     overall_risk: str | None, timeline: list | None,
                     model: str | None, input_tokens: int | None,
                     output_tokens: int | None, error: str | None) -> None:
        async with self.connect() as conn:
            await conn.execute(
                text("""
                    UPDATE analyses
                       SET status = 'done', summary = :summary,
                           overall_risk = CAST(:risk AS severity),
                           timeline = CAST(:timeline AS jsonb),
                           model = :model, input_tokens = :in_tok,
                           output_tokens = :out_tok, error = :err,
                           finished_at = now()
                     WHERE id = :id
                """),
                {"id": analysis_id, "summary": summary, "risk": overall_risk,
                 "timeline": json.dumps(timeline) if timeline is not None else None,
                 "model": model, "in_tok": input_tokens, "out_tok": output_tokens,
                 "err": error})

    async def save_anomalies(self, analysis_id: str, rows: list[dict]) -> int:
        """Replace an analysis's findings.

        Delete-then-insert so a re-run after a requeue does not duplicate
        everything -- the reaper exists precisely to cause re-runs.
        """
        async with self.connect() as conn:
            await conn.execute(
                text("DELETE FROM anomalies WHERE analysis_id = :id"),
                {"id": analysis_id})
            for row in rows:
                await conn.execute(
                    text("""
                        INSERT INTO anomalies (
                            analysis_id, kind, severity, urgency, action_required,
                            action_label, confidence, explanation, recommendation,
                            entry_ids)
                        VALUES (
                            :analysis_id, :kind, CAST(:severity AS severity),
                            CAST(:urgency AS urgency_level), :action_required,
                            :action_label, :confidence, :explanation,
                            :recommendation, :entry_ids)
                    """), {**row, "analysis_id": analysis_id})
            return len(rows)

    async def record_timing(self, analysis_id: str, org_id: str, user_id: str,
                            stage: str, duration_ms: float,
                            queue_wait_ms: float | None = None,
                            worker_cpu_percent: float | None = None) -> None:
        """Persist a stage timing.

        v1 kept these in an in-process registry that reset on every restart,
        so no percentile outlived a deploy.
        """
        async with self.connect() as conn:
            await conn.execute(
                text("""
                    INSERT INTO analysis_timings (
                        analysis_id, org_id, user_id, stage, duration_ms,
                        queue_wait_ms, worker_cpu_percent)
                    VALUES (:a, :o, :u, :stage, :ms, :wait, :cpu)
                """),
                {"a": analysis_id, "o": org_id, "u": user_id, "stage": stage,
                 "ms": duration_ms, "wait": queue_wait_ms, "cpu": worker_cpu_percent})

    async def requeue_stale(self, older_than_seconds: int) -> list[dict]:
        """Find analyses whose worker stopped reporting in.

        v1 had no equivalent: a restart left rows in 'running' for ever with
        nothing to notice or retry them.
        """
        async with self.connect() as conn:
            result = await conn.execute(
                text("""
                    UPDATE analyses a
                       SET status = 'queued', heartbeat_at = NULL
                      FROM uploads u
                     WHERE u.id = a.upload_id
                       AND a.status = 'running'
                       AND a.heartbeat_at < now() - make_interval(secs => :secs)
                 RETURNING a.id, a.upload_id, a.org_id, u.user_id,
                           a.scope::text, a.baseline_window_days
                """), {"secs": older_than_seconds})
            return [dict(row._mapping) for row in result]

    async def save_embeddings(self, analysis_id: str, org_id: str, user_id: str,
                              rows: list[dict]) -> int:
        """Replace an analysis's finding vectors.

        Delete-then-insert for the same reason findings are: the reaper causes
        re-runs, and a re-run must not leave two copies of every vector.
        """
        async with self.connect() as conn:
            await conn.execute(
                text("DELETE FROM finding_embeddings WHERE analysis_id = :id"),
                {"id": analysis_id})
            for row in rows:
                await conn.execute(
                    text("""
                        INSERT INTO finding_embeddings (
                            org_id, user_id, analysis_id, anomaly_id, kind,
                            bucket_key, content, embedding)
                        VALUES (:org, :usr, :analysis, :anomaly, :kind,
                                :bucket, :content, CAST(:embedding AS vector))
                    """),
                    {"org": org_id, "usr": user_id, "analysis": analysis_id,
                     "anomaly": row.get("anomaly_id"), "kind": row["kind"],
                     "bucket": row.get("bucket_key"), "content": row["content"],
                     "embedding": row["embedding"]})
            return len(rows)

    async def anomaly_ids(self, analysis_id: str) -> list[dict]:
        """The persisted findings, so vectors can reference real rows."""
        async with self.connect() as conn:
            result = await conn.execute(
                text("""
                    SELECT id, kind, explanation, recommendation
                      FROM anomalies WHERE analysis_id = :id ORDER BY id
                """), {"id": analysis_id})
            return [dict(row._mapping) for row in result]
