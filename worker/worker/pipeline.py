"""The analysis pipeline, split across workers.

    shard ─► map ─► partial ─┐
    shard ─► map ─► partial ─┼─► reduce ─► score ─► Claude ─► findings
    shard ─► map ─► partial ─┘

Each stage is timed separately and the timings are persisted. A single
"analysis took 3s" cannot tell you whether the detectors are slow or the model
is, and those have completely different fixes.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from worker.ai import analyze_candidates, build_evidence_packet
from worker.db import Database
from worker.embeddings import finding_text, get_embedder
from worker.ai.evidence import MAX_SAMPLE_ROWS
from worker.detection import Candidate, map_shard, merge_all, score
from worker.queue import Job, Queue
from worker.serialize import dumps, loads

log = logging.getLogger("logmonitor.pipeline")

# Confidence alone does not say how soon something needs attention, so urgency
# is derived from what the finding *is* as well as how sure we are. A blocked
# threat is high severity and low urgency: the proxy already stopped it.
URGENCY_BY_KIND = {
    "data_exfil":       "immediate",
    "beaconing":        "immediate",
    "volume_spike":     "today",
    "off_hours":        "today",
    "rare_destination": "this_week",
    "blocked_threat":   "monitor",
}
SEVERITY_BY_KIND = {
    "data_exfil":       "critical",
    "beaconing":        "high",
    "blocked_threat":   "high",
    "volume_spike":     "medium",
    "off_hours":        "medium",
    "rare_destination": "low",
}


class Timer:
    """Elapsed milliseconds, readable inside the block as well as after it."""

    def __init__(self) -> None:
        self._start = time.perf_counter()
        self._ms: float | None = None

    def __enter__(self) -> "Timer":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *exc: object) -> None:
        self._ms = (time.perf_counter() - self._start) * 1000.0

    @property
    def ms(self) -> float:
        if self._ms is not None:
            return self._ms
        return (time.perf_counter() - self._start) * 1000.0


async def run_map(job: Job, db: Database, queue: Queue) -> None:
    """Aggregate one shard and publish the partial.

    Emits no scores: three of the six detectors compare against a baseline no
    shard can see. See worker/detection/partial.py.
    """
    with Timer() as t:
        entries = await db.load_shard(job.upload_id, job.offset, job.limit)
        partial = map_shard(entries)
        await queue.put_partial(job.analysis_id, job.shard, dumps(partial))

    await db.record_timing(job.analysis_id, job.org_id, job.user_id,
                           "map", t.ms)
    log.info("shard mapped", extra={
        "event": "map.done", "analysis_id": job.analysis_id,
        "shard": job.shard, "of": job.shard_count,
        "entries": len(entries), "duration_ms": round(t.ms, 2)})

    # Whoever takes the counter to zero owns the reduce. DECR is atomic, so
    # exactly one worker sees that regardless of interleaving.
    if await queue.complete_shard(job.analysis_id):
        await queue.enqueue(Job(
            kind="reduce", analysis_id=job.analysis_id, upload_id=job.upload_id,
            org_id=job.org_id, user_id=job.user_id, shard_count=job.shard_count,
            scope=job.scope, baseline_window_days=job.baseline_window_days))
        log.info("fan-in complete; reduce enqueued",
                 extra={"event": "map.fanin", "analysis_id": job.analysis_id})


async def run_reduce(job: Job, db: Database, queue: Queue) -> None:
    """Merge partials, score once, narrate, persist."""
    overall = Timer()

    raw = await queue.get_partials(job.analysis_id, job.shard_count)
    if len(raw) < job.shard_count:
        # A partial expired or a shard never landed. Scoring on an incomplete
        # merge would silently under-report, which is worse than failing.
        raise RuntimeError(
            f"expected {job.shard_count} partials, found {len(raw)}")

    with Timer() as t_reduce:
        merged = merge_all([loads(r) for r in raw])
        candidates = score(merged)
    await db.record_timing(job.analysis_id, job.org_id, job.user_id,
                           "reduce", t_reduce.ms)

    baseline = None
    if job.scope == "history" and job.baseline_window_days:
        # Rollups only, never raw rows: aggregate statistics may cross users,
        # individual log lines may not.
        baseline = await db.historical_baseline(
            job.org_id, job.baseline_window_days, job.upload_id)

    with Timer() as t_evidence:
        # Only the rows a candidate actually cites, which is why the reduce
        # step never needs the whole upload in memory.
        needed = {i for c in candidates for i in c.entry_ids[:MAX_SAMPLE_ROWS]}
        rows = await db.load_entries_by_id(sorted(needed))
        packet = build_evidence_packet(merged, candidates, rows, baseline)
    await db.record_timing(job.analysis_id, job.org_id, job.user_id,
                           "evidence", t_evidence.ms)

    with Timer() as t_llm:
        report, meta = await analyze_candidates(packet, candidates)
    await db.record_timing(job.analysis_id, job.org_id, job.user_id,
                           "llm", t_llm.ms)

    with Timer() as t_persist:
        anomalies = _to_rows(report, candidates)
        await db.save_anomalies(job.analysis_id, anomalies)
        await db.finish(
            job.analysis_id,
            summary=report.summary,
            overall_risk=report.overall_risk,
            timeline=[e.model_dump() for e in report.timeline],
            model=meta.get("model"),
            input_tokens=meta.get("input_tokens"),
            output_tokens=meta.get("output_tokens"),
            error=meta.get("error"))
    await db.record_timing(job.analysis_id, job.org_id, job.user_id,
                           "persist", t_persist.ms)

    # Vectors last: they are an enhancement to search, so a provider outage
    # must not fail an analysis that has already produced its findings.
    with Timer() as t_embed:
        embedded = await _embed_findings(job, db, candidates)
    if embedded:
        await db.record_timing(job.analysis_id, job.org_id, job.user_id,
                               "embed", t_embed.ms)

    await queue.drop_partials(job.analysis_id, job.shard_count)
    await db.record_timing(job.analysis_id, job.org_id, job.user_id,
                           "total", overall.ms)

    log.info("analysis completed", extra={
        "event": "analysis.completed", "analysis_id": job.analysis_id,
        "candidates": len(candidates), "anomalies": len(anomalies),
        "overall_risk": report.overall_risk,
        "ai_fallback": meta.get("error") is not None,
        "scope": job.scope, "duration_ms": round(overall.ms, 2)})


async def _embed_findings(job: Job, db: Database, candidates: list[Candidate]) -> int:
    """Embed each persisted finding, when a provider is configured.

    Findings only, not every log row: hundreds of vectors per upload rather
    than millions. This is the level analysts search at -- "exfil to a Russian
    host", not one HTTP GET -- and it keeps embedding cost near zero.
    """
    embedder = get_embedder()
    if not embedder.available():
        return 0

    by_kind = {c.kind: c for c in candidates}
    stored = await db.anomaly_ids(job.analysis_id)
    if not stored:
        return 0

    texts, rows = [], []
    for row in stored:
        candidate = by_kind.get(row["kind"])
        content = finding_text(row["kind"], row["explanation"],
                               row.get("recommendation"),
                               candidate.evidence if candidate else None)
        texts.append(content)
        rows.append({"anomaly_id": row["id"], "kind": row["kind"],
                     "content": content, "bucket_key": None})

    try:
        vectors = await embedder.embed(texts)
    except Exception:  # noqa: BLE001
        log.exception("embedding failed; similarity search will miss this analysis",
                      extra={"event": "embeddings.failed",
                             "analysis_id": job.analysis_id})
        return 0

    if len(vectors) != len(rows):
        log.error("embedding count mismatch; skipping",
                  extra={"event": "embeddings.mismatch",
                         "want": len(rows), "got": len(vectors)})
        return 0

    for row, vector in zip(rows, vectors):
        row["embedding"] = str(vector)
    return await db.save_embeddings(job.analysis_id, job.org_id, job.user_id, rows)


def _to_rows(report, candidates: list[Candidate]) -> list[dict]:
    """Map the model's findings back onto real candidates.

    The model never sees a candidate's entry ids, only an opaque handle, so it
    is structurally incapable of citing a row that does not exist. Anything it
    returns that does not resolve is dropped rather than trusted.
    """
    by_index = {f"c{i}": c for i, c in enumerate(candidates)}
    rows: list[dict] = []

    for item in report.anomalies:
        candidate = by_index.get(item.candidate_id)
        if candidate is None:
            log.warning("unknown candidate id -- skipped", extra={
                "event": "analysis.unknown_candidate",
                "candidate_id": item.candidate_id})
            continue
        urgency = getattr(item, "urgency", None) or URGENCY_BY_KIND.get(
            candidate.kind, "this_week")
        rows.append({
            "kind": candidate.kind,
            "severity": item.severity,
            "urgency": urgency,
            "action_required": urgency in ("immediate", "today"),
            "action_label": (item.recommendation or "")[:120] or None,
            "confidence": item.confidence,
            "explanation": item.explanation,
            "recommendation": item.recommendation,
            "entry_ids": candidate.entry_ids,
        })
    return rows


def fallback_rows(candidates: list[Candidate]) -> list[dict]:
    """Findings without the narrative, for when the model is unavailable.

    Detection and every confidence score are unaffected by the model being
    absent; only the prose is.
    """
    return [{
        "kind": c.kind,
        "severity": SEVERITY_BY_KIND.get(c.kind, "medium"),
        "urgency": URGENCY_BY_KIND.get(c.kind, "this_week"),
        "action_required": URGENCY_BY_KIND.get(c.kind) in ("immediate", "today"),
        "action_label": None,
        "confidence": c.score,
        "explanation": c.title,
        "recommendation": None,
        "entry_ids": c.entry_ids,
    } for c in candidates]
