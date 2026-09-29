"""Stage 2 of threat detection: the LLM pass.

What the model does here is narrow and deliberate:

  * turn ranked statistical candidates into SOC-readable findings
  * write the plain-English "why was this flagged" explanation
  * assign severity by weighing candidates against each other in context
  * assemble a chronological timeline an analyst can skim

What it explicitly does NOT do:

  * see raw logs in bulk (only aggregates -- see evidence.py)
  * compute the confidence scores (those come from detection/stats.py)
  * choose which rows are anomalous (it references candidate ids; the server
    maps those back to rows, so a hallucinated row id is impossible)

If no API key is configured the app degrades to a deterministic report built
straight from the statistical candidates. The findings and confidence scores
are unchanged -- only the narrative is lost -- so the product still works.
"""

from __future__ import annotations

import logging
from typing import Literal, Sequence

import anthropic
from pydantic import BaseModel, Field

from worker.config import get_settings
from worker.detection import Candidate
from worker.observability.metrics import REGISTRY, Timer

log = logging.getLogger("logmonitor.ai")

Severity = Literal["critical", "high", "medium", "low", "info"]

SYSTEM_PROMPT = """You are a SOC analyst reviewing pre-aggregated proxy log evidence.

You are given an overview of a ZScaler web proxy log and a ranked list of
candidate anomalies. Each candidate was produced by a statistical detector and
carries its own `statistical_confidence` plus the evidence behind it.

Your job:
1. Write a short `summary` an analyst reads first -- what happened, what matters.
2. Build a `timeline` of the notable events in chronological order.
3. For each candidate worth reporting, produce an `anomalies` entry that explains
   in plain English why it was flagged and what to do about it.
4. Assign `overall_risk` for the file.

Rules:
- Reference candidates ONLY by the `id` field given to you (e.g. "c0").
- Report only what the evidence supports. Never invent IPs, users, domains,
  timestamps, or counts that do not appear in the input.
- Corroborate: if several candidates describe one incident, say so in the
  explanation rather than repeating yourself.
- If the evidence is weak or the activity looks benign, say that plainly.
  Do not manufacture findings to fill the report.
- Keep each explanation to two or three sentences."""


class AnomalyOut(BaseModel):
    candidate_id: str = Field(description="The candidate `id`, e.g. 'c0'")
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    recommendation: str


class TimelineEvent(BaseModel):
    time_range: str
    headline: str
    detail: str
    severity: Severity


class Report(BaseModel):
    summary: str
    overall_risk: Literal["critical", "high", "medium", "low"]
    timeline: list[TimelineEvent]
    anomalies: list[AnomalyOut]


def _severity_for(score: float) -> Severity:
    if score >= 0.9:
        return "critical"
    if score >= 0.7:
        return "high"
    if score >= 0.5:
        return "medium"
    return "low"


def fallback_report(candidates: Sequence[Candidate]) -> Report:
    """Deterministic report used when no API key is configured, or when the
    model call fails. Statistical findings and scores are preserved."""
    if not candidates:
        return Report(
            summary="No anomalies were detected in this log.",
            overall_risk="low",
            timeline=[],
            anomalies=[],
        )

    top = max(c.score for c in candidates)
    return Report(
        summary=(
            f"{len(candidates)} anomal{'y' if len(candidates) == 1 else 'ies'} "
            f"detected by statistical analysis. AI narrative is unavailable "
            f"(no ANTHROPIC_API_KEY configured), so explanations below are "
            f"generated from detector evidence."
        ),
        overall_risk=_severity_for(top) if _severity_for(top) != "info" else "low",
        timeline=[],
        anomalies=[
            AnomalyOut(
                candidate_id=f"c{n}",
                title=c.title,
                severity=_severity_for(c.score),
                confidence=round(c.score, 3),
                explanation=f"Detector '{c.kind}' flagged this pattern. Evidence: {c.evidence}",
                recommendation="Review the highlighted entries.",
            )
            for n, c in enumerate(candidates)
        ],
    )


async def analyze_candidates(
    evidence_packet: str, candidates: Sequence[Candidate]
) -> tuple[Report, dict]:
    """Run the LLM pass. Returns the report plus call metadata.

    Never raises: any failure degrades to `fallback_report` so an upload always
    produces a result.
    """
    settings = get_settings()
    meta: dict = {"model": None, "input_tokens": None, "output_tokens": None, "error": None}

    if not settings.anthropic_api_key:
        log.warning("no API key -- deterministic fallback report",
                    extra={"event": "llm.skipped", "reason": "no_api_key"})
        REGISTRY.llm_calls.inc(outcome="no_api_key")
        meta["error"] = "no_api_key"
        return fallback_report(candidates), meta

    client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)

    try:
        with Timer(REGISTRY.llm_latency_ms) as timer:
            response = await client.messages.parse(
                model=settings.anthropic_model,
                max_tokens=16000,
                # Severity is a judgement call, so let the model reason before
                # committing. Note: budget_tokens is rejected on Opus 5.
                thinking={"type": "adaptive"},
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": evidence_packet}],
                output_format=Report,
            )
    except Exception as exc:                      # noqa: BLE001 - never fail an upload
        REGISTRY.llm_calls.inc(outcome="error")
        log.exception("Claude call failed",
                      extra={"event": "llm.error", "error_type": type(exc).__name__})
        meta["error"] = f"{type(exc).__name__}: {exc}"
        return fallback_report(candidates), meta

    meta["model"] = settings.anthropic_model
    if response.usage:
        meta["input_tokens"] = response.usage.input_tokens
        meta["output_tokens"] = response.usage.output_tokens
        REGISTRY.llm_tokens.inc(response.usage.input_tokens, direction="input")
        REGISTRY.llm_tokens.inc(response.usage.output_tokens, direction="output")

    # A safety classifier can decline the request. This returns HTTP 200 rather
    # than raising, so without this check it looks like an empty response with
    # no cause -- a real risk for an app whose whole job is analysing attacks.
    if response.stop_reason == "refusal":
        REGISTRY.llm_calls.inc(outcome="refusal")
        log.warning("Claude declined the request",
                    extra={"event": "llm.refusal", "duration_ms": round(timer.ms, 2)})
        meta["error"] = "refusal"
        return fallback_report(candidates), meta

    report = response.parsed_output
    if report is None:
        REGISTRY.llm_calls.inc(outcome="parse_failed")
        log.warning("structured output failed validation",
                    extra={"event": "llm.parse_failed"})
        meta["error"] = "parse_failed"
        return fallback_report(candidates), meta

    # Drop any candidate_id the model did not receive. Belt-and-braces: the id
    # scheme already prevents fabricated row numbers.
    valid = {f"c{n}" for n in range(len(candidates))}
    dropped = [a for a in report.anomalies if a.candidate_id not in valid]
    if dropped:
        log.warning("dropping anomalies with unknown candidate ids",
                    extra={"event": "llm.unknown_candidates", "dropped": len(dropped)})
        report.anomalies = [a for a in report.anomalies if a.candidate_id in valid]

    REGISTRY.llm_calls.inc(outcome="ok")
    log.info("claude call complete",
             extra={"event": "llm.completed",
                    "duration_ms": round(timer.ms, 2),
                    "input_tokens": meta["input_tokens"],
                    "output_tokens": meta["output_tokens"],
                    "anomalies": len(report.anomalies),
                    "timeline_events": len(report.timeline)})
    return report, meta
