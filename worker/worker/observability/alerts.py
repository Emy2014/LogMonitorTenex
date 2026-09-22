"""Threshold evaluation.

Metrics on their own are a dashboard nobody is watching at 3am. An alert is a
metric crossing a threshold that someone has decided is actionable.

This emits a structured ``alert`` log event rather than paging anyone. On GCP
those events become log-based alerting policies in Cloud Monitoring; elsewhere
they are what a log pipeline would route to PagerDuty or Slack. Building real
delivery is out of scope -- see docs/OBSERVABILITY.md.

Two properties that matter more than the thresholds themselves:

  * **Alerts need a minimum sample count.** A p95 over three requests is noise.
  * **Alerts fire on transitions, not every evaluation.** Re-logging the same
    breach every 60 seconds trains people to ignore it.
"""

from __future__ import annotations

import logging

from worker.observability.metrics import REGISTRY

log = logging.getLogger("logmonitor.alerts")

# A percentile over a handful of samples is not a signal.
MIN_SAMPLES = 20

# Tracks which alerts are currently firing, so each transition is logged once.
_firing: set[str] = set()


def _evaluate(name: str, breached: bool, **context: object) -> bool:
    """Log only when an alert's state changes."""
    if breached and name not in _firing:
        _firing.add(name)
        log.warning("alert firing: %s", name, extra={"event": "alert.firing",
                                                     "alert": name, **context})
        return True
    if not breached and name in _firing:
        _firing.discard(name)
        log.info("alert resolved: %s", name, extra={"event": "alert.resolved",
                                                    "alert": name, **context})
    return False


def check_all(
    *,
    max_p95_latency_ms: float,
    max_error_rate: float,
    max_cpu_percent: float,
) -> list[str]:
    """Evaluate every threshold. Returns the names currently firing."""
    REGISTRY.sample_process()

    # --- API latency ------------------------------------------------------
    http_samples = sum(len(s) for s in REGISTRY.http_latency._samples.values())
    if http_samples >= MIN_SAMPLES:
        p95 = REGISTRY.http_latency.overall_percentile(0.95)
        _evaluate("http_latency_p95", p95 > max_p95_latency_ms,
                  p95_ms=round(p95, 1), threshold_ms=max_p95_latency_ms,
                  samples=http_samples)

    # --- failing requests -------------------------------------------------
    requests = REGISTRY.http_requests.total()
    if requests >= MIN_SAMPLES:
        error_rate = REGISTRY.http_errors.total() / requests
        _evaluate("http_error_rate", error_rate > max_error_rate,
                  error_rate=round(error_rate, 4), threshold=max_error_rate,
                  requests=int(requests))

    # --- CPU --------------------------------------------------------------
    cpu = REGISTRY.cpu_percent.get()
    if cpu > 0:
        _evaluate("cpu_high", cpu > max_cpu_percent,
                  cpu_percent=round(cpu, 1), threshold=max_cpu_percent)

    # --- the AI stage falling back ---------------------------------------
    # Not a latency or resource problem: it means findings are shipping without
    # explanations, which is a product regression a user would notice.
    llm_calls = REGISTRY.llm_calls.total()
    if llm_calls >= 5:
        fallback_rate = REGISTRY.derived()["llm_fallback_rate"] or 0.0
        _evaluate("llm_fallback_rate", fallback_rate > 0.20,
                  fallback_rate=fallback_rate, threshold=0.20,
                  calls=int(llm_calls))

    return sorted(_firing)


def reset() -> None:
    """Clear firing state. Tests only."""
    _firing.clear()
