"""A small in-process metrics registry.

The distinction this module exists to make concrete: **a log is one occurrence,
a metric is an aggregate over many.** "Analysis 68e0 took 2.8s" is a log line.
"p95 analysis latency is 3.4s over the last 512 analyses" is a metric.

Three instrument types, which is all this application needs:

  Counter    monotonic total, optionally broken down by labels
  Histogram  distribution of observed values -> p50/p95/p99
  Gauge      a point-in-time reading (CPU, memory, in-flight work)

Deliberately hand-rolled rather than `prometheus-client`:

  * true percentiles from the retained samples, not approximations from
    pre-declared histogram buckets
  * no scrape server needed to see anything -- GET /api/metrics returns JSON
  * about 150 readable lines, which matters when you have to explain it

The production answer is Prometheus or OpenTelemetry shipping to a central
store. See docs/OBSERVABILITY.md.

**Scope: per-process and in-memory.** With several Cloud Run instances each
reports its own view, and everything resets when an instance goes away. That is
a real limitation, stated rather than hidden.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Iterator

# Samples retained per histogram series. 512 is enough for a stable p95 while
# staying bounded -- a percentile over an unbounded buffer is a memory leak
# with extra steps.
MAX_SAMPLES = 512


def _label_key(labels: dict[str, str] | None) -> tuple[tuple[str, str], ...]:
    """Labels as a hashable, order-independent key."""
    return tuple(sorted((labels or {}).items()))


def _percentile(sorted_values: list[float], fraction: float) -> float:
    """Nearest-rank percentile.

    Chosen over interpolation because it always returns a value that was
    actually observed, which is easier to reason about when reading a metric.
    """
    if not sorted_values:
        return 0.0
    rank = max(1, min(len(sorted_values), round(fraction * len(sorted_values))))
    return sorted_values[rank - 1]


@dataclass
class Counter:
    """Monotonically increasing total."""

    name: str
    description: str = ""
    _values: dict[tuple, float] = field(default_factory=lambda: defaultdict(float))

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        self._values[_label_key(labels)] += amount

    def total(self) -> float:
        return sum(self._values.values())

    def snapshot(self) -> dict:
        return {
            "type": "counter",
            "description": self.description,
            "total": round(self.total(), 3),
            "series": [
                {"labels": dict(key), "value": round(value, 3)}
                for key, value in sorted(self._values.items())
            ],
        }


@dataclass
class Histogram:
    """Distribution of observed values, kept as a bounded ring buffer."""

    name: str
    description: str = ""
    unit: str = "ms"
    _samples: dict[tuple, deque] = field(default_factory=dict)

    def observe(self, value: float, **labels: str) -> None:
        key = _label_key(labels)
        if key not in self._samples:
            self._samples[key] = deque(maxlen=MAX_SAMPLES)
        self._samples[key].append(value)

    def _stats(self, values: deque) -> dict:
        ordered = sorted(values)
        return {
            "count": len(ordered),
            "min": round(ordered[0], 3),
            "p50": round(_percentile(ordered, 0.50), 3),
            "p95": round(_percentile(ordered, 0.95), 3),
            "p99": round(_percentile(ordered, 0.99), 3),
            "max": round(ordered[-1], 3),
            "mean": round(sum(ordered) / len(ordered), 3),
        }

    def percentile(self, fraction: float, **labels: str) -> float:
        values = self._samples.get(_label_key(labels))
        return _percentile(sorted(values), fraction) if values else 0.0

    def overall_percentile(self, fraction: float) -> float:
        """Percentile across every label series -- what alerts key off."""
        combined = [v for series in self._samples.values() for v in series]
        return _percentile(sorted(combined), fraction) if combined else 0.0

    def snapshot(self) -> dict:
        return {
            "type": "histogram",
            "description": self.description,
            "unit": self.unit,
            "series": [
                {"labels": dict(key), **self._stats(values)}
                for key, values in sorted(self._samples.items())
                if values
            ],
        }


@dataclass
class Gauge:
    """A single point-in-time value."""

    name: str
    description: str = ""
    unit: str = ""
    _value: float = 0.0

    def set(self, value: float) -> None:
        self._value = value

    def inc(self, amount: float = 1.0) -> None:
        self._value += amount

    def dec(self, amount: float = 1.0) -> None:
        self._value -= amount

    def get(self) -> float:
        return self._value

    def snapshot(self) -> dict:
        return {
            "type": "gauge",
            "description": self.description,
            "unit": self.unit,
            "value": round(self._value, 3),
        }


class Registry:
    """Holds every instrument and renders the /api/metrics payload."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started_at = time.time()

        # --- traffic -------------------------------------------------------
        self.http_requests = Counter("http.requests", "HTTP requests by route and status")
        self.http_errors = Counter("http.errors", "HTTP responses with status >= 400")
        self.http_latency = Histogram("http.latency_ms", "Request handling time")

        # --- domain work ---------------------------------------------------
        self.uploads = Counter("uploads.total", "Log files accepted")
        self.upload_bytes = Counter("uploads.bytes", "Bytes of log ingested")
        self.upload_parse_ms = Histogram("upload.parse_ms", "Time to parse an uploaded file")
        self.analyses = Counter("analyses.total", "Analyses by outcome")
        self.analysis_total_ms = Histogram("analysis.total_ms", "End-to-end analysis time")
        self.stage_ms = Histogram("pipeline.stage_ms", "Per-stage analysis time")
        self.anomalies = Counter("anomalies.detected", "Anomalies persisted, by detector")
        self.analyses_in_flight = Gauge("analyses.in_flight", "Analyses currently running")

        # --- the LLM stage -------------------------------------------------
        self.llm_calls = Counter("llm.calls", "Claude calls by outcome")
        self.llm_latency_ms = Histogram("llm.latency_ms", "Claude call duration")
        self.llm_tokens = Counter("llm.tokens", "Tokens by direction")

        # --- process -------------------------------------------------------
        self.cpu_percent = Gauge("process.cpu_percent", "Process CPU utilisation", "%")
        self.memory_mb = Gauge("process.memory_mb", "Process resident memory", "MB")

    def _instruments(self) -> Iterator[tuple[str, object]]:
        for attr in vars(self).values():
            if isinstance(attr, (Counter, Histogram, Gauge)):
                yield attr.name, attr

    def sample_process(self) -> None:
        """Refresh the process gauges. Cheap; called on each scrape."""
        try:
            import psutil

            process = psutil.Process()
            self.cpu_percent.set(process.cpu_percent(interval=None))
            self.memory_mb.set(process.memory_info().rss / (1024 * 1024))
        except Exception:  # noqa: BLE001 - metrics must never break a request
            pass

    def derived(self) -> dict:
        """Ratios that only make sense as aggregates.

        This is the clearest illustration of metrics-vs-logs: no single log
        line can tell you a success rate.
        """
        requests = self.http_requests.total()
        errors = self.http_errors.total()
        llm_total = self.llm_calls.total()
        llm_ok = sum(
            value for key, value in self.llm_calls._values.items()
            if dict(key).get("outcome") == "ok"
        )
        analyses_total = self.analyses.total()
        analyses_ok = sum(
            value for key, value in self.analyses._values.items()
            if dict(key).get("outcome") == "done"
        )
        ratio = lambda num, den: round(num / den, 4) if den else None  # noqa: E731

        return {
            "http_success_rate": ratio(requests - errors, requests),
            "http_error_rate": ratio(errors, requests),
            "analysis_success_rate": ratio(analyses_ok, analyses_total),
            "llm_success_rate": ratio(llm_ok, llm_total),
            "llm_fallback_rate": ratio(llm_total - llm_ok, llm_total),
        }

    def snapshot(self) -> dict:
        with self._lock:
            self.sample_process()
            return {
                "uptime_seconds": round(time.time() - self.started_at, 1),
                "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "note": (
                    "Per-process and in-memory. With multiple instances each "
                    "reports its own view; values reset when an instance stops."
                ),
                "derived": self.derived(),
                "metrics": {name: inst.snapshot() for name, inst in self._instruments()},
            }


REGISTRY = Registry()


class Timer:
    """Context manager that records elapsed milliseconds into a Histogram.

        with Timer(REGISTRY.stage_ms, stage="detect"):
            candidates = detect_all(entries)

    Also exposes ``.ms`` afterwards, for log lines that want the duration.
    """

    def __init__(self, histogram: Histogram, **labels: str) -> None:
        self._histogram = histogram
        self._labels = labels
        self._start = time.perf_counter()
        self._ms: float | None = None

    def __enter__(self) -> "Timer":
        self._start = time.perf_counter()
        self._ms = None
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._ms = (time.perf_counter() - self._start) * 1000.0
        # Record even on failure: a slow path that raises is still a slow path.
        self._histogram.observe(self._ms, **self._labels)

    @property
    def ms(self) -> float:
        """Elapsed milliseconds.

        Readable *inside* the block as well as after it -- a log line emitted
        before the block closes (reporting how long the work took so far) would
        otherwise always read 0.
        """
        if self._ms is not None:
            return self._ms
        return (time.perf_counter() - self._start) * 1000.0
