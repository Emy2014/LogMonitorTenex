"""Observability tests.

The important one here is test_no_customer_data_in_logs -- for a product that
ingests customer proxy logs, leaking that content into application logs is the
failure with real consequences.
"""

import json
import logging

import pytest

from worker.observability import alerts
from worker.observability.context import bind_user, get_request_id, request_context
from worker.observability.logging import JsonFormatter
from worker.observability.metrics import MAX_SAMPLES, Counter, Gauge, Histogram, Registry, Timer
from worker.observability.redaction import FORBIDDEN_FIELDS, hash_identifier, safe_extra


def _record(msg="hello", level=logging.INFO, **extra):
    record = logging.LogRecord("logmonitor.test", level, "/app/x.py", 42, msg, (), None)
    record.module, record.funcName = "x", "do_thing"
    for key, value in extra.items():
        setattr(record, key, value)
    return record


# --- structured logging -----------------------------------------------------

def test_formatter_emits_valid_json_with_required_fields():
    payload = json.loads(JsonFormatter().format(_record()))

    for field in ("ts", "level", "event", "logger", "msg", "module", "func", "line"):
        assert field in payload, f"missing {field}"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "logmonitor.test"
    assert payload["line"] == 42
    assert payload["ts"].endswith("Z")


def test_event_defaults_to_logger_name_so_every_line_has_a_type():
    assert json.loads(JsonFormatter().format(_record()))["event"] == "logmonitor.test"
    assert json.loads(JsonFormatter().format(_record(event="upload.accepted")))["event"] \
        == "upload.accepted"


def test_extra_fields_are_included():
    payload = json.loads(JsonFormatter().format(_record(duration_ms=12.5, entries=2734)))
    assert payload["duration_ms"] == 12.5
    assert payload["entries"] == 2734


def test_request_and_user_ids_come_from_context():
    formatter = JsonFormatter()
    assert "request_id" not in json.loads(formatter.format(_record()))

    with request_context("abc123"):
        bind_user("u_deadbeef")
        payload = json.loads(formatter.format(_record()))
    assert payload["request_id"] == "abc123"
    assert payload["user_id"] == "u_deadbeef"


def test_request_context_restores_previous_value():
    with request_context("outer"):
        with request_context("inner"):
            assert get_request_id() == "inner"
        assert get_request_id() == "outer"


def test_exception_is_serialised():
    try:
        raise ValueError("boom")
    except ValueError:
        import sys
        record = _record(level=logging.ERROR)
        record.exc_info = sys.exc_info()
        payload = json.loads(JsonFormatter().format(record))
    assert "ValueError: boom" in payload["exception"]


def test_unserialisable_values_do_not_break_logging():
    import uuid
    payload = json.loads(JsonFormatter().format(_record(analysis_id=uuid.uuid4())))
    assert isinstance(payload["analysis_id"], str)


# --- the PII boundary -------------------------------------------------------

def test_hash_identifier_is_stable_and_never_the_input():
    assert hash_identifier("m.chen") == hash_identifier("m.chen")
    assert hash_identifier("m.chen") != hash_identifier("j.okafor")
    assert "m.chen" not in hash_identifier("m.chen")
    assert hash_identifier("m.chen", prefix="u_").startswith("u_")


def test_forbidden_fields_are_stripped():
    cleaned = safe_extra({
        "username": "m.chen",
        "client_ip": "10.12.7.88",
        "url": "https://files.dropzone-sync.ru/upload",
        "raw": "2024-03-14,m.chen,...",
        "entries": 2734,
        "duration_ms": 12.0,
    })
    assert cleaned == {"entries": 2734, "duration_ms": 12.0}


def test_formatter_drops_customer_content_even_if_a_call_site_passes_it():
    """The backstop: call sites should not pass these, but if one does, the
    formatter must not write it out."""
    payload = json.loads(JsonFormatter().format(
        _record(username="m.chen", client_ip="10.12.7.88", host="files.dropzone-sync.ru")
    ))
    serialised = json.dumps(payload)
    assert "m.chen" not in serialised
    assert "10.12.7.88" not in serialised
    assert "files.dropzone-sync.ru" not in serialised


def test_every_forbidden_field_is_actually_stripped():
    payload = safe_extra({name: "SENSITIVE" for name in FORBIDDEN_FIELDS})
    assert payload == {}


# --- metrics ----------------------------------------------------------------

def test_counter_totals_and_labels():
    c = Counter("test.counter")
    c.inc(route="/a", status="200")
    c.inc(route="/a", status="200")
    c.inc(route="/b", status="500")

    assert c.total() == 3
    snapshot = c.snapshot()
    assert snapshot["type"] == "counter"
    assert len(snapshot["series"]) == 2


def test_counter_label_order_does_not_create_separate_series():
    c = Counter("test.counter")
    c.inc(route="/a", status="200")
    c.inc(status="200", route="/a")
    assert len(c.snapshot()["series"]) == 1


def test_histogram_percentiles_on_a_known_distribution():
    h = Histogram("test.latency")
    for value in range(1, 101):        # 1..100
        h.observe(float(value))

    stats = h.snapshot()["series"][0]
    assert stats["count"] == 100
    assert stats["min"] == 1.0
    assert stats["max"] == 100.0
    assert stats["p50"] == 50.0
    assert stats["p95"] == 95.0
    assert stats["p99"] == 99.0


def test_histogram_is_bounded():
    """A percentile over an unbounded buffer is a memory leak."""
    h = Histogram("test.latency")
    for value in range(MAX_SAMPLES * 3):
        h.observe(float(value))
    assert h.snapshot()["series"][0]["count"] == MAX_SAMPLES


def test_histogram_percentile_across_all_label_series():
    h = Histogram("test.latency")
    for value in range(1, 51):
        h.observe(float(value), route="/a")
    for value in range(51, 101):
        h.observe(float(value), route="/b")
    assert h.overall_percentile(0.95) == 95.0


def test_empty_histogram_does_not_explode():
    h = Histogram("test.latency")
    assert h.overall_percentile(0.95) == 0.0
    assert h.snapshot()["series"] == []


def test_gauge():
    g = Gauge("test.gauge")
    g.set(10)
    g.inc()
    g.dec(3)
    assert g.get() == 8


def test_timer_records_elapsed_time():
    h = Histogram("test.latency")
    with Timer(h, stage="detect") as timer:
        sum(range(50_000))
    assert timer.ms > 0
    assert h.snapshot()["series"][0]["count"] == 1


def test_timer_records_even_when_the_block_raises():
    """A slow path that fails is still a slow path."""
    h = Histogram("test.latency")
    with pytest.raises(ValueError):
        with Timer(h):
            raise ValueError("boom")
    assert h.snapshot()["series"][0]["count"] == 1


def test_derived_rates_are_aggregates_not_single_events():
    """The metrics-vs-logs distinction: no single log line can state a rate."""
    r = Registry()
    for _ in range(9):
        r.http_requests.inc(route="/a", status="200")
    r.http_requests.inc(route="/a", status="500")
    r.http_errors.inc(route="/a", status="500")

    derived = r.derived()
    assert derived["http_success_rate"] == 0.9
    assert derived["http_error_rate"] == 0.1


def test_derived_rates_are_none_before_any_traffic():
    """Better than reporting 100% success on zero requests."""
    assert Registry().derived()["http_success_rate"] is None


def test_registry_snapshot_is_json_serialisable():
    r = Registry()
    r.http_requests.inc(route="/a", method="GET", status="200")
    r.http_latency.observe(12.0, route="/a")
    json.dumps(r.snapshot())          # must not raise


# --- alerting ---------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_alerts():
    alerts.reset()
    yield
    alerts.reset()


def _load(registry_attr, count, value):
    for _ in range(count):
        registry_attr.observe(value, route="/x")


def test_alert_fires_above_threshold():
    from worker.observability.metrics import REGISTRY
    REGISTRY.http_latency._samples.clear()
    _load(REGISTRY.http_latency, alerts.MIN_SAMPLES, 9000.0)

    firing = alerts.check_all(max_p95_latency_ms=5000, max_error_rate=1.0,
                              max_cpu_percent=100.0)
    assert "http_latency_p95" in firing


def test_alert_silent_below_threshold():
    from worker.observability.metrics import REGISTRY
    REGISTRY.http_latency._samples.clear()
    _load(REGISTRY.http_latency, alerts.MIN_SAMPLES, 50.0)

    firing = alerts.check_all(max_p95_latency_ms=5000, max_error_rate=1.0,
                              max_cpu_percent=100.0)
    assert "http_latency_p95" not in firing


def test_alert_needs_a_minimum_sample_count():
    """A p95 over three requests is noise, not a signal."""
    from worker.observability.metrics import REGISTRY
    REGISTRY.http_latency._samples.clear()
    _load(REGISTRY.http_latency, 3, 60_000.0)

    firing = alerts.check_all(max_p95_latency_ms=5000, max_error_rate=1.0,
                              max_cpu_percent=100.0)
    assert "http_latency_p95" not in firing


def test_alert_fires_once_not_on_every_evaluation():
    """Re-logging the same breach every 60s trains people to ignore alerts."""
    from worker.observability.metrics import REGISTRY
    REGISTRY.http_latency._samples.clear()
    _load(REGISTRY.http_latency, alerts.MIN_SAMPLES, 9000.0)

    kwargs = dict(max_p95_latency_ms=5000, max_error_rate=1.0, max_cpu_percent=100.0)
    first = alerts._evaluate("demo_alert", True)
    second = alerts._evaluate("demo_alert", True)
    assert first is True and second is False

    alerts._evaluate("demo_alert", False)          # resolves
    assert alerts._evaluate("demo_alert", True) is True   # can fire again


def test_timer_ms_is_readable_inside_the_block():
    """Regression: a log line emitted inside the `with` reported 0.0, because
    the elapsed time was only assigned on exit."""
    h = Histogram("test.latency")
    with Timer(h) as timer:
        sum(range(50_000))
        inside = timer.ms
    assert inside > 0, "elapsed time must be readable before the block closes"
    assert timer.ms >= inside, "final value must be at least the in-block reading"


# --- the leak test ----------------------------------------------------------

def test_no_customer_data_in_logs():
    """Real sample data, pushed through the formatter the way a careless call
    site would, must not come out the other side.

    This is the failure with actual consequences: LogMonitor ingests customer
    proxy logs, so leaking their content into application logs turns the
    observability pipeline into a second, less-guarded copy of that data.
    """
    from pathlib import Path

    from tests.fixtures import load_sample

    sample = Path(__file__).resolve().parent.parent.parent / "samples" / "zscaler_suspicious.log"
    if not sample.exists():
        pytest.skip("samples not generated")

    entries = load_sample(sample)[:200]
    formatter = JsonFormatter()

    # Values that genuinely appear in the file and must never be logged.
    sensitive: set[str] = set()
    for e in entries:
        sensitive.update(
            str(v) for v in (e.username, e.client_ip, e.host, e.url, e.user_agent, e.raw)
            if v
        )
    assert sensitive, "sample produced no sensitive values -- test would be vacuous"

    # Emit a log line per entry, passing customer fields the way a careless
    # future edit might.
    output = []
    for e in entries:
        output.append(formatter.format(_record(
            "processing entry",
            event="analysis.entry",
            username=e.username,
            client_ip=e.client_ip,
            host=e.host,
            url=e.url,
            user_agent=e.user_agent,
            raw=e.raw,
            line_no=e.line_no,          # safe: an index, not content
        )))
    blob = "\n".join(output)

    leaked = sorted(v for v in sensitive if v and v in blob)
    assert not leaked, f"customer data reached the log output: {leaked[:5]}"

    # And confirm the safe field did survive -- otherwise this would pass by
    # stripping everything.
    assert '"line_no"' in blob
