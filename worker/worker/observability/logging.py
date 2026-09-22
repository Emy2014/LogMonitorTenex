"""Structured JSON logging.

A log line is one occurrence, so it has to carry enough context to answer
"what happened, to whom, where, and how long did it take" without needing the
lines around it. Free-text loses that the moment you have more than one
concurrent request.

Every line carries:

  ts, level          when and how severe
  event              machine-readable type -- what alerts and dashboards key off
  logger             hierarchy: logmonitor.pipeline, logmonitor.ai, ...
  module/func/line   provenance: which code emitted this
  request_id         correlation across the whole request, background work included
  user_id            hashed -- see redaction.py

plus whatever the call site passes as ``extra``.

``event`` is the design's "log type": a stable name like ``analysis.completed``
that survives message rewording, which free-text greps do not.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import sys
from typing import Any

from worker.observability.context import get_request_id, get_user_id
from worker.observability.redaction import safe_extra

# LogRecord's own attributes; anything else a call site attached is ours.
_RESERVED = frozenset(vars(logging.LogRecord("", 0, "", 0, "", (), None)).keys()) | {
    "asctime", "message", "taskName", "event",
}


class JsonFormatter(logging.Formatter):
    """Renders a LogRecord as a single line of JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": dt.datetime.fromtimestamp(record.created, dt.timezone.utc)
                    .isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z"),
            "level": record.levelname,
            # Falls back to the logger name so every line has an event type,
            # including ones from libraries that know nothing about this.
            "event": getattr(record, "event", record.name),
            "logger": record.name,
            "msg": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }

        if (request_id := get_request_id()) is not None:
            payload["request_id"] = request_id
        if (user_id := get_user_id()) is not None:
            payload["user_id"] = user_id

        extras = {
            key: value for key, value in vars(record).items()
            if key not in _RESERVED and not key.startswith("_")
        }
        payload.update(safe_extra(extras))

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        # default=str so a stray UUID or datetime degrades to a string rather
        # than throwing inside the logging call.
        return json.dumps(payload, default=str)


class PlainFormatter(logging.Formatter):
    """Human-readable fallback for local work, where JSON is tiring to read."""

    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)-7s %(name)-18s %(message)s", "%H:%M:%S")


def setup_logging(level: str = "INFO", json_output: bool = True) -> None:
    """Install the root handler. Call once, at startup."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if json_output else PlainFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

    # uvicorn duplicates every request line, and the access log is emitted by
    # our own middleware with far more context attached.
    logging.getLogger("uvicorn.access").disabled = True
    for noisy in ("uvicorn", "uvicorn.error"):
        logging.getLogger(noisy).handlers.clear()
        logging.getLogger(noisy).propagate = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
