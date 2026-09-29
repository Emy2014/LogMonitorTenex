"""Read a sample log into LogEntry objects.

Test-only. Production parsing lives in the Go gateway; this is a fixture
reader for the labelled sample files, deliberately minimal and deliberately
not a second parser implementation — it handles exactly the shape
scripts/generate_samples.py writes.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

from worker.entry import LogEntry

# Column header -> LogEntry field, for the columns detection actually reads.
COLUMNS = {
    "datetime": "ts",
    "login": "username",
    "ClientIP": "client_ip",
    "url": "url",
    "host": "host",
    "urlcategory": "category",
    "action": "action",
    "requestsize": "req_bytes",
    "responsesize": "resp_bytes",
    "useragent": "user_agent",
    "threatname": "threat_name",
    "respcode": "resp_code",
    "requestmethod": "method",
}
INT_FIELDS = {"req_bytes", "resp_bytes", "resp_code"}
ABSENT = {"", "-", "None", "NA", "N/A"}


def load_sample(path: Path) -> list[LogEntry]:
    entries: list[LogEntry] = []
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        for i, row in enumerate(csv.DictReader(fh), start=1):
            fields: dict = {}
            for column, field in COLUMNS.items():
                raw = (row.get(column) or "").strip()
                if raw in ABSENT:
                    continue
                if field == "ts":
                    fields[field] = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(
                        tzinfo=timezone.utc)
                elif field in INT_FIELDS:
                    try:
                        fields[field] = int(float(raw))
                    except ValueError:
                        pass
                else:
                    fields[field] = raw
            entries.append(LogEntry(id=i, line_no=i + 1, **fields))
    return entries
