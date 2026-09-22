#!/usr/bin/env python3
"""Generate example ZScaler NSS web proxy logs for testing and the demo.

Produces five files in samples/. The two labelled ones first:

  zscaler_benign.log      -- ordinary corporate browsing, nothing to find
  zscaler_suspicious.log  -- the same baseline with six attacks seeded in

then three smaller ones for hand testing:

  zscaler_quick.log        -- ~200 rows, two attacks; analyses in seconds
  zscaler_beacon_only.log  -- one attack class, so exactly one finding
  zscaler_nss_tsv.log      -- tab-delimited, different field names and order,
                              ISO timestamps, malformed lines; one attack

The seeded attacks are deliberate and known-correct, so the detectors can be
tested against a ground truth and the demo recording always has something to
show. Seeded with a constant, so output is reproducible. The small files are
generated last so the labelled pair stays byte-identical across regenerations
(scripts/measure_accuracy.py gates CI on them).

Usage:  python3 scripts/generate_samples.py
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(1337)

# A realistic Zscaler NSS Web Log field set. NSS feeds are operator-configured,
# so tenants emit different subsets in different orders -- these are the real
# field names as they appear in Zscaler's Web Log documentation.
HEADER = [
    "datetime", "recordid", "login", "department", "location",
    "ClientIP", "clientpublicIP", "serverip",
    "requestmethod", "requestsize", "responsesize", "transactionsize",
    "url", "refererURL", "host",
    "urlcategory", "urlsupercategory", "urlclass",
    "action", "reason", "respcode",
    "useragent", "threatname", "threatcategory", "threatclass",
    "appname", "appclass", "pagerisk",
    "filetype", "dlpengine", "dlpdictionaries", "contenttype", "proto",
    "devicehostname", "deviceowner",
    # Added so the dashboard's latency percentiles and cache hit rate are
    # measured from the log rather than left blank. Real NSS feeds carry both;
    # the first version of these samples did not, so those panels were empty
    # no matter how much data was ingested.
    "totaltime", "cachehit",
]

USERS = [
    ("a.rivera", "Engineering", "10.12.4.31"),
    ("m.chen", "Finance", "10.12.7.88"),
    ("s.patel", "Marketing", "10.12.4.102"),
    ("j.okafor", "Engineering", "10.12.4.55"),
    ("l.novak", "HR", "10.12.9.14"),
    ("d.kim", "Sales", "10.12.7.23"),
]

BENIGN_SITES = [
    ("github.com", "Professional Services", "Information Technology"),
    ("docs.google.com", "Web Based Productivity", "Business"),
    ("slack.com", "Instant Messaging", "Business"),
    ("stackoverflow.com", "Professional Services", "Information Technology"),
    ("outlook.office365.com", "Webmail", "Business"),
    ("salesforce.com", "Business Applications", "Business"),
    ("news.ycombinator.com", "News and Media", "News"),
    ("linkedin.com", "Social Networking", "Social"),
    ("aws.amazon.com", "Professional Services", "Information Technology"),
]

UA_CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
UA_CURL = "curl/8.4.0"
UA_PYTHON = "python-requests/2.31.0"

DAY = datetime(2024, 3, 14, 0, 0, 0)


_RECORD_ID = [0]


# Response-time model.
#
# Proxy latency is heavy-tailed, not normal: most requests are fast, a long
# tail is slow, and the occasional request is very slow. A lognormal draw
# reproduces that shape, which matters because the detectors score on
# median + MAD and a normal distribution would make p95 meaningless.
def _latency_ms(status: int, cached: bool, base_mu: float = 3.9) -> int:
    if cached:
        return max(1, int(random.lognormvariate(1.9, 0.5)))      # ~7ms typical
    value = int(random.lognormvariate(base_mu, 0.7))             # ~50ms typical
    if status >= 500:
        value += random.randint(2000, 28000)                     # upstream stalls
    elif status == 429:
        value += random.randint(50, 400)
    elif status in (401, 403, 407):
        value = max(5, int(value * 0.4))                         # rejected early
    return max(1, min(value, 120_000))


def _cache_status(method: str, status: int) -> str:
    # Only idempotent successful reads are cacheable.
    if method != "GET" or status not in (200, 304):
        return "TCP_MISS"
    return "TCP_HIT" if random.random() < 0.34 else "TCP_MISS"


def row(ts, user, dept, ip, host, path, category, supercat, action,
        req, resp, status=200, ua=UA_CHROME, threat="", risk=0, reason="Allowed",
        app="General Browsing", appclass="General Browsing",
        ctype="text/html", filetype="None", latency=None):
    _RECORD_ID[0] += 1
    method = "POST" if req > 4000 else "GET"
    threat_cat = "Malware" if threat else "None"
    threat_class = "Malware & Virus" if threat else "None"
    url = f"https://{host}{path}"
    device = f"{user.split('.')[-1].upper()}-LT-{(_RECORD_ID[0] % 40) + 1:02d}"
    cache = _cache_status(method, status)

    return [
        ts.strftime("%Y-%m-%d %H:%M:%S"),
        str(_RECORD_ID[0]),
        user, dept, "HQ-SanFrancisco",
        ip,
        f"198.51.100.{(_RECORD_ID[0] % 200) + 1}",
        f"93.184.{random.randint(1, 250)}.{random.randint(1, 250)}",
        method, str(req), str(resp), str(req + resp),
        url, "", host,
        category, supercat, "Business Use" if risk < 50 else "Suspicious Destination",
        action, reason, str(status),
        ua, threat, threat_cat, threat_class,
        app, appclass, str(risk),
        filetype, "None", "None", ctype, "HTTPS",
        device, user,
        str(_latency_ms(status, cache == "TCP_HIT") if latency is None else latency),
        cache,
    ]


def benign_traffic(rows: list, count: int = 1800) -> None:
    """Ordinary browsing spread across the working day."""
    for _ in range(count):
        user, dept, ip = random.choice(USERS)
        host, cat, supercat = random.choice(BENIGN_SITES)
        # Working hours, normally distributed around 1pm.
        hour = min(18, max(8, int(random.gauss(13, 2.5))))
        ts = DAY + timedelta(
            hours=hour, minutes=random.randint(0, 59), seconds=random.randint(0, 59)
        )
        status, reason = pick_status()
        rows.append(row(
            ts, user, dept, ip, host, random.choice(["/", "/search", "/api/v2/items", "/assets/app.js"]),
            cat, supercat, "Allowed",
            req=random.randint(300, 2500),
            # A 304 or a 204 carries no body; pretending otherwise would make
            # the bytes panel disagree with the status panel.
            resp=0 if status in (204, 304) else random.randint(800, 90000),
            status=status, reason=reason,
        ))


# --- Seeded attacks ---------------------------------------------------------

def attack_data_exfil(rows: list) -> None:
    """m.chen uploads ~240MB to an unknown file-sharing host in 12 large POSTs."""
    ts = DAY + timedelta(hours=19, minutes=12)
    for i in range(12):
        rows.append(row(
            ts + timedelta(minutes=i * 3, seconds=random.randint(-70, 70)), "m.chen", "Finance", "10.12.7.88",
            "files.dropzone-sync.ru", f"/upload/chunk-{i:03d}",
            "File Host", "Uncategorized", "Allowed",
            req=random.randint(18_000_000, 24_000_000), resp=random.randint(200, 900),
            ua=UA_PYTHON, risk=65,
        ))


def attack_beaconing(rows: list, hits: int = 300) -> None:
    """j.okafor's host checks in to one domain every 60s for 5 hours -- C2 pattern."""
    start = DAY + timedelta(hours=9)
    for i in range(hits):
        # Near-constant interval with only a second of jitter.
        ts = start + timedelta(seconds=i * 60 + random.randint(-1, 1))
        rows.append(row(
            ts, "j.okafor", "Engineering", "10.12.4.55",
            "cdn-telemetry-sync.net", "/v1/ping",
            "Uncategorized", "Uncategorized", "Allowed",
            req=412, resp=138, ua=UA_CURL, risk=40,
        ))


def attack_volume_spike(rows: list) -> None:
    """One host fires 600 requests in 3 minutes -- internal scanning / enumeration."""
    start = DAY + timedelta(hours=14, minutes=22)
    for i in range(600):
        ts = start + timedelta(seconds=i * 0.3)
        rows.append(row(
            ts, "s.patel", "Marketing", "10.12.4.102",
            "internal-api.partner-portal.io", f"/v1/records/{10000 + i}",
            "Business Applications", "Business", "Allowed",
            req=280, resp=1400, ua=UA_PYTHON, risk=30,
        ))


def attack_blocked_threats(rows: list) -> None:
    """Malware downloads blocked by the proxy -- high-confidence, deterministic."""
    threats = [
        ("malware-delivery.tk", "/payload/invoice.doc.exe", "Win32.Trojan.Emotet"),
        ("malware-delivery.tk", "/payload/update.bin", "Win32.Trojan.Emotet"),
        ("phish-login-verify.xyz", "/o365/signin", "Phish.Credential.O365"),
    ]
    ts = DAY + timedelta(hours=11, minutes=5)
    for i, (host, path, threat) in enumerate(threats):
        rows.append(row(
            ts + timedelta(minutes=i * 7), "l.novak", "HR", "10.12.9.14",
            host, path, "Malware", "Security Risk", "Blocked",
            req=340, resp=0, status=403, threat=threat, risk=95,
            reason="Blocked - Malicious Content",
        ))


def attack_off_hours(rows: list) -> None:
    """d.kim browses admin tooling at 03:00 -- well outside this file's norm."""
    start = DAY + timedelta(hours=3, minutes=8)
    for i in range(18):
        rows.append(row(
            start + timedelta(minutes=i * 2, seconds=random.randint(-50, 50)), "d.kim", "Sales", "10.12.7.23",
            "admin.crm-internal.com", f"/export/customers?page={i}",
            "Business Applications", "Business", "Allowed",
            req=390, resp=random.randint(40_000, 120_000), risk=25,
        ))


# Response-code texture on ordinary traffic. Without this every sample is 200
# and the success-rate panel is a flat line at 100%.
ERROR_MIX = [
    (200, "Allowed", 0.905),
    (204, "Allowed", 0.015),
    (304, "Allowed", 0.030),
    (301, "Allowed", 0.010),
    (404, "Not Found", 0.018),
    (403, "Blocked - Policy", 0.008),
    (401, "Authentication Required", 0.006),
    (429, "Rate Limited by Origin", 0.003),
    (500, "Origin Error", 0.003),
    (502, "Bad Gateway", 0.001),
    (503, "Origin Unavailable", 0.001),
]


def pick_status() -> tuple:
    r, cumulative = random.random(), 0.0
    for status, reason, weight in ERROR_MIX:
        cumulative += weight
        if r <= cumulative:
            return status, reason
    return 200, "Allowed"


def incident_auth_failures(rows: list) -> None:
    """A burst of 401s against one host: a credential problem, not an attack.

    Included so the error breakdown has something an analyst would actually
    triage differently from a threat -- the value of splitting 4xx by code is
    that 401 and 404 mean different things.
    """
    base = DAY.replace(hour=10, minute=12)
    for i in range(140):
        rows.append(row(
            base + timedelta(seconds=i * 3), "s.patel", "Engineering", "10.12.4.102",
            "sso.partner-portal.io", f"/oauth/token?attempt={i}",
            "Business Applications", "Business", "Allowed",
            420, 180, status=401, reason="Authentication Required"))


def incident_origin_errors(rows: list) -> None:
    """A sustained 5xx episode with very slow responses.

    Latency and status class move together here, which is what makes a p95
    chart worth having next to a success-rate chart.
    """
    base = DAY.replace(hour=15, minute=30)
    for i in range(90):
        status = 502 if i % 3 == 0 else 503
        rows.append(row(
            base + timedelta(seconds=i * 20), random.choice(USERS)[0],
            "Finance", "10.12.7.88", "reports.vendor-metrics.com",
            f"/api/v1/report?id={i}", "Business Applications", "Business",
            "Allowed", 900, 0, status=status, reason="Origin Unavailable",
            latency=random.randint(8000, 30000)))


def attack_rare_destination(rows: list) -> None:
    """A single visit to a domain nobody else in the file touches."""
    rows.append(row(
        DAY + timedelta(hours=16, minutes=44), "a.rivera", "Engineering", "10.12.4.31",
        "paste-anon-share.onion.ly", "/raw/x7f2a9",
        "Uncategorized", "Uncategorized", "Allowed",
        req=520, resp=8400, ua=UA_CURL, risk=55,
    ))


def write(path: Path, rows: list) -> None:
    # Sort by timestamp so the file reads like a real chronological feed.
    rows.sort(key=lambda r: r[0])
    lines = [",".join(HEADER)]
    lines += [",".join(f'"{c}"' if "," in c else c for c in r) for r in rows]
    path.write_text("\n".join(lines) + "\n")
    print(f"{path}: {len(rows)} rows")


# --- A differently-configured NSS feed --------------------------------------
#
# NSS feeds are operator-configured: a second tenant emits a different subset
# of fields, under different names, in a different order, with its own
# delimiter and timestamp format. The parser keys off the header row and a
# table of aliases precisely so this file ingests the same as the others. Each
# entry is (this feed's header name, the HEADER column it is derived from).
# `dept` is deliberately not a name the parser knows; unknown columns are
# ignored, not fatal.
TSV_COLUMNS = [
    ("cip", "ClientIP"),
    ("user", "login"),
    ("dept", "department"),
    ("httpmethod", "requestmethod"),
    ("requesturl", "url"),
    ("hostname", "host"),
    ("statuscode", "respcode"),
    ("eventtime", "datetime"),
    ("sentbytes", "requestsize"),
    ("receivedbytes", "responsesize"),
    ("category", "urlcategory"),
    ("policyaction", "action"),
    ("blockreason", "reason"),
    ("timetaken", "totaltime"),
    ("tcpstatus", "cachehit"),
    ("useragentheader", "useragent"),
    ("malwarename", "threatname"),
]

# Lines a real feed produces and a parser must survive: collector restart
# markers, a record cut short mid-write, and a timestamp the collector
# mangled. The parser keeps every one of them as a row (raw text, nothing
# parsed) rather than dropping it or failing the upload -- those are exactly
# the lines an analyst wants to see. Positions are row indices to insert at.
TSV_MALFORMED = [
    (40, "### NSS feed reconnected: 3 records dropped upstream ###"),
    (120, None),                              # truncated: first four fields only
    (200, "eventtime=not-a-timestamp"),       # bad timestamp in the ts column
    (260, "### NSS feed reconnected: 0 records dropped upstream ###"),
]


def write_tsv(path: Path, rows: list) -> None:
    rows.sort(key=lambda r: r[0])
    index = {name: i for i, name in enumerate(HEADER)}

    def cell(r: list, source: str) -> str:
        value = r[index[source]]
        if source == "datetime":
            # ISO 8601 with a Z, one of the layouts the parser accepts.
            return value.replace(" ", "T") + "Z"
        return value

    lines = ["\t".join(name for name, _ in TSV_COLUMNS)]
    lines += ["\t".join(cell(r, source) for _, source in TSV_COLUMNS) for r in rows]

    for offset, (at, text) in enumerate(TSV_MALFORMED):
        pos = at + 1 + offset                 # +1 for the header row
        if text is None:
            lines.insert(pos, "\t".join(lines[pos].split("\t")[:4]))
        elif text.startswith("eventtime="):
            fields = lines[pos].split("\t")
            fields[[n for n, _ in TSV_COLUMNS].index("eventtime")] = text.split("=", 1)[1]
            lines.insert(pos, "\t".join(fields))
        else:
            lines.insert(pos, text)

    path.write_text("\n".join(lines) + "\n")
    print(f"{path}: {len(rows)} rows + {len(TSV_MALFORMED)} malformed lines")


def main() -> None:
    out = Path(__file__).resolve().parent.parent / "samples"
    out.mkdir(exist_ok=True)

    benign: list = []
    benign_traffic(benign, count=1200)
    write(out / "zscaler_benign.log", benign)

    suspicious: list = []
    benign_traffic(suspicious, count=1800)
    attack_data_exfil(suspicious)
    attack_beaconing(suspicious)
    attack_volume_spike(suspicious)
    attack_blocked_threats(suspicious)
    attack_off_hours(suspicious)
    attack_rare_destination(suspicious)
    # Not attacks: an authentication problem and an upstream outage. They are
    # here so the error breakdown has traffic an analyst would triage
    # differently from a threat, which is the point of splitting 4xx and 5xx
    # by code rather than counting them together.
    incident_auth_failures(suspicious)
    incident_origin_errors(suspicious)
    write(out / "zscaler_suspicious.log", suspicious)

    # --- Small files for hand testing. Everything below draws from the RNG
    # after the labelled pair is written, so adding or changing these never
    # alters zscaler_benign.log or zscaler_suspicious.log.

    # Two attacks whose detection is not statistical (proxy-flagged malware,
    # a host nobody else visits), so even a tiny file yields findings.
    quick: list = []
    benign_traffic(quick, count=200)
    attack_blocked_threats(quick)
    attack_rare_destination(quick)
    write(out / "zscaler_quick.log", quick)

    # A single attack class. Useful for reading one finding's evidence in
    # full, and for confirming the other five detectors stay quiet.
    beacon: list = []
    benign_traffic(beacon, count=400)
    attack_beaconing(beacon, hits=120)
    write(out / "zscaler_beacon_only.log", beacon)

    # A second tenant's feed: different names, order, delimiter and timestamp
    # format, with malformed lines. One attack, so parsing and detection can
    # both be checked from one upload.
    tsv: list = []
    benign_traffic(tsv, count=300)
    attack_data_exfil(tsv)
    write_tsv(out / "zscaler_nss_tsv.log", tsv)


if __name__ == "__main__":
    main()
