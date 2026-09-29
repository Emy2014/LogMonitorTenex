"""Partial aggregates on the wire.

Partials travel between workers through Redis, so they need a representation
that survives JSON. Sets become sorted lists and tuple keys become strings;
the important property is that a round trip is lossless, because a partial
that changes in transit changes the result.
"""

from __future__ import annotations

import json
from collections import defaultdict

from worker.detection.partial import ActorHour, ByteGroup, HostGroup, Partial, ThreatGroup

SEP = "\x1f"  # unit separator: cannot occur in a hostname, IP or username


def _join(*parts) -> str:
    return SEP.join(str(p) for p in parts)


def _split(key: str) -> list[str]:
    return key.split(SEP)


def dumps(p: Partial) -> str:
    return json.dumps({
        "ip_minute": {_join(ip, m): ids for (ip, m), ids in p.ip_minute.items()},
        "user_host": {
            _join(u, h): {"ids": g.ids, "total": g.total_bytes, "logs": g.log_values}
            for (u, h), g in p.user_host.items()
        },
        "req_byte_logs": p.req_byte_logs,
        "ip_host_times": {_join(ip, h): t for (ip, h), t in p.ip_host_times.items()},
        "threats": {
            _join(t, h): {"ids": g.ids, "users": sorted(g.users), "actions": sorted(g.actions)}
            for (t, h), g in p.threats.items()
        },
        "hosts": {
            h: {"ids": g.ids, "users": sorted(g.users), "urls": sorted(g.urls)}
            for h, g in p.hosts.items()
        },
        "hour_counts": {str(h): n for h, n in p.hour_counts.items()},
        "hour_actors": {
            _join(hour, actor): {"ids": a.ids, "hosts": sorted(a.hosts)}
            for (hour, actor), a in p.hour_actors.items()
        },
        "entries_seen": p.entries_seen,
    }, separators=(",", ":"))


def loads(raw: str) -> Partial:
    d = json.loads(raw)
    p = Partial()

    p.ip_minute = defaultdict(list)
    for key, ids in d["ip_minute"].items():
        ip, minute = _split(key)
        p.ip_minute[(ip, int(minute))] = ids

    for key, g in d["user_host"].items():
        u, h = _split(key)
        p.user_host[(u, h)] = ByteGroup(ids=g["ids"], total_bytes=g["total"],
                                        log_values=g["logs"])

    p.req_byte_logs = d["req_byte_logs"]

    p.ip_host_times = defaultdict(list)
    for key, times in d["ip_host_times"].items():
        ip, h = _split(key)
        # JSON arrays come back as lists; the scorer sorts tuples.
        p.ip_host_times[(ip, h)] = [(float(t), int(i)) for t, i in times]

    for key, g in d["threats"].items():
        t, h = _split(key)
        p.threats[(t, h)] = ThreatGroup(ids=g["ids"], users=set(g["users"]),
                                        actions=set(g["actions"]))

    for h, g in d["hosts"].items():
        p.hosts[h] = HostGroup(ids=g["ids"], users=set(g["users"]), urls=set(g["urls"]))

    p.hour_counts = defaultdict(int)
    for h, n in d["hour_counts"].items():
        p.hour_counts[int(h)] = n

    for key, a in d["hour_actors"].items():
        hour, actor = _split(key)
        p.hour_actors[(int(hour), actor)] = ActorHour(ids=a["ids"], hosts=set(a["hosts"]))

    p.entries_seen = d["entries_seen"]
    return p
