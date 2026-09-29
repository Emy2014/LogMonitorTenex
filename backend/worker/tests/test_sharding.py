"""Sharded and unsharded detection must produce identical results.

This is the whole safety argument for Phase 4. Detection was split so it can
run across workers; if a split changes the answer, the split is wrong and the
speed is worthless.

The failure mode being guarded against is specific. Three detectors compare
against a baseline computed over everything -- beaconing needs a complete
interval series, rare_destination needs the busiest host, off_hours needs the
median hour. Running those on a shard does not produce a partial answer, it
produces a confidently wrong one.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest

from worker.detection import detect_all, map_shard, reduce_partials
from worker.entry import LogEntry

BASE = datetime(2024, 3, 14, 9, 0, 0, tzinfo=timezone.utc)


def realistic_corpus(n: int = 1400, seed: int = 1337) -> list[LogEntry]:
    """Background traffic plus every pattern the detectors look for.

    A uniform corpus would collapse MAD to zero and make the comparison
    vacuous, so this deliberately carries the shapes that actually score.
    """
    rng = random.Random(seed)
    users = ["m.chen", "j.okafor", "s.patel", "d.kim", "l.novak"]
    hosts = ["github.com", "slack.com", "news.ycombinator.com",
             "stackoverflow.com", "docs.python.org", "drive.google.com"]
    out: list[LogEntry] = []
    next_id = iter(range(1, 10_000_000))

    def add(**kw) -> None:
        out.append(LogEntry(id=next(next_id), line_no=len(out) + 2, **kw))

    for _ in range(n):
        add(ts=BASE + timedelta(seconds=rng.randint(0, 8 * 3600)),
            client_ip=f"10.12.{rng.randint(1, 4)}.{rng.randint(1, 60)}",
            username=rng.choice(users), host=rng.choice(hosts),
            url="https://x/", category="News", action="Allowed",
            req_bytes=rng.randint(200, 3000), resp_bytes=rng.randint(500, 40000))

    # volume spike: one IP, one minute, well past the burst floor
    for _ in range(90):
        add(ts=BASE + timedelta(hours=2), client_ip="10.12.4.102",
            username="s.patel", host="internal-api.partner.io", url="https://x/",
            action="Allowed", req_bytes=400, resp_bytes=900)

    # data exfil: many large chunks to one host
    for k in range(14):
        add(ts=BASE + timedelta(hours=3, minutes=k), client_ip="10.12.7.88",
            username="m.chen", host="files.dropzone-sync.ru", url="https://x/",
            action="Allowed", req_bytes=20_000_000, resp_bytes=200)

    # beaconing: exactly regular check-ins
    for k in range(40):
        add(ts=BASE + timedelta(hours=1, seconds=k * 60), client_ip="10.12.2.31",
            username="j.okafor", host="cdn-telemetry-sync.net", url="https://x/",
            action="Allowed", req_bytes=300, resp_bytes=300)

    # blocked threats
    for k in range(6):
        add(ts=BASE + timedelta(hours=4, minutes=k), client_ip="10.12.3.10",
            username="l.novak", host="malware.example", url="https://x/",
            action="Blocked", threat_name="Emotet", req_bytes=100, resp_bytes=0)

    # rare destination: one user, one hit
    add(ts=BASE + timedelta(hours=5), client_ip="10.12.1.7", username="d.kim",
        host="paste-anon-share.onion.ly", url="https://x/a", action="Allowed",
        req_bytes=800, resp_bytes=400)

    # off hours: sustained activity at 03:00
    quiet = BASE.replace(hour=3)
    for k in range(18):
        add(ts=quiet + timedelta(minutes=k), client_ip="10.12.5.44",
            username="d.kim", host="admin.crm-internal.com", url="https://x/export",
            action="Allowed", req_bytes=900, resp_bytes=120_000)

    rng.shuffle(out)
    return out


def fingerprint(candidates):
    """Everything that must survive sharding: kind, title, score, rows."""
    return [
        (c.kind, c.title, round(c.score, 10), sorted(c.entry_ids), c.evidence)
        for c in candidates
    ]


def split(entries, n):
    """Round-robin shards -- the least forgiving split, since it scatters
    every interval series and every host group across all shards."""
    shards = [[] for _ in range(n)]
    for i, e in enumerate(entries):
        shards[i % n].append(e)
    return shards


def by_time(entries, n):
    """Contiguous time slices, which is how the real sharder splits."""
    ordered = sorted(entries, key=lambda e: (e.ts or BASE))
    size = max(1, len(ordered) // n)
    return [ordered[i:i + size] for i in range(0, len(ordered), size)]


CORPUS = realistic_corpus()


def test_the_corpus_actually_triggers_every_detector():
    """Without this the comparison below could pass on an empty result."""
    kinds = {c.kind for c in detect_all(CORPUS)}
    expected = {"volume_spike", "data_exfil", "beaconing",
                "blocked_threat", "rare_destination", "off_hours"}
    missing = expected - kinds
    assert not missing, f"corpus does not exercise {missing}"


@pytest.mark.parametrize("shards", [2, 3, 5, 8, 17])
def test_round_robin_shards_match_single_pass(shards):
    baseline = fingerprint(detect_all(CORPUS))
    sharded = fingerprint(reduce_partials([map_shard(s) for s in split(CORPUS, shards)]))
    assert sharded == baseline


@pytest.mark.parametrize("shards", [2, 4, 9])
def test_time_sliced_shards_match_single_pass(shards):
    baseline = fingerprint(detect_all(CORPUS))
    sharded = fingerprint(reduce_partials([map_shard(s) for s in by_time(CORPUS, shards)]))
    assert sharded == baseline


def test_merge_order_does_not_matter():
    """Workers finish in whatever order they finish."""
    shards = [map_shard(s) for s in split(CORPUS, 6)]
    forward = fingerprint(reduce_partials(shards))
    backward = fingerprint(reduce_partials(list(reversed(shards))))
    assert forward == backward


def test_empty_shards_are_harmless():
    """A time slice with no entries in it is normal, not an error."""
    shards = [map_shard(s) for s in split(CORPUS, 4)]
    shards.insert(0, map_shard([]))
    shards.append(map_shard([]))
    assert fingerprint(reduce_partials(shards)) == fingerprint(detect_all(CORPUS))


def test_one_shard_is_the_same_as_no_sharding():
    assert fingerprint(reduce_partials([map_shard(CORPUS)])) == fingerprint(detect_all(CORPUS))
