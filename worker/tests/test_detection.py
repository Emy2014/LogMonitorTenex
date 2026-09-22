"""Detector tests.

Each detector is a pure function over LogEntry, so these run with no
database and no network. Synthetic inputs have a known-correct expected
result, which is what makes the confidence scores auditable.
"""

from datetime import datetime, timedelta, timezone

import pytest

from worker.detection.stats import (
    detect_all,
    detect_beaconing,
    detect_blocked_threats,
    detect_data_exfil,
    detect_off_hours,
    detect_rare_destination,
    detect_volume_spike,
)
from worker.entry import LogEntry

BASE = datetime(2024, 3, 14, 12, 0, 0, tzinfo=timezone.utc)


def entry(n=0, *, minutes=0, seconds=0, ip="10.0.0.1", user="alice",
          host="example.com", req=500, resp=1000, action="Allowed", threat=None):
    return LogEntry(
        id=n, line_no=n, raw="", ts=BASE + timedelta(minutes=minutes, seconds=seconds),
        client_ip=ip, username=user, host=host, url=f"https://{host}/",
        category="News", action=action, req_bytes=req, resp_bytes=resp,
        user_agent="Chrome", threat_name=threat,
    )


def background(count=600):
    """Ordinary traffic: varied sizes and several requests per minute.

    Real proxy traffic has spread. An artificially uniform baseline (one
    request per minute, all the same size) collapses the MAD to zero and is
    not representative of what the detectors actually run against.
    """
    import random
    rng = random.Random(42)
    return [
        entry(i,
              minutes=i % 90,
              seconds=rng.randint(0, 59),
              ip=f"10.0.1.{i % 40}",
              user=f"u{i % 15}",
              host=f"site{i % 25}.com",
              req=rng.randint(300, 2500),
              resp=rng.randint(800, 90_000))
        for i in range(count)
    ]


# --- volume_spike -----------------------------------------------------------

def test_volume_spike_flags_a_burst_from_one_ip():
    entries = background()
    # 200 requests inside a single minute from one IP.
    entries += [entry(1000 + i, minutes=5, seconds=i % 60, ip="10.9.9.9") for i in range(200)]

    found = detect_volume_spike(entries)

    assert found, "a 200-request minute should be flagged"
    assert found[0].evidence["client_ip"] == "10.9.9.9"
    assert found[0].score > 0.8
    assert len(found[0].entry_ids) == 200


def test_volume_spike_ignores_uniform_traffic():
    assert detect_volume_spike(background()) == []


def test_volume_spike_survives_zero_mad():
    """Regression: when most (ip, minute) buckets hold exactly one request the
    MAD is 0. An earlier version returned a constant below its own threshold,
    so bursts were never reported."""
    entries = [entry(i, minutes=i, ip=f"10.0.1.{i}") for i in range(60)]
    entries += [entry(500 + i, minutes=5, seconds=i, ip="10.9.9.9") for i in range(50)]

    found = detect_volume_spike(entries)
    assert found, "burst must be flagged despite MAD == 0"
    assert found[0].evidence["client_ip"] == "10.9.9.9"


# --- data_exfil -------------------------------------------------------------

def test_data_exfil_flags_outsized_uploads():
    entries = background()
    entries += [
        entry(2000 + i, minutes=i * 3, ip="10.5.5.5", user="mallory",
              host="dropzone.example", req=20_000_000, resp=300)
        for i in range(8)
    ]

    found = detect_data_exfil(entries)

    assert found
    top = found[0]
    assert top.evidence["username"] == "mallory"
    assert top.evidence["total_bytes_sent"] == 160_000_000
    assert top.score > 0.8


def test_data_exfil_ignores_normal_uploads():
    assert detect_data_exfil(background()) == []


# --- beaconing --------------------------------------------------------------

def test_beaconing_flags_constant_interval_checkins():
    entries = background()
    # Exactly 60s apart, 1s of jitter -- a C2 check-in pattern.
    entries += [
        entry(3000 + i, minutes=i, seconds=(i % 3) - 1, ip="10.7.7.7", host="c2.example")
        for i in range(40)
    ]

    found = detect_beaconing(entries)

    assert found
    assert found[0].evidence["host"] == "c2.example"
    assert found[0].evidence["regularity"] > 0.9
    assert found[0].score > 0.5


def test_beaconing_ignores_irregular_human_browsing():
    import random
    random.seed(7)
    entries = [
        entry(i, minutes=sum(random.randint(1, 40) for _ in range(i + 1)),
              ip="10.7.7.7", host="news.example")
        for i in range(30)
    ]

    assert detect_beaconing(entries) == []


def test_beaconing_needs_enough_hits():
    entries = [entry(i, minutes=i, ip="10.7.7.7", host="c2.example") for i in range(5)]
    assert detect_beaconing(entries) == []


# --- blocked_threat ---------------------------------------------------------

def test_blocked_threats_are_grouped_and_high_confidence():
    entries = background()
    entries += [
        entry(4000 + i, minutes=i, ip="10.3.3.3", user="bob", host="bad.example",
              action="Blocked", threat="Win32.Trojan.Test")
        for i in range(3)
    ]

    found = detect_blocked_threats(entries)

    assert len(found) == 1, "same threat + host should collapse into one candidate"
    assert found[0].evidence["hit_count"] == 3
    assert found[0].evidence["users"] == ["bob"]
    assert found[0].score == 0.95


def test_no_threats_means_no_candidates():
    assert detect_blocked_threats(background()) == []


# --- rare_destination -------------------------------------------------------

def test_rare_destination_flags_a_one_user_one_hit_host():
    entries = background()
    entries.append(entry(5000, minutes=7, user="carol", host="paste.example"))

    found = detect_rare_destination(entries)

    assert any(c.evidence["host"] == "paste.example" for c in found)


def test_popular_hosts_are_not_rare():
    found = detect_rare_destination(background())
    assert all(c.evidence["hit_count"] <= 3 for c in found)


# --- off_hours --------------------------------------------------------------

def test_off_hours_flags_sustained_activity_in_a_dead_hour():
    # Busy working day: ~150 requests/hour across eight hours.
    entries = [
        entry(i, minutes=(i % 480), ip="10.0.0.5", user="alice")
        for i in range(1200)
    ]
    base = datetime(2024, 3, 14, 3, 0, 0, tzinfo=timezone.utc)
    night = [
        LogEntry(id=9000 + i, line_no=9000 + i, raw="", ts=base + timedelta(minutes=i * 2),
                    client_ip="10.0.0.9", username="mallory", host="admin.example",
                    url="https://admin.example/", action="Allowed",
                    req_bytes=300, resp_bytes=50_000)
        for i in range(10)
    ]

    found = detect_off_hours(entries + night)

    assert any(c.evidence["actor"] == "mallory" for c in found)


def test_off_hours_ignores_a_single_late_request():
    entries = [entry(i, minutes=(i % 480), user="alice") for i in range(1200)]
    base = datetime(2024, 3, 14, 3, 0, 0, tzinfo=timezone.utc)
    entries.append(
        LogEntry(id=9999, line_no=9999, raw="", ts=base, client_ip="10.0.0.9",
                    username="mallory", host="x.example", url="https://x.example/",
                    action="Allowed", req_bytes=300, resp_bytes=100)
    )

    assert not any(c.evidence["actor"] == "mallory" for c in detect_off_hours(entries)), \
        "one late request is not an off-hours pattern"


# --- integration over the whole detector set --------------------------------

def test_detect_all_returns_candidates_ranked_by_confidence():
    entries = background()
    entries += [entry(6000 + i, minutes=2, seconds=i % 60, ip="10.9.9.9") for i in range(200)]

    found = detect_all(entries)

    assert found
    assert found == sorted(found, key=lambda c: c.score, reverse=True)
    assert all(0.0 <= c.score <= 1.0 for c in found)


def test_quiet_traffic_produces_no_findings():
    """The false-positive guard: ordinary traffic must stay silent."""
    assert detect_all(background()) == []
