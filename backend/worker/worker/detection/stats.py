"""Threat detection: map to aggregates, merge, then score.

This module produces the **confidence scores**. Nothing here calls an LLM --
every score is a reproducible number derived from the data itself, which means
there is no model to train, no artifact to ship, and the same input always
yields the same score.

Baselines are computed from the data under analysis, not from a fixed
threshold. "Unusual" therefore means unusual for this environment: 500
requests/minute is alarming in a quiet office log and unremarkable on a busy
proxy feed.

Scoring uses median + MAD (median absolute deviation) rather than mean + stdev.
Proxy log distributions are heavy-tailed, and a single 200MB upload would drag
a mean-based baseline up far enough to hide itself.

**Shape.** Detection is split into a map half and a score half so the work can
be spread across workers:

    map_shard(entries) -> Partial        runs on each shard, in parallel
    score(partial)     -> [Candidate]    runs once, after merging

Scores are never computed on a shard. Three of the six detectors compare
against a file-wide baseline that a shard cannot see -- see partial.py. The
per-detector functions kept below are thin façades over map+score, so a caller
with everything in memory can still write ``detect_all(entries)``.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Sequence

from worker.detection.partial import (
    ActorHour,
    ByteGroup,
    HostGroup,
    MAX_EVIDENCE_VALUES,
    Partial,
    ThreatGroup,
    merge_all,
)
from worker.entry import LogEntry

# A detector must clear this to be reported at all.
MIN_SCORE = 0.30
# Cap per detector, so the evidence packet sent to the LLM stays small.
MAX_PER_DETECTOR = 5
# An hour counts as "quiet" below this fraction of the median hour's volume.
# Tuned so the tail of a normal working day does not register as off-hours.
QUIET_HOUR_RATIO = 0.15
# Ignore one-off late requests; off-hours matters when there is sustained activity.
MIN_OFF_HOURS_REQUESTS = 5
# A burst must also be large in absolute terms. A z-score alone is noisy over
# sparse counts -- four requests in a minute is a statistical outlier in a very
# quiet log, but it is never worth an analyst's attention.
MIN_BURST_REQUESTS = 20
# Minimum check-ins before an interval series is worth measuring.
MIN_BEACON_HITS = 12


@dataclass
class Candidate:
    """One suspicious pattern, with the evidence that justifies its score."""

    kind: str
    title: str
    score: float                    # 0..1 confidence
    entry_ids: list[int] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)


# --- scoring helpers --------------------------------------------------------

def _mad(values: Sequence[float], median: float) -> float:
    """Median absolute deviation, scaled to be comparable to a stdev."""
    if not values:
        return 0.0
    return 1.4826 * statistics.median([abs(v - median) for v in values])


def _robust_z(value: float, values: Sequence[float]) -> float:
    """How many robust standard deviations `value` sits above the median."""
    if len(values) < 2:
        return 0.0
    median = statistics.median(values)
    spread = _mad(values, median)
    if spread == 0:
        # MAD collapses to 0 whenever most observations share the same value
        # -- very common here, since most (ip, minute) buckets hold exactly one
        # request. Fall back to stdev so a genuine outlier still scores.
        spread = statistics.pstdev(values)
    if spread == 0:
        # Every observation is identical; there is no scale to measure against.
        return 0.0 if value <= median else 50.0
    return (value - median) / spread


def _score_from_z(z: float, flag_at: float = 3.0, certain_at: float = 12.0) -> float:
    """Map a z-score onto 0..1.

    Below `flag_at` scores 0 (not reported). At or above `certain_at` scores 1.
    Linear in between -- deliberately simple, so the number is explainable.
    """
    if z <= flag_at:
        return 0.0
    return min(1.0, (z - flag_at) / (certain_at - flag_at))


def _top(candidates: list[Candidate]) -> list[Candidate]:
    keep = [c for c in candidates if c.score >= MIN_SCORE]
    keep.sort(key=lambda c: (-c.score, c.title))
    return keep[:MAX_PER_DETECTOR]


def _minute_epoch(ts: datetime) -> int:
    return int(ts.replace(second=0, microsecond=0).timestamp())


def _from_epoch(value: float) -> datetime:
    return datetime.fromtimestamp(value, tz=timezone.utc)


# --- map --------------------------------------------------------------------

def map_shard(entries: Iterable[LogEntry]) -> Partial:
    """Reduce a shard of entries to aggregates. Emits no scores."""
    p = Partial()

    for e in entries:
        p.entries_seen += 1

        if e.client_ip and e.ts:
            p.ip_minute[(e.client_ip, _minute_epoch(e.ts))].append(e.id)

        if e.req_bytes and e.req_bytes > 0:
            p.req_byte_logs.append(math.log10(e.req_bytes))
            key = (e.username or "unknown", e.host or "unknown")
            group = p.user_host.setdefault(key, ByteGroup())
            group.ids.append(e.id)
            group.total_bytes += e.req_bytes
            group.log_values.append(math.log10(e.req_bytes))

        if e.client_ip and e.host and e.ts:
            p.ip_host_times[(e.client_ip, e.host)].append((e.ts.timestamp(), e.id))

        if e.threat_name:
            group = p.threats.setdefault((e.threat_name, e.host or "unknown"), ThreatGroup())
            group.ids.append(e.id)
            if e.username:
                group.users.add(e.username)
            if e.action:
                group.actions.add(e.action)

        if e.host:
            host = p.hosts.setdefault(e.host, HostGroup())
            host.ids.append(e.id)
            if e.username:
                host.users.add(e.username)
            if e.url and len(host.urls) < MAX_EVIDENCE_VALUES:
                host.urls.add(e.url)

        if e.ts:
            hour = e.ts.hour
            p.hour_counts[hour] += 1
            actor = p.hour_actors.setdefault((hour, e.actor), ActorHour())
            actor.ids.append(e.id)
            if e.host and len(actor.hosts) < MAX_EVIDENCE_VALUES:
                actor.hosts.add(e.host)

    return p


# --- score ------------------------------------------------------------------

def score_volume_spike(p: Partial) -> list[Candidate]:
    """Unusual number of requests from a single IP in a short time frame.

    Counts requests per (client_ip, minute), then scores each bucket against
    the distribution of *all* per-minute buckets.
    """
    if len(p.ip_minute) < 5:
        return []

    counts = [len(v) for v in p.ip_minute.values()]
    flagged: dict[str, list[tuple[int, list[int], float]]] = defaultdict(list)

    for (ip, minute), ids in p.ip_minute.items():
        if len(ids) < MIN_BURST_REQUESTS:
            continue
        score = _score_from_z(_robust_z(len(ids), counts), flag_at=3.0, certain_at=10.0)
        if score > 0:
            flagged[ip].append((minute, ids, score))

    out: list[Candidate] = []
    for ip, windows in flagged.items():
        windows.sort()
        ids = [i for _, group, _ in windows for i in group]
        peak = max(len(group) for _, group, _ in windows)
        out.append(Candidate(
            kind="volume_spike",
            title=f"Request burst from {ip}",
            score=max(s for _, _, s in windows),
            entry_ids=ids,
            evidence={
                "client_ip": ip,
                "peak_requests_per_minute": peak,
                "median_requests_per_minute": round(statistics.median(counts), 1),
                "minutes_affected": len(windows),
                "window_start": _from_epoch(windows[0][0]).isoformat(),
                "window_end": _from_epoch(windows[-1][0]).isoformat(),
                "total_requests": len(ids),
            },
        ))
    return _top(out)


def score_data_exfil(p: Partial) -> list[Candidate]:
    """Outbound upload volume far above the norm.

    Scores on log10(bytes), because upload sizes span several orders of
    magnitude and a linear scale would flag every moderately large POST.
    """
    if len(p.req_byte_logs) < 10:
        return []

    logs = p.req_byte_logs
    out: list[Candidate] = []
    for (user, host), group in p.user_host.items():
        if not group.log_values:
            continue
        peak_log = max(group.log_values)
        score = _score_from_z(_robust_z(peak_log, logs), flag_at=3.0, certain_at=7.0)
        if score <= 0:
            continue
        out.append(Candidate(
            kind="data_exfil",
            title=f"Large outbound transfer: {user} → {host}",
            score=score,
            entry_ids=list(group.ids),
            evidence={
                "username": user,
                "host": host,
                "total_bytes_sent": group.total_bytes,
                "request_count": len(group.ids),
                "largest_request_bytes": int(10 ** peak_log),
                "median_request_bytes": int(10 ** statistics.median(logs)),
            },
        ))
    return _top(out)


def score_beaconing(p: Partial, min_hits: int = MIN_BEACON_HITS) -> list[Candidate]:
    """Near-constant intervals between requests to one host -- C2 check-in.

    Regularity = 1 - (stdev / mean) of the inter-request intervals. Automated
    beacons cluster near 1.0; human browsing is bursty and scores far lower.

    This is the clearest example of why shards cannot score: half of an
    interval series has a different standard deviation from the whole.
    """
    out: list[Candidate] = []
    for (ip, host), hits in p.ip_host_times.items():
        if len(hits) < min_hits:
            continue
        hits = sorted(hits)
        times = [t for t, _ in hits]
        gaps = [times[k + 1] - times[k] for k in range(len(times) - 1)]
        gaps = [g for g in gaps if g > 0]
        if len(gaps) < min_hits - 1:
            continue

        mean_gap = statistics.mean(gaps)
        if not 5 <= mean_gap <= 86400:   # ignore floods and once-a-day noise
            continue

        regularity = 1.0 - (statistics.pstdev(gaps) / mean_gap)
        if regularity < 0.80:
            continue

        # Rescale 0.80..1.00 regularity onto 0..1 confidence.
        out.append(Candidate(
            kind="beaconing",
            title=f"Periodic check-in: {ip} → {host}",
            score=min(1.0, (regularity - 0.80) / 0.18),
            entry_ids=[i for _, i in hits],
            evidence={
                "client_ip": ip,
                "host": host,
                "request_count": len(hits),
                "mean_interval_seconds": round(mean_gap, 1),
                "interval_stdev_seconds": round(statistics.pstdev(gaps), 2),
                "regularity": round(regularity, 4),
                "first_seen": _from_epoch(times[0]).isoformat(),
                "last_seen": _from_epoch(times[-1]).isoformat(),
            },
        ))
    return _top(out)


def score_blocked_threats(p: Partial) -> list[Candidate]:
    """Proxy-identified malware or phishing. Deterministic, not statistical.

    The proxy already made this call, so confidence is fixed and high; the
    value we add is grouping and surfacing it, not re-deciding it.
    """
    return _top([
        Candidate(
            kind="blocked_threat",
            title=f"{threat} at {host}",
            score=0.95,
            entry_ids=list(group.ids),
            evidence={
                "threat_name": threat,
                "host": host,
                "hit_count": len(group.ids),
                "users": sorted(group.users),
                "actions": sorted(group.actions),
            },
        )
        for (threat, host), group in p.threats.items()
    ])


def score_rare_destination(p: Partial) -> list[Candidate]:
    """A host touched by exactly one user, a handful of times.

    Score is inverse to frequency: the rarer the destination relative to the
    busiest host, the higher the confidence. A shard cannot know what the
    busiest host is, which is why this runs after the merge.
    """
    if len(p.hosts) < 5:
        return []

    busiest = max(len(g.ids) for g in p.hosts.values())
    out: list[Candidate] = []
    for host, group in p.hosts.items():
        if len(group.users) != 1 or len(group.ids) > 3:
            continue
        # One hit against a file whose busiest host has thousands -> ~1.0
        score = min(1.0, math.log10(busiest / len(group.ids) + 1) / math.log10(busiest + 1))
        out.append(Candidate(
            kind="rare_destination",
            title=f"Rarely-seen destination: {host}",
            score=round(score, 3),
            entry_ids=list(group.ids),
            evidence={
                "host": host,
                "hit_count": len(group.ids),
                "distinct_users": len(group.users),
                "username": next(iter(sorted(group.users)), None),
                "busiest_host_hits": busiest,
                "urls": sorted(group.urls)[:3],
            },
        ))
    return _top(out)


def score_off_hours(p: Partial) -> list[Candidate]:
    """Activity in hours that are quiet *for this data*.

    Builds an hour-of-day histogram, then flags activity landing in hours whose
    volume is far below the median hour. The median is a property of the whole
    histogram, so again this cannot be decided on a shard.
    """
    if len(p.hour_counts) < 4:
        return []

    volumes = list(p.hour_counts.values())
    median_volume = statistics.median(volumes)
    if median_volume == 0:
        return []

    quiet_hours = {h for h, n in p.hour_counts.items() if n < QUIET_HOUR_RATIO * median_volume}
    if not quiet_hours:
        return []

    # Group the quiet-hour activity by actor, so we report actors not hours.
    actors: dict[str, ActorHour] = {}
    actor_hours: dict[str, set[int]] = defaultdict(set)
    for (hour, actor), activity in p.hour_actors.items():
        if hour not in quiet_hours:
            continue
        merged = actors.setdefault(actor, ActorHour())
        merged.merge(activity)
        actor_hours[actor].add(hour)

    out: list[Candidate] = []
    for actor, activity in actors.items():
        if len(activity.ids) < MIN_OFF_HOURS_REQUESTS:
            continue
        hours = sorted(actor_hours[actor])
        hour_volume = statistics.mean(p.hour_counts[h] for h in hours)
        # The quieter the hour and the more activity from one actor, the higher.
        quietness = 1.0 - (hour_volume / median_volume)
        score = min(1.0, quietness * min(1.0, len(activity.ids) / 10))
        if score <= 0:
            continue
        out.append(Candidate(
            kind="off_hours",
            title=f"Off-hours activity: {actor}",
            score=round(score, 3),
            entry_ids=list(activity.ids),
            evidence={
                "actor": actor,
                "request_count": len(activity.ids),
                "hours": hours,
                "median_hourly_volume": median_volume,
                "these_hours_volume": round(hour_volume, 1),
                "hosts": sorted(activity.hosts)[:5],
            },
        ))
    return _top(out)


SCORERS = (
    score_volume_spike,
    score_data_exfil,
    score_beaconing,
    score_blocked_threats,
    score_rare_destination,
    score_off_hours,
)


def score(partial: Partial) -> list[Candidate]:
    """Run every scorer over merged aggregates, ranked by confidence."""
    found: list[Candidate] = []
    for scorer in SCORERS:
        found.extend(scorer(partial))
    found.sort(key=lambda c: (-c.score, c.kind, c.title))
    return found


def reduce_partials(partials: list[Partial]) -> list[Candidate]:
    """Merge shard aggregates and score once."""
    return score(merge_all(partials))


# --- single-process façades -------------------------------------------------
#
# Equivalent to map+score over one shard. Kept so callers holding everything in
# memory -- and the detector tests -- do not have to know about sharding.

def detect_all(entries: Sequence[LogEntry]) -> list[Candidate]:
    return reduce_partials([map_shard(entries)])


def detect_volume_spike(entries: Sequence[LogEntry]) -> list[Candidate]:
    return score_volume_spike(map_shard(entries))


def detect_data_exfil(entries: Sequence[LogEntry]) -> list[Candidate]:
    return score_data_exfil(map_shard(entries))


def detect_beaconing(entries: Sequence[LogEntry], min_hits: int = MIN_BEACON_HITS) -> list[Candidate]:
    return score_beaconing(map_shard(entries), min_hits=min_hits)


def detect_blocked_threats(entries: Sequence[LogEntry]) -> list[Candidate]:
    return score_blocked_threats(map_shard(entries))


def detect_rare_destination(entries: Sequence[LogEntry]) -> list[Candidate]:
    return score_rare_destination(map_shard(entries))


def detect_off_hours(entries: Sequence[LogEntry]) -> list[Candidate]:
    return score_off_hours(map_shard(entries))
