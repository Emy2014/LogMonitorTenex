"""Partial aggregates: what a shard emits, and how shards combine.

The reason this type exists is that **three of the six detectors cannot be
split by time**:

    beaconing          needs the complete inter-request interval series for a
                       (client_ip, host) pair. Half the series has a different
                       standard deviation, so a split changes the answer.
    rare_destination   scores a host against the busiest host in the file. A
                       shard does not know what the busiest host is.
    off_hours          compares each hour against the median hour. A shard
                       holding one hour has no median to compare against.

Splitting a window under any of those produces *wrong* answers, not partial
ones -- which is why shards emit aggregates and never scores, and all scoring
happens once, after the merge.

Everything here is a commutative, associative combine: merging is order
independent, which is what makes the sharded and unsharded results identical.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

# Evidence lists are capped so a partial cannot grow without bound on a
# pathological input. These only feed the report text, never the score.
MAX_EVIDENCE_VALUES = 8


@dataclass
class ByteGroup:
    """Upload volume for one (username, host) pair."""

    ids: list[int] = field(default_factory=list)
    total_bytes: int = 0
    log_values: list[float] = field(default_factory=list)

    def merge(self, other: ByteGroup) -> None:
        self.ids.extend(other.ids)
        self.total_bytes += other.total_bytes
        self.log_values.extend(other.log_values)


@dataclass
class ThreatGroup:
    """Proxy-identified threats at one (threat_name, host)."""

    ids: list[int] = field(default_factory=list)
    users: set[str] = field(default_factory=set)
    actions: set[str] = field(default_factory=set)

    def merge(self, other: ThreatGroup) -> None:
        self.ids.extend(other.ids)
        self.users |= other.users
        self.actions |= other.actions


@dataclass
class HostGroup:
    """Everything scoring needs about one host."""

    ids: list[int] = field(default_factory=list)
    users: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)

    def merge(self, other: HostGroup) -> None:
        self.ids.extend(other.ids)
        self.users |= other.users
        # Capped: urls are illustrative in the report, not part of the score.
        self.urls |= set(list(other.urls)[:MAX_EVIDENCE_VALUES])


@dataclass
class ActorHour:
    """One actor's activity within one hour of the day."""

    ids: list[int] = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)

    def merge(self, other: ActorHour) -> None:
        self.ids.extend(other.ids)
        self.hosts |= set(list(other.hosts)[:MAX_EVIDENCE_VALUES])


def _merge_maps(into: dict, other: dict, factory) -> None:
    for key, value in other.items():
        if key not in into:
            into[key] = factory()
        into[key].merge(value)


@dataclass
class Partial:
    """Aggregates from one shard of entries."""

    # (client_ip, minute_epoch) -> entry ids. Drives volume_spike.
    ip_minute: dict[tuple[str, int], list[int]] = field(
        default_factory=lambda: defaultdict(list))

    # (username, host) -> upload volume. Drives data_exfil.
    user_host: dict[tuple[str, str], ByteGroup] = field(default_factory=dict)
    # log10 of every positive request size in the shard, for the global
    # distribution data_exfil scores against.
    req_byte_logs: list[float] = field(default_factory=list)

    # (client_ip, host) -> (epoch_seconds, entry id). Drives beaconing.
    ip_host_times: dict[tuple[str, str], list[tuple[float, int]]] = field(
        default_factory=lambda: defaultdict(list))

    # (threat_name, host) -> group. Drives blocked_threat.
    threats: dict[tuple[str, str], ThreatGroup] = field(default_factory=dict)

    # host -> group. Drives rare_destination.
    hosts: dict[str, HostGroup] = field(default_factory=dict)

    # hour-of-day -> total entries, and -> actor -> activity. Drives off_hours.
    hour_counts: dict[int, int] = field(default_factory=lambda: defaultdict(int))
    hour_actors: dict[tuple[int, str], ActorHour] = field(default_factory=dict)

    entries_seen: int = 0

    def merge(self, other: Partial) -> None:
        """Fold another shard's aggregates in. Order independent."""
        for key, ids in other.ip_minute.items():
            self.ip_minute[key].extend(ids)
        _merge_maps(self.user_host, other.user_host, ByteGroup)
        self.req_byte_logs.extend(other.req_byte_logs)
        for key, times in other.ip_host_times.items():
            self.ip_host_times[key].extend(times)
        _merge_maps(self.threats, other.threats, ThreatGroup)
        _merge_maps(self.hosts, other.hosts, HostGroup)
        for hour, count in other.hour_counts.items():
            self.hour_counts[hour] += count
        _merge_maps(self.hour_actors, other.hour_actors, ActorHour)
        self.entries_seen += other.entries_seen


def merge_all(partials: list[Partial]) -> Partial:
    """Combine shard aggregates into one."""
    combined = Partial()
    for p in partials:
        combined.merge(p)
    return combined
