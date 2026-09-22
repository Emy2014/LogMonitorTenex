"""A partial that changes in transit changes the result, so a round trip
through Redis has to be lossless."""

from worker.detection import detect_all, map_shard, reduce_partials
from worker.serialize import dumps, loads
from tests.test_sharding import CORPUS, fingerprint, split


def test_round_trip_preserves_results():
    baseline = fingerprint(detect_all(CORPUS))
    wired = [loads(dumps(map_shard(s))) for s in split(CORPUS, 5)]
    assert fingerprint(reduce_partials(wired)) == baseline


def test_round_trip_is_stable_under_repetition():
    """Serialising an already-deserialised partial must not drift."""
    once = dumps(map_shard(CORPUS))
    twice = dumps(loads(once))
    assert once == twice


def test_empty_partial_survives():
    assert fingerprint(reduce_partials([loads(dumps(map_shard([])))])) == []


def test_separator_cannot_collide_with_real_values():
    """Keys are joined on a unit separator, which must not appear in the data."""
    from worker.serialize import SEP
    for e in CORPUS[:200]:
        for value in (e.host, e.username, e.client_ip):
            assert value is None or SEP not in value
