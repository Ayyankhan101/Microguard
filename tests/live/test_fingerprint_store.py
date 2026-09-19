"""Tests for fingerprint storage — binding a hash to an actor.

The binding rule is the security-critical part. `/fp` is public and
unauthenticated, and the cross-IP rule it feeds blocks OTHER people: an
attacker who harvests a hash real browsers produce and replays it from a
botnet would get those real users flagged. A hash is therefore only accepted
from an IP that already has session history, and only once per session.
"""

import json
from datetime import datetime, timezone

import pytest
import redis

from microguard.live.fingerprint import (
    ACTOR_PREFIX,
    FP_IPS_PREFIX,
    FP_PREFIX,
    RejectReason,
    is_valid_hash,
    record_fingerprint,
)
from microguard.live.redis_store import RedisSessionStateStore
from microguard.parser import LogEntry

BASE = datetime(2023, 3, 24, 17, 0, 0, tzinfo=timezone.utc)
HASH_A = "a" * 64
HASH_B = "b" * 64


@pytest.fixture(scope="module")
def redis_client():
    try:
        c = redis.Redis(host="localhost", port=6379, db=15, decode_responses=True)
        c.ping()
        yield c
        c.flushdb()
        c.close()
    except redis.ConnectionError:
        pytest.skip("Redis not available on localhost:6379")


@pytest.fixture()
def clean(redis_client):
    redis_client.flushdb()
    return redis_client


def _seed_session(client, ip):
    RedisSessionStateStore(client, default_ttl=300).record_request(
        ip, "Mozilla/5.0",
        LogEntry(ip=ip, timestamp=BASE, method="GET", url="/", status=200,
                 size=1, referer="", user_agent="Mozilla/5.0"),
    )


class TestHashValidation:
    """Rejected before parse, before Redis, before anything allocates."""

    def test_a_sha256_hex_digest_is_valid(self):
        assert is_valid_hash(HASH_A) is True

    def test_uppercase_hex_is_valid(self):
        assert is_valid_hash("A" * 64) is True

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "a" * 63,
            "a" * 65,
            "g" * 64,
            "a" * 32,
            "../../etc/passwd",
            "a" * 64 + "\n",
        ],
        ids=["empty", "short", "long", "non-hex", "md5-length", "path", "trailing-newline"],
    )
    def test_anything_else_is_rejected(self, bad):
        assert is_valid_hash(bad) is False


class TestBinding:
    def test_a_hash_from_a_known_actor_is_recorded(self, clean):
        _seed_session(clean, "203.0.113.5")

        assert record_fingerprint(clean, "203.0.113.5", HASH_A) is None

        stored = json.loads(clean.get(f"{FP_PREFIX}203.0.113.5"))
        assert stored["hash"] == HASH_A
        assert stored["shared_ips"] == 1

    def test_a_hash_from_an_actor_with_no_session_is_refused(self, clean):
        """Decision 7A. Without this an attacker associates any hash with any
        IP they like, and the cross-IP rule then blocks whoever really owns
        that fingerprint."""
        assert record_fingerprint(clean, "198.51.100.9", HASH_A) is RejectReason.NO_SESSION
        assert clean.get(f"{FP_PREFIX}198.51.100.9") is None
        assert clean.scard(f"{FP_IPS_PREFIX}{HASH_A}") == 0

    def test_a_second_hash_for_one_session_is_refused(self, clean):
        """First hash wins. Otherwise one bound session can inflate the
        cross-IP count for an unlimited number of hashes."""
        _seed_session(clean, "203.0.113.5")
        record_fingerprint(clean, "203.0.113.5", HASH_A)

        assert record_fingerprint(clean, "203.0.113.5", HASH_B) is RejectReason.ALREADY_BOUND

        assert json.loads(clean.get(f"{FP_PREFIX}203.0.113.5"))["hash"] == HASH_A
        assert clean.scard(f"{FP_IPS_PREFIX}{HASH_B}") == 0

    def test_resubmitting_the_same_hash_is_a_no_op_not_an_error(self, clean):
        """A page that loads twice, or a `keepalive` POST that retries, is
        normal traffic and must not read as an attack."""
        _seed_session(clean, "203.0.113.5")
        record_fingerprint(clean, "203.0.113.5", HASH_A)

        assert record_fingerprint(clean, "203.0.113.5", HASH_A) is None
        assert clean.scard(f"{FP_IPS_PREFIX}{HASH_A}") == 1

    def test_an_invalid_hash_never_reaches_redis(self, clean):
        _seed_session(clean, "203.0.113.5")
        assert record_fingerprint(clean, "203.0.113.5", "nope") is RejectReason.BAD_HASH
        assert clean.get(f"{FP_PREFIX}203.0.113.5") is None


class TestCrossIpCount:
    def test_the_count_rises_as_distinct_ips_share_a_hash(self, clean):
        for i in range(3):
            ip = f"203.0.113.{i}"
            _seed_session(clean, ip)
            record_fingerprint(clean, ip, HASH_A)

        assert json.loads(clean.get(f"{FP_PREFIX}203.0.113.2"))["shared_ips"] == 3

    def test_an_earlier_actor_keeps_its_own_snapshot(self, clean):
        """Decision 5A's accepted trade: the count is denormalized at write
        time, so the newest actor sees the true number immediately and earlier
        ones update on their next page load. That is the right direction --
        the newest member of a farm is the one still doing damage."""
        for i in range(3):
            ip = f"203.0.113.{i}"
            _seed_session(clean, ip)
            record_fingerprint(clean, ip, HASH_A)

        assert json.loads(clean.get(f"{FP_PREFIX}203.0.113.0"))["shared_ips"] == 1

    def test_the_ip_set_expires_so_the_window_slides(self, clean):
        _seed_session(clean, "203.0.113.5")
        record_fingerprint(clean, "203.0.113.5", HASH_A, window=600)

        assert 0 < clean.ttl(f"{FP_IPS_PREFIX}{HASH_A}") <= 600


class TestActorRecord:
    def test_a_first_sighting_creates_the_record(self, clean):
        _seed_session(clean, "203.0.113.5")
        record_fingerprint(clean, "203.0.113.5", HASH_A)

        actor = clean.hgetall(f"{ACTOR_PREFIX}{HASH_A}")
        assert float(actor["first_seen"]) > 0
        assert int(actor["sightings"]) == 1

    def test_a_return_visit_from_a_new_ip_increments_sightings(self, clean):
        for ip in ("203.0.113.5", "198.51.100.7"):
            _seed_session(clean, ip)
            record_fingerprint(clean, ip, HASH_A)

        actor = clean.hgetall(f"{ACTOR_PREFIX}{HASH_A}")
        assert int(actor["sightings"]) == 2
        assert int(actor["distinct_ips"]) == 2

    def test_the_first_seen_timestamp_does_not_move(self, clean):
        _seed_session(clean, "203.0.113.5")
        record_fingerprint(clean, "203.0.113.5", HASH_A)
        first = clean.hget(f"{ACTOR_PREFIX}{HASH_A}", "first_seen")

        _seed_session(clean, "198.51.100.7")
        record_fingerprint(clean, "198.51.100.7", HASH_A)

        assert clean.hget(f"{ACTOR_PREFIX}{HASH_A}", "first_seen") == first

    def test_the_record_has_a_sliding_ttl(self, clean):
        """The only structure here that outlives a session. It slides on each
        sighting so an actor that stops appearing ages out on its own, with no
        sweeper -- the same discipline live:v2: already uses."""
        _seed_session(clean, "203.0.113.5")
        record_fingerprint(clean, "203.0.113.5", HASH_A, actor_ttl=1000)

        assert 0 < clean.ttl(f"{ACTOR_PREFIX}{HASH_A}") <= 1000

    def test_a_wrong_type_at_the_actor_key_is_replaced_rather_than_fatal(self, clean, caplog):
        """HINCRBY against a string is WRONGTYPE. Nothing in this package
        writes one at a v2 key, but losing an actor permanently over one bad
        value is the worse outcome."""
        _seed_session(clean, "203.0.113.5")
        clean.set(f"{ACTOR_PREFIX}{HASH_A}", "not a hash")

        assert record_fingerprint(clean, "203.0.113.5", HASH_A) is None
        assert int(clean.hget(f"{ACTOR_PREFIX}{HASH_A}", "sightings")) == 1
        assert "wrong type" in caplog.text


class TestCorruptBinding:
    def test_a_corrupt_fp_record_is_treated_as_unbound(self, clean):
        """One unreadable value must not lock an actor out of ever binding a
        fingerprint again."""
        _seed_session(clean, "203.0.113.5")
        clean.set(f"{FP_PREFIX}203.0.113.5", "{not json")

        assert record_fingerprint(clean, "203.0.113.5", HASH_A) is None
        assert json.loads(clean.get(f"{FP_PREFIX}203.0.113.5"))["hash"] == HASH_A

    def test_a_record_without_a_hash_field_is_treated_as_unbound(self, clean):
        _seed_session(clean, "203.0.113.5")
        clean.set(f"{FP_PREFIX}203.0.113.5", json.dumps({"shared_ips": 3}))

        assert record_fingerprint(clean, "203.0.113.5", HASH_A) is None


class TestBindingIsAtomic:
    """The first-hash-wins gate has to survive concurrency.

    A check-then-set version of this passed every test above and was still
    defeated by two concurrent requests: both read "no binding", both passed
    the gate, and both bound. That let one IP with a live session bind
    unlimited harvested hashes, inflating the cross-IP count for each -- which
    is exactly the amplification the binding rule exists to prevent.
    """

    def test_concurrent_distinct_hashes_bind_exactly_one(self, clean):
        import threading

        _seed_session(clean, "203.0.113.5")
        hashes = [f"{i:064x}" for i in range(12)]
        results = []
        barrier = threading.Barrier(len(hashes))

        def submit(h):
            barrier.wait(timeout=5)
            results.append(record_fingerprint(clean, "203.0.113.5", h))

        threads = [threading.Thread(target=submit, args=(h,)) for h in hashes]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert results.count(None) == 1, "more than one hash won the binding"
        assert results.count(RejectReason.ALREADY_BOUND) == len(hashes) - 1

    def test_only_the_winning_hash_gets_an_ip_recorded(self, clean):
        import threading

        _seed_session(clean, "203.0.113.5")
        hashes = [f"{i:064x}" for i in range(12)]
        barrier = threading.Barrier(len(hashes))

        def submit(h):
            barrier.wait(timeout=5)
            record_fingerprint(clean, "203.0.113.5", h)

        threads = [threading.Thread(target=submit, args=(h,)) for h in hashes]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        populated = [h for h in hashes if clean.scard(f"{FP_IPS_PREFIX}{h}") > 0]
        assert len(populated) == 1, f"{len(populated)} hashes were credited, expected 1"

    def test_the_winner_still_records_its_cross_ip_count(self, clean):
        """The claim happens before the count is known, so the count is
        written in a second step. It must still land."""
        _seed_session(clean, "203.0.113.5")
        record_fingerprint(clean, "203.0.113.5", HASH_A)

        assert json.loads(clean.get(f"{FP_PREFIX}203.0.113.5"))["shared_ips"] == 1


class TestActorCountsAreAtomic:
    def test_concurrent_sightings_all_count(self, clean):
        """GET-then-SET lost increments under exactly the traffic these
        numbers are for: a farm hitting one fingerprint hard."""
        import threading

        ips = [f"203.0.113.{i}" for i in range(12)]
        for ip in ips:
            _seed_session(clean, ip)
        barrier = threading.Barrier(len(ips))

        def submit(ip):
            barrier.wait(timeout=5)
            record_fingerprint(clean, ip, HASH_A)

        threads = [threading.Thread(target=submit, args=(ip,)) for ip in ips]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        actor = clean.hgetall(f"{ACTOR_PREFIX}{HASH_A}")
        assert int(actor["sightings"]) == len(ips)

    def test_first_seen_never_moves_even_under_concurrency(self, clean):
        _seed_session(clean, "203.0.113.5")
        record_fingerprint(clean, "203.0.113.5", HASH_A)
        first = clean.hget(f"{ACTOR_PREFIX}{HASH_A}", "first_seen")

        _seed_session(clean, "198.51.100.7")
        record_fingerprint(clean, "198.51.100.7", HASH_A)

        assert clean.hget(f"{ACTOR_PREFIX}{HASH_A}", "first_seen") == first

    def test_a_v1_json_actor_record_does_not_break_the_v2_store(self, clean):
        """HINCRBY against a string is WRONGTYPE. The session store hit this
        exact trap once; the prefix carries a version for the same reason."""
        assert "v2" in ACTOR_PREFIX

        _seed_session(clean, "203.0.113.5")
        clean.set("mg:v1:actor:" + HASH_A, json.dumps({"sightings": 99}))

        assert record_fingerprint(clean, "203.0.113.5", HASH_A) is None
        assert int(clean.hget(f"{ACTOR_PREFIX}{HASH_A}", "sightings")) == 1

    def test_an_empty_binding_record_reads_as_unbound(self, clean):
        """Redis can hand back an empty string for a key mid-expiry."""
        _seed_session(clean, "203.0.113.5")
        clean.set(f"{FP_PREFIX}203.0.113.5", "")

        assert record_fingerprint(clean, "203.0.113.5", HASH_A) is None
        assert json.loads(clean.get(f"{FP_PREFIX}203.0.113.5"))["hash"] == HASH_A


class TestActorRecordsAreCapped:
    """`mg:v2:actor:*` was the last unbounded structure.

    A 30-day sliding TTL is fine when the number of distinct fingerprints is
    small and stable, which is what normal traffic looks like. It is not fine
    against a farm generating novel hashes: one key per hash, nothing evicting
    them for a month.

    Same failure class as `mg:v1:blocked_ips`, which grew with the number of
    distinct attackers until it was capped -- so the fix is the same
    ZREMRANGEBYRANK pattern from `live/redis_events.py`, keeping the most
    recently seen rather than the busiest.
    """

    def test_the_index_tracks_every_actor_touched(self, clean):
        from microguard.live.fingerprint import ACTOR_INDEX_KEY, _touch_actor

        for i in range(5):
            _touch_actor(clean, f"hash{i}", distinct_ips=1, ttl=3600)

        assert clean.zcard(ACTOR_INDEX_KEY) == 5

    def test_the_index_is_capped_and_evicts_the_least_recent(self, clean, monkeypatch):
        import microguard.live.fingerprint as fp

        monkeypatch.setattr(fp, "MAX_TRACKED_ACTORS", 3)
        for i in range(6):
            fp._touch_actor(clean, f"hash{i}", distinct_ips=1, ttl=3600)

        members = clean.zrange(fp.ACTOR_INDEX_KEY, 0, -1)

        assert len(members) == 3
        # Newest three survive; the first three were evicted by recency.
        assert set(members) == {"hash3", "hash4", "hash5"}

    def test_evicting_an_actor_drops_its_record_too(self, clean, monkeypatch):
        """An index entry without its hash is a lie the health panel would
        report as a tracked actor."""
        import microguard.live.fingerprint as fp

        monkeypatch.setattr(fp, "MAX_TRACKED_ACTORS", 2)
        for i in range(4):
            fp._touch_actor(clean, f"hash{i}", distinct_ips=1, ttl=3600)

        assert not clean.exists(f"{fp.ACTOR_PREFIX}hash0")
        assert clean.exists(f"{fp.ACTOR_PREFIX}hash3")

    def test_a_returning_actor_is_refreshed_not_duplicated(self, clean):
        """Re-seeing an actor must move it up the index, not add a second
        entry -- otherwise a patient adversary is evicted by its own return."""
        from microguard.live.fingerprint import ACTOR_INDEX_KEY, _touch_actor

        _touch_actor(clean, "steady", distinct_ips=1, ttl=3600)
        _touch_actor(clean, "noisy", distinct_ips=1, ttl=3600)
        _touch_actor(clean, "steady", distinct_ips=2, ttl=3600)

        assert clean.zcard(ACTOR_INDEX_KEY) == 2
        # "steady" was touched last, so it ranks highest.
        assert clean.zrange(ACTOR_INDEX_KEY, -1, -1) == ["steady"]

    def test_the_index_expires_so_it_cannot_outlive_its_records(self, clean):
        from microguard.live.fingerprint import ACTOR_INDEX_KEY, _touch_actor

        _touch_actor(clean, "h", distinct_ips=1, ttl=3600)

        assert clean.ttl(ACTOR_INDEX_KEY) > 0


class TestEvictionEdgeCases:
    """The eviction helper never raises on the /fp path, and no-ops when there
    is nothing to drop."""

    def test_a_redis_error_is_swallowed_not_raised(self):
        from unittest.mock import MagicMock

        from microguard.live.fingerprint import _evict_surplus_actors
        client = MagicMock()
        client.zcard.side_effect = redis.RedisError("down")
        # Must not raise — a failed eviction is a memory cost, not a 500.
        _evict_surplus_actors(client)

    def test_no_op_when_the_index_reports_over_cap_but_returns_no_members(self, monkeypatch):
        from unittest.mock import MagicMock

        import microguard.live.fingerprint as fp
        monkeypatch.setattr(fp, "MAX_TRACKED_ACTORS", 1)
        client = MagicMock()
        client.zcard.return_value = 5       # surplus > 0
        client.zrange.return_value = []     # ...but nothing came back
        fp._evict_surplus_actors(client)
        client.pipeline.assert_not_called()  # returned before touching the pipe
