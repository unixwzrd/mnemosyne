"""S2a synthetic byte observations, not protected-mode or expansion acceptance."""

import asyncio
import hashlib
import io
import socket
import sqlite3
from dataclasses import FrozenInstanceError

import pytest

from mnemosyne.core.media import MediaStore, MomentDraft
from mnemosyne.core.resolvers import CallableContentResolver, ResolvedMeta
from mnemosyne.core.source_verification import verify_source_revision


@pytest.fixture
def store(tmp_path):
    instance = MediaStore(db_path=tmp_path / "media.db")
    yield instance
    instance.conn.close()


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("unexpected socket or DNS use")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def revision(store, data=b"synthetic source", **kwargs):
    parent = store.upsert_asset(
        ref_kind="url", ref_value="archive://synthetic/original", modality="document",
    ).asset_id
    values = {"content_hash": hashlib.sha256(data).hexdigest(), "byte_size": len(data)}
    values.update(kwargs)
    registered = store.register_source_revision(parent, revision_key="v1", **values)
    return registered.revision_id


def resolver(open_func):
    def unexpected(*args, **kwargs):
        pytest.fail("verification must not call HEAD or presign")

    return CallableContentResolver(
        "synthetic", frozenset({"archive"}),
        head_func=unexpected, open_func=open_func, presign_func=unexpected,
    )


def verify(store, identity, source, **kwargs):
    return verify_source_revision(
        store, identity, locator="archive://synthetic/relocated", resolver=source, **kwargs,
    )


def test_verifies_registered_revision_without_storage_or_legacy_changes(store, tmp_path):
    original = b"private synthetic marker not to retain" * 4000
    identity = revision(store, original)
    parent = store.get_source_revision(identity)["asset_id"]
    store.add_moments(parent, [MomentDraft(kind="page", text="bounded excerpt")])
    rows_before = list(store.conn.iterdump())
    changes = store.conn.total_changes
    files_before = sorted(path.name for path in tmp_path.iterdir())
    handles = []

    def opened(uri):
        assert uri == "archive://synthetic/relocated"
        stream = io.BytesIO(original)
        handles.append(stream)
        return stream

    first = verify(store, identity, resolver(opened))
    second = verify(store, identity, resolver(opened))
    assert (first.status, first.reason) == ("verified", "bytes_match")
    assert first.expected_sha256 == first.observed_sha256 == hashlib.sha256(original).hexdigest()
    assert first.expected_byte_size == first.observed_byte_size == len(original)
    assert second.revision_id == first.revision_id == identity
    assert first.asset_id == parent
    assert first.locator == "archive://synthetic/relocated"
    assert first.checked_at.endswith("Z")
    assert all(handle.closed for handle in handles)
    assert store.conn.total_changes == changes
    assert list(store.conn.iterdump()) == rows_before
    assert sorted(path.name for path in tmp_path.iterdir()) == files_before
    assert store.get_source_revision(identity)["digest_status"] == "asserted"
    assert all(not isinstance(value, bytes) for value in vars(first).values())
    assert identity not in repr(first) and first.locator not in repr(first)
    assert first.expected_sha256 not in repr(first)
    with pytest.raises(FrozenInstanceError):
        first.status = "changed"


@pytest.mark.parametrize("data,budget", [(b"", 0), (b"", 20), (b"abc", 3), (b"a" * 65536, 65536)])
def test_exact_fit_and_empty_source_need_eof(store, data, budget):
    identity = revision(store, data)
    requests = []

    class Source(io.BytesIO):
        def read(self, size=-1):
            requests.append(size)
            assert 0 < size <= 65536
            return super().read(size)

    stream = Source(data)
    observation = verify(store, identity, resolver(lambda _: stream), max_bytes=budget)
    assert observation.status == "verified"
    assert requests[-1] == min(65536, budget - len(data) + 1)
    assert stream.closed


@pytest.mark.parametrize("original,current", [(b"old", b"new"), (b"old", b""), (b"", b"new")])
def test_changed_source_keeps_expected_revision_and_legacy_identity(store, original, current):
    identity = revision(store, original)
    before = store.get_source_revision(identity)
    observation = verify(store, identity, resolver(lambda _: io.BytesIO(current)))
    assert observation.status == "changed"
    assert observation.observed_sha256 == hashlib.sha256(current).hexdigest()
    assert observation.observed_byte_size == len(current)
    assert store.get_source_revision(identity) == before


def test_declared_size_mismatch_is_changed_even_when_digest_matches(store):
    identity = revision(store, b"same", byte_size=5)
    observation = verify(store, identity, resolver(lambda _: io.BytesIO(b"same")))
    assert observation.status == "changed"
    assert observation.expected_sha256 == observation.observed_sha256
    assert observation.expected_byte_size == 5 and observation.observed_byte_size == 4


def test_move_checks_explicit_location_without_rewriting_reference(store, tmp_path):
    data = b"image-shaped synthetic bytes"
    identity = revision(store, data)
    original = tmp_path / "old.bin"
    relocated = tmp_path / "new.bin"
    original.write_bytes(data)
    original.rename(relocated)
    source = CallableContentResolver(
        "local-fixture", frozenset({"file"}), open_func=lambda uri: relocated.open("rb"),
    )
    before = store.get_source_revision(identity)
    observation = verify_source_revision(store, identity, locator=relocated.as_uri(), resolver=source)
    assert observation.status == "verified"
    assert store.get_source_revision(identity) == before
    assert relocated.read_bytes() == data


@pytest.mark.parametrize("failure,status,reason", [
    (FileNotFoundError("secret path"), "missing", "source_missing"),
    (PermissionError("secret path"), "inaccessible", "source_inaccessible"),
    (TimeoutError("secret host"), "unavailable", "source_unavailable"),
    (ConnectionError("secret host"), "unavailable", "source_unavailable"),
    (RuntimeError("private resolver detail"), "unverified", "resolver_failure"),
])
@pytest.mark.parametrize("during_read", [False, True])
def test_resolver_failures_are_not_empty_success_and_close_stream(store, failure, status, reason, during_read):
    identity = revision(store)

    class Broken(io.BytesIO):
        def read(self, size=-1):
            raise failure

    stream = Broken(b"unread")

    def opened(uri):
        if during_read:
            return stream
        raise failure

    observation = verify(store, identity, resolver(opened))
    assert (observation.status, observation.reason) == (status, reason)
    assert observation.observed_sha256 is None
    assert str(failure) not in repr(observation)
    assert stream.closed == during_read
    stream.close()


def test_none_does_not_fabricate_missing_or_offline_status(store):
    identity = revision(store)
    assert verify(store, identity, resolver(lambda _: None)).status == "unavailable"
    observation = verify(store, identity, None)
    assert (observation.status, observation.reason) == ("unavailable", "resolver_unconfigured")


@pytest.mark.parametrize("value", [-1, True, 1.5, "64", None, 1073741825])
def test_invalid_budget_refuses_before_database_or_io(store, monkeypatch, value):
    monkeypatch.setattr(store, "get_source_revision", lambda _: pytest.fail("unexpected DB access"))
    with pytest.raises(ValueError, match="max_bytes"):
        verify(store, "unused", resolver(lambda _: pytest.fail("unexpected IO")), max_bytes=value)


@pytest.mark.parametrize("locator", ["", "relative/path", "/absolute/path", "data://payload", "javascript://x", "archive://x\n", "archive://" + "x" * 4096, None])
def test_invalid_locator_refuses_before_source_access(store, locator):
    with pytest.raises(ValueError, match="locator"):
        verify_source_revision(store, "unused", locator=locator, resolver=resolver(lambda _: pytest.fail("IO")))


def test_missing_revision_does_not_open_or_create_revision_schema(store):
    before = list(store.conn.iterdump())
    observation = verify(store, "not-registered", resolver(lambda _: pytest.fail("unexpected IO")))
    assert (observation.status, observation.reason) == ("missing", "revision_missing")
    assert list(store.conn.iterdump()) == before


def test_unsupported_representation_and_scheme_do_not_open(store):
    identity = revision(store, representation="http-response")
    source = resolver(lambda _: pytest.fail("unexpected IO"))
    assert verify(store, identity, source).reason == "unsupported_representation"
    store.conn.execute("UPDATE media_source_revisions SET representation = 'original-bytes'")
    source.schemes = frozenset({"other"})
    assert verify(store, identity, source).reason == "unsupported_scheme"


@pytest.mark.parametrize("column,value", [
    ("content_hash", "bad"), ("byte_size", -1), ("byte_size", 0.5),
    ("digest_status", "verified"), ("asset_id", ""),
])
def test_corrupted_revision_metadata_cannot_claim_verification(store, column, value):
    identity = revision(store)
    store.conn.execute(f"UPDATE media_source_revisions SET {column} = ?", (value,))
    observation = verify(store, identity, resolver(lambda _: pytest.fail("unexpected IO")))
    assert observation.reason == "invalid_revision"


def test_known_oversize_refuses_without_io(store):
    identity = revision(store)
    observation = verify(store, identity, resolver(lambda _: pytest.fail("unexpected IO")), max_bytes=3)
    assert observation.reason == "expected_size_exceeds_budget"
    assert observation.observed_byte_size is observation.observed_sha256 is None


def test_unknown_length_is_bounded_and_prefix_hash_is_never_evidence(store):
    identity = revision(store, b"abcdef", byte_size=None)
    requests = []

    class Endless(io.BytesIO):
        def read(self, size=-1):
            requests.append(size)
            return b"x" * min(size, 2)

    stream = Endless()
    observation = verify(store, identity, resolver(lambda _: stream), max_bytes=3)
    assert observation.status == "limit_exceeded"
    assert observation.observed_byte_size == 4
    assert observation.observed_sha256 is None
    assert requests == [4, 2]
    assert stream.closed


@pytest.mark.parametrize("chunk", [None, "text", bytearray(b"a"), b"x" * 65537])
def test_invalid_stream_never_verifies(store, chunk):
    identity = revision(store, byte_size=None)

    class Invalid(io.BytesIO):
        def read(self, size=-1):
            return chunk

    stream = Invalid()
    observation = verify(store, identity, resolver(lambda _: stream))
    assert (observation.status, observation.reason) == ("unverified", "invalid_stream")
    assert observation.observed_sha256 is None and stream.closed


def test_forged_head_hash_does_not_replace_actual_bytes(store):
    identity = revision(store)
    source = resolver(lambda _: io.BytesIO(b"different bytes"))
    source.head_func = lambda _: ResolvedMeta(True, content_hash=store.get_source_revision(identity)["content_hash"])
    assert verify(store, identity, source).status == "changed"


def test_close_failure_refuses_complete_hash_claim(store):
    identity = revision(store)

    class BadClose(io.BytesIO):
        def close(self):
            super().close()
            raise OSError("private path in close error")

    stream = BadClose(b"synthetic source")
    observation = verify(store, identity, resolver(lambda _: stream))
    assert observation.reason == "close_failed"
    assert observation.observed_sha256 is None and stream.closed


@pytest.mark.parametrize("exception", [KeyboardInterrupt, asyncio.CancelledError])
@pytest.mark.parametrize("during_read", [False, True])
def test_cancellation_propagates_and_acquired_stream_is_closed(store, exception, during_read):
    identity = revision(store)

    class Cancelled(io.BytesIO):
        def read(self, size=-1):
            raise exception()

    stream = Cancelled()

    def opened(uri):
        if during_read:
            return stream
        raise exception()

    with pytest.raises(exception):
        verify(store, identity, resolver(opened))
    assert stream.closed == during_read
    stream.close()


def test_read_only_transaction_remains_caller_owned_and_errors_propagate(store):
    identity = revision(store)
    store.conn.commit()
    store.conn.execute("PRAGMA query_only = ON")
    store.conn.execute("BEGIN")
    changes = store.conn.total_changes
    observation = verify(store, identity, resolver(lambda _: io.BytesIO(b"synthetic source")))
    assert observation.status == "verified" and store.conn.in_transaction
    assert store.conn.total_changes == changes
    store.conn.rollback()
    store.conn.close()
    with pytest.raises(sqlite3.ProgrammingError):
        verify(store, identity, resolver(lambda _: pytest.fail("unexpected IO")))
