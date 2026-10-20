"""Synthetic SP2 exact-byte expansion; no live stores, providers or activation."""

from dataclasses import replace
import asyncio
import builtins
import hashlib
import io
import socket
import sqlite3

import pytest

from mnemosyne.core.media import MediaStore
from mnemosyne.core.policy import AccessContext, MemoryPolicy, PolicyDefinition, PolicyRefusal, RefusalReason
from mnemosyne.core.policy_read import BankReadGrant, PolicyReader
from mnemosyne.core.policy_store import PolicyStore, RecordKind
from mnemosyne.core.resolvers import CallableContentResolver
from mnemosyne.core.source_expansion import (
    MAX_EXPANSION_BYTES, AuthorizedSourceBytes, SourceExpander, SourceExpansionError, SourceExpansionGrant,
)
from mnemosyne.runtime_context import bind_access_context


class Stream(io.BytesIO):
    def __init__(self, host, data):
        super().__init__(data)
        self.host, self.read_sizes, self.close_calls = host, [], 0

    def read(self, count):
        self.read_sizes.append(count)
        value = super().read(count)
        if self.host.read_hook:
            self.host.read_hook(self, count)
        return value

    def close(self):
        self.close_calls += 1
        super().close()
        if self.host.close_hook:
            self.host.close_hook()


class Host:
    """Trusted fixture authority, not a substitute for authenticated adapters."""

    def __init__(self, tmp_path):
        self.media = MediaStore(db_path=tmp_path / "expansion.db")
        self.store = PolicyStore(self.media.conn)
        self.store.prepare("domain:a")
        self.store.register_definition(PolicyDefinition("synthetic", 1, ("unclassified", "internal", "restricted")))
        self.context = AccessContext(context_id="ctx:a", epoch=1, policy_id="synthetic", policy_version=1,
            issuer="fixture-host", platform="fixture", principals={"person:a"}, classification_ceiling="internal",
            purpose="engineering", assurance="authenticated", banks={"bank:a"}, audiences={"team"},
            destinations={"channel:a"}, operations={"read:bank", "read:source-revision", "expand:source-revision"})
        self.data = b"Synthetic original evidence, kept outside the database."
        self.policy = MemoryPolicy("synthetic", 1, "internal", "person:a", "manual", audiences={"team"}, purposes={"engineering"})
        self.locator = "archive://fixture/relocated-source"
        self.streams, self.opens, self.decisions, self.phases = [], [], [], []
        self.hook = self.read_hook = self.close_hook = self.override = None
        self.factory = lambda: Stream(self, self.data)
        self.resolver = CallableContentResolver("fixture-confined", frozenset({"archive"}), open_func=self.open,
            head_func=lambda *a: pytest.fail("HEAD must not supply integrity"),
            presign_func=lambda *a, **k: pytest.fail("presigning bypasses exact-byte verification"))
        self.reader = PolicyReader(self.store, bank="bank:a", verify_context=self.metadata)
        self.expander = SourceExpander(self.reader, authorize_source=self.authorize)
        self.identity = self.register()

    def register(self, key="initial", *, data=None, policy=None, bind=True, size=True, representation="original-bytes"):
        data = self.data if data is None else data
        asset = self.media.upsert_asset(ref_kind="url", ref_value=f"archive://fixture/{key}", modality="document")
        revision = self.media.register_source_revision(asset.asset_id, revision_key=key,
            content_hash=hashlib.sha256(data).hexdigest(), byte_size=len(data) if size else None, representation=representation)
        if bind:
            self.store.bind(RecordKind.SOURCE_REVISION, revision.revision_id, policy or self.policy)
        return revision.revision_id

    def metadata(self, ctx, *, bank, destination):
        self.decisions.append((ctx.fingerprint(), bank, destination))
        if ctx != self.context:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return BankReadGrant(ctx.fingerprint(), "domain:a", bank, destination,
                             f"metadata:{len(self.decisions)}", {"person:a"})

    def authorize(self, ctx, *, intent, phase):
        self.phases.append((phase, intent))
        if self.hook:
            self.hook(phase, intent)
        if ctx != self.context:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        if self.override:
            return self.override(ctx, intent, phase)
        return SourceExpansionGrant(intent.fingerprint(), phase, f"expansion:{len(self.phases)}", self.locator, self.resolver)

    def open(self, locator):
        self.opens.append(locator)
        stream = self.factory()
        if stream is not None:
            self.streams.append(stream)
        return stream

    def expand(self, identity=None, *, context=None, **kwargs):
        with bind_access_context(context or self.context):
            return self.expander.expand(identity or self.identity, destination="channel:a", **kwargs)


@pytest.fixture
def host(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected network or resolver registry")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    from mnemosyne.core import resolvers
    monkeypatch.setattr(resolvers, "get_resolver", forbidden)
    instance = Host(tmp_path)
    yield instance
    instance.media.conn.close()


def test_exact_original_bytes_one_open_closed_before_release_and_no_writes(host):
    before = host.media.conn.total_changes
    initial = list(host.media.conn.iterdump())

    def release(phase, intent):
        if phase == "release":
            assert host.streams[0].closed

    host.hook = release
    result = host.expand()
    assert type(result) is AuthorizedSourceBytes and result.content == host.data
    assert result.content_sha256 == hashlib.sha256(result.content).hexdigest()
    assert result.source.record_id == host.identity and result.destination == "channel:a"
    assert result.release_decision_id.startswith("expansion:")
    assert host.opens == [host.locator]
    assert host.streams[0].closed and host.streams[0].close_calls == 1
    assert [phase for phase, _ in host.phases] == ["open", "read", "read", "release"]
    assert len(host.decisions) == 1 + len(host.phases)
    assert host.media.conn.total_changes == before and not host.media.conn.in_transaction
    assert list(host.media.conn.iterdump()) == initial
    assert host.data.decode() not in "\n".join(initial)
    assert host.identity not in repr(result) and host.locator not in repr(result)
    assert not hasattr(result, "locator")


@pytest.mark.parametrize("data,budget", [(b"", 0), (b"x", 1), (b"x" * 65536, 65536), (b"x" * MAX_EXPANSION_BYTES, MAX_EXPANSION_BYTES)])
def test_exact_fit_and_eof_are_required(host, data, budget):
    host.data = data
    identity = host.register("fit", data=data)
    assert host.expand(identity, max_bytes=budget).content == data
    assert 1 in host.streams[-1].read_sizes
    assert all(0 < count <= 65536 for count in host.streams[-1].read_sizes)
    assert len(host.opens) == 1 and host.streams[-1].close_calls == 1


@pytest.mark.parametrize("identity_kind", ["missing", "unbound", "restricted", "no-audience"])
def test_denied_or_absent_never_reaches_expansion_callback_or_source_io(host, identity_kind):
    identity = "missing"
    if identity_kind != "missing":
        policy = replace(host.policy, classification="restricted") if identity_kind == "restricted" else host.policy
        if identity_kind == "no-audience":
            policy = replace(policy, classification="unclassified", audiences=frozenset())
        identity = host.register(identity_kind, bind=identity_kind != "unbound", policy=policy)
    with pytest.raises(PolicyRefusal) as error:
        host.expand(identity)
    assert error.value.reason is RefusalReason.ACCESS_DENIED
    assert host.opens == [] and host.phases == []


@pytest.mark.parametrize("missing", ["read:bank", "read:source-revision", "expand:source-revision"])
def test_each_operation_is_required(host, missing):
    host.context = replace(host.context, operations=host.context.operations - {missing})
    with pytest.raises(PolicyRefusal):
        host.expand()
    assert not host.opens and not host.phases


@pytest.mark.parametrize("budget", [-1, True, 1.5, "1", MAX_EXPANSION_BYTES + 1])
def test_invalid_budget_refuses_without_source_or_metadata_calls(host, budget):
    with pytest.raises(ValueError):
        host.expand(max_bytes=budget)
    assert host.decisions == [] and host.opens == []


def test_missing_context_refuses_without_io(host):
    with bind_access_context(None), pytest.raises(PolicyRefusal):
        host.expander.expand(host.identity, destination="channel:a")
    assert not host.decisions and not host.opens


def test_caller_transaction_is_never_committed_or_held_during_io(host):
    conn = host.media.conn
    conn.execute("BEGIN")
    with pytest.raises(PolicyRefusal) as error:
        host.expand()
    assert error.value.reason is RefusalReason.UNSUPPORTED_SURFACE
    assert conn.in_transaction and not host.opens and not host.decisions
    conn.rollback()


def test_unknown_length_overflow_never_returns_partial_or_reopens(host):
    identity = host.register("unknown-size", size=False)
    with pytest.raises(SourceExpansionError) as error:
        host.expand(identity, max_bytes=3)
    assert error.value.code == "limit_exceeded"
    assert len(host.opens) == 1 and host.streams[-1].closed
    assert "release" not in [p for p, _ in host.phases]


def test_known_oversize_refuses_before_resolver_authorization(host):
    with pytest.raises(SourceExpansionError) as error:
        host.expand(max_bytes=1)
    assert error.value.code == "limit_exceeded" and not host.phases and not host.opens


def test_changed_bytes_refuse_without_reopening_for_result(host):
    host.data = b"different same-location source"
    with pytest.raises(SourceExpansionError) as error:
        host.expand()
    assert error.value.code == "changed"
    assert len(host.opens) == 1 and host.streams[-1].closed


def test_source_changes_after_open_return_does_not_change_verified_result(host):
    original = host.data

    def once():
        stream = Stream(host, original)
        host.data = b"would be different on another open"
        return stream

    host.factory = once
    assert host.expand().content == original
    assert len(host.opens) == 1


@pytest.mark.parametrize("phase", ["open", "read", "release"])
def test_host_revocation_at_each_phase_discards_bytes(host, phase):
    def revoke(current, intent):
        if current == phase:
            host.context = replace(host.context, epoch=host.context.epoch + 1)

    host.hook = revoke
    with pytest.raises(PolicyRefusal):
        host.expand()
    assert len(host.opens) == (0 if phase == "open" else 1)
    if host.streams:
        assert host.streams[0].closed


def test_policy_binding_revocation_during_read_stops_before_next_read(host):
    def revoke(stream, count):
        host.media.conn.execute("DELETE FROM main.policy_bindings WHERE record_id=?", (host.identity,))
        host.media.conn.commit()

    host.read_hook = revoke
    with pytest.raises(PolicyRefusal):
        host.expand()
    assert len(host.streams[0].read_sizes) == 1 and host.streams[0].closed


def test_source_metadata_change_during_close_discards_verified_buffer(host):
    def change():
        host.media.conn.execute("UPDATE main.media_source_revisions SET content_hash=? WHERE revision_id=?", ("b" * 64, host.identity))
        host.media.conn.commit()

    host.close_hook = change
    with pytest.raises(PolicyRefusal):
        host.expand()
    assert host.streams[0].closed and len(host.opens) == 1


def test_participant_context_change_without_host_epoch_change_refuses(host):
    import mnemosyne.runtime_context as runtime

    def change(phase, intent):
        if phase == "read":
            runtime._access_context.set(replace(host.context, principals=frozenset({"person:a", "person:b"})))

    host.hook = change
    with pytest.raises(PolicyRefusal):
        host.expand()
    assert host.streams[0].read_sizes == [] and host.streams[0].closed


@pytest.mark.parametrize("change", ["fingerprint", "phase", "locator", "resolver"])
def test_mismatched_or_changed_grants_refuse(host, change):
    def wrong(ctx, intent, phase):
        fingerprint = "a" * 64 if change == "fingerprint" else intent.fingerprint()
        actual_phase = "release" if change == "phase" else phase
        locator, resolver = host.locator, host.resolver
        if phase == "read" and change == "locator":
            locator = "archive://fixture/different"
        if phase == "read" and change == "resolver":
            resolver = CallableContentResolver("other", frozenset({"archive"}), open_func=lambda _: pytest.fail("wrong resolver opened"))
        return SourceExpansionGrant(fingerprint, actual_phase, "wrong", locator, resolver)

    host.override = wrong
    with pytest.raises(PolicyRefusal):
        host.expand()
    if host.streams:
        assert host.streams[0].closed and host.streams[0].read_sizes == []


def test_prior_request_grant_cannot_be_replayed(host):
    saved = []

    def save(ctx, intent, phase):
        grant = SourceExpansionGrant(intent.fingerprint(), phase, "saved", host.locator, host.resolver)
        if phase == "open":
            saved.append(grant)
        return grant

    host.override = save
    host.expand()
    host.override = lambda *args: saved[0]
    with pytest.raises(PolicyRefusal):
        host.expand()
    assert len(host.opens) == 1


@pytest.mark.parametrize("exception,code", [
    (FileNotFoundError("private-location"), "missing"), (PermissionError("private-location"), "inaccessible"),
    (TimeoutError("private-location"), "unavailable"), (ConnectionError("private-location"), "unavailable"),
    (RuntimeError("private-location"), "unverified"),
])
def test_source_open_errors_are_content_free(host, exception, code):
    def broken():
        raise exception

    host.factory = broken
    with pytest.raises(SourceExpansionError) as error:
        host.expand()
    assert error.value.code == code and "private-location" not in str(error.value)
    assert len(host.opens) == 1


def test_missing_stream_is_unavailable(host):
    host.factory = lambda: None
    with pytest.raises(SourceExpansionError) as error:
        host.expand()
    assert error.value.code == "unavailable"


@pytest.mark.parametrize("value", ["not bytes", bytearray(b"bytes"), b"x" * 70000])
def test_malformed_or_oversized_reads_never_return_content(host, value):
    class Invalid(Stream):
        def read(self, count):
            return value

    host.factory = lambda: Invalid(host, host.data)
    with pytest.raises(SourceExpansionError) as error:
        host.expand()
    assert error.value.code == "unverified" and host.streams[0].closed


def test_close_failure_suppresses_even_matching_bytes(host):
    def fail():
        raise OSError("private-close-message")

    host.close_hook = fail
    with pytest.raises(SourceExpansionError) as error:
        host.expand()
    assert error.value.code == "unverified" and host.streams[0].closed
    assert "private-close-message" not in str(error.value)


def test_keyboard_interrupt_closes_stream_without_release(host):
    def cancel(stream, count):
        raise KeyboardInterrupt()

    host.read_hook = cancel
    with pytest.raises(KeyboardInterrupt):
        host.expand()
    assert host.streams[0].closed and "release" not in [p for p, _ in host.phases]


def test_async_grant_is_closed_and_refused(host):
    async def value():
        return None

    host.override = lambda *args: value()
    with pytest.raises(PolicyRefusal) as error:
        host.expand()
    assert error.value.reason is RefusalReason.UNSUPPORTED_SURFACE and not host.opens


def test_host_exception_does_not_expose_request_or_source(host):
    host.override = lambda *args: (_ for _ in ()).throw(RuntimeError("private-authority"))
    with pytest.raises(PolicyRefusal) as error:
        host.expand()
    assert str(error.value) == "policy_refused:context_unavailable"
    assert not host.opens


def test_unsupported_representation_or_scheme_has_no_fallback(host):
    other = host.register("representation", representation=" original-bytes ")
    with pytest.raises(PolicyRefusal):
        host.expand(other)
    host.locator = "https://example.invalid/not-approved"
    with pytest.raises(PolicyRefusal):
        host.expand()
    assert not host.opens


def test_owner_creating_transaction_during_read_is_not_committed(host):
    host.read_hook = lambda stream, count: host.media.conn.execute("BEGIN")
    with pytest.raises(PolicyRefusal):
        host.expand()
    assert host.media.conn.in_transaction and host.streams[0].closed
    host.media.conn.rollback()


def test_readonly_catalog_can_expand_and_no_original_payload_is_written(host):
    conn = sqlite3.connect(f"file:{host.media.db_path}?mode=ro", uri=True)
    try:
        reader = PolicyReader(PolicyStore(conn), bank="bank:a", verify_context=host.metadata)
        host.expander = SourceExpander(reader, authorize_source=host.authorize)
        assert host.expand().content == host.data
    finally:
        conn.close()


@pytest.mark.parametrize("locator", ["data://inline", "javascript://payload", "relative/path", "archive://bad\0source"])
def test_invalid_grant_locator_is_refused_without_open(host, locator):
    host.locator = locator
    with pytest.raises(PolicyRefusal) as error:
        host.expand()
    assert error.value.reason is RefusalReason.CONTEXT_UNAVAILABLE and not host.opens


def test_explicit_unclassified_source_still_needs_full_policy(host):
    identity = host.register("unclassified", policy=replace(host.policy, classification="unclassified"))
    assert host.expand(identity).source.classification == "unclassified"
    other = host.register("unclassified-unbound", bind=False)
    with pytest.raises(PolicyRefusal):
        host.expand(other)
    assert len(host.opens) == 1


def test_corrected_revision_never_reuses_predecessor_permission(host):
    asset = host.media.get_source_revision(host.identity)["asset_id"]
    revision = host.media.register_source_revision(asset, revision_key="correction",
        content_hash=hashlib.sha256(host.data).hexdigest(), predecessor_revision_id=host.identity)
    with pytest.raises(PolicyRefusal):
        host.expand(revision.revision_id)
    assert host.opens == []


def test_close_time_grant_revocation_discards_buffer(host):
    host.close_hook = lambda: setattr(host, "context", replace(host.context, epoch=2))
    with pytest.raises(PolicyRefusal):
        host.expand()
    assert host.streams[0].closed


def test_failed_release_does_not_keep_a_second_plaintext_copy_in_its_frame(host):
    def deny(phase, intent):
        if phase == "release":
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)

    host.hook = deny
    with pytest.raises(PolicyRefusal) as error:
        host.expand()
    frame = error.value.__traceback__
    while frame:
        if frame.tb_frame.f_code is SourceExpander.expand.__code__:
            assert frame.tb_frame.f_locals.get("content") is None
            assert frame.tb_frame.f_locals["buffer"] == bytearray()
        frame = frame.tb_next


def test_bytes_subclass_with_misleading_length_is_not_a_valid_stream_chunk(host):
    class Misleading(bytes):
        def __len__(self):
            return 0

    class Invalid(Stream):
        def read(self, count):
            return Misleading(b"not an empty source")

    host.factory = lambda: Invalid(host, host.data)
    with pytest.raises(SourceExpansionError) as error:
        host.expand()
    assert error.value.code == "unverified" and host.streams[0].closed


def test_release_requires_its_own_phase_grant(host):
    prior = []

    def grant(ctx, intent, phase):
        if phase == "release":
            return prior[-1]
        value = SourceExpansionGrant(intent.fingerprint(), phase, "fixture", host.locator, host.resolver)
        prior.append(value)
        return value

    host.override = grant
    with pytest.raises(PolicyRefusal):
        host.expand()
    assert host.streams[0].closed


def test_read_refusal_does_not_return_verifier_traceback_with_previous_chunk(host):
    def revoke(stream, count):
        host.context = replace(host.context, epoch=2)

    host.read_hook = revoke
    with pytest.raises(PolicyRefusal) as error:
        host.expand()
    names = []
    frame = error.value.__traceback__
    while frame:
        names.append(frame.tb_frame.f_code.co_name)
        frame = frame.tb_next
    assert "verify_source_revision" not in names
    assert host.streams[0].closed


def assert_no_verifier_payload(error):
    pending, seen = [error], set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        frame = current.__traceback__
        while frame:
            if frame.tb_frame.f_code.co_name == "verify_source_revision":
                assert frame.tb_frame.f_locals == {}
            if frame.tb_frame.f_code is SourceExpander.expand.__code__:
                assert frame.tb_frame.f_locals.get("content") is None
                assert frame.tb_frame.f_locals["buffer"] == bytearray()
            assert not any(type(value) is bytes and value.startswith(b"CANCEL-PAYLOAD:")
                           for value in frame.tb_frame.f_locals.values())
            frame = frame.tb_next
        pending.extend(related for related in (current.__cause__, current.__context__) if related is not None)
        if isinstance(current, getattr(builtins, "BaseExceptionGroup", ())):
            pending.extend(current.exceptions)


@pytest.mark.parametrize("kind", [KeyboardInterrupt, asyncio.CancelledError, SystemExit])
@pytest.mark.parametrize("site", ["authority", "stream"])
def test_multichunk_cancellation_preserves_identity_but_not_plaintext_frames(host, kind, site):
    host.data = b"CANCEL-PAYLOAD:" + b"x" * 70000
    identity = host.register("cancel-multichunk")
    reads = []
    cancellation = kind("synthetic cancellation")

    def read(stream, count):
        reads.append(count)
        if len(reads) == 2 and site == "stream":
            raise cancellation

    def gate(phase, intent):
        if phase == "read" and len(reads) == 1 and site == "authority":
            raise cancellation

    host.read_hook, host.hook = read, gate
    with pytest.raises(kind) as error:
        host.expand(identity, max_bytes=1048576)
    assert error.value is cancellation and error.value.args == ("synthetic cancellation",)
    assert_no_verifier_payload(error.value)
    assert host.streams[0].closed and host.streams[0].close_calls == 1
    assert "release" not in [phase for phase, _ in host.phases]


@pytest.mark.parametrize("group", [False, True])
def test_cancellation_cause_context_cycles_and_groups_are_cleared(host, group):
    if group and not hasattr(builtins, "BaseExceptionGroup"):
        pytest.skip("exception groups require Python 3.11+")
    host.data = b"CANCEL-PAYLOAD:" + b"x" * 70000
    identity = host.register("cancel-chained")
    cancellation = KeyboardInterrupt("synthetic cancellation")
    reads = []

    def read(stream, count):
        reads.append(count)
        if len(reads) == 2:
            chunk = b"CANCEL-PAYLOAD:chained-local"
            try:
                raise RuntimeError("synthetic prior failure")
            except RuntimeError as prior:
                assert chunk
                prior.__cause__ = cancellation
                if group:
                    raise builtins.BaseExceptionGroup("synthetic group", [cancellation, prior])
                raise cancellation from prior

    host.read_hook = read
    with pytest.raises(BaseException) as error:
        host.expand(identity, max_bytes=1048576)
    assert_no_verifier_payload(error.value)
    assert host.streams[0].closed
