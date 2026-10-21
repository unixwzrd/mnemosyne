"""Explicit synchronous deliveries; no live provider or implicit retry."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict, replace
import inspect
import sqlite3

import pytest

from mnemosyne.core.policy import PolicyRefusal
from mnemosyne.core.policy_evidence import EvidenceDeliveryReceipt, PolicyEvidence
from mnemosyne.core.policy_lifecycle import PolicyLifecycle, PolicyRecordRef
from mnemosyne.core.policy_read import PolicyReader
from mnemosyne.core.policy_store import RecordKind
from mnemosyne.runtime_context import bind_access_context
from tests.test_policy_read import add, context, fixture as fixture
from tests.test_policy_evidence import evidence as evidence, issue
from tests import test_policy_sources as source_tests
from tests.test_policy_projects import projects as projects, assign

source_fixture = source_tests.fixture


@pytest.mark.parametrize("kind,identity", [(RecordKind.WORKING,"w"), (RecordKind.EPISODIC,"e"), (RecordKind.CANONICAL,1)])
def test_delivery_is_fresh_payload_free_and_explicitly_repeatable(evidence, kind, identity):
    store, registry, _, api, _ = evidence
    add(store, identity, kind=kind, content="DELIVERY-SYNTHETIC")
    lease = issue(evidence, identity, kind=kind)
    calls, receipts = [], []
    changes = store.conn.total_changes
    with bind_access_context(context()):
        for _ in range(2):
            before = len(registry.calls)
            receipts.append(api.deliver(lease, lambda hit: calls.append(hit)))
            assert len(registry.calls) > before
    assert len(calls) == 2 and all(hit.content == "DELIVERY-SYNTHETIC" for hit in calls)
    assert receipts[0].decision_id != receipts[1].decision_id
    assert receipts[0].lease == receipts[1].lease == lease
    assert "DELIVERY-SYNTHETIC" not in str(asdict(receipts[0]))
    assert "content" not in asdict(receipts[0])["lease"]
    assert type(receipts[0]) is EvidenceDeliveryReceipt
    with pytest.raises(FrozenInstanceError):
        receipts[0].context_epoch = 99
    assert store.conn.total_changes == changes and not store.conn.in_transaction


@pytest.mark.parametrize("mutation", ["quarantine", "content", "delete", "grant", "context", "forged", "missing_context"])
def test_stale_lease_never_invokes_consumer(evidence, mutation):
    store, registry, lifecycle, api, _ = evidence
    add(store, "w")
    lease = issue(evidence)
    ctx = context()
    if mutation == "quarantine":
        lifecycle.quarantine(PolicyRecordRef(RecordKind.WORKING, "w"))
    elif mutation == "content":
        store.conn.execute("UPDATE working_memory SET content='changed' WHERE id='w'")
        store.conn.commit()
    elif mutation == "delete":
        store.conn.execute("DELETE FROM working_memory WHERE id='w'")
        store.conn.commit()
    elif mutation == "grant":
        registry.register(ctx, owners={"person:b"})
    elif mutation == "context":
        ctx = replace(ctx, context_id="ctx:other")
        registry.register(ctx)
    elif mutation == "forged":
        lease = replace(lease, destination="channel:other")
    delivered = []
    with bind_access_context(None if mutation == "missing_context" else ctx), pytest.raises(PolicyRefusal):
        api.deliver(lease, lambda hit: delivered.append(hit))
    assert not delivered


def test_consumer_quarantine_blocks_next_delivery(evidence):
    store, _, lifecycle, api, _ = evidence
    add(store, "w")
    lease = issue(evidence)
    delivered = []
    def consume(hit):
        delivered.append(hit.content)
        lifecycle.quarantine(PolicyRecordRef(RecordKind.WORKING, "w"))
    with bind_access_context(context()):
        receipt = api.deliver(lease, consume)
        assert receipt.lease.lifecycle_epoch == 0
        with pytest.raises(PolicyRefusal):
            api.deliver(lease, consume)
    assert delivered == ["allowed synthetic"] and not store.conn.in_transaction


def test_public_private_public_interleaving_uses_current_scope(evidence):
    store, registry, _, api, _ = evidence
    add(store, "w")
    lease = issue(evidence)
    other = context(context_id="ctx:private", principals={"person:b"})
    registry.register(other, owners={"person:b"})
    calls = []
    for ctx, allowed in ((context(),True), (other,False), (context(),True)):
        with bind_access_context(ctx):
            if allowed:
                api.deliver(lease, lambda hit: calls.append(hit.context_id))
            else:
                with pytest.raises(PolicyRefusal):
                    api.deliver(lease, lambda hit: calls.append(hit.context_id))
    assert calls == [context().context_id] * 2


@pytest.mark.parametrize("kind", ["async", "asyncgen", "generator"])
@pytest.mark.parametrize("object_form", [False, True])
def test_deferred_callable_refuses_before_resolving(evidence, kind, object_form):
    api = evidence[3]
    async def coroutine(hit):
        raise AssertionError("must not execute")
    async def asyncgen(hit):
        yield hit
    def generator(hit):
        yield hit
    callback = {"async":coroutine, "asyncgen":asyncgen, "generator":generator}[kind]
    if object_form:
        callback = type("Deferred", (), {"__call__":callback})()
    api.resolve = lambda lease: pytest.fail("must validate callable before resolving")
    with pytest.raises(TypeError, match="consumer must be synchronous"):
        api.deliver(None, callback)


@pytest.mark.parametrize("value", [None, 1, "not callable"])
def test_noncallables_refuse(evidence, value):
    with pytest.raises(TypeError):
        evidence[3].deliver(None, value)


@pytest.mark.parametrize("kind", ["coroutine", "generator", "asyncgen", "awaitable", "text", "false"])
def test_deferred_or_nonempty_return_refuses_without_running(evidence, kind):
    add(evidence[0], "w")
    lease = issue(evidence)
    ran, returned = [], []
    async def coroutine():
        ran.append(True)
    def generator():
        ran.append(True)
        yield "payload"
    async def asyncgen():
        ran.append(True)
        yield "payload"
    class Awaitable:
        def __await__(self):
            ran.append(True)
            yield
    def callback(hit):
        result = {"coroutine":coroutine, "generator":generator, "asyncgen":asyncgen,
                  "awaitable":Awaitable, "text":lambda: hit.content, "false":lambda: False}[kind]()
        returned.append(result)
        return result
    with bind_access_context(context()), pytest.raises(PolicyRefusal, match="unsupported_surface"):
        evidence[3].deliver(lease, callback)
    assert not ran
    if kind == "coroutine":
        assert inspect.getcoroutinestate(returned[0]) == inspect.CORO_CLOSED
    if kind == "generator":
        assert inspect.getgeneratorstate(returned[0]) == inspect.GEN_CLOSED


@pytest.mark.parametrize("error", [RuntimeError("callback failure"), asyncio.CancelledError("stop"), KeyboardInterrupt("stop")])
def test_callback_error_preserves_identity_clears_payload_and_never_retries(evidence, error):
    add(evidence[0], "w")
    lease = issue(evidence)
    calls = []
    def callback(hit):
        private = hit.content
        assert private == "allowed synthetic"
        calls.append(True)
        raise error
    with bind_access_context(context()), pytest.raises(type(error)) as caught:
        evidence[3].deliver(lease, callback)
    assert caught.value is error and calls == [True]
    tb = error.__traceback__
    checked = set()
    while tb is not None:
        if tb.tb_frame.f_code.co_name in {"callback", "deliver"}:
            assert not tb.tb_frame.f_locals
            checked.add(tb.tb_frame.f_code.co_name)
        tb = tb.tb_next
    assert checked == {"callback", "deliver"}
    assert not evidence[0].conn.in_transaction


def test_caller_transaction_refuses_before_consumer(evidence):
    store, _, _, api, _ = evidence
    add(store, "w")
    lease = issue(evidence)
    store.conn.execute("UPDATE working_memory SET content='pending' WHERE id='w'")
    with bind_access_context(context()), pytest.raises(PolicyRefusal, match="unsupported_surface"):
        api.deliver(lease, lambda hit: pytest.fail("consumer must not run"))
    assert store.conn.in_transaction
    store.conn.rollback()


def test_other_thread_does_not_inherit_context_or_consume(evidence):
    add(evidence[0], "w")
    lease = issue(evidence)
    calls = []
    with bind_access_context(context()), ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(evidence[3].deliver, lease, lambda hit: calls.append(hit))
        with pytest.raises(PolicyRefusal, match="missing_context"):
            future.result()
    assert not calls


@pytest.mark.parametrize("stage", [1,2,3,4,5])
def test_authority_failure_at_each_checkpoint_prevents_consumer(evidence, stage):
    store, _, _, _, original = evidence
    add(store, "w")
    lease = issue(evidence)
    calls, decisions = [], []
    def verify(ctx, **intent):
        decisions.append(True)
        if len(decisions) == stage:
            raise RuntimeError("private verifier details must not escape")
        return original(ctx, **intent)
    api = PolicyEvidence(PolicyReader(store, bank="bank:a", verify_context=verify))
    with bind_access_context(context()), pytest.raises(PolicyRefusal) as caught:
        api.deliver(lease, lambda hit: calls.append(hit))
    assert not calls and "private verifier" not in str(caught.value)


def test_denied_and_absent_never_reach_consumer_or_sql_content(evidence):
    store, _, _, api, _ = evidence
    add(store, "w")
    lease = issue(evidence)
    add(store, "denied", owner="person:b", content="DENIED-DELIVERY-CANARY")
    def guard(cursor, row):
        assert "DENIED-DELIVERY-CANARY" not in row
        return sqlite3.Row(cursor, row)
    store.conn.row_factory = guard
    for identity in ("denied", "absent"):
        with bind_access_context(context()), pytest.raises(PolicyRefusal, match="access_denied"):
            api.deliver(replace(lease, record_id=identity), lambda hit: pytest.fail("must not consume"))


def test_source_delivery_is_metadata_only_without_source_fetch(source_fixture, monkeypatch):
    media, store, registry, _ = source_fixture
    identity = source_tests.source(source_fixture)
    PolicyLifecycle(store).prepare()
    authority = sqlite3.connect(media.conn.execute("PRAGMA database_list").fetchone()[2])
    try:
        current = PolicyLifecycle(type(store)(authority))
        def verify(ctx, **intent):
            return replace(registry(ctx, **intent), lifecycle_epoch=current.epoch())
        api = PolicyEvidence(PolicyReader(store, bank="bank:a", verify_context=verify))
        import mnemosyne.core.source_verification as verification
        monkeypatch.setattr(verification, "verify_source_revision", lambda *a, **kw: pytest.fail("source fetch"))
        received = []
        with bind_access_context(source_tests.context()):
            lease = api.issue(RecordKind.SOURCE_REVISION, identity, destination="channel:a")
            receipt = api.deliver(lease, lambda hit: received.append(hit))
        assert receipt.lease == lease and received[0].record_id == identity
        assert not hasattr(received[0], "content") and not hasattr(received[0], "archive_locator")
    finally:
        authority.close()


def test_project_delivery_keeps_exact_selection(projects):
    store, catalog, ctx, registry, _ = projects
    add(store, "w")
    assign(catalog, "w")
    PolicyLifecycle(store).prepare()
    authority = sqlite3.connect(store.conn.execute("PRAGMA database_list").fetchone()[2])
    try:
        current = PolicyLifecycle(type(store)(authority))
        def verify(context, **intent):
            return replace(registry(context, **intent), lifecycle_epoch=current.epoch())
        api = PolicyEvidence(PolicyReader(store, bank="bank:a", verify_context=verify))
        received = []
        with bind_access_context(ctx):
            lease = api.issue(RecordKind.WORKING, "w", destination="channel:a", projects={"project:a"})
            api.deliver(lease, lambda hit: received.append(hit.record_id))
            with pytest.raises(PolicyRefusal):
                api.deliver(replace(lease, projects=frozenset({"project:b"})), lambda hit: received.append(hit.record_id))
        assert received == ["w"]
    finally:
        authority.close()


@pytest.mark.parametrize("changes", [{"lease":None}, {"decision_id":""}, {"context_id":""},
                                     {"context_epoch":True}, {"context_epoch":-1}])
def test_invalid_receipt_metadata_refuses(evidence, changes):
    add(evidence[0], "w")
    lease = issue(evidence)
    with pytest.raises((ValueError, TypeError)):
        EvidenceDeliveryReceipt(**(dict(lease=lease, decision_id="decision:a", context_id="ctx:a", context_epoch=1) | changes))


def test_legacy_catalog_still_cannot_deliver(fixture):
    store, _, reader = fixture
    add(store, "w")
    from mnemosyne.core.policy_evidence import EvidenceLease
    lease = EvidenceLease(RecordKind.WORKING, "w", "binding:fake", "bank:a", "channel:a", None, 0, "a"*64, "b"*64)
    with bind_access_context(context()), pytest.raises(PolicyRefusal, match="unsupported_surface"):
        PolicyEvidence(reader).deliver(lease, lambda hit: pytest.fail("consumer must not run"))
    assert store.get_domain().schema_version == 1
