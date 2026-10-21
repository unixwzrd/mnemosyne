"""Payload-free lease/reload probes using disposable v2 catalogs only."""

from dataclasses import FrozenInstanceError, asdict, replace
from pathlib import Path
import runpy
import sqlite3

import pytest

from mnemosyne.core.policy import PolicyRefusal
from mnemosyne.core.policy_evidence import EvidenceLease, PolicyEvidence
from mnemosyne.core.policy_lifecycle import PolicyLifecycle, PolicyRecordRef
from mnemosyne.core.policy_read import PolicyReader
from mnemosyne.core.policy_store import RecordKind
from mnemosyne.runtime_context import bind_access_context
from tests.test_policy_read import add, context, fixture as fixture
from tests import test_policy_sources as source_tests
from tests.test_policy_sources import source, context as source_context
from tests.test_policy_projects import projects as projects, assign

source_fixture = source_tests.fixture


@pytest.fixture
def evidence(fixture):
    store, registry, _ = fixture
    store.conn.execute("PRAGMA journal_mode=WAL")
    lifecycle = PolicyLifecycle(store)
    lifecycle.prepare()
    path = store.conn.execute("PRAGMA database_list").fetchone()[2]
    authority = sqlite3.connect(path)
    current = PolicyLifecycle(type(store)(authority))

    def verify(ctx, **intent):
        grant = registry(ctx, **intent)
        return replace(grant, decision_id=f"decision:{len(registry.calls)}", lifecycle_epoch=current.epoch())

    reader = PolicyReader(store, bank="bank:a", verify_context=verify)
    yield store, registry, lifecycle, PolicyEvidence(reader), verify
    authority.close()


def issue(fx, identity="w", *, kind=RecordKind.WORKING):
    with bind_access_context(context()):
        return fx[3].issue(kind, identity, destination="channel:a")


@pytest.mark.parametrize("kind,identity", [(RecordKind.WORKING,"w"), (RecordKind.EPISODIC,"e"), (RecordKind.CANONICAL,1)])
def test_positive_native_lease_is_payload_free_and_resolve_reloads(evidence, kind, identity):
    store, registry, _, api, _ = evidence
    add(store, identity, kind=kind, content="synthetic evidence")
    before = store.conn.total_changes
    lease = issue(evidence, identity, kind=kind)
    assert type(lease) is EvidenceLease and lease.lifecycle_epoch == 0
    assert "content" not in asdict(lease) and "synthetic evidence" not in repr(lease)
    with pytest.raises(FrozenInstanceError):
        lease.bank = "changed"
    with bind_access_context(context()):
        first, second = api.resolve(lease), api.resolve(lease)
    assert first.content == second.content == "synthetic evidence"
    assert first.decision_id != second.decision_id
    assert lease == issue(evidence, identity, kind=kind)
    assert store.conn.total_changes == before and not store.conn.in_transaction
    assert len(registry.calls) > 3


@pytest.mark.parametrize("mutation", ["content", "binding", "delete"])
def test_changed_native_value_refuses_existing_lease(evidence, mutation):
    store, _, _, api, _ = evidence
    add(store, "w")
    lease = issue(evidence)
    sql = {"content": "UPDATE working_memory SET content='changed' WHERE id='w'",
           "binding": "UPDATE policy_bindings SET binding_id='binding:changed' WHERE record_id='w'",
           "delete": "DELETE FROM working_memory WHERE id='w'"}[mutation]
    store.conn.execute(sql)
    store.conn.commit()
    with bind_access_context(context()), pytest.raises(PolicyRefusal, match="access_denied"):
        api.resolve(lease)


@pytest.mark.parametrize("root", ["w", "other"])
def test_quarantine_invalidates_even_unrelated_old_epoch(evidence, root):
    store, _, lifecycle, api, _ = evidence
    add(store, "w")
    add(store, "other")
    lease = issue(evidence)
    lifecycle.quarantine(PolicyRecordRef(RecordKind.WORKING, root))
    with bind_access_context(context()), pytest.raises(PolicyRefusal, match="access_denied"):
        api.resolve(lease)
    if root == "other":
        fresh = issue(evidence)
        assert fresh.lifecycle_epoch == 1
        with bind_access_context(context()):
            assert api.resolve(fresh).content == "allowed synthetic"


@pytest.mark.parametrize("changes", [{"epoch":2}, {"purpose":"research"}, {"principals":{"person:a","person:b"}},
    {"classification_ceiling":"sealed"}, {"destinations":{"channel:a","channel:b"}}, {"context_id":"ctx:b"}])
def test_context_changes_do_not_reuse_prior_evidence(evidence, changes):
    store, registry, _, api, _ = evidence
    add(store, "w")
    lease = issue(evidence)
    ctx = context(**changes)
    registry.register(ctx)
    with bind_access_context(ctx), pytest.raises(PolicyRefusal, match="access_denied"):
        api.resolve(lease)


@pytest.mark.parametrize("changes", [{"owners":{"person:a","person:b"}}, {"tenants":set()}, {"domain_id":"domain:other"}])
def test_changed_trusted_grant_invalidates_lease(evidence, changes):
    store, registry, _, api, _ = evidence
    add(store, "w")
    lease = issue(evidence)
    registry.register(context(), **changes)
    with bind_access_context(context()), pytest.raises(PolicyRefusal, match="access_denied"):
        api.resolve(lease)


@pytest.mark.parametrize("change", [{"binding_id":"binding:forged"}, {"bank":"bank:other"},
    {"scope_fingerprint":"0"*64}, {"value_fingerprint":"0"*64}, {"lifecycle_epoch":1},
    {"destination":"channel:other"}, {"record_id":"missing"}])
def test_constructing_a_lease_never_grants_access(evidence, change):
    add(evidence[0], "w")
    lease = replace(issue(evidence), **change)
    with bind_access_context(context()), pytest.raises(PolicyRefusal, match="access_denied"):
        evidence[3].resolve(lease)


@pytest.mark.parametrize("identity,policy", [("missing",None), ("denied",{"owner":"person:b"}),
    ("denied",{"classification":"sealed"})])
def test_issue_denied_and_absent_have_identical_error_without_content(evidence, identity, policy):
    store = evidence[0]
    if policy is not None:
        add(store, identity, content="DENIED-LEASE-CANARY", **policy)
    def guard(cursor, row):
        assert "DENIED-LEASE-CANARY" not in row
        return sqlite3.Row(cursor, row)
    store.conn.row_factory = guard
    with pytest.raises(PolicyRefusal) as caught:
        issue(evidence, identity)
    assert str(caught.value) == "policy_refused:access_denied"


@pytest.mark.parametrize("action", ["issue", "resolve"])
def test_caller_transactions_refuse_without_losing_pending_work(evidence, action):
    store, _, _, api, _ = evidence
    add(store, "w")
    lease = issue(evidence)
    store.conn.execute("UPDATE working_memory SET content='pending' WHERE id='w'")
    with bind_access_context(context()), pytest.raises(PolicyRefusal, match="unsupported_surface"):
        api.resolve(lease) if action == "resolve" else api.issue(RecordKind.WORKING, "w", destination="channel:a")
    assert store.conn.in_transaction
    assert store.conn.execute("SELECT content FROM working_memory").fetchone()[0] == "pending"
    store.conn.rollback()


def test_v1_remains_unchanged_and_cannot_issue(fixture):
    store, _, reader = fixture
    add(store, "w")
    changes = store.conn.total_changes
    with bind_access_context(context()), pytest.raises(PolicyRefusal, match="unsupported_surface"):
        PolicyEvidence(reader).issue(RecordKind.WORKING,"w",destination="channel:a")
    assert store.get_domain().schema_version == 1 and store.conn.total_changes == changes


@pytest.mark.parametrize("action", ["issue", "resolve"])
@pytest.mark.parametrize("stage", [1,2,3,4,5])
def test_context_switch_at_each_checkpoint_refuses(evidence, action, stage):
    store, _, lifecycle, _, original = evidence
    add(store, "w")
    lease = issue(evidence)
    calls, entered = [], []
    def verify(ctx, **intent):
        calls.append(True)
        result = original(ctx, **intent)
        if len(calls) == stage:
            manager = bind_access_context(replace(ctx, context_id="ctx:changed"))
            manager.__enter__()
            entered.append(manager)
        return result
    api = PolicyEvidence(PolicyReader(store, bank="bank:a", verify_context=verify))
    with bind_access_context(context()):
        try:
            with pytest.raises(PolicyRefusal, match="access_denied"):
                api.resolve(lease) if action == "resolve" else api.issue(RecordKind.WORKING,"w",destination="channel:a")
            assert entered
        finally:
            for manager in reversed(entered):
                manager.__exit__(None,None,None)


def test_source_lease_is_metadata_only_and_changed_assertion_refuses(source_fixture, monkeypatch):
    media, store, registry, _ = source_fixture
    identity = source(source_fixture)
    lifecycle = PolicyLifecycle(store)
    lifecycle.prepare()
    authority = sqlite3.connect(media.conn.execute("PRAGMA database_list").fetchone()[2])
    try:
        current = PolicyLifecycle(type(store)(authority))
        reader = PolicyReader(store, bank="bank:a", verify_context=lambda ctx, **intent: replace(registry(ctx, **intent), lifecycle_epoch=current.epoch()))
        api = PolicyEvidence(reader)
        import mnemosyne.core.source_verification as verifier
        monkeypatch.setattr(verifier, "verify_source_revision", lambda *a, **kw: pytest.fail("source bytes opened"))
        with bind_access_context(source_context()):
            lease = api.issue(RecordKind.SOURCE_REVISION, identity, destination="channel:a")
            hit = api.resolve(lease)
        assert hit.record_id == identity and not hasattr(hit,"archive_locator") and not hasattr(hit,"content")
        store.conn.execute("UPDATE media_source_revisions SET content_hash=? WHERE revision_id=?", ("b"*64,identity))
        store.conn.commit()
        with bind_access_context(source_context()), pytest.raises(PolicyRefusal, match="access_denied"):
            api.resolve(lease)
    finally:
        authority.close()


def test_projects_use_exact_confirmed_selection(projects):
    store, catalog, ctx, registry, _ = projects
    add(store,"w")
    assign(catalog,"w")
    lifecycle = PolicyLifecycle(store)
    lifecycle.prepare()
    authority = sqlite3.connect(store.conn.execute("PRAGMA database_list").fetchone()[2])
    try:
        current = PolicyLifecycle(type(store)(authority))
        api = PolicyEvidence(PolicyReader(store, bank="bank:a", verify_context=lambda c, **intent: replace(registry(c, **intent), lifecycle_epoch=current.epoch())))
        with bind_access_context(ctx):
            lease = api.issue(RecordKind.WORKING,"w",destination="channel:a",projects={"project:a"})
            assert api.resolve(lease).record_id == "w"
            with pytest.raises(PolicyRefusal, match="access_denied"):
                api.resolve(replace(lease, projects=frozenset({"project:b"})))
    finally:
        authority.close()


@pytest.mark.parametrize("changes", [{"lifecycle_epoch":True}, {"lifecycle_epoch":-1}, {"value_fingerprint":"bad"},
    {"scope_fingerprint":"x"*64}, {"binding_id":""}, {"projects":"project:a"}])
def test_invalid_lease_shapes_refuse(evidence, changes):
    add(evidence[0],"w")
    with pytest.raises((ValueError, TypeError)):
        replace(issue(evidence), **changes)


def test_cancellation_keeps_exception_identity_and_no_transaction(evidence):
    store, _, _, _, original = evidence
    add(store,"w")
    lease = issue(evidence)
    error = KeyboardInterrupt("synthetic cancellation")
    def cancel(ctx, **intent):
        raise error
    api = PolicyEvidence(PolicyReader(store,bank="bank:a",verify_context=cancel))
    with bind_access_context(context()), pytest.raises(KeyboardInterrupt) as caught:
        api.resolve(lease)
    assert caught.value is error and not store.conn.in_transaction


@pytest.mark.parametrize("action", ["issue", "resolve"])
@pytest.mark.parametrize("stage", [2,3,4,5])
def test_independent_epoch_change_during_wal_snapshot_refuses(evidence, action, stage):
    store, _, _, _, original = evidence
    add(store,"w")
    lease = issue(evidence)
    conn = sqlite3.connect(store.conn.execute("PRAGMA database_list").fetchone()[2])
    current = PolicyLifecycle(type(store)(conn))
    calls = []
    def verify(ctx, **intent):
        calls.append(True)
        if len(calls) == stage:
            current.quarantine(PolicyRecordRef(RecordKind.WORKING,"w"))
        return original(ctx, **intent)
    api = PolicyEvidence(PolicyReader(store,bank="bank:a",verify_context=verify))
    try:
        with bind_access_context(context()), pytest.raises(PolicyRefusal,match="access_denied"):
            api.resolve(lease) if action == "resolve" else api.issue(RecordKind.WORKING,"w",destination="channel:a")
        assert current.epoch() == 1 and not store.conn.in_transaction
    finally:
        conn.close()


def test_descendant_lease_is_invalidated_and_denied_before_next_content(evidence):
    store, _, lifecycle, api, _ = evidence
    add(store,"parent")
    store.conn.execute("INSERT INTO working_memory VALUES('child','DERIVATIVE-LEASE-CANARY')")
    store.conn.commit()
    lifecycle.bind_derivative(PolicyRecordRef(RecordKind.WORKING,"child"),[PolicyRecordRef(RecordKind.WORKING,"parent")])
    lease = issue(evidence,"child")
    lifecycle.quarantine(PolicyRecordRef(RecordKind.WORKING,"parent"))
    def guard(cursor,row):
        assert "DERIVATIVE-LEASE-CANARY" not in row
        return sqlite3.Row(cursor,row)
    store.conn.row_factory = guard
    with bind_access_context(context()), pytest.raises(PolicyRefusal,match="access_denied"):
        api.resolve(lease)
    with pytest.raises(PolicyRefusal,match="access_denied"):
        issue(evidence,"child")


@pytest.mark.parametrize("action", ["issue","resolve"])
def test_awaitable_verifier_refuses_without_running(evidence, action):
    store = evidence[0]
    add(store,"w")
    lease = issue(evidence)
    async def async_grant():
        pytest.fail("async verifier ran")
    api = PolicyEvidence(PolicyReader(store,bank="bank:a",verify_context=lambda *a,**kw: async_grant()))
    with bind_access_context(context()), pytest.raises(PolicyRefusal,match="unsupported_surface"):
        api.resolve(lease) if action == "resolve" else api.issue(RecordKind.WORKING,"w",destination="channel:a")


def test_missing_context_and_lost_authority_refuse(evidence):
    add(evidence[0],"w")
    lease = issue(evidence)
    with pytest.raises(PolicyRefusal,match="missing_context"):
        evidence[3].resolve(lease)
    evidence[1].contexts.clear()
    with bind_access_context(context()), pytest.raises(PolicyRefusal,match="access_denied"):
        evidence[3].resolve(lease)


@pytest.mark.parametrize("invalid", [None,{},"token"])
def test_wrong_public_api_input_refuses(invalid):
    with pytest.raises(TypeError):
        PolicyEvidence(invalid)


def test_documented_complete_example(capsys):
    demo = runpy.run_path(str(Path(__file__).resolve().parents[1]/"examples/policy_evidence_demo.py"))
    result = demo["main"]()
    assert result == {"resolved":True, "lease_contains_payload":False, "quarantine_epoch":1,
        "old_lease":"access_denied", "native_rows_preserved":2, "protected_mode_activated":False}
    assert '"old_lease": "access_denied"' in capsys.readouterr().out
