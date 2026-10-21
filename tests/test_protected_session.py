"""Audited facade with synthetic authority, contexts and encrypted generations."""

import asyncio
from dataclasses import replace
import json
import sqlite3

import pytest

from mnemosyne.core.policy import PolicyRefusal, RefusalReason
from mnemosyne.core.policy_audit import PolicyAudit
from mnemosyne.core.policy_store import RecordKind
from mnemosyne.core.protected_session import ProtectedSession
from mnemosyne.runtime_context import bind_access_context
from tests.test_policy_read import add, context, fixture as fixture
from tests.test_policy_evidence import evidence as evidence
from tests.test_snapshot_authority import authority as authority
from tests.test_protected_repository import repository as repository, publish
from tests.test_protected_snapshot import identity


@pytest.fixture
def session(evidence, repository, tmp_path):
    first = publish(evidence, repository)
    if first is None:
        pytest.skip(
            "normal protected snapshots require SQLite serialize/crypto capability"
        )
    # Seed both IDs before publishing a new current immutable generation.
    add(evidence[0], "denied", content="DENIED-SESSION-CANARY", owner="person:b")
    repo, _, api = repository
    second = repo.publish(
        evidence[0].conn,
        identity(generation=2),
        previous=first.checkpoint,
        operation_id="second",
    )
    conn = sqlite3.connect(tmp_path / "session-audit.sqlite")
    conn.execute("PRAGMA synchronous=EXTRA")
    audit = PolicyAudit(
        conn, domain_id="domain:a", bank="bank:a", verify_read=lambda *a, **k: None
    )
    audit.prepare()
    state = {"owners": frozenset({"person:a"}), "revoke": False}

    def verify(ctx, **intent):
        if state["revoke"]:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return replace(evidence[4](ctx, **intent), owners=state["owners"])

    with bind_access_context(context()):
        reader = ProtectedSession(
            repo, "a" * 32, destination="channel:a", verify_context=verify, audit=audit
        )
        try:
            yield reader, audit, state, second, verify
        finally:
            reader.close()
            conn.close()


def events(audit):
    return [
        json.loads(row[0])
        for row in audit._store.conn.execute(
            "SELECT payload FROM policy_audit_events ORDER BY sequence"
        )
    ]


def test_direct_candidates_lease_and_delivery_are_audited(session):
    api, audit, *_ = session
    assert api.get(RecordKind.WORKING, "w").content == "PRIVATE-REPOSITORY-CANARY"
    assert [hit.record_id for hit in api.candidates(RecordKind.WORKING)] == ["w"]
    lease = api.issue(RecordKind.WORKING, "w")
    assert api.resolve(lease).content == "PRIVATE-REPOSITORY-CANARY"
    delivered = []
    api.deliver(lease, delivered.append)
    assert len(delivered) == 1
    assert {item["operation"] for item in events(audit)} == {
        "get",
        "candidates",
        "issue",
        "resolve",
        "deliver",
    }
    assert "PRIVATE-REPOSITORY-CANARY" not in json.dumps(events(audit))
    assert "DENIED-SESSION-CANARY" not in json.dumps(events(audit))


def test_forbidden_and_absent_ids_are_indistinguishable_without_payload(session):
    api, *_ = session

    def guard(cursor, row):
        assert "DENIED-SESSION-CANARY" not in row
        return sqlite3.Row(cursor, row)

    api._conn.row_factory = guard
    assert api.get(RecordKind.WORKING, "denied") is None
    assert api.get(RecordKind.WORKING, "missing") is None


@pytest.mark.parametrize(
    "operation",
    [
        "recall",
        "graph",
        "write",
        "create",
        "derive",
        "quarantine",
        "export",
        "import",
        "sync",
        "debug",
        "persona",
        "open",
        "prepare",
    ],
)
def test_unsupported_operations_never_fall_back(session, operation):
    api, audit, *_ = session
    before = api._conn.total_changes
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        api.dispatch(operation)
    assert api._conn.total_changes == before
    recorded, = events(audit)
    assert recorded["result"] == "deny" and recorded["operation"] == "dispatch"
    assert recorded["reason"] == "unsupported_surface"
    assert recorded["requested"] == recorded["returned"] == []


def test_stale_generation_refuses_all_reuse_without_reopening(
    session, evidence, repository
):
    api, _, _, previous, _ = session
    lease = api.issue(RecordKind.WORKING, "w")
    repository[0].publish(
        evidence[0].conn,
        identity(generation=3),
        previous=previous.checkpoint,
        operation_id="third",
    )
    for call in (
        lambda: api.get(RecordKind.WORKING, "w"),
        lambda: api.resolve(lease),
        lambda: api.deliver(lease, lambda _: pytest.fail("stale consumer invoked")),
    ):
        with pytest.raises(PolicyRefusal, match="access_denied"):
            call()


def test_revoked_host_grant_refuses_before_native_query(session):
    api, _, state, *_ = session
    statements = []
    api._conn.set_trace_callback(statements.append)
    state["revoke"] = True
    with pytest.raises(PolicyRefusal, match="access_denied"):
        api.get(RecordKind.WORKING, "w")
    assert not statements


def test_other_context_without_host_mapping_refuses(session):
    api, *_ = session
    with bind_access_context(context(context_id="unknown", principals={"unknown"})):
        with pytest.raises(PolicyRefusal, match="access_denied"):
            api.get(RecordKind.WORKING, "w")


def test_audit_failure_blocks_payload_delivery(session, monkeypatch):
    api, audit, *_ = session

    def fail(*args, **kwargs):
        raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)

    monkeypatch.setattr(audit, "admit", fail)
    statements = []
    api._conn.set_trace_callback(statements.append)
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        api.get(RecordKind.WORKING, "w")
    assert not statements


def test_authority_changed_by_audit_prevents_query(
    session, repository, evidence, monkeypatch
):
    api, audit, _, previous, _ = session
    admit = audit.admit

    def change(*args, **kwargs):
        result = admit(*args, **kwargs)
        repository[0].publish(
            evidence[0].conn,
            identity(generation=3),
            previous=previous.checkpoint,
            operation_id="third",
        )
        return result

    monkeypatch.setattr(audit, "admit", change)
    statements = []
    api._conn.set_trace_callback(statements.append)
    with pytest.raises(PolicyRefusal, match="access_denied"):
        api.get(RecordKind.WORKING, "w")
    assert not statements


def test_permission_ceiling_changed_at_delivery_audit_never_emits_old_payload(
    session, monkeypatch
):
    api, audit, state, *_ = session
    lease = api.issue(RecordKind.WORKING, "w")
    admit = audit.admit
    calls = []

    def change(event, consumer):
        result = admit(event, consumer)
        if event.operation == "deliver":
            calls.append(True)
            if len(calls) == 2:
                state["owners"] = frozenset({"person:b"})
        return result

    monkeypatch.setattr(audit, "admit", change)
    seen = []
    with pytest.raises(PolicyRefusal, match="access_denied"):
        api.deliver(lease, seen.append)
    assert seen == []


def test_stream_audits_chunks_and_stops_on_generation_change(
    session, repository, evidence
):
    api, audit, _, previous, _ = session
    lease = api.issue(RecordKind.WORKING, "w")

    async def producer(hits):
        assert len(hits) == 1
        yield "first"
        repository[0].publish(
            evidence[0].conn,
            identity(generation=3),
            previous=previous.checkpoint,
            operation_id="third",
        )
        yield "must-not-emit"

    seen = []
    with pytest.raises(PolicyRefusal, match="access_denied"):
        asyncio.run(api.stream([lease], producer, seen.append))
    assert seen == ["first"]
    assert any(event["operation"] == "stream" for event in events(audit))


def test_session_closes_and_dispatch_remains_explicit(session):
    api, *_ = session
    assert api.dispatch("get", kind=RecordKind.WORKING, record_id="w").record_id == "w"
    api.close()
    api.close()
    with pytest.raises(PolicyRefusal, match="context_unavailable"):
        api.get(RecordKind.WORKING, "w")


def test_missing_authentication_never_opens_snapshot(
    evidence, repository, tmp_path, monkeypatch
):
    first = publish(evidence, repository)
    if first is None:
        return
    conn = sqlite3.connect(tmp_path / "metadata.sqlite")
    audit = PolicyAudit(
        conn, domain_id="domain:a", bank="bank:a", verify_read=lambda *a, **k: None
    )
    monkeypatch.setattr(
        repository[0],
        "open_current",
        lambda *a: pytest.fail("decrypted without authorization"),
    )
    try:
        with bind_access_context(context(assurance="asserted")):
            with pytest.raises(PolicyRefusal, match="access_denied"):
                ProtectedSession(
                    repository[0],
                    "a" * 32,
                    destination="channel:a",
                    verify_context=evidence[4],
                    audit=audit,
                )
    finally:
        conn.close()
