"""Witnessed synthetic audit metadata, independent from grant/content rights."""

from dataclasses import asdict, replace
import hashlib
import json
import sqlite3

import pytest

from mnemosyne.core.administration_audit_contract import AdministrativeActor, AdministrationIntent, AdministrationJournalRead
from mnemosyne.core.administration_journal import AdministrationJournal, _DDL
from mnemosyne.core.host_grant_administration import GrantAdministration
from mnemosyne.core.policy import PolicyRefusal
from tests.test_host_grant_administration import grant_admin as grant_admin, preview
from tests.test_host_registry import authority as authority, connection


@pytest.fixture
def audited(grant_admin, tmp_path, request):
    original, owner, proposer, reviewer, claims, calls, config, witness = grant_admin
    conn, audit_witness = connection(tmp_path, "journal"), connection(tmp_path, "journal-witness")
    reader = object()
    state = {"claim": AdministrationJournalRead("audit-login", "auditor", "a" * 32, "e" * 32,
             "audit:private", "d" * 64, 1, frozenset({"admin-journal:read"}))}

    def authenticate(request):
        if request is not reader:
            raise PermissionError("SECRET-credential")
        return state["claim"]

    journal = AdministrationJournal(conn, witness_connection=audit_witness, authority_id="a" * 32,
        journal_id="e" * 32, witness_id="f" * 32, issuer="audit-login", authenticate_read=authenticate)
    journal.prepare(max_operations=getattr(request, "param", 8))
    admin = GrantAdministration(owner, authority_id="a" * 32, issuer="admin-login",
                                authenticate=original._authenticate, journal=journal)
    yield (admin, owner, proposer, reviewer, claims, calls, config, witness), journal, reader, state, conn, audit_witness
    conn.close()
    audit_witness.close()


def apply(fixture):
    admin, _, proposer, reviewer, *_ = fixture
    plan = preview(fixture)
    receipt = admin.apply(proposer, plan, approval=admin.approve(reviewer, plan))
    return plan, receipt


def read(audited):
    _, journal, reader, *_ = audited
    return journal.read(reader, destination="audit:private")


def intent_for(fixture):
    admin, owner, _, reviewer, *_ = fixture
    plan = preview(fixture)
    admin.approve(reviewer, plan)
    pending = admin._pending[plan.operation_id]
    candidate = admin._candidate(owner.current(), (plan.principal_id, plan.store_id), plan.replacement)

    def actor(claim):
        return AdministrativeActor(claim.issuer, claim.principal_id, claim.separation_id,
                                   claim.authorization_revision, claim.epoch, claim.fingerprint())

    return AdministrationIntent(plan.operation_id, plan.digest, plan.previous, candidate.revision,
        plan.principal_id, plan.store_id, actor(pending.actor), actor(pending.approver))


def test_intent_precedes_configuration_and_completion_is_attributed(audited):
    fixture, journal, _, _, conn, _ = audited
    _, owner, _, _, claims, *_ = fixture
    plan, receipt = apply(fixture)
    records = read(audited)
    assert [r.kind for r in records] == ["intent", "committed"]
    intent = records[0].intent
    assert intent.operation_id == plan.operation_id and intent.plan_sha256 == plan.digest
    assert intent.previous == plan.previous and intent.candidate == receipt.revision
    assert intent.proposer.principal_id == "operator" and intent.approver.principal_id == "reviewer"
    assert {intent.proposer.claim_sha256, intent.approver.claim_sha256} == {c.fingerprint() for c in claims.values()}
    assert records[1].intent_sha256 == records[0].intent_sha256
    assert all(r.recorded_at.endswith("Z") for r in records)
    assert journal.observe(plan.operation_id, owner=owner) == records[1]
    assert len(read(audited)) == 2
    payloads = b" ".join(row[0] for row in conn.execute("SELECT payload FROM administration_journal_events"))
    assert b"controlled_principals" not in payloads and b"SECRET" not in payloads and b"replacement" not in payloads


def test_unknown_and_grant_only_readers_refuse_before_journal_sql(audited):
    fixture, journal, reader, state, conn, witness = audited
    statements = []
    conn.set_trace_callback(statements.append)
    witness.set_trace_callback(statements.append)
    with pytest.raises(PolicyRefusal) as caught:
        journal.read("SECRET-request", destination="audit:private")
    assert "SECRET" not in str(caught.value) and not statements
    state["claim"] = next(iter(fixture[4].values()))
    with pytest.raises(PolicyRefusal):
        journal.read(reader, destination="audit:private")
    assert not statements


@pytest.mark.parametrize("changes", [{"issuer": "other"}, {"authority_id": "b" * 32},
                                     {"journal_id": "c" * 32}, {"destination": "public"}])
def test_wrong_journal_scope_denies_before_reads(audited, changes):
    _, journal, reader, state, conn, _ = audited
    state["claim"] = replace(state["claim"], **changes)
    statements = []
    conn.set_trace_callback(statements.append)
    with pytest.raises(PolicyRefusal):
        journal.read(reader, destination="audit:private")
    assert not statements


@pytest.mark.parametrize("call", [2, 3])
def test_read_authorization_rechecked_after_materializing_page(audited, call):
    fixture, journal, _, state, *_ = audited
    apply(fixture)
    original, count = journal._authenticate_read, [0]

    def revoked(request):
        count[0] += 1
        if count[0] == call:
            state["claim"] = replace(state["claim"], epoch=2)
        return original(request)

    journal._authenticate_read = revoked
    with pytest.raises(PolicyRefusal):
        read(audited)


@pytest.mark.parametrize("boundary", ["before-witness", "after-witness", "after-local-finalize"])
def test_ambiguous_intent_consumes_plan_and_never_stages_config(audited, monkeypatch, boundary):
    fixture, journal, *_ = audited
    admin, owner, proposer, reviewer, *_ = fixture
    plan = preview(fixture)
    approval = admin.approve(reviewer, plan)
    original = journal._witness.publish if boundary != "after-local-finalize" else journal._finish

    def interrupted(*args, **kwargs):
        if boundary != "before-witness":
            original(*args, **kwargs)
        raise OSError("SECRET-lost-ack")

    if boundary == "after-local-finalize":
        monkeypatch.setattr(journal, "_finish", interrupted)
    else:
        monkeypatch.setattr(journal._witness, "publish", interrupted)
    with pytest.raises(PolicyRefusal) as caught:
        admin.apply(proposer, plan, approval=approval)
    assert "SECRET" not in str(caught.value) and owner.receipt(plan.operation_id) is None
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    monkeypatch.undo()
    journal.recover()
    assert [r.kind for r in read(audited)] == ["intent"]
    assert journal.observe(plan.operation_id, owner=owner) is None
    assert owner.receipt(plan.operation_id) is None


def test_intent_io_delay_reauthenticates_before_configuration_stage(audited, monkeypatch):
    fixture, journal, *_ = audited
    admin, owner, proposer, reviewer, claims, *_ = fixture
    plan = preview(fixture)
    approval = admin.approve(reviewer, plan)
    append = journal.append_intent

    def revoked(*args, **kwargs):
        result = append(*args, **kwargs)
        claims[proposer] = replace(claims[proposer], epoch=2)
        return result

    monkeypatch.setattr(journal, "append_intent", revoked)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.receipt(plan.operation_id) is None and [r.kind for r in read(audited)] == ["intent"]


def test_committed_config_with_missing_observation_reconciles_without_replay(audited, monkeypatch):
    fixture, journal, *_ = audited
    admin, owner, proposer, reviewer, *_ = fixture
    plan = preview(fixture)
    approval = admin.approve(reviewer, plan)
    original = journal.observe
    monkeypatch.setattr(journal, "observe", lambda *a, **kw: (_ for _ in ()).throw(OSError("lost audit I/O")))
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    receipt = owner.receipt(plan.operation_id)
    assert receipt.phase == "committed" and [r.kind for r in read(audited)] == ["intent"]
    before = owner.current()
    monkeypatch.setattr(journal, "observe", original)
    journal.observe(plan.operation_id, owner=owner)
    assert [r.kind for r in read(audited)] == ["intent", "committed"] and owner.current() == before


def test_revocation_after_config_commit_still_records_observed_receipt(audited, monkeypatch):
    fixture, _, *_ = audited
    admin, owner, proposer, reviewer, claims, *_ = fixture
    plan = preview(fixture)
    approval = admin.approve(reviewer, plan)
    finalize = owner.finalize

    def revoked(*args, **kwargs):
        result = finalize(*args, **kwargs)
        claims[reviewer] = replace(claims[reviewer], epoch=2)
        return result

    monkeypatch.setattr(owner, "finalize", revoked)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.receipt(plan.operation_id).phase == "committed"
    assert [r.kind for r in read(audited)] == ["intent", "committed"]


@pytest.mark.parametrize("audited", [1, 8], indirect=True)
def test_config_prepared_observation_and_explicit_owner_recovery(audited, monkeypatch):
    fixture, journal, *_ = audited
    admin, owner, proposer, reviewer, claims, *_ = fixture
    plan = preview(fixture)
    approval = admin.approve(reviewer, plan)
    stage = owner.stage

    def interrupted(*args, **kwargs):
        result = stage(*args, **kwargs)
        claims[proposer] = replace(claims[proposer], epoch=2)
        return result

    monkeypatch.setattr(owner, "stage", interrupted)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    journal.observe(plan.operation_id, owner=owner)
    assert [r.kind for r in read(audited)] == ["intent", "prepared"]
    receipt = owner.receipt(plan.operation_id)
    owner.advance_witness(receipt)
    with pytest.raises(PolicyRefusal):
        journal.observe(plan.operation_id, owner=owner)
    journal.recover()
    assert owner.receipt(plan.operation_id).phase == "prepared"
    owner.recover(plan.operation_id)
    journal.observe(plan.operation_id, owner=owner)
    assert [r.kind for r in read(audited)] == ["intent", "prepared", "committed"]


@pytest.mark.parametrize("audited", [1], indirect=True)
def test_capacity_reserves_completion_without_eviction(audited):
    fixture, journal, *_ = audited
    admin, owner, proposer, reviewer, *_ = fixture
    apply(fixture)
    assert len(read(audited)) == 2
    plan = admin.preview(proposer, "human", next(iter(owner.current().registry.stores)).store_id, None)
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        admin.apply(proposer, plan, approval=admin.approve(reviewer, plan))
    assert owner.receipt(plan.operation_id) is None and len(read(audited)) == 2


@pytest.mark.parametrize("which", ["journal", "witness"])
def test_independent_restore_fences_missing_history(audited, which):
    fixture, journal, _, _, conn, witness = audited
    backup = sqlite3.connect(":memory:")
    target = conn if which == "journal" else witness
    try:
        target.backup(backup)
        apply(fixture)
        backup.backup(target)
        with pytest.raises(PolicyRefusal):
            read(audited)
        with pytest.raises(PolicyRefusal):
            journal.recover()
    finally:
        backup.close()


def test_missing_interior_event_refuses_complete_listing(audited):
    fixture, _, _, _, conn, _ = audited
    apply(fixture)
    conn.execute("DROP TRIGGER administration_journal_events_no_delete")
    conn.execute("DELETE FROM administration_journal_events WHERE sequence=1")
    conn.execute(_DDL["administration_journal_events_no_delete"])
    conn.commit()
    with pytest.raises(PolicyRefusal):
        read(audited)


def test_recomputed_historical_digest_does_not_replace_witness(audited):
    fixture, _, _, _, conn, _ = audited
    apply(fixture)
    payload, = conn.execute("SELECT payload FROM administration_journal_events WHERE sequence=1").fetchone()
    data = json.loads(payload)
    data["body"]["intent"]["proposer"]["principal_id"] = "forged-but-valid-actor"
    replacement = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    conn.execute("DROP TRIGGER administration_journal_finalize_only")
    conn.execute("UPDATE administration_journal_events SET payload=?,digest=? WHERE sequence=1",
                 (replacement, hashlib.sha256(replacement).hexdigest()))
    conn.execute(_DDL["administration_journal_finalize_only"])
    conn.commit()
    with pytest.raises(PolicyRefusal):
        read(audited)


@pytest.mark.parametrize("after", [False, True])
def test_interrupted_root_provisioning_is_explicit_and_repeatable(grant_admin, tmp_path, monkeypatch, after):
    from mnemosyne.core.snapshot_authority import SnapshotAuthority
    conn, witness = connection(tmp_path, "root-journal"), connection(tmp_path, "root-witness")
    original = SnapshotAuthority.provision

    def interrupted(*args, **kwargs):
        if after:
            original(*args, **kwargs)
        raise OSError("lost root acknowledgment")

    try:
        journal = AdministrationJournal(conn, witness_connection=witness, authority_id="a" * 32,
            journal_id="e" * 32, witness_id="f" * 32, issuer="audit-login", authenticate_read=lambda _: None)
        monkeypatch.setattr(SnapshotAuthority, "provision", interrupted)
        with pytest.raises(PolicyRefusal):
            journal.prepare()
        monkeypatch.setattr(SnapshotAuthority, "provision", original)
        journal.prepare()
        assert journal.recover() is None
    finally:
        conn.close()
        witness.close()


@pytest.mark.parametrize("changes", [{"capabilities": frozenset({"grants:view"})}, {"epoch": 0},
                                     {"journal_id": "bad"}, {"authorization_revision": "bad"}])
def test_reader_contract_is_strict(audited, changes):
    state = audited[3]
    with pytest.raises((TypeError, ValueError)):
        replace(state["claim"], **changes)


def test_pagination_and_empty_journal_are_bounded(audited):
    fixture, journal, reader, *_ = audited
    assert read(audited) == ()
    apply(fixture)
    first = journal.read(reader, destination="audit:private", limit=1)
    second = journal.read(reader, destination="audit:private", after_sequence=first[0].sequence, limit=1)
    assert first[0].kind == "intent" and second[0].kind == "committed"
    assert journal.read(reader, destination="audit:private", after_sequence=second[0].sequence) == ()


@pytest.mark.parametrize("changes", [{"limit": 0}, {"limit": True}, {"limit": 1001},
    {"after_sequence": -1}, {"after_sequence": True}, {"after_sequence": 12289}])
def test_invalid_page_bounds_refuse_without_reading(audited, changes):
    _, journal, reader, _, conn, witness = audited
    statements = []
    conn.set_trace_callback(statements.append)
    witness.set_trace_callback(statements.append)
    with pytest.raises(PolicyRefusal):
        journal.read(reader, destination="audit:private", **changes)
    assert not statements


def test_prepared_tail_blocks_other_appends_until_explicit_recovery(audited, monkeypatch):
    fixture, journal, *_ = audited
    admin, owner, proposer, reviewer, *_ = fixture
    plan = preview(fixture)
    approval = admin.approve(reviewer, plan)
    publish = journal._witness.publish
    monkeypatch.setattr(journal._witness, "publish", lambda *a, **kw: (_ for _ in ()).throw(OSError("interrupted")))
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    monkeypatch.setattr(journal._witness, "publish", publish)
    another = preview(fixture)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, another, approval=admin.approve(reviewer, another))
    assert owner.receipt(plan.operation_id) is None and owner.receipt(another.operation_id) is None
    journal.recover()
    assert [r.operation_id for r in read(audited)] == [plan.operation_id]


@pytest.mark.parametrize("which", ["journal", "witness"])
def test_unsafe_file_permissions_refuse(audited, which):
    _, journal, _, _, conn, witness = audited
    from pathlib import Path
    connection = conn if which == "journal" else witness
    path = Path(next(row[2] for row in connection.execute("PRAGMA database_list") if row[1] == "main"))
    path.chmod(0o644)
    try:
        with pytest.raises(PolicyRefusal):
            read(audited)
        with pytest.raises(PolicyRefusal):
            journal.recover()
    finally:
        path.chmod(0o600)


def test_same_file_connections_are_refused(audited):
    _, _, _, _, conn, *_ = audited
    with pytest.raises(PolicyRefusal):
        AdministrationJournal(conn, witness_connection=conn, authority_id="a" * 32, journal_id="e" * 32,
                              witness_id="f" * 32, issuer="audit-login", authenticate_read=lambda _: None)


def test_foreign_journal_is_not_silently_accepted(audited):
    fixture, _, _, _, conn, witness = audited
    original, owner, *_ = fixture
    journal = AdministrationJournal(conn, witness_connection=witness, authority_id="b" * 32,
        journal_id="e" * 32, witness_id="f" * 32, issuer="audit-login", authenticate_read=lambda _: None)
    with pytest.raises(TypeError):
        GrantAdministration(owner, authority_id="a" * 32, issuer="admin-login",
                            authenticate=original._authenticate, journal=journal)


def test_observation_cannot_forget_a_committed_receipt_after_config_restore(audited):
    fixture, journal, _, _, *_ = audited
    _, owner, _, _, _, _, config, witness = fixture
    backups = [sqlite3.connect(":memory:"), sqlite3.connect(":memory:")]
    try:
        for source, backup in zip((config, witness), backups):
            source.backup(backup)
        plan, _ = apply(fixture)
        for backup, target in zip(backups, (config, witness)):
            backup.backup(target)
        assert owner.receipt(plan.operation_id) is None
        with pytest.raises(PolicyRefusal):
            journal.observe(plan.operation_id, owner=owner)
        assert [r.kind for r in read(audited)] == ["intent", "committed"]
    finally:
        for backup in backups:
            backup.close()


@pytest.mark.parametrize("audited", [1], indirect=True)
def test_nonempty_journal_capacity_stays_bound_to_witnessed_root(audited):
    fixture, journal, _, _, conn, _ = audited
    journal.append_intent(intent_for(fixture), owner=fixture[1])
    before = journal._witness.current(journal._journal_id)
    conn.execute("DROP TRIGGER administration_journal_state_no_update")
    conn.execute("UPDATE administration_journal_state SET max_operations=2")
    conn.execute(_DDL["administration_journal_state_no_update"])
    conn.commit()
    with pytest.raises(PolicyRefusal):
        journal.append_intent(intent_for(fixture), owner=fixture[1])
    with pytest.raises(PolicyRefusal):
        read(audited)
    with pytest.raises(PolicyRefusal):
        journal.recover()
    assert journal._witness.current(journal._journal_id) == before


@pytest.mark.parametrize("hidden_sequence", [0, -1])
def test_nonpositive_sequence_cannot_hide_missing_event(audited, hidden_sequence):
    fixture, journal, _, _, conn, _ = audited
    for _ in range(2):
        journal.append_intent(intent_for(fixture), owner=fixture[1])
    row = conn.execute("SELECT * FROM administration_journal_events WHERE sequence=1").fetchone()
    conn.execute("DROP TRIGGER administration_journal_events_no_delete")
    conn.execute("DELETE FROM administration_journal_events WHERE sequence=1")
    conn.execute("INSERT INTO administration_journal_events VALUES(?,?,?,?,?,?)", (hidden_sequence,) + row[1:])
    conn.execute(_DDL["administration_journal_events_no_delete"])
    conn.commit()
    with pytest.raises(PolicyRefusal):
        read(audited)
    with pytest.raises(PolicyRefusal):
        journal.recover()


@pytest.mark.parametrize("mutation", ["intent-digest", "candidate"])
def test_recovery_checks_semantics_before_witness_publication(audited, monkeypatch, mutation):
    fixture, journal, _, _, conn, _ = audited
    admin, owner, *_ = fixture
    intent = intent_for(fixture)
    journal.append_intent(intent, owner=owner)
    pending = admin._pending[intent.operation_id]
    candidate = admin._candidate(owner.current(), (pending.plan.principal_id, pending.plan.store_id), pending.plan.replacement)
    owner.stage(candidate.profiles, previous=intent.previous, operation_id=intent.operation_id, registry=candidate.registry)
    publish = journal._witness.publish
    monkeypatch.setattr(journal._witness, "publish", lambda *a, **kw: (_ for _ in ()).throw(OSError("interrupted")))
    with pytest.raises(PolicyRefusal):
        journal.observe(intent.operation_id, owner=owner)
    data = json.loads(conn.execute("SELECT payload FROM administration_journal_events WHERE sequence=2").fetchone()[0])
    if mutation == "intent-digest":
        data["body"]["intent_sha256"] = "0" * 64
    else:
        data["body"]["candidate"]["sha256"] = "0" * 64
    payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    conn.execute("DROP TRIGGER administration_journal_finalize_only")
    conn.execute("UPDATE administration_journal_events SET payload=?,digest=? WHERE sequence=2",
                 (payload, hashlib.sha256(payload).hexdigest()))
    conn.execute(_DDL["administration_journal_finalize_only"])
    conn.commit()
    monkeypatch.setattr(journal._witness, "publish", publish)
    before = journal._witness.current(journal._journal_id)
    with pytest.raises(PolicyRefusal):
        journal.recover()
    assert journal._witness.current(journal._journal_id) == before
    assert owner.receipt(intent.operation_id).phase == "prepared"


def test_recovery_cannot_witness_observation_downgrade(audited):
    fixture, journal, _, _, conn, _ = audited
    plan, receipt = apply(fixture)
    first = read(audited)[0]
    body = {"authority_id": journal._authority_id, "journal_id": journal._journal_id,
        "operation_id": plan.operation_id, "kind": "prepared", "candidate": asdict(receipt.revision),
        "intent_sha256": first.intent_sha256}
    payload = json.dumps({"sequence": 3, "recorded_at": first.recorded_at, "body": body},
                         sort_keys=True, separators=(",", ":")).encode()
    conn.execute("INSERT INTO administration_journal_events VALUES(?,?,?,?,?,'prepared')",
                 (3, plan.operation_id, "prepared", payload, hashlib.sha256(payload).hexdigest()))
    conn.commit()
    before = journal._witness.current(journal._journal_id)
    with pytest.raises(PolicyRefusal):
        journal.recover()
    assert journal._witness.current(journal._journal_id) == before
