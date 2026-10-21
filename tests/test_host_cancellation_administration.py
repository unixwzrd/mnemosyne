"""Fresh recovery authority and real witnessed cancellation; synthetic actors only."""

from dataclasses import replace
import threading

import pytest

from mnemosyne.core.administration_audit_contract import CancellationAdministrationIntent, _intent
from mnemosyne.core.host_cancellation_administration import CancellationAdministration, CancellationAdministrationSnapshot
from mnemosyne.core.host_grant_administration import GrantAdministration
from mnemosyne.core.policy import PolicyRefusal
from tests.test_host_administration_journal import audited as audited, read
from tests.test_host_grant_administration import grant_admin as grant_admin, preview as grant_preview
from tests.test_host_registry import authority as authority
from tests.test_host_profile_journal import profiles as profiles, replacement as profile_replacement
from tests.test_host_registry_management import managed as managed, change as registry_change


@pytest.fixture
def recovering(audited, request):
    fixture, journal, *_ = audited
    original, old, proposer, reviewer, claims, calls, *_ = fixture
    mode = getattr(request, "param", "ordinary")
    if mode in ("proposer-benefits", "reviewer-benefits"):
        before = old.current()
        principal = "operator" if mode == "proposer-benefits" else "reviewer"
        added = replace(before.registry.grants[0], principal_id=principal)
        old.publish(before.profiles, previous=before.revision, operation_id="beneficiary",
            registry=replace(before.registry, grants=before.registry.grants + (added,)))
    owner = old.migrate_cancellable(operation_id="migration")
    before = owner.current()
    if mode in ("disable-proposer", "disable-reviewer"):
        principal = "operator" if mode == "disable-proposer" else "reviewer"
        proposed = replace(before.registry, principals=tuple(replace(p, enabled=False) if p.principal_id == principal else p
            for p in before.registry.principals))
        pending = owner.stage(before.profiles, previous=before.revision, operation_id="identity-proposal", registry=proposed)
        original_plan = None
    else:
        source = GrantAdministration(owner, authority_id="a" * 32, issuer="admin-login",
            authenticate=original._authenticate, journal=journal)
        source_fixture = (source, owner, proposer, reviewer, claims, calls, *fixture[-2:])
        original_plan = grant_preview(source_fixture)
        approval = source.approve(reviewer, original_plan)
        stage = owner.stage

        def interrupt(*args, **kwargs):
            stage(*args, **kwargs)
            raise OSError("SECRET-lost-ack")

        owner.stage = interrupt
        try:
            with pytest.raises(PolicyRefusal):
                source.apply(proposer, original_plan, approval=approval)
        finally:
            owner.stage = stage
        pending = owner.receipt(original_plan.operation_id)
    for key, prior in tuple(claims.items()):
        claims[key] = CancellationAdministrationSnapshot(prior.issuer, prior.principal_id, prior.separation_id,
            prior.authority_id, prior.authorization_revision, prior.epoch,
            frozenset({pending.operation_id, "unknown-operation", "migration"}), prior.controlled_principals,
            frozenset({"recovery:view", "recovery:cancel", "recovery:approve"}))
    admin = CancellationAdministration(owner, authority_id="a" * 32, issuer="admin-login",
        authenticate=original._authenticate, journal=journal)
    return admin, owner, proposer, reviewer, claims, calls, audited, pending, before, original_plan


def preview(recovering):
    admin, _, proposer, _, _, _, _, original, *_ = recovering
    return admin.preview(proposer, original.operation_id)


def test_independent_cancellation_preserves_original_and_records_truth(recovering):
    admin, owner, proposer, reviewer, _, _, audited, original, before, _ = recovering
    plan = preview(recovering)
    assert admin.view(proposer, original.operation_id).original == original
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan)
    with pytest.raises(PolicyRefusal):
        admin.approve(proposer, plan)
    approval = admin.approve(reviewer, plan)
    result = admin.apply(proposer, plan, approval=approval)
    after = owner.current()
    assert result.phase == "committed" and result.revision == plan.candidate
    assert after.registry == before.registry and after.profiles == before.profiles
    assert owner.receipt(original.operation_id).phase == "cancelled"
    assert owner.receipt(result.operation_id) == result
    records = read(audited)
    assert [r.kind for r in records] == ["intent", "intent", "committed"]
    intent = records[1].intent
    assert type(intent) is CancellationAdministrationIntent and intent.original_operation_id == original.operation_id
    assert intent.original_revision == original.revision and intent.candidate == result.revision
    assert intent.proposer.principal_id == "operator" and intent.approver.principal_id == "reviewer"
    assert _intent(intent.to_dict()) == intent
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        audited[1].observe(original.operation_id, owner=owner)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    with pytest.raises(PolicyRefusal):
        admin.preview(proposer, original.operation_id)


@pytest.mark.parametrize("method", ["view", "preview"])
@pytest.mark.parametrize("mutation", ["scope", "capability", "issuer", "authority", "wrong-type"])
def test_recovery_scope_is_checked_before_owner_access(recovering, monkeypatch, method, mutation):
    admin, owner, proposer, _, claims, _, _, original, *_ = recovering
    if mutation == "wrong-type":
        claims[proposer] = object()
    else:
        changes = {"scope": {"operations": frozenset({"other"})},
            "capability": {"capabilities": frozenset({"recovery:approve"})},
            "issuer": {"issuer": "wrong"}, "authority": {"authority_id": "f" * 32}}[mutation]
        claims[proposer] = replace(claims[proposer], **changes)
    monkeypatch.setattr(owner, "current", lambda: pytest.fail("unauthorized owner read"))
    with pytest.raises(PolicyRefusal):
        getattr(admin, method)(proposer, original.operation_id)


@pytest.mark.parametrize("recovering", ["proposer-benefits", "reviewer-benefits", "disable-proposer", "disable-reviewer"], indirect=True)
def test_content_and_identity_self_preservation_refuse(recovering):
    admin, owner, proposer, reviewer, *_ = recovering
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        plan = preview(recovering)
        admin.approve(reviewer, plan)
    assert owner.current() == before


@pytest.mark.parametrize("mode", ["same-actor", "controlled-reviewer", "shared-control"])
def test_alias_or_control_relationship_does_not_supply_independence(recovering, mode):
    admin, _, proposer, reviewer, claims, *_ = recovering
    if mode == "same-actor":
        claims[reviewer] = replace(claims[reviewer], separation_id=claims[proposer].separation_id)
    elif mode == "controlled-reviewer":
        claims[proposer] = replace(claims[proposer], controlled_principals=frozenset({"operator", "reviewer"}))
    else:
        # Shared controlled content beneficiary refuses already at preview.
        for key in claims:
            claims[key] = replace(claims[key], controlled_principals=claims[key].controlled_principals | {"agent"})
    with pytest.raises(PolicyRefusal):
        admin.approve(reviewer, preview(recovering))


@pytest.mark.parametrize("who", ["proposer", "reviewer"])
@pytest.mark.parametrize("changes", [
    {"epoch": 2}, {"authorization_revision": "1" * 64},
    {"operations": frozenset({"other"})}, {"capabilities": frozenset({"recovery:view"})},
    {"controlled_principals": frozenset({"operator", "reviewer"})},
])
def test_changed_claim_refuses_before_cancellation_write(recovering, who, changes):
    admin, owner, proposer, reviewer, claims, _, audited, *_ = recovering
    plan = preview(recovering)
    approval = admin.approve(reviewer, plan)
    key = proposer if who == "proposer" else reviewer
    claims[key] = replace(claims[key], **changes)
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.current() == before and len(read(audited)) == 1


@pytest.mark.parametrize("phase", ["stage_cancellation", "advance_witness", "finalize"])
def test_uncertain_cancellation_never_replays_consumed_plan(recovering, monkeypatch, phase):
    admin, owner, proposer, reviewer, _, _, _, original, *_ = recovering
    plan = preview(recovering)
    approval = admin.approve(reviewer, plan)
    method = getattr(owner, phase)

    def fail(*args, **kwargs):
        method(*args, **kwargs)
        raise OSError("SECRET-lost-cancellation-ack")

    monkeypatch.setattr(owner, phase, fail)
    with pytest.raises(PolicyRefusal) as caught:
        admin.apply(proposer, plan, approval=approval)
    assert "SECRET" not in str(caught.value)
    assert owner.receipt(plan.operation_id) is not None
    assert owner.receipt(original.operation_id).phase == ("cancelled" if phase == "finalize" else "prepared")
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)


def test_journal_failure_prevents_resolution_and_consumes_plan(recovering, monkeypatch):
    admin, owner, proposer, reviewer, _, _, audited, original, *_ = recovering
    plan = preview(recovering)
    approval = admin.approve(reviewer, plan)
    monkeypatch.setattr(audited[1], "append_intent", lambda *a, **kw: (_ for _ in ()).throw(OSError("SECRET")))
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.receipt(original.operation_id) == original and owner.receipt(plan.operation_id) is None
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)


def test_ordinary_commit_after_preview_wins_without_cancellation(recovering):
    admin, owner, proposer, reviewer, _, _, _, original, *_ = recovering
    plan = preview(recovering)
    approval = admin.approve(reviewer, plan)
    owner.advance_witness(original)
    owner.finalize(original)
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.current() == before and owner.receipt(plan.operation_id) is None
    assert owner.receipt(original.operation_id).phase == "committed"


def test_copy_cancel_and_foreign_approval_are_not_cancellation_authority(recovering):
    admin, owner, proposer, reviewer, _, _, _, original, *_ = recovering
    plan = preview(recovering)
    with pytest.raises(PolicyRefusal):
        admin.approve(reviewer, replace(plan))
    approval = admin.approve(reviewer, plan)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=replace(approval))
    admin.cancel(plan)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.receipt(original.operation_id) == original


@pytest.mark.parametrize("kind", ["profiles", "managed", "audited"])
def test_existing_administration_facades_match_cancellable_candidate_format(request, kind):
    fixture = request.getfixturevalue(kind)
    values = fixture[0] if kind == "audited" else fixture
    original, old, proposer, reviewer, *_ = values
    journal = fixture[1] if kind == "audited" else values[-1][1]
    owner = old.migrate_cancellable(operation_id="format-migration")
    admin = type(original)(owner, authority_id="a" * 32, issuer="admin-login",
        authenticate=original._authenticate, journal=journal)
    updated = (admin, owner, *values[2:])
    if kind == "profiles":
        plan = admin.preview(proposer, "example", profile_replacement(owner))
    elif kind == "managed":
        plan = registry_change(updated)
    else:
        plan = grant_preview(updated)
    receipt = admin.apply(proposer, plan, approval=admin.approve(reviewer, plan))
    assert receipt.phase == "committed" and owner.current().storage_version == 2
    records = read(fixture if kind == "audited" else values[-1])
    assert records[0].intent.candidate == receipt.revision == owner.current().revision


@pytest.mark.parametrize("boundary", ["append_intent", "stage_cancellation", "advance_witness", "finalize"])
def test_revocation_during_io_prevents_next_admission_and_consumes_plan(recovering, monkeypatch, boundary):
    admin, owner, proposer, reviewer, claims, _, audited, original, *_ = recovering
    plan = preview(recovering)
    approval = admin.approve(reviewer, plan)
    target = audited[1] if boundary == "append_intent" else owner
    method = getattr(target, boundary)

    def revoke(*args, **kwargs):
        result = method(*args, **kwargs)
        claims[reviewer] = replace(claims[reviewer], epoch=2)
        return result

    monkeypatch.setattr(target, boundary, revoke)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    receipt = owner.receipt(plan.operation_id)
    assert (receipt is None) == (boundary == "append_intent")
    if boundary == "finalize":
        assert receipt.phase == "committed" and owner.receipt(original.operation_id).phase == "cancelled"
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)


@pytest.mark.parametrize("guard", ["thread", "process", "reentry", "expired"])
def test_cancellation_locality_and_deadline_guards(recovering, monkeypatch, guard):
    import mnemosyne.core.host_cancellation_administration as module
    admin, owner, proposer, reviewer, *_ = recovering
    plan = preview(recovering)
    approval = admin.approve(reviewer, plan)
    before = owner.current()
    if guard == "thread":
        outcomes = []

        def foreign():
            with pytest.raises(PolicyRefusal, match="unsupported_surface"):
                admin.apply(proposer, plan, approval=approval)
            outcomes.append(True)

        thread = threading.Thread(target=foreign)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive() and outcomes == [True]
    else:
        if guard == "process":
            admin._process = -1
        elif guard == "reentry":
            admin._busy = True
        else:
            monkeypatch.setattr(module.time, "monotonic", lambda: admin._pending[plan.operation_id].deadline + 1)
        with pytest.raises(PolicyRefusal):
            admin.apply(proposer, plan, approval=approval)
    assert owner.current() == before


@pytest.mark.parametrize("change", ["unknown", "hybrid", "wrong-generation", "same-operation", "same-actor"])
def test_cancellation_intent_rejects_ambiguous_or_forged_metadata(recovering, change):
    admin, _, proposer, reviewer, _, _, audited, *_ = recovering
    plan = preview(recovering)
    admin.apply(proposer, plan, approval=admin.approve(reviewer, plan))
    data = read(audited)[1].intent.to_dict()
    if change == "unknown":
        data["unknown"] = "value"
    elif change == "hybrid":
        data["profile_id"] = "example"
    elif change == "wrong-generation":
        data["original_revision"]["generation"] -= 1
    elif change == "same-operation":
        data["original_operation_id"] = data["operation_id"]
    else:
        data["approver"] = data["proposer"]
    with pytest.raises((TypeError, ValueError, PolicyRefusal)):
        _intent(data)
