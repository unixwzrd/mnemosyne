"""Composed disposable administration/request/restore qualification, not deployment."""

from dataclasses import replace
import sqlite3

import pytest

from mnemosyne.core.host_request_binding import LocalRequestBinding
from mnemosyne.core.policy import PolicyRefusal
from tests.test_host_administration_journal import audited as audited, read
from tests.test_host_grant_administration import claim, grant_admin as grant_admin, preview as grant_preview
from tests.test_host_profile_journal import profiles, preview as profile_preview, apply as profile_apply
from tests.test_host_registry_management import managed, change as registry_change, apply as registry_apply
from tests.test_host_registry import authority as authority
from tests.test_host_request_binding import audience


def grant_fixture(audited):
    fixture = audited[0]
    proposer, reviewer, claims = fixture[2:5]
    claims[proposer] = claim()
    claims[reviewer] = claim(principal_id="reviewer", separation_id="actor:reviewer",
                             controlled_principals=frozenset({"reviewer"}))
    return fixture


def restrict(audited):
    fixture = grant_fixture(audited)
    admin, _, proposer, reviewer, *_ = fixture
    plan = grant_preview(fixture)
    receipt = admin.apply(proposer, plan, approval=admin.approve(reviewer, plan))
    return plan, receipt


def binding(owner):
    state = {"claim": audience()}
    loader = LocalRequestBinding(owner, authority_id="a" * 32, issuer="login", authenticate=lambda _: state["claim"])
    return loader, object(), state


def test_profile_grant_route_sequence_preserves_restriction_and_fences_each_old_handle(audited):
    owner = audited[0][1]
    loader, request, state = binding(owner)
    handle = loader.admit(request)
    assert loader.load_snapshot(handle).effective()[0].classification_ceiling == "L1"
    original_profiles = owner.current().profiles
    profile_fixture = profiles.__wrapped__(audited)
    profile_apply(profile_fixture, profile_preview(profile_fixture))
    accepted_profiles = owner.current().profiles
    assert accepted_profiles != original_profiles
    assert accepted_profiles[0].levels[0].user_label == "Chosen label"
    with pytest.raises(PolicyRefusal):
        loader.load_snapshot(handle)
    handle = loader.admit(request)
    assert loader.load_snapshot(handle).effective()[0].classification_ceiling == "L1"
    plan, receipt = restrict(audited)
    assert owner.current().profiles == accepted_profiles
    with pytest.raises(PolicyRefusal):
        loader.load_snapshot(handle)
    handle = loader.admit(request)
    assert loader.load_snapshot(handle).effective()[0].classification_ceiling == "L0"
    registry_fixture = managed.__wrapped__(audited)
    registry_apply(registry_fixture, registry_change(registry_fixture, "destinations"))
    assert owner.current().profiles == accepted_profiles
    with pytest.raises(PolicyRefusal):
        loader.load_snapshot(handle)
    with pytest.raises(PolicyRefusal):
        loader.admit(request)
    state["claim"] = replace(state["claim"], route_revision=2)
    fresh = loader.admit(request)
    assert loader.load_snapshot(fresh).effective()[0].classification_ceiling == "L0"
    assert owner.receipt(plan.operation_id) == receipt
    records = read(audited)
    assert len(records) == 6 and [r.kind for r in records] == ["intent", "committed"] * 3
    assert len({r.operation_id for r in records}) == 3


@pytest.mark.parametrize("which", ["configuration", "configuration-witness", "journal", "journal-witness"])
def test_single_domain_restore_cannot_undo_revocation_or_silently_resume_writes(audited, which):
    fixture, journal, _, _, audit, audit_witness = audited
    owner, config, config_witness = fixture[1], fixture[-2], fixture[-1]
    connections = {"configuration": config, "configuration-witness": config_witness,
        "journal": audit, "journal-witness": audit_witness}
    target = connections[which]
    backup = sqlite3.connect(":memory:")
    try:
        target.backup(backup)
        plan, receipt = restrict(audited)
        loader, request, _ = binding(owner)
        current = owner.current()
        assert loader.load_snapshot(loader.admit(request)).effective()[0].classification_ceiling == "L0"
        backup.backup(target)
        if which.startswith("configuration"):
            with pytest.raises(PolicyRefusal):
                owner.current()
            with pytest.raises(PolicyRefusal):
                loader.admit(request)
        else:
            # Audit availability does not grant permission or undo the current
            # separately witnessed configuration restriction.
            assert owner.current() == current
            assert loader.load_snapshot(loader.admit(request)).effective()[0].classification_ceiling == "L0"
            with pytest.raises(PolicyRefusal):
                read(audited)
            with pytest.raises(PolicyRefusal):
                journal.recover()
            admin, _, proposer, reviewer, *_ = grant_fixture(audited)
            old = admin.view(proposer, "human", "c" * 32).grant
            new_plan = admin.preview(proposer, "human", "c" * 32, replace(old, classification_ceiling="L1"))
            with pytest.raises(PolicyRefusal):
                admin.apply(proposer, new_plan, approval=admin.approve(reviewer, new_plan))
            assert owner.current() == current and owner.receipt(new_plan.operation_id) is None
            assert owner.receipt(plan.operation_id) == receipt
    finally:
        backup.close()


@pytest.mark.parametrize("kind", ["grant", "registry", "profile"])
def test_explicit_journal_recovery_never_replays_any_administrative_kind(audited, monkeypatch, kind):
    if kind == "grant":
        fixture = grant_fixture(audited)
        admin, owner, proposer, reviewer, *_ = fixture
        plan = grant_preview(fixture)
    elif kind == "registry":
        fixture = managed.__wrapped__(audited)
        admin, owner, proposer, reviewer, *_ = fixture
        plan = registry_change(fixture)
    else:
        fixture = profiles.__wrapped__(audited)
        admin, owner, proposer, reviewer, *_ = fixture
        plan = profile_preview(fixture)
    approval = admin.approve(reviewer, plan)
    journal = audited[1]
    before = owner.current()
    original = journal._finish

    def fail():
        raise OSError("SECRET-interruption")

    monkeypatch.setattr(journal, "_finish", fail)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.current() == before and owner.receipt(plan.operation_id) is None
    with pytest.raises(PolicyRefusal):
        read(audited)
    monkeypatch.setattr(journal, "_finish", original)
    result = journal.recover()
    assert result.kind == "intent" and result.operation_id == plan.operation_id
    assert owner.current() == before and journal.observe(plan.operation_id, owner=owner) is None
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)


@pytest.mark.parametrize("kind", ["grant", "registry", "profile"])
def test_configuration_recovery_and_audit_reconciliation_are_distinct(audited, monkeypatch, kind):
    if kind == "grant":
        fixture = grant_fixture(audited)
        admin, owner, proposer, reviewer, *_ = fixture
        plan = grant_preview(fixture)
    elif kind == "registry":
        fixture = managed.__wrapped__(audited)
        admin, owner, proposer, reviewer, *_ = fixture
        plan = registry_change(fixture, "conversations")
    else:
        fixture = profiles.__wrapped__(audited)
        admin, owner, proposer, reviewer, *_ = fixture
        plan = profile_preview(fixture)
    approval = admin.approve(reviewer, plan)
    journal = audited[1]
    before = owner.current()
    original = owner.advance_witness

    def fail(receipt):
        original(receipt)
        raise OSError("SECRET-lost-ack")

    monkeypatch.setattr(owner, "advance_witness", fail)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    receipt = owner.receipt(plan.operation_id)
    assert receipt.phase == "prepared"
    with pytest.raises(PolicyRefusal):
        owner.current()
    with pytest.raises(PolicyRefusal):
        journal.observe(plan.operation_id, owner=owner)
    assert journal.recover().kind == "intent"
    assert owner.receipt(plan.operation_id) == receipt
    with pytest.raises(PolicyRefusal):
        owner.current()
    committed = owner.recover(plan.operation_id)
    assert committed.phase == "committed" and committed.revision.generation == before.revision.generation + 1
    assert [r.kind for r in read(audited)] == ["intent"]
    assert journal.observe(plan.operation_id, owner=owner).kind == "committed"
    assert [r.kind for r in read(audited)] == ["intent", "committed"]
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)


def test_new_lower_participant_cannot_reuse_old_ingress_context(audited):
    owner = audited[0][1]
    loader, request, state = binding(owner)
    handle = loader.admit(request)
    state["claim"] = replace(state["claim"], session_epoch=2,
        participants=state["claim"].participants + (("login", "unmapped-new-person"),))
    with pytest.raises(PolicyRefusal):
        loader.load_snapshot(handle)
    with pytest.raises(PolicyRefusal):
        loader.admit(request)
    state["claim"] = audience(session_epoch=3)
    with pytest.raises(PolicyRefusal):
        loader.load_snapshot(handle)
    fresh = loader.admit(request)
    assert loader.load_snapshot(fresh).effective()[0].classification_ceiling == "L1"


def test_unwitnessed_preparation_is_inert_but_requires_an_owner_recovery_decision(audited, monkeypatch):
    fixture = grant_fixture(audited)
    admin, owner, proposer, reviewer, *_ = fixture
    before = owner.current()
    plan = grant_preview(fixture)
    approval = admin.approve(reviewer, plan)
    original = owner.stage

    def lose_ack(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("SECRET-pre-witness-interruption")

    monkeypatch.setattr(owner, "stage", lose_ack)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    receipt = owner.receipt(plan.operation_id)
    assert receipt.phase == "prepared"
    assert owner.current() == before
    assert owner.recover(plan.operation_id) == receipt
    assert owner.current() == before
    monkeypatch.setattr(owner, "stage", original)
    fresh = grant_preview(fixture)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, fresh, approval=admin.approve(reviewer, fresh))
    assert owner.receipt(fresh.operation_id) is None and owner.current() == before
    assert [r.kind for r in read(audited)] == ["intent", "intent"]
    # Receipt inspection does not authorize silently applying, removing or
    # overwriting the old proposal merely to unblock later writes.
    assert not any(hasattr(owner, name) for name in ("abort", "abandon", "cancel_prepared"))
