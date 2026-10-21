"""Scoped profile edits preserve witnessed registry bindings; no host activation."""

from dataclasses import replace
import json

import pytest

from mnemosyne.core.host_administration import AdministrationSnapshot
from mnemosyne.core.host_registry import AuthorizationRegistry
from mnemosyne.core.host_request_binding import LocalRequestBinding
from mnemosyne.core.policy import PolicyRefusal
from tests.test_host_administration import fixture as fixture, profile
from tests.test_host_registry import registry
from tests.test_host_request_binding import audience


@pytest.fixture(params=["empty", "populated"])
def registered(fixture, request):
    admin, owner, proposer, reviewer, claims, calls = fixture
    before = owner.current()
    value = AuthorizationRegistry() if request.param == "empty" else registry()
    owner.publish(before.profiles, previous=before.revision,
                  operation_id="register", registry=value)
    return admin, owner, proposer, reviewer, claims, calls


def registry_bytes(snapshot):
    return json.dumps(snapshot.registry.to_dict(), sort_keys=True, separators=(",", ":")).encode()


def test_labels_preserve_exact_registry_and_unrelated_profile(registered):
    admin, owner, proposer, _, claims, _ = registered
    claims[proposer] = replace(claims[proposer], capabilities=frozenset({"profiles:view", "profiles:labels"}))
    before = owner.current()
    plan = admin.preview(proposer, "example", profile(2, label="Chosen label"))
    assert plan.change_kind == "labels" and owner.current() == before
    receipt = admin.apply(proposer, plan)
    after = owner.current()
    assert receipt.phase == "committed" and after.revision.generation == before.revision.generation + 1
    assert registry_bytes(after) == registry_bytes(before)
    assert after.profiles == (profile(2, label="Chosen label"), profile(identity="other"))
    assert json.loads(after.canonical_bytes())["contract_version"] == 2
    assert not any(hasattr(admin, name) for name in ("grant", "recall", "activate", "recover", "export", "set_registry"))


def test_semantic_change_keeps_independent_approval_and_registry(registered):
    admin, owner, proposer, reviewer, _, _ = registered
    before = owner.current()
    replacement = profile(2, policy_version=2, levels=("L1", "L0"))
    plan = admin.preview(proposer, "example", replacement)
    assert plan.change_kind == "policy"
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan)
    with pytest.raises(PolicyRefusal):
        admin.approve(proposer, plan)
    approval = admin.approve(reviewer, plan)
    assert admin.apply(proposer, plan, approval=approval).phase == "committed"
    assert registry_bytes(owner.current()) == registry_bytes(before)
    assert owner.current().profiles[0] == replacement


def test_label_administrator_cannot_reorder_existing_clearances(registered):
    admin, owner, proposer, _, claims, _ = registered
    claims[proposer] = replace(claims[proposer], capabilities=frozenset({"profiles:view", "profiles:labels"}))
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.preview(proposer, "example", profile(2, policy_version=2, levels=("L1", "L0")))
    assert owner.current() == before


def test_same_actor_alias_cannot_approve_registry_profile_change(registered):
    admin, owner, proposer, reviewer, claims, _ = registered
    claims[reviewer] = replace(claims[reviewer], separation_id=claims[proposer].separation_id)
    plan = admin.preview(proposer, "example", profile(2, policy_version=2))
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.approve(reviewer, plan)
    assert owner.current() == before


def test_copied_plan_and_approval_cannot_change_registered_configuration(registered):
    admin, owner, proposer, reviewer, _, _ = registered
    plan = admin.preview(proposer, "example", profile(2, policy_version=2))
    approval = admin.approve(reviewer, plan)
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, replace(plan), approval=approval)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=replace(approval))
    assert owner.current() == before
    admin.apply(proposer, plan, approval=approval)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)


@pytest.mark.parametrize("replacement", [None, profile(2, policy_version=2, levels=("L0",))])
def test_referenced_profile_or_ceiling_cannot_disappear(fixture, replacement):
    admin, owner, proposer, _, _, _ = fixture
    before = owner.current()
    owner.publish(before.profiles, previous=before.revision, operation_id="register", registry=registry())
    before = owner.current()
    with pytest.raises(PolicyRefusal) as caught:
        admin.preview(proposer, "example", replacement)
    assert "example" not in str(caught.value) and "L1" not in str(caught.value)
    assert owner.current() == before and not admin._pending


def test_unused_profile_removal_preserves_registry(registered):
    admin, owner, proposer, reviewer, claims, _ = registered
    for key in claims:
        claims[key] = replace(claims[key], profiles=frozenset({"example", "other"}))
    before = owner.current()
    plan = admin.preview(proposer, "other", None)
    approval = admin.approve(reviewer, plan)
    admin.apply(proposer, plan, approval=approval)
    assert owner.current().profiles == (profile(),)
    assert registry_bytes(owner.current()) == registry_bytes(before)


@pytest.mark.parametrize("who", ["proposer", "reviewer"])
@pytest.mark.parametrize("mutation", ["scope", "epoch", "capability", "revision"])
def test_current_admin_authorization_still_required(registered, who, mutation):
    admin, owner, proposer, reviewer, claims, _ = registered
    plan = admin.preview(proposer, "example", profile(2, policy_version=2))
    approval = admin.approve(reviewer, plan)
    key = proposer if who == "proposer" else reviewer
    changes = {"scope": {"profiles": frozenset({"other"})}, "epoch": {"epoch": 2},
               "capability": {"capabilities": frozenset({"profiles:view"})},
               "revision": {"authorization_revision": "d" * 64}}[mutation]
    claims[key] = replace(claims[key], **changes)
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.current() == before and owner.receipt(plan.operation_id) is None


def test_registry_writer_invalidates_plan_without_resurrecting_grants(registered):
    admin, owner, proposer, _, _, _ = registered
    plan = admin.preview(proposer, "example", profile(2))
    before = owner.current()
    value = before.registry
    changed = replace(value, grants=()) if value.grants else registry()
    owner.publish(before.profiles, previous=before.revision, operation_id="other-writer", registry=changed)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan)
    assert owner.current().registry == changed and owner.receipt(plan.operation_id) is None


@pytest.mark.parametrize("boundary", ["stage", "advance_witness", "finalize"])
def test_uncertain_registry_publication_keeps_receipt_and_never_replays(registered, monkeypatch, boundary):
    admin, owner, proposer, _, claims, _ = registered
    before = owner.current()
    plan = admin.preview(proposer, "example", profile(2))
    original = getattr(owner, boundary)

    def intercepted(*args, **kwargs):
        result = original(*args, **kwargs)
        claims[proposer] = replace(claims[proposer], epoch=2)
        return result

    monkeypatch.setattr(owner, boundary, intercepted)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan)
    receipt = owner.receipt(plan.operation_id)
    assert receipt.phase == ("committed" if boundary == "finalize" else "prepared")
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan)
    if boundary == "stage":
        assert owner.current() == before
    elif boundary == "advance_witness":
        with pytest.raises(PolicyRefusal):
            owner.current()
        assert owner.recover(plan.operation_id).phase == "committed"
    if boundary != "stage":
        assert registry_bytes(owner.current()) == registry_bytes(before)


@pytest.mark.parametrize("semantic", [False, True])
def test_profile_edit_fences_existing_request_handle(fixture, semantic):
    admin, owner, proposer, reviewer, _, _ = fixture
    before = owner.current()
    owner.publish(before.profiles, previous=before.revision, operation_id="register", registry=registry())
    loader = LocalRequestBinding(owner, authority_id="a" * 32, issuer="login", authenticate=lambda _: audience())
    request = object()
    handle = loader.admit(request)
    prior = loader.load_snapshot(handle)
    candidate = profile(2, policy_version=2) if semantic else profile(2, label="Changed")
    plan = admin.preview(proposer, "example", candidate)
    approval = admin.approve(reviewer, plan) if semantic else None
    admin.apply(proposer, plan, approval=approval)
    with pytest.raises(PolicyRefusal):
        loader.load_snapshot(handle)
    fresh = loader.load_snapshot(loader.admit(request))
    assert fresh.context.epoch > prior.context.epoch
    assert fresh.effective()[0].classification_ceiling == prior.effective()[0].classification_ceiling


def test_configuration_admin_does_not_become_registered_content_principal(registered):
    admin, owner, proposer, _, _, _ = registered
    plan = admin.preview(proposer, "example", profile(2))
    admin.apply(proposer, plan)
    claim = audience(subject="operator", participants=(("login", "operator"), ("login", "agent-subject")))
    loader = LocalRequestBinding(owner, authority_id="a" * 32, issuer="login", authenticate=lambda _: claim)
    with pytest.raises(PolicyRefusal):
        loader.admit(object())


def test_no_new_administration_capability():
    with pytest.raises(ValueError):
        AdministrationSnapshot("login", "admin", "actor", "a" * 32, "c" * 64, 1,
                               frozenset({"example"}), frozenset({"registry:write"}))
