"""Explicit journaled profile changes and canonical beneficiary exclusions."""

from dataclasses import replace
import hashlib
import json

import pytest

from mnemosyne.core.administration_audit_contract import ProfileAdministrationIntent, _intent
from mnemosyne.core.host_administration import AdministrationSnapshot, ProfileAdministration
from mnemosyne.core.host_configuration import _canonical
from mnemosyne.core.host_registry import PrincipalRegistration
from mnemosyne.core.policy import PolicyRefusal
from tests.test_host_administration_journal import audited as audited, read
from tests.test_host_grant_administration import grant_admin as grant_admin
from tests.test_host_registry import authority as authority


@pytest.fixture
def profiles(audited):
    fixture, journal, *_ = audited
    original, owner, proposer, reviewer, claims, calls, *_ = fixture
    for request, prior in tuple(claims.items()):
        claims[request] = AdministrationSnapshot(prior.issuer, prior.principal_id, prior.separation_id,
            prior.authority_id, prior.authorization_revision, prior.epoch, frozenset({"example", "unused"}),
            frozenset({"profiles:view", "profiles:labels", "profiles:policy", "profiles:approve"}),
            prior.controlled_principals)
    admin = ProfileAdministration(owner, authority_id="a" * 32, issuer="admin-login",
        authenticate=original._authenticate, journal=journal)
    return admin, owner, proposer, reviewer, claims, calls, audited


def replacement(owner, kind="labels"):
    prior = next(p for p in owner.current().profiles if p.profile_id == "example")
    if kind == "labels":
        return replace(prior, version=prior.version + 1,
            levels=(replace(prior.levels[0], user_label="Chosen label"), *prior.levels[1:]))
    return replace(prior, version=prior.version + 1,
        policy=replace(prior.policy, version=prior.policy.version + 1, levels=tuple(reversed(prior.policy.levels))),
        levels=tuple(reversed(prior.levels)))


def preview(profiles, kind="labels"):
    admin, owner, proposer, *_ = profiles
    return admin.preview(proposer, "example", replacement(owner, kind))


def apply(profiles, plan):
    admin, _, proposer, reviewer, *_ = profiles
    return admin.apply(proposer, plan, approval=admin.approve(reviewer, plan))


@pytest.mark.parametrize("kind", ["labels", "policy"])
def test_journaled_changes_require_independent_approval_and_preserve_registry(profiles, kind):
    admin, owner, proposer, reviewer, _, _, audited = profiles
    before = owner.current()
    plan = preview(profiles, kind)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan)
    with pytest.raises(PolicyRefusal):
        admin.approve(proposer, plan)
    receipt = apply(profiles, plan)
    assert receipt.phase == "committed" and owner.current().registry == before.registry
    records = read(audited)
    assert [r.kind for r in records] == ["intent", "committed"]
    intent = records[0].intent
    assert type(intent) is ProfileAdministrationIntent and intent.profile_id == "example"
    assert intent.plan_sha256 == plan.digest and intent.candidate == receipt.revision
    assert intent.proposer.principal_id == "operator" and intent.approver.principal_id == "reviewer"
    assert _intent(json.loads(json.dumps(intent.to_dict()))) == intent
    assert "replacement" not in intent.to_dict() and "principal_id" not in intent.to_dict()
    assert journal_types(profiles) == [ProfileAdministrationIntent]
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=admin.approve(reviewer, plan))


def journal_types(profiles):
    return [type(record.intent) for record in read(profiles[-1]) if record.intent is not None]


@pytest.mark.parametrize("who", ["proposer", "reviewer"])
@pytest.mark.parametrize("mode", ["direct-grant", "controlled", "canonical-alias", "context-participant"])
def test_profile_change_cannot_elevate_either_actor(profiles, who, mode):
    admin, owner, proposer, reviewer, claims, *_ = profiles
    key = proposer if who == "proposer" else reviewer
    before = owner.current()
    value = before.registry
    person = claims[key].principal_id
    if mode == "controlled":
        claims[key] = replace(claims[key], controlled_principals=claims[key].controlled_principals | {"human"})
    else:
        if mode == "canonical-alias":
            person = "admin-alias"
            alias = PrincipalRegistration(person, "login", "alias-subject", claims[key].separation_id, "agent", True)
            value = replace(value, principals=value.principals + (alias,))
        if mode == "context-participant":
            participants = value.conversations[0].participants | {person}
            value = replace(value, destinations=(replace(value.destinations[0], recipients=participants),),
                conversations=(replace(value.conversations[0], participants=participants),))
        else:
            value = replace(value, grants=value.grants + (replace(value.grants[0], principal_id=person),))
        owner.publish(before.profiles, previous=before.revision, operation_id="beneficiary", registry=value)
    current = owner.current()
    with pytest.raises(PolicyRefusal):
        if who == "proposer":
            preview(profiles)
        else:
            admin.approve(reviewer, preview(profiles))
    assert owner.current() == current and not read(profiles[-1])


@pytest.mark.parametrize("mode", ["same-canonical", "shared-control", "controls-approver"])
def test_alias_and_controlled_approval_is_not_independent(profiles, mode):
    admin, owner, proposer, reviewer, claims, *_ = profiles
    if mode == "same-canonical":
        claims[reviewer] = replace(claims[reviewer], separation_id=claims[proposer].separation_id)
    elif mode == "shared-control":
        # A separate unbenefiting registered service can still be jointly controlled.
        current = owner.current()
        principal = PrincipalRegistration("shared", "login", "shared", "actor:shared", "service", True)
        owner.publish(current.profiles, previous=current.revision, operation_id="shared",
            registry=replace(current.registry, principals=current.registry.principals + (principal,)))
        for key in claims:
            claims[key] = replace(claims[key], controlled_principals=claims[key].controlled_principals | {"shared"})
    else:
        claims[proposer] = replace(claims[proposer], controlled_principals=frozenset({"operator", "reviewer"}))
    plan = preview(profiles)
    with pytest.raises(PolicyRefusal):
        admin.approve(reviewer, plan)


def test_missing_controls_refuse_before_metadata_access(profiles, monkeypatch):
    admin, owner, proposer, _, claims, *_ = profiles
    claims[proposer] = replace(claims[proposer], controlled_principals=None)
    monkeypatch.setattr(owner, "current", lambda: pytest.fail("unauthorized owner read"))
    with pytest.raises(PolicyRefusal):
        admin.view(proposer, "example")


@pytest.mark.parametrize("changes", [
    {"controlled_principals": frozenset({"operator", "unknown"})},
    {"separation_id": "contradiction"}, {"issuer": "wrong"},
])
def test_unresolved_or_contradictory_claims_refuse(profiles, changes):
    admin, owner, proposer, _, claims, *_ = profiles
    claims[proposer] = replace(claims[proposer], **changes)
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.view(proposer, "example")
    with pytest.raises(PolicyRefusal):
        preview(profiles)
    assert owner.current() == before


@pytest.mark.parametrize("who", ["proposer", "reviewer"])
@pytest.mark.parametrize("changes", [
    {"epoch": 2}, {"authorization_revision": "1" * 64},
    {"controlled_principals": frozenset({"operator", "reviewer"})},
    {"capabilities": frozenset({"profiles:view"})}, {"profiles": frozenset({"unused"})},
])
def test_fresh_claim_changes_deny_before_write(profiles, who, changes):
    admin, owner, proposer, reviewer, claims, *_ = profiles
    plan = preview(profiles)
    approval = admin.approve(reviewer, plan)
    key = proposer if who == "proposer" else reviewer
    claims[key] = replace(claims[key], **changes)
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.current() == before and not read(profiles[-1])


@pytest.mark.parametrize("phase", ["stage", "advance_witness", "finalize"])
def test_uncertain_publication_consumes_plan_and_retains_attribution(profiles, monkeypatch, phase):
    admin, owner, proposer, reviewer, *_ = profiles
    plan = preview(profiles)
    approval = admin.approve(reviewer, plan)
    original = getattr(owner, phase)

    def fail(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("SECRET")

    monkeypatch.setattr(owner, phase, fail)
    with pytest.raises(PolicyRefusal) as caught:
        admin.apply(proposer, plan, approval=approval)
    assert "SECRET" not in str(caught.value) and owner.receipt(plan.operation_id) is not None
    assert read(profiles[-1])[0].intent.plan_sha256 == plan.digest
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)


def test_journal_delay_can_expire_plan_without_configuration_stage(profiles, monkeypatch):
    admin, owner, proposer, reviewer, _, _, audited = profiles
    plan = preview(profiles)
    approval = admin.approve(reviewer, plan)
    pending = admin._pending[plan.operation_id]
    journal = audited[1]
    original = journal.append_intent

    def append(*args, **kwargs):
        result = original(*args, **kwargs)
        pending.deadline = 0
        return result

    monkeypatch.setattr(journal, "append_intent", append)
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.current() == before and owner.receipt(plan.operation_id) is None
    assert [r.kind for r in read(audited)] == ["intent"]


def test_profile_and_registry_intents_share_existing_journal(profiles):
    from tests.test_host_registry_management import managed, change, apply as registry_apply
    apply(profiles, preview(profiles))
    registry_fixture = managed.__wrapped__(profiles[-1])
    registry_apply(registry_fixture, change(registry_fixture))
    types = journal_types(profiles)
    assert types[0] is ProfileAdministrationIntent and types[1].__name__ == "RegistryAdministrationIntent"


def test_unused_profile_create_delete_is_attributed_without_registry_mutation(profiles):
    admin, owner, proposer, *_ = profiles
    before = owner.current()
    original = before.profiles[0]
    unused = replace(original, profile_id="unused", policy=replace(original.policy, policy_id="unused"))
    plan = admin.preview(proposer, "unused", unused)
    apply(profiles, plan)
    assert owner.current().registry == before.registry
    apply(profiles, admin.preview(proposer, "unused", None))
    assert owner.current().profiles == before.profiles and owner.current().registry == before.registry
    assert all(r.intent.profile_id == "unused" for r in read(profiles[-1]) if r.intent is not None)


def test_referenced_profile_delete_refuses_before_journal(profiles):
    admin, owner, proposer, *_ = profiles
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.preview(proposer, "example", None)
    assert owner.current() == before and not read(profiles[-1])


def test_shared_policy_namespace_cannot_poison_unrelated_revocations(profiles):
    admin, owner, proposer, *_ = profiles
    before = owner.current()
    original = before.profiles[0]
    unused = replace(original, profile_id="unused", policy=replace(original.policy, version=original.policy.version + 1))
    with pytest.raises(PolicyRefusal):
        admin.preview(proposer, "unused", unused)
    assert owner.current() == before and not read(profiles[-1])


def test_profile_capabilities_do_not_authorize_sensitive_journal_reads(profiles):
    _, _, proposer, _, claims, _, audited = profiles
    _, journal, reader, state, *_ = audited
    state["claim"] = claims[proposer]
    with pytest.raises(PolicyRefusal):
        journal.read(reader, destination="audit:private")


def test_hybrid_profile_intent_refuses_without_changing_stored_form(profiles):
    apply(profiles, preview(profiles))
    intent = read(profiles[-1])[0].intent
    value = intent.to_dict()
    for extra in ({"target_kind": "principals", "target_id": "human"}, {"principal_id": "human", "store_id": "c" * 32}):
        with pytest.raises(ValueError):
            _intent(dict(value, **extra))
    assert _intent(value) == intent


def test_lost_observation_preserves_committed_receipt_and_requires_explicit_reconcile(profiles, monkeypatch):
    admin, owner, proposer, reviewer, _, _, audited = profiles
    journal = audited[1]
    plan = preview(profiles)
    approval = admin.approve(reviewer, plan)
    original = journal.observe

    def fail(*args, **kwargs):
        raise OSError("SECRET")

    monkeypatch.setattr(journal, "observe", fail)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.receipt(plan.operation_id).phase == "committed"
    assert [r.kind for r in read(audited)] == ["intent"]
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    monkeypatch.setattr(journal, "observe", original)
    assert journal.observe(plan.operation_id, owner=owner).kind == "committed"
    assert [r.kind for r in read(audited)] == ["intent", "committed"]


def test_legacy_default_fingerprint_remains_exact(profiles):
    claims = profiles[4]
    current = next(iter(claims.values()))
    legacy = replace(current, controlled_principals=None)
    expected = {"issuer": legacy.issuer, "principal_id": legacy.principal_id, "separation_id": legacy.separation_id,
        "authority_id": legacy.authority_id, "authorization_revision": legacy.authorization_revision,
        "epoch": legacy.epoch, "profiles": sorted(legacy.profiles), "capabilities": sorted(legacy.capabilities)}
    assert legacy.fingerprint() == hashlib.sha256(_canonical(expected)).hexdigest()
    assert legacy.fingerprint() != current.fingerprint()


@pytest.mark.parametrize("value", [frozenset(), frozenset({"not-actor"}), {"operator"}, frozenset({"operator", " x"})])
def test_controls_contract_is_explicit_and_bounded(profiles, value):
    with pytest.raises((TypeError, ValueError)):
        replace(next(iter(profiles[4].values())), controlled_principals=value)
