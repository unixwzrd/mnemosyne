"""Disposable exact-target metadata administration; no live identity authority."""

from dataclasses import replace
import json
import threading

import pytest

from mnemosyne.core.administration_audit_contract import RegistryAdministrationIntent, _intent
from mnemosyne.core.host_registry_administration import RegistryAdministration, RegistryAdministrationSnapshot
from mnemosyne.core.host_registry import PrincipalRegistration
from mnemosyne.core.policy import PolicyRefusal
from tests.test_host_administration_journal import apply as apply_grant, audited as audited, read
from tests.test_host_grant_administration import claim, grant_admin as grant_admin
from tests.test_host_registry import STORE, authority as authority


@pytest.fixture
def managed(audited):
    fixture, journal, *_ = audited
    original, owner, proposer, reviewer, claims, calls, *_ = fixture
    targets = frozenset({("principals", p.principal_id) for p in owner.current().registry.principals} | {
        ("principals", "new-person"), ("stores", STORE), ("stores", "1" * 32),
        ("destinations", "private"), ("destinations", "new-destination"),
        ("conversations", "context:one"), ("conversations", "new-context"),
    })
    for request, prior in tuple(claims.items()):
        claims[request] = RegistryAdministrationSnapshot(prior.issuer, prior.principal_id, prior.separation_id,
            prior.authority_id, prior.authorization_revision, prior.epoch, targets, prior.controlled_principals,
            frozenset({"registry:view", "registry:write", "registry:approve"}))
    admin = RegistryAdministration(owner, authority_id="a" * 32, issuer="admin-login",
        authenticate=original._authenticate, journal=journal)
    return admin, owner, proposer, reviewer, claims, calls, audited


def change(managed, kind="principals"):
    admin, owner, proposer, *_ = managed
    registry = owner.current().registry
    if kind == "principals":
        identity, replacement = "human", replace(next(p for p in registry.principals if p.principal_id == "human"), enabled=False)
    elif kind == "stores":
        identity, replacement = STORE, replace(registry.stores[0], lifecycle_epoch=1)
    elif kind == "destinations":
        identity, replacement = "private", replace(registry.destinations[0], route_revision=2)
    else:
        identity, replacement = "context:one", replace(registry.conversations[0], classification_ceiling="L0")
    return admin.preview(proposer, kind, identity, replacement)


def apply(managed, plan):
    admin, _, proposer, reviewer, *_ = managed
    approval = admin.approve(reviewer, plan)
    return admin.apply(proposer, plan, approval=approval)


@pytest.mark.parametrize("kind", ["principals", "stores", "destinations", "conversations"])
def test_exact_target_edit_preserves_grants_profiles_and_attributes(managed, kind):
    admin, owner, proposer, _, _, _, audited = managed
    before = owner.current()
    plan = change(managed, kind)
    assert owner.current() == before
    assert admin.view(proposer, kind, plan.target_id).record == plan.prior
    receipt = apply(managed, plan)
    after = owner.current()
    assert receipt.phase == "committed" and after.revision.generation == before.revision.generation + 1
    assert after.profiles == before.profiles and after.registry.grants == before.registry.grants
    assert replace(after.registry, **{kind: getattr(before.registry, kind)}) == before.registry
    assert admin.view(proposer, kind, plan.target_id).record == plan.replacement
    records = read(audited)
    assert [r.kind for r in records] == ["intent", "committed"]
    intent = records[0].intent
    assert type(intent) is RegistryAdministrationIntent
    assert (intent.target_kind, intent.target_id) == (kind, plan.target_id)
    assert intent.plan_sha256 == plan.digest and intent.candidate == receipt.revision
    assert _intent(json.loads(json.dumps(intent.to_dict()))) == intent
    assert "replacement" not in json.dumps(intent.to_dict())
    with pytest.raises(PolicyRefusal):
        apply(managed, plan)


@pytest.mark.parametrize("kind", ["principals", "stores", "destinations", "conversations"])
def test_creation_requires_separate_provisioning_and_unreferenced_delete_is_explicit(managed, kind):
    admin, owner, proposer, *_ = managed
    registry = owner.current().registry
    if kind == "principals":
        identity = "new-person"
        replacement = PrincipalRegistration(identity, "login", "new-subject", "actor:new", "human", True)
    elif kind == "stores":
        identity, replacement = "1" * 32, replace(registry.stores[0], store_id="1" * 32)
    elif kind == "destinations":
        identity = "new-destination"
        replacement = replace(registry.destinations[0], destination_id=identity, route_id="route:new")
    else:
        identity = "new-context"
        replacement = replace(registry.conversations[0], context_id=identity, conversation_id="thread:new")
    before = owner.current()
    assert admin.view(proposer, kind, identity).record is None
    with pytest.raises(PolicyRefusal):
        admin.preview(proposer, kind, identity, replacement)
    assert owner.current() == before
    # Trusted owner provisioning is deliberately not an administrative facade.
    prepared = replace(before.registry, **{kind: getattr(before.registry, kind) + (replacement,)})
    owner.publish(before.profiles, previous=before.revision, operation_id="owner-provision", registry=prepared)
    assert admin.view(proposer, kind, identity).record == replacement
    apply(managed, admin.preview(proposer, kind, identity, None))
    assert owner.current().registry == before.registry
    assert owner.current().revision != before.revision


@pytest.mark.parametrize("method", ["view", "preview"])
@pytest.mark.parametrize("mutation", ["scope", "capability", "issuer", "authority", "wrong-type"])
def test_authentication_precedes_owner_access(managed, monkeypatch, method, mutation):
    admin, owner, proposer, _, claims, *_ = managed
    replacement = replace(next(p for p in owner.current().registry.principals if p.principal_id == "human"), enabled=False)
    if mutation == "wrong-type":
        claims[proposer] = object()
    else:
        changes = {"scope": {"targets": frozenset({("principals", "agent")})},
            "capability": {"capabilities": frozenset({"registry:approve"})},
            "issuer": {"issuer": "wrong"}, "authority": {"authority_id": "f" * 32}}[mutation]
        claims[proposer] = replace(claims[proposer], **changes)
    monkeypatch.setattr(owner, "current", lambda: pytest.fail("unauthorized owner read"))
    with pytest.raises(PolicyRefusal):
        if method == "view":
            admin.view(proposer, "principals", "human")
        else:
            admin.preview(proposer, "principals", "human", replacement)


@pytest.mark.parametrize("kind", ["principals", "stores", "destinations", "conversations"])
@pytest.mark.parametrize("who", ["proposer", "reviewer"])
def test_direct_or_indirect_beneficiary_cannot_administer(managed, kind, who):
    admin, owner, proposer, reviewer, claims, *_ = managed
    key = proposer if who == "proposer" else reviewer
    before = owner.current()
    claims[key] = replace(claims[key], controlled_principals=claims[key].controlled_principals | {"human"})
    with pytest.raises(PolicyRefusal):
        if who == "proposer":
            change(managed, kind)
        else:
            admin.approve(reviewer, change(managed, kind))
    assert owner.current() == before


@pytest.mark.parametrize("field", ["issuer", "subject", "separation_id", "kind"])
def test_existing_principal_identity_cannot_rebind_retained_grants(managed, field):
    admin, owner, proposer, *_ = managed
    prior = next(p for p in owner.current().registry.principals if p.principal_id == "human")
    value = "service" if field == "kind" else "changed"
    with pytest.raises(PolicyRefusal):
        admin.preview(proposer, "principals", "human", replace(prior, **{field: value}))


@pytest.mark.parametrize("field", ["domain_id", "bank", "profile_id", "owner_registry_key"])
def test_existing_store_cannot_redirect_retained_grants(managed, field):
    admin, owner, proposer, *_ = managed
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.preview(proposer, "stores", STORE, replace(before.registry.stores[0], **{field: "changed"}))
    assert owner.current() == before


@pytest.mark.parametrize("kind,field,value", [
    ("destinations", "issuer", "other"), ("destinations", "platform", "other"),
    ("destinations", "route_id", "other"), ("destinations", "recipients", frozenset({"human"})),
    ("destinations", "route_revision", 1), ("conversations", "store_id", "1" * 32),
    ("conversations", "destination_id", "other"), ("conversations", "participants", frozenset({"human"})),
    ("conversations", "conversation_id", "other"), ("conversations", "issuer", "other"),
])
def test_route_and_audience_substitution_refuses(managed, kind, field, value):
    admin, owner, proposer, *_ = managed
    before = owner.current()
    prior = getattr(before.registry, kind)[0]
    identity = "private" if kind == "destinations" else "context:one"
    with pytest.raises(PolicyRefusal):
        admin.preview(proposer, kind, identity, replace(prior, **{field: value}))
    assert owner.current() == before


@pytest.mark.parametrize("kind,identity", [("principals", "human"), ("stores", STORE), ("destinations", "private")])
def test_referenced_deletion_has_no_implicit_cascade(managed, kind, identity):
    admin, owner, proposer, *_ = managed
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.preview(proposer, kind, identity, None)
    assert owner.current() == before


@pytest.mark.parametrize("mode", ["alias", "shared-control", "controlled-approver", "new-target-alias"])
def test_canonical_control_exclusions_cover_both_snapshots(managed, mode):
    admin, owner, proposer, reviewer, claims, *_ = managed
    before = owner.current()
    if mode == "new-target-alias":
        replacement = PrincipalRegistration("new-person", "login", "new-subject", "actor:operator", "agent", True)
        with pytest.raises(PolicyRefusal):
            admin.preview(proposer, "principals", "new-person", replacement)
        return
    if mode == "alias":
        claims[reviewer] = replace(claims[reviewer], separation_id="actor:operator")
    elif mode == "shared-control":
        for key in claims:
            claims[key] = replace(claims[key], controlled_principals=claims[key].controlled_principals | {"agent"})
    else:
        claims[proposer] = replace(claims[proposer], controlled_principals=frozenset({"operator", "reviewer"}))
    with pytest.raises(PolicyRefusal):
        admin.approve(reviewer, change(managed))
    assert owner.current() == before


@pytest.mark.parametrize("who", ["proposer", "reviewer"])
@pytest.mark.parametrize("field", ["epoch", "authorization_revision", "capabilities", "targets", "controlled_principals"])
def test_claim_changes_consume_no_configuration_write(managed, who, field):
    admin, owner, proposer, reviewer, claims, *_ = managed
    plan = change(managed)
    approval = admin.approve(reviewer, plan)
    key = proposer if who == "proposer" else reviewer
    changes = {"epoch": 2, "authorization_revision": "0" * 64,
        "capabilities": frozenset({"registry:view"}), "targets": frozenset({("principals", "agent")}),
        "controlled_principals": claims[key].controlled_principals | {"agent"}}
    claims[key] = replace(claims[key], **{field: changes[field]})
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.current() == before


def test_cancel_copy_foreign_approval_and_missing_approval(managed):
    admin, owner, proposer, reviewer, *_ = managed
    plan = change(managed)
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan)
    with pytest.raises(PolicyRefusal):
        admin.approve(reviewer, replace(plan))
    approval = admin.approve(reviewer, plan)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=replace(approval))
    admin.cancel(plan)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.current() == before


def test_grant_and_registry_intents_coexist_without_rewriting_old_forms(managed):
    _, _, proposer, reviewer, claims, _, audited = managed
    apply(managed, change(managed))
    claims[proposer] = claim()
    claims[reviewer] = claim(principal_id="reviewer", separation_id="actor:reviewer",
                             controlled_principals=frozenset({"reviewer"}))
    apply_grant(audited[0])
    rows = read(audited)
    assert [r.kind for r in rows] == ["intent", "committed", "intent", "committed"]
    assert rows[0].intent.target_kind == "principals"
    assert rows[2].intent.principal_id == "human"
    assert "target_kind" not in rows[2].intent.to_dict()
    assert all(_intent(r.intent.to_dict()) == r.intent for r in rows if r.intent is not None)


@pytest.mark.parametrize("who", ["proposer", "reviewer"])
def test_disabled_or_unresolved_administrative_actor_refuses(managed, who):
    admin, owner, proposer, reviewer, claims, *_ = managed
    key = proposer if who == "proposer" else reviewer
    claims[key] = replace(claims[key], controlled_principals=claims[key].controlled_principals | {"unknown"})
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        if who == "proposer":
            change(managed)
        else:
            admin.approve(reviewer, change(managed))
    assert owner.current() == before


def test_reentrant_authentication_refuses_and_cleans_entry_guard(managed):
    admin, _, proposer, *_ = managed
    original = admin._authenticate

    def recurse(request):
        admin.view(request, "principals", "human")

    admin._authenticate = recurse
    with pytest.raises(PolicyRefusal):
        admin.view(proposer, "principals", "human")
    admin._authenticate = original
    assert admin.view(proposer, "principals", "human").record is not None


def test_pending_limit_expiry_and_no_content_or_recovery_api(managed, monkeypatch):
    admin, _, proposer, *_ = managed
    import mnemosyne.core.host_registry_administration as module
    monkeypatch.setattr(module, "MAX_PENDING_CHANGES", 1)
    first = change(managed)
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        change(managed)
    admin._pending[first.operation_id].deadline = 0
    second = change(managed)
    assert first.operation_id not in admin._pending
    admin.cancel(second)
    assert not any(hasattr(admin, name) for name in ("recall", "recover", "set_grant", "set_registry", "activate", "export"))
    assert admin.view(proposer, "principals", "human").record is not None


def test_aba_publication_invalidates_plan(managed):
    admin, owner, proposer, reviewer, *_ = managed
    plan = change(managed)
    approval = admin.approve(reviewer, plan)
    before = owner.current()
    modified = replace(before.registry, conversations=(replace(before.registry.conversations[0], enabled=False),))
    intermediate = owner.publish(before.profiles, previous=before.revision, operation_id="B", registry=modified)
    owner.publish(before.profiles, previous=intermediate.revision, operation_id="A-again", registry=before.registry)
    current = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.current() == current


@pytest.mark.parametrize("phase", ["stage", "advance_witness", "finalize"])
def test_consumed_plan_never_replays_after_uncertain_failure(managed, monkeypatch, phase):
    admin, owner, proposer, reviewer, *_ = managed
    plan = change(managed)
    approval = admin.approve(reviewer, plan)
    original = getattr(owner, phase)

    def fail(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("SECRET-failure")

    monkeypatch.setattr(owner, phase, fail)
    with pytest.raises(PolicyRefusal) as caught:
        admin.apply(proposer, plan, approval=approval)
    assert "SECRET" not in str(caught.value)
    assert owner.receipt(plan.operation_id) is not None
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)


def test_journal_failure_consumes_plan_before_configuration(managed, monkeypatch):
    admin, owner, proposer, reviewer, _, _, audited = managed
    journal = audited[1]
    plan = change(managed)
    approval = admin.approve(reviewer, plan)
    before = owner.current()
    monkeypatch.setattr(journal, "append_intent", lambda *a, **kw: (_ for _ in ()).throw(OSError("SECRET")))
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.current() == before and owner.receipt(plan.operation_id) is None
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)


def test_expiry_during_journal_write_prevents_stage(managed, monkeypatch):
    admin, owner, proposer, reviewer, _, _, audited = managed
    journal = audited[1]
    plan = change(managed)
    approval = admin.approve(reviewer, plan)
    pending = admin._pending[plan.operation_id]
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


def test_foreign_thread_refuses_and_local_thread_recovers(managed):
    admin, _, proposer, *_ = managed
    result = []

    def call():
        try:
            admin.view(proposer, "principals", "human")
        except PolicyRefusal:
            result.append("denied")

    thread = threading.Thread(target=call)
    thread.start()
    thread.join()
    assert result == ["denied"]
    assert admin.view(proposer, "principals", "human").record is not None


@pytest.mark.parametrize("changes", [
    {"targets": frozenset()}, {"targets": frozenset({("grants", "human")})},
    {"targets": frozenset({("stores", "not-an-id")})}, {"targets": frozenset({("principals",)})},
    {"controlled_principals": frozenset()}, {"capabilities": frozenset({"grants:write"})},
    {"epoch": True}, {"authorization_revision": "bad"},
])
def test_claim_contract_refuses_invalid_or_legacy_authority(managed, changes):
    claims = managed[4]
    with pytest.raises((ValueError, TypeError)):
        replace(next(iter(claims.values())), **changes)
