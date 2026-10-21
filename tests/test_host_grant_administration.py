"""Synthetic scoped grant administration; no real credentials or live stores."""

from dataclasses import replace
import threading

import pytest

from mnemosyne.core.host_grant_administration import GrantAdministration, GrantAdministrationSnapshot
from mnemosyne.core.host_registry import GrantRegistration, PrincipalRegistration
from mnemosyne.core.host_request_binding import LocalRequestBinding
from mnemosyne.core.policy import PolicyRefusal
from tests.test_host_registry import STORE, authority as authority, profile, registry
from tests.test_host_request_binding import audience


def claim(**changes):
    values = dict(issuer="admin-login", principal_id="operator", separation_id="actor:operator",
        authority_id="a" * 32, authorization_revision="d" * 64, epoch=1,
        targets=frozenset({("human", STORE)}), controlled_principals=frozenset({"operator"}),
        capabilities=frozenset({"grants:view", "grants:write", "grants:approve"}))
    values.update(changes)
    return GrantAdministrationSnapshot(**values)


@pytest.fixture
def grant_admin(authority):
    owner, conn, witness = authority
    value = registry()
    administrators = tuple(PrincipalRegistration(identity, "admin-login", identity + "-subject",
        "actor:" + identity, "human", True) for identity in ("operator", "reviewer"))
    owner.publish((profile(),), previous=None, operation_id="initial",
                  registry=replace(value, principals=value.principals + administrators))
    proposer, reviewer = object(), object()
    claims = {proposer: claim(), reviewer: claim(principal_id="reviewer", separation_id="actor:reviewer",
                                               controlled_principals=frozenset({"reviewer"}))}
    calls = []

    def authenticate(request):
        calls.append(request)
        return claims[request]

    admin = GrantAdministration(owner, authority_id="a" * 32, issuer="admin-login", authenticate=authenticate)
    return admin, owner, proposer, reviewer, claims, calls, conn, witness


def target_grant(owner):
    return next(g for g in owner.current().registry.grants if g.principal_id == "human")


def preview(fixture, replacement="restrict"):
    admin, owner, proposer, *_ = fixture
    candidate = replace(target_grant(owner), classification_ceiling="L0") if replacement == "restrict" else replacement
    return admin.preview(proposer, "human", STORE, candidate)


def test_view_and_replace_preserve_every_unrelated_record(grant_admin):
    admin, owner, proposer, reviewer, *_ = grant_admin
    before = owner.current()
    assert admin.view(proposer, "human", STORE).grant == target_grant(owner)
    plan = preview(grant_admin)
    assert owner.current() == before and plan.prior == target_grant(owner)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan)
    approval = admin.approve(reviewer, plan)
    assert admin.apply(proposer, plan, approval=approval).phase == "committed"
    after = owner.current()
    assert after.profiles == before.profiles
    assert replace(after.registry, grants=before.registry.grants) == before.registry
    assert tuple(g for g in after.registry.grants if g.principal_id != "human") == tuple(
        g for g in before.registry.grants if g.principal_id != "human")
    assert target_grant(owner).classification_ceiling == "L0"
    assert after.revision.generation == before.revision.generation + 1
    assert not any(hasattr(admin, name) for name in ("recall", "activate", "recover", "set_registry", "export", "set_principal"))


def test_delete_then_explicit_create_never_unions_old_grants(grant_admin):
    admin, owner, proposer, reviewer, *_ = grant_admin
    prior = target_grant(owner)
    plan = preview(grant_admin, None)
    approval = admin.approve(reviewer, plan)
    admin.apply(proposer, plan, approval=approval)
    assert admin.view(proposer, "human", STORE).grant is None
    with pytest.raises(PolicyRefusal):
        preview(grant_admin, None)
    replacement = replace(prior, projects=frozenset(), classification_ceiling="L0")
    plan = preview(grant_admin, replacement)
    assert plan.prior is None
    admin.apply(proposer, plan, approval=admin.approve(reviewer, plan))
    assert target_grant(owner) == replacement and not target_grant(owner).projects


@pytest.mark.parametrize("method", ["view", "preview"])
@pytest.mark.parametrize("changes", [
    {"targets": frozenset({("agent", STORE)})}, {"capabilities": frozenset({"grants:approve"})},
    {"issuer": "wrong"}, {"authority_id": "e" * 32},
])
def test_scope_and_capabilities_refuse_before_owner_read(grant_admin, monkeypatch, method, changes):
    admin, owner, proposer, _, claims, *_ = grant_admin
    replacement = replace(target_grant(owner), classification_ceiling="L0")
    claims[proposer] = replace(claims[proposer], **changes)
    monkeypatch.setattr(owner, "current", lambda: pytest.fail("unauthorized owner read"))
    with pytest.raises(PolicyRefusal):
        if method == "view":
            admin.view(proposer, "human", STORE)
        else:
            admin.preview(proposer, "human", STORE, replacement)


@pytest.mark.parametrize("who", ["proposer", "reviewer"])
@pytest.mark.parametrize("mode", ["direct", "controlled-agent", "registered-alias"])
def test_neither_administrator_can_benefit_from_own_change(grant_admin, who, mode):
    admin, owner, proposer, reviewer, claims, *_ = grant_admin
    key = proposer if who == "proposer" else reviewer
    changed = {"direct": {"principal_id": "human", "controlled_principals": frozenset({"human"})},
               "controlled-agent": {"controlled_principals": claims[key].controlled_principals | {"human"}},
               "registered-alias": {"separation_id": "actor:human"}}[mode]
    before = owner.current()
    if who == "proposer":
        claims[key] = replace(claims[key], **changed)
        with pytest.raises(PolicyRefusal):
            preview(grant_admin)
    else:
        plan = preview(grant_admin)
        claims[key] = replace(claims[key], **changed)
        with pytest.raises(PolicyRefusal):
            admin.approve(reviewer, plan)
    assert owner.current() == before


def test_same_actor_alias_is_not_independent_approval(grant_admin):
    admin, _, proposer, reviewer, claims, *_ = grant_admin
    plan = preview(grant_admin)
    claims[reviewer] = replace(claims[reviewer], separation_id=claims[proposer].separation_id)
    with pytest.raises(PolicyRefusal):
        admin.approve(reviewer, plan)
    with pytest.raises(PolicyRefusal):
        admin.approve(proposer, plan)


@pytest.mark.parametrize("who", ["proposer", "reviewer"])
def test_alias_of_controlled_identity_is_also_a_beneficiary(grant_admin, who):
    admin, owner, proposer, reviewer, claims, *_ = grant_admin
    before = owner.current()
    alias = PrincipalRegistration("controlled-alias", "login", "alias-subject", "actor:human", "agent", True)
    owner.publish(before.profiles, previous=before.revision, operation_id="alias",
                  registry=replace(before.registry, principals=before.registry.principals + (alias,)))
    key = proposer if who == "proposer" else reviewer
    changes = {"controlled_principals": claims[key].controlled_principals | {"controlled-alias"}}
    if who == "proposer":
        claims[key] = replace(claims[key], **changes)
        with pytest.raises(PolicyRefusal):
            preview(grant_admin)
    else:
        plan = preview(grant_admin)
        claims[key] = replace(claims[key], **changes)
        with pytest.raises(PolicyRefusal):
            admin.approve(reviewer, plan)


@pytest.mark.parametrize("mode", ["proposer-controls-reviewer", "reviewer-controls-proposer", "shared-control"])
def test_controlled_approver_and_shared_control_are_not_independent(grant_admin, mode):
    admin, owner, proposer, reviewer, claims, *_ = grant_admin
    if mode == "proposer-controls-reviewer":
        claims[proposer] = replace(claims[proposer], controlled_principals=frozenset({"operator", "reviewer"}))
    elif mode == "reviewer-controls-proposer":
        claims[reviewer] = replace(claims[reviewer], controlled_principals=frozenset({"operator", "reviewer"}))
    else:
        for key in claims:
            claims[key] = replace(claims[key], controlled_principals=claims[key].controlled_principals | {"agent"})
    plan = preview(grant_admin)
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.approve(reviewer, plan)
    assert owner.current() == before


@pytest.mark.parametrize("changes", [
    {"controlled_principals": frozenset({"operator", "unknown-controlled-identity"})},
    {"separation_id": "contradictory-actor"},
])
def test_unresolved_or_contradictory_identity_map_refuses(grant_admin, changes):
    admin, owner, proposer, _, claims, *_ = grant_admin
    claims[proposer] = replace(claims[proposer], **changes)
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.view(proposer, "human", STORE)
    with pytest.raises(PolicyRefusal):
        preview(grant_admin)
    assert owner.current() == before


@pytest.mark.parametrize("who", ["proposer", "reviewer"])
@pytest.mark.parametrize("changes", [
    {"epoch": 2}, {"authorization_revision": "e" * 64}, {"issuer": "other"},
    {"targets": frozenset({("agent", STORE)})}, {"controlled_principals": frozenset({"operator", "reviewer", "human"})},
    {"capabilities": frozenset({"grants:view"})}, {"separation_id": "new-actor"},
])
def test_changed_actor_or_approver_claims_refuse_before_write(grant_admin, who, changes):
    admin, owner, proposer, reviewer, claims, *_ = grant_admin
    plan = preview(grant_admin)
    approval = admin.approve(reviewer, plan)
    key = proposer if who == "proposer" else reviewer
    claims[key] = replace(claims[key], **changes)
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.current() == before and owner.receipt(plan.operation_id) is None


@pytest.mark.parametrize("changes", [{"epoch": 2}, {"authorization_revision": "e" * 64}])
def test_approval_requires_same_independent_admin_revision(grant_admin, changes):
    admin, _, _, reviewer, claims, *_ = grant_admin
    plan = preview(grant_admin)
    claims[reviewer] = replace(claims[reviewer], **changes)
    with pytest.raises(PolicyRefusal):
        admin.approve(reviewer, plan)


@pytest.mark.parametrize("replacement", [
    {"principal_id": "agent"}, {"store_id": "f" * 32}, {"classification_ceiling": "unknown"},
    {"destinations": frozenset({"unregistered"})},
])
def test_invalid_or_retargeted_proposals_never_write(grant_admin, replacement):
    admin, owner, proposer, *_ = grant_admin
    before = owner.current()
    candidate = replace(target_grant(owner), **replacement)
    with pytest.raises(PolicyRefusal):
        admin.preview(proposer, "human", STORE, candidate)
    assert owner.current() == before and not admin._pending


def test_profile_only_authority_is_not_provisioned(authority):
    owner, *_ = authority
    owner.publish((profile(),), previous=None, operation_id="legacy")
    before = owner.current()
    admin = GrantAdministration(owner, authority_id="a" * 32, issuer="admin-login", authenticate=lambda _: claim())
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        admin.view(None, "human", STORE)
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        admin.preview(None, "human", STORE, GrantRegistration("human", STORE, "L0"))
    assert owner.current() == before


def test_copied_foreign_replayed_and_cancelled_handles_refuse(grant_admin):
    admin, owner, proposer, reviewer, *_ = grant_admin
    plan = preview(grant_admin)
    approval = admin.approve(reviewer, plan)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, replace(plan), approval=approval)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=replace(approval))
    other = GrantAdministration(owner, authority_id="a" * 32, issuer="admin-login", authenticate=lambda _: claim())
    with pytest.raises(PolicyRefusal):
        other.cancel(plan)
    admin.apply(proposer, plan, approval=approval)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    another = admin.preview(proposer, "human", STORE, None)
    admin.cancel(another)
    with pytest.raises(PolicyRefusal):
        admin.approve(reviewer, another)


@pytest.mark.parametrize("aba", [False, True])
def test_competing_writer_and_aba_never_restore_prior_grants(grant_admin, aba):
    admin, owner, proposer, reviewer, *_ = grant_admin
    plan = preview(grant_admin)
    approval = admin.approve(reviewer, plan)
    before = owner.current()
    receipt = owner.publish(before.profiles, previous=before.revision, operation_id="revoke",
                            registry=replace(before.registry, grants=()))
    if aba:
        owner.publish(before.profiles, previous=receipt.revision, operation_id="restore-explicit", registry=before.registry)
    after = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.current() == after and owner.receipt(plan.operation_id) is None


@pytest.mark.parametrize("boundary", ["stage", "advance_witness", "finalize"])
@pytest.mark.parametrize("who", ["proposer", "reviewer"])
def test_revocation_at_each_publication_boundary_consumes_plan(grant_admin, monkeypatch, boundary, who):
    admin, owner, proposer, reviewer, claims, *_ = grant_admin
    plan = preview(grant_admin)
    approval = admin.approve(reviewer, plan)
    original = getattr(owner, boundary)
    key = proposer if who == "proposer" else reviewer

    def intercepted(*args, **kwargs):
        result = original(*args, **kwargs)
        claims[key] = replace(claims[key], epoch=2)
        return result

    monkeypatch.setattr(owner, boundary, intercepted)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    receipt = owner.receipt(plan.operation_id)
    assert receipt.phase == ("committed" if boundary == "finalize" else "prepared")
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)


def test_grant_change_fences_request_and_preserves_complete_audience(grant_admin):
    admin, owner, proposer, reviewer, *_ = grant_admin
    loader = LocalRequestBinding(owner, authority_id="a" * 32, issuer="login", authenticate=lambda _: audience())
    request = object()
    old = loader.admit(request)
    assert loader.load_snapshot(old).effective()[0].classification_ceiling == "L1"
    plan = preview(grant_admin)
    admin.apply(proposer, plan, approval=admin.approve(reviewer, plan))
    with pytest.raises(PolicyRefusal):
        loader.load_snapshot(old)
    effective = loader.load_snapshot(loader.admit(request)).effective()[0]
    assert effective.classification_ceiling == "L0" and effective.principals == {"human", "agent"}


def test_capacity_and_expiry(grant_admin, monkeypatch):
    import mnemosyne.core.host_grant_administration as module
    admin, _, proposer, reviewer, *_ = grant_admin
    clock = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    plans = [preview(grant_admin) for _ in range(64)]
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        preview(grant_admin)
    clock[0] = 60.0
    with pytest.raises(PolicyRefusal):
        admin.approve(reviewer, plans[0])
    assert not admin._pending
    preview(grant_admin)
    assert admin.view(proposer, "human", STORE).grant


@pytest.mark.parametrize("threshold", [1, 2, 3, 4, 5, 6, 7, 8])
def test_slow_authentication_never_crosses_write_deadline(grant_admin, monkeypatch, threshold):
    import mnemosyne.core.host_grant_administration as module
    admin, owner, proposer, reviewer, _, *_ = grant_admin
    clock, count = [0.0], [0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    plan = preview(grant_admin)
    approval = admin.approve(reviewer, plan)
    authenticate = admin._authenticate

    def slow(request):
        count[0] += 1
        result = authenticate(request)
        if count[0] == threshold:
            clock[0] = 61.0
        return result

    admin._authenticate = slow
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    receipt = owner.receipt(plan.operation_id)
    if threshold <= 4:
        assert receipt is None
    else:
        assert receipt.phase == "prepared"


def test_public_errors_reentry_foreign_thread_and_process_are_bounded(grant_admin, monkeypatch):
    import mnemosyne.core.host_grant_administration as module
    admin, _, proposer, _, _, *_ = grant_admin
    with pytest.raises(PolicyRefusal) as caught:
        admin.view("SECRET-REQUEST", "human", STORE)
    assert "SECRET" not in str(caught.value)
    original = admin._authenticate
    admin._authenticate = lambda request: admin.view(request, "human", STORE)
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        admin.view(proposer, "human", STORE)
    admin._authenticate = original
    failures = []

    def other_thread():
        try:
            admin.view(proposer, "human", STORE)
        except PolicyRefusal as error:
            failures.append(str(error))

    thread = threading.Thread(target=other_thread)
    thread.start()
    thread.join(timeout=2)
    assert failures == ["policy_refused:unsupported_surface"] and not thread.is_alive()
    assert admin.view(proposer, "human", STORE).grant
    monkeypatch.setattr(module.os, "getpid", lambda: -1)
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        admin.view(proposer, "human", STORE)


@pytest.mark.parametrize("changes", [
    {"targets": frozenset()}, {"targets": {("human", STORE)}}, {"targets": frozenset({"human"})},
    {"targets": frozenset({("human", "invalid")})}, {"targets": frozenset((f"p:{i}", STORE) for i in range(257))},
    {"controlled_principals": frozenset()}, {"controlled_principals": frozenset({"not-actor"})},
    {"controlled_principals": frozenset({"operator", "\ud800"})}, {"capabilities": frozenset()},
    {"capabilities": frozenset({"memory:read"})}, {"capabilities": frozenset({"profiles:approve"})},
    {"epoch": True}, {"epoch": 0}, {"authorization_revision": "not-a-hash"},
])
def test_strict_admin_claims(changes):
    with pytest.raises((TypeError, ValueError)):
        claim(**changes)


def test_target_scope_is_not_cartesian_product(grant_admin, monkeypatch):
    admin, owner, proposer, _, claims, *_ = grant_admin
    other_store = "f" * 32
    claims[proposer] = replace(claims[proposer], targets=frozenset({("human", STORE), ("agent", other_store)}))
    monkeypatch.setattr(owner, "current", lambda: pytest.fail("out-of-pair owner read"))
    with pytest.raises(PolicyRefusal):
        admin.view(proposer, "human", other_store)


@pytest.mark.parametrize("identity", ["operator", "human"])
def test_disabled_administrator_refuses_and_grant_does_not_enable_target(grant_admin, identity):
    admin, owner, proposer, reviewer, *_ = grant_admin
    before = owner.current()
    principals = tuple(replace(p, enabled=False) if p.principal_id == identity else p
                       for p in before.registry.principals)
    owner.publish(before.profiles, previous=before.revision, operation_id="disable",
                  registry=replace(before.registry, principals=principals))
    if identity == "operator":
        with pytest.raises(PolicyRefusal):
            preview(grant_admin)
        with pytest.raises(PolicyRefusal):
            admin.view(proposer, "human", STORE)
    else:
        plan = preview(grant_admin)
        admin.apply(proposer, plan, approval=admin.approve(reviewer, plan))
        assert not next(p for p in owner.current().registry.principals if p.principal_id == "human").enabled
        loader = LocalRequestBinding(owner, authority_id="a" * 32, issuer="login", authenticate=lambda _: audience())
        with pytest.raises(PolicyRefusal):
            loader.admit(object())


def test_stale_cas_during_stage_cannot_undo_revocation(grant_admin, monkeypatch):
    admin, owner, proposer, reviewer, *_ = grant_admin
    plan = preview(grant_admin)
    approval = admin.approve(reviewer, plan)
    stage = owner.stage

    def competing(*args, **kwargs):
        current = owner.current()
        receipt = stage(current.profiles, previous=current.revision, operation_id="race-revoke",
                        registry=replace(current.registry, grants=()))
        owner.advance_witness(receipt)
        owner.finalize(receipt)
        return stage(*args, **kwargs)

    monkeypatch.setattr(owner, "stage", competing)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert not owner.current().registry.grants and owner.receipt(plan.operation_id) is None
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
