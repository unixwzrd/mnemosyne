"""Synthetic authenticated administrative sessions; no actual host activation."""

from dataclasses import replace
import sqlite3

import pytest

from mnemosyne.core.host_administration import (
    AdministrationApproval, AdministrationPlan, AdministrationSnapshot,
    ProfileAdministration,
)
from mnemosyne.core.host_configuration import HostConfigurationAuthority
from mnemosyne.core.host_profile import LevelDisplayMetadata, ProfileDefinition
from mnemosyne.core.policy import PolicyDefinition, PolicyRefusal


def profile(version=1, *, identity="example", policy_version=1, levels=("L0", "L1"), label="Restricted"):
    return ProfileDefinition(identity, version, PolicyDefinition("policy:" + identity, policy_version, levels),
        tuple(LevelDisplayMetadata(level, label + level, "Admin " + level) for level in levels), ())


def claim(*, principal="operator", separation="human:one", profiles=frozenset({"example"}),
          capabilities=frozenset({"profiles:view", "profiles:labels", "profiles:policy", "profiles:approve"}), **values):
    return AdministrationSnapshot("test:authenticated", principal, separation, "a" * 32, "c" * 64,
        1, profiles, capabilities, **values)


@pytest.fixture
def fixture(tmp_path):
    connections = []
    for name in ("configuration", "witness"):
        root = tmp_path / name
        root.mkdir(mode=0o700)
        path = root / "state.sqlite"
        conn = sqlite3.connect(path, timeout=0)
        path.chmod(0o600)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        connections.append(conn)
    owner = HostConfigurationAuthority(connections[0], authority_id="a" * 32,
        witness_connection=connections[1], witness_id="b" * 32)
    owner.prepare()
    owner.publish((profile(), profile(identity="other")), previous=None, operation_id="initial")
    proposer, reviewer = object(), object()
    claims = {proposer: claim(), reviewer: claim(principal="reviewer", separation="human:two")}
    calls = []

    def authenticate(request):
        calls.append(request)
        return claims[request]

    admin = ProfileAdministration(owner, authority_id="a" * 32,
        issuer="test:authenticated", authenticate=authenticate)
    yield admin, owner, proposer, reviewer, claims, calls
    for conn in connections:
        conn.close()


def test_view_and_display_only_change_never_grant_content(fixture):
    admin, owner, proposer, _, _, _ = fixture
    before = owner.current()
    view = admin.view(proposer, "example")
    assert view.profile == profile() and view.revision == before.revision
    candidate = profile(2, label="User chosen")
    plan = admin.preview(proposer, "example", candidate)
    assert plan.change_kind == "labels" and owner.current() == before
    result = admin.apply(proposer, plan)
    assert result.phase == "committed"
    assert owner.current().profiles == (candidate, profile(identity="other"))
    assert not any(hasattr(admin, name) for name in ("recall", "get_memory", "grant", "activate", "recover", "export"))
    assert set(row[0] for row in owner._store.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")) == {
        "host_configuration_state", "host_configuration_revisions", "host_profile_versions", "host_policy_versions"}


@pytest.mark.parametrize("method", ["view", "preview"])
def test_out_of_scope_refuses_before_owner_read(fixture, monkeypatch, method):
    admin, owner, proposer, _, _, _ = fixture
    monkeypatch.setattr(owner, "current", lambda: pytest.fail("unauthorized metadata read"))
    with pytest.raises(PolicyRefusal, match="access_denied"):
        if method == "view":
            admin.view(proposer, "other")
        else:
            admin.preview(proposer, "other", profile(2, identity="other"))


@pytest.mark.parametrize("change", ["add", "delete", "order", "policy_version", "policy_identity"])
def test_semantic_changes_need_independent_exact_approval(fixture, change):
    admin, owner, proposer, reviewer, claims, _ = fixture
    target = "example"
    replacement = {
        "add": profile(identity="new"), "delete": None,
        "order": profile(2, policy_version=2, levels=("L1", "L0")),
        "policy_version": profile(2, policy_version=2),
        "policy_identity": replace(profile(2), policy=PolicyDefinition("different", 1, ("L0", "L1"))),
    }[change]
    if change == "add":
        target = "new"
        for key in claims:
            claims[key] = replace(claims[key], profiles=frozenset({"example", "new"}))
    plan = admin.preview(proposer, target, replacement)
    assert plan.change_kind == "policy"
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan)
    with pytest.raises(PolicyRefusal):
        admin.approve(proposer, plan)
    approval = admin.approve(reviewer, plan)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=replace(approval))
    assert admin.apply(proposer, plan, approval=approval).phase == "committed"
    assert next((p for p in owner.current().profiles if p.profile_id == target), None) == replacement


def test_alias_is_not_independent_approval(fixture):
    admin, _, proposer, reviewer, claims, _ = fixture
    claims[reviewer] = replace(claims[reviewer], separation_id=claims[proposer].separation_id)
    plan = admin.preview(proposer, "example", profile(2, policy_version=2))
    with pytest.raises(PolicyRefusal, match="access_denied"):
        admin.approve(reviewer, plan)


@pytest.mark.parametrize("changes", [{"epoch": 2}, {"authorization_revision": "d" * 64}])
def test_approval_requires_same_current_authority_revision(fixture, changes):
    admin, _, proposer, reviewer, claims, _ = fixture
    plan = admin.preview(proposer, "example", profile(2, policy_version=2))
    claims[reviewer] = replace(claims[reviewer], **changes)
    with pytest.raises(PolicyRefusal):
        admin.approve(reviewer, plan)


@pytest.mark.parametrize("capability", ["profiles:view", "profiles:labels"])
def test_display_administrator_cannot_change_policy(fixture, capability):
    admin, _, proposer, _, claims, _ = fixture
    claims[proposer] = replace(claims[proposer], capabilities=frozenset({"profiles:view", capability}))
    with pytest.raises(PolicyRefusal):
        admin.preview(proposer, "example", profile(2, policy_version=2))


@pytest.mark.parametrize("mutate", [
    {"epoch": 2}, {"authorization_revision": "d" * 64}, {"profiles": frozenset({"other"})},
    {"capabilities": frozenset({"profiles:view"})}, {"issuer": "other"},
    {"principal_id": "other"}, {"authority_id": "e" * 32}, {"separation_id": "human:changed"},
])
@pytest.mark.parametrize("who", ["proposer", "reviewer"])
def test_changed_authorization_invalidates_exact_plan_or_approval(fixture, mutate, who):
    admin, owner, proposer, reviewer, claims, _ = fixture
    plan = admin.preview(proposer, "example", profile(2, policy_version=2))
    approval = admin.approve(reviewer, plan)
    key = proposer if who == "proposer" else reviewer
    claims[key] = replace(claims[key], **mutate)
    before = owner.current()
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.current() == before


def test_foreign_and_copied_handles_replay_cancellation(fixture):
    admin, owner, proposer, _, _, _ = fixture
    plan = admin.preview(proposer, "example", profile(2))
    assert type(plan) is AdministrationPlan
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, replace(plan))
    foreign = ProfileAdministration(owner, authority_id="a" * 32, issuer="test:authenticated",
        authenticate=lambda request: claim())
    with pytest.raises(PolicyRefusal):
        foreign.apply(proposer, plan)
    admin.cancel(plan)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan)
    another = admin.preview(proposer, "example", profile(2))
    admin.apply(proposer, another)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, another)


def test_expiration_and_capacity_are_bounded(fixture, monkeypatch):
    import mnemosyne.core.host_administration as module
    admin, _, proposer, _, _, _ = fixture
    clock = [100.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    plan = admin.preview(proposer, "example", profile(2))
    for _ in range(63):
        admin.preview(proposer, "example", profile(2))
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        admin.preview(proposer, "example", profile(2))
    clock[0] = 160.0
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan)
    assert not admin._pending
    admin.preview(proposer, "example", profile(2))


def test_other_writer_requires_fresh_preview(fixture):
    admin, owner, proposer, _, _, _ = fixture
    plan = admin.preview(proposer, "example", profile(2))
    prior = owner.current()
    owner.publish((profile(), profile(2, identity="other")), previous=prior.revision, operation_id="other-writer")
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan)
    assert owner.receipt(plan.operation_id) is None


@pytest.mark.parametrize("boundary", ["stage", "advance_witness", "finalize"])
def test_revocation_at_publication_boundary_never_replays(fixture, monkeypatch, boundary):
    admin, owner, proposer, _, claims, _ = fixture
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
    assert receipt is not None
    assert receipt.phase == ("committed" if boundary == "finalize" else "prepared")
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan)
    if boundary == "stage":
        assert owner.current() == before
    elif boundary == "advance_witness":
        with pytest.raises(PolicyRefusal):
            owner.current()
    else:
        assert owner.current().revision == receipt.revision


def test_read_rechecks_before_releasing_metadata(fixture, monkeypatch):
    admin, owner, proposer, _, claims, _ = fixture
    original = owner.current

    def current():
        value = original()
        claims[proposer] = replace(claims[proposer], epoch=2)
        return value

    monkeypatch.setattr(owner, "current", current)
    with pytest.raises(PolicyRefusal):
        admin.view(proposer, "example")


def test_unknown_request_callback_failures_are_content_free_and_unlock(fixture):
    admin, _, proposer, _, _, _ = fixture
    with pytest.raises(PolicyRefusal) as error:
        admin.view("SECRET-unauthenticated-token", "example")
    assert "SECRET" not in str(error.value)
    assert admin.view(proposer, "example").profile == profile()


def test_reentrancy_and_foreign_process_refuse(fixture, monkeypatch):
    import mnemosyne.core.host_administration as module
    admin, _, proposer, _, _, _ = fixture
    original = admin._authenticate
    admin._authenticate = lambda request: admin.view(request, "example")
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        admin.view(proposer, "example")
    admin._authenticate = original
    assert admin.view(proposer, "example").profile == profile()
    monkeypatch.setattr(module.os, "getpid", lambda: -1)
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        admin.view(proposer, "example")


@pytest.mark.parametrize("changes", [
    {"capabilities": frozenset({"*"})}, {"capabilities": frozenset({"memory:read"})},
    {"capabilities": frozenset()}, {"profiles": frozenset()}, {"profiles": {"example"}},
    {"authorization_revision": "not-a-hash"}, {"epoch": True}, {"epoch": 0},
    {"separation_id": "\ud800"}, {"profiles": frozenset({"*"})},
])
def test_strict_claims_or_literal_nonmatching_scope(fixture, changes):
    admin, _, proposer, _, claims, _ = fixture
    if changes == {"profiles": frozenset({"*"})}:
        claims[proposer] = replace(claims[proposer], **changes)
        with pytest.raises(PolicyRefusal):
            admin.view(proposer, "example")
    else:
        with pytest.raises((TypeError, ValueError)):
            replace(claims[proposer], **changes)


def test_wrong_input_and_label_approval_do_not_write(fixture):
    admin, owner, proposer, reviewer, _, _ = fixture
    before = owner.current()
    for replacement in (profile(), profile(identity="other"), object()):
        with pytest.raises(PolicyRefusal):
            admin.preview(proposer, "example", replacement)
    plan = admin.preview(proposer, "example", profile(2))
    with pytest.raises(PolicyRefusal):
        admin.approve(reviewer, plan)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=AdministrationApproval(plan.operation_id, plan.digest))
    assert owner.current() == before


@pytest.mark.parametrize("boundary", ["stage", "advance_witness", "finalize"])
def test_lost_acknowledgment_consumes_plan_without_implying_rollback(fixture, monkeypatch, boundary):
    admin, owner, proposer, _, _, _ = fixture
    plan = admin.preview(proposer, "example", profile(2))
    original = getattr(owner, boundary)

    def uncertain(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("PRIVATE synthetic acknowledgment loss")

    monkeypatch.setattr(owner, boundary, uncertain)
    with pytest.raises(PolicyRefusal) as error:
        admin.apply(proposer, plan)
    assert "PRIVATE" not in str(error.value)
    receipt = owner.receipt(plan.operation_id)
    assert receipt.phase == ("committed" if boundary == "finalize" else "prepared")
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan)
    monkeypatch.setattr(owner, boundary, original)
    recovered = owner.recover(plan.operation_id)
    assert recovered.phase == ("prepared" if boundary == "stage" else "committed")


def test_approver_revoked_after_staging_keeps_proposal_inert(fixture, monkeypatch):
    admin, owner, proposer, reviewer, claims, _ = fixture
    before = owner.current()
    plan = admin.preview(proposer, "example", profile(2, policy_version=2))
    approval = admin.approve(reviewer, plan)
    original = owner.stage

    def revoke(*args, **kwargs):
        result = original(*args, **kwargs)
        claims[reviewer] = replace(claims[reviewer], epoch=2)
        return result

    monkeypatch.setattr(owner, "stage", revoke)
    with pytest.raises(PolicyRefusal):
        admin.apply(proposer, plan, approval=approval)
    assert owner.current() == before


def test_foreign_thread_refuses_and_does_not_change_authority(fixture):
    import threading
    admin, owner, proposer, _, _, _ = fixture
    errors = []
    before = owner.current()

    def read():
        try:
            admin.view(proposer, "example")
        except PolicyRefusal as error:
            errors.append(error.reason.value)

    thread = threading.Thread(target=read)
    thread.start()
    thread.join(timeout=3)
    assert not thread.is_alive() and errors == ["unsupported_surface"]
    assert owner.current() == before


def test_missing_authority_never_provisions_on_read(fixture):
    admin, owner, proposer, _, _, _ = fixture
    # This tests a missing schema, not a real installation or cleanup target.
    owner._store.conn.execute("DROP TABLE host_configuration_state")
    with pytest.raises(PolicyRefusal):
        admin.view(proposer, "example")
    assert owner._store.conn.execute("SELECT 1 FROM sqlite_master WHERE name='host_configuration_state'").fetchone() is None
