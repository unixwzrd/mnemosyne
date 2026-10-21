"""Fresh ingress with synthetic authentication and disposable registry stores."""

from dataclasses import replace
import copy
import threading

import pytest

from mnemosyne.core.host_request_binding import (
    AuthenticatedAudience, LocalRequestBinding, RequestHandle,
)
from mnemosyne.core.policy import PolicyRefusal
from tests.test_host_registry import authority as authority, profile, registry


def audience(**changes):
    values = dict(issuer="login", subject="human-subject", platform="fixture",
        conversation_id="thread:one", route_id="route:private", route_revision=1, session_epoch=1,
        participants=(("login", "human-subject"), ("login", "agent-subject")))
    values.update(changes)
    return AuthenticatedAudience(**values)


@pytest.fixture
def binding(authority):
    api, conn, witness = authority
    api.publish((profile(),), previous=None, operation_id="initial", registry=registry())
    request = object()
    state = {"claim": audience(), "calls": 0}

    def authenticate(value):
        state["calls"] += 1
        if value is not request:
            raise PermissionError("synthetic denied input must not be disclosed")
        return state["claim"]

    loader = LocalRequestBinding(api, authority_id="a" * 32, issuer="login", authenticate=authenticate)
    return loader, request, state, api, conn, witness


def publish(api, value, operation):
    return api.publish((profile(),), previous=api.current().revision, operation_id=operation, registry=value)


def test_complete_authenticated_audience_loads_existing_host_contract(binding):
    loader, request, state, *_ = binding
    handle = loader.admit(request)
    snapshot = loader.load_snapshot(handle)
    effective, owners, tenants = snapshot.effective()
    assert effective.principals == {"human", "agent"}
    assert effective.projects == {"notes"} and effective.classification_ceiling == "L1"
    assert owners == {"owner"} and tenants == {"tenant"}
    assert effective.epoch == 1 and snapshot.destination == "private" and snapshot.bank == "bank"
    assert state["calls"] == 4
    loader.close(handle)
    with pytest.raises(PolicyRefusal):
        loader.load_snapshot(handle)


@pytest.mark.parametrize("changes", [
    {"issuer": "other", "participants": (("other", "human-subject"), ("login", "agent-subject"))},
    {"subject": "unknown", "participants": (("login", "unknown"), ("login", "agent-subject"))},
    {"platform": "title:pretending-platform"}, {"conversation_id": "different"},
    {"route_id": "different"}, {"route_revision": 2},
    {"participants": (("login", "human-subject"),)},
    {"participants": (("login", "human-subject"), ("login", "agent-subject"), ("login", "silent-recipient"))},
])
def test_wrong_identity_incomplete_audience_or_route_never_admits(binding, changes):
    loader, request, state, *_ = binding
    state["claim"] = audience(**changes)
    with pytest.raises(PolicyRefusal):
        loader.admit(request)
    assert not loader._pending


@pytest.mark.parametrize("mutation", ["principal", "conversation", "grant", "purpose", "project", "operation", "destination"])
def test_disabled_or_insufficient_registered_claims_refuse(binding, mutation):
    loader, request, _, api, *_ = binding
    value = registry()
    if mutation == "principal":
        value = replace(value, principals=tuple(replace(p, enabled=False) if p.principal_id == "human" else p for p in value.principals))
    elif mutation == "conversation":
        value = replace(value, conversations=(replace(value.conversations[0], enabled=False),))
    elif mutation == "grant":
        value = replace(value, grants=value.grants[:1])
    else:
        field = {"purpose": "purposes", "project": "projects", "operation": "operations", "destination": "destinations"}[mutation]
        value = replace(value, grants=tuple(replace(g, **{field: frozenset()}) if g.principal_id == "human" else g for g in value.grants))
    publish(api, value, "restrict")
    with pytest.raises(PolicyRefusal):
        loader.admit(request)


def test_agent_broader_access_does_not_raise_human_ceiling_or_scope(binding):
    loader, request, _, api, *_ = binding
    value = registry()
    value = replace(value, grants=tuple(replace(g, classification_ceiling="L0") if g.principal_id == "human"
        else replace(g, compartments=frozenset({"A", "B"}), projects=frozenset({"notes", "secret"})) for g in value.grants))
    publish(api, value, "scope")
    snapshot = loader.load_snapshot(loader.admit(request))
    effective = snapshot.effective()[0]
    assert effective.classification_ceiling == "L0"
    assert effective.compartments == {"A"} and effective.projects == {"notes"}


def test_empty_project_is_not_bank_wide_permission(binding):
    loader, request, _, api, *_ = binding
    value = registry()
    value = replace(value, conversations=(replace(value.conversations[0], projects=frozenset(), operations=frozenset({"read:bank"})),))
    publish(api, value, "empty-project")
    with pytest.raises(PolicyRefusal):
        loader.admit(request)


def test_registry_revocation_and_aba_invalidate_old_handle_permanently(binding):
    loader, request, _, api, *_ = binding
    handle = loader.admit(request)
    initial = loader.load_snapshot(handle)
    publish(api, replace(registry(), grants=()), "revoke")
    with pytest.raises(PolicyRefusal):
        loader.load_snapshot(handle)
    publish(api, registry(), "restore-explicit")
    with pytest.raises(PolicyRefusal):
        loader.load_snapshot(handle)
    fresh = loader.load_snapshot(loader.admit(request))
    assert fresh.context.epoch > initial.context.epoch
    assert fresh.context.fingerprint() != initial.context.fingerprint()


def test_transport_session_aba_changes_context_and_fences_old_handle(binding):
    loader, request, state, *_ = binding
    old = loader.admit(request)
    snapshot = loader.load_snapshot(old)
    state["claim"] = audience(session_epoch=3)
    with pytest.raises(PolicyRefusal):
        loader.load_snapshot(old)
    fresh = loader.load_snapshot(loader.admit(request))
    assert fresh.context.epoch == snapshot.context.epoch
    assert fresh.context.context_id != snapshot.context.context_id
    assert fresh.context.fingerprint() != snapshot.context.fingerprint()


def test_forged_copied_foreign_or_plain_handles_refuse(binding):
    loader, request, *_ = binding
    real = loader.admit(request)
    for forged in (RequestHandle(), copy.copy(real), {}, object(), "not-a-handle"):
        with pytest.raises(PolicyRefusal):
            loader.load_snapshot(forged)
    assert loader.load_snapshot(real)


def test_unknown_transport_is_refused_before_authority_read(binding):
    loader, _, _, _, conn, witness = binding
    sql = []
    conn.set_trace_callback(sql.append)
    witness.set_trace_callback(sql.append)
    with pytest.raises(PolicyRefusal) as caught:
        loader.admit({"principal": "human", "clearance": "L1"})
    assert not sql
    assert "synthetic denied" not in str(caught.value)


def test_no_permission_snapshot_is_cached_between_loads(binding):
    loader, request, state, _, conn, _ = binding
    handle = loader.admit(request)
    statements = []
    conn.set_trace_callback(statements.append)
    loader.load_snapshot(handle)
    count = len(statements)
    loader.load_snapshot(handle)
    assert count and len(statements) == count * 2 and state["calls"] == 6


@pytest.mark.parametrize("phase", ["admit-first", "admit-second", "load-first", "load-second"])
def test_slow_authentication_cannot_cross_expiry(binding, monkeypatch, phase):
    _, request, _, api, *_ = binding
    clock, calls = [0.0], [0]
    monkeypatch.setattr("mnemosyne.core.host_request_binding.time.monotonic", lambda: clock[0])
    threshold = {"admit-first": 1, "admit-second": 2, "load-first": 3, "load-second": 4}[phase]

    def authenticate(_):
        calls[0] += 1
        if calls[0] == threshold:
            clock[0] = 2.0
        return audience()

    loader = LocalRequestBinding(api, authority_id="a" * 32, issuer="login", authenticate=authenticate, lifetime_seconds=1)
    with pytest.raises(PolicyRefusal):
        if phase.startswith("admit"):
            loader.admit(request)
        else:
            loader.load_snapshot(loader.admit(request))
    assert not loader._pending


def test_bounded_handles_expiry_and_explicit_close(binding, monkeypatch):
    loader, request, *_ = binding
    clock = [0.0]
    monkeypatch.setattr("mnemosyne.core.host_request_binding.time.monotonic", lambda: clock[0])
    handles = [loader.admit(request) for _ in range(64)]
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        loader.admit(request)
    loader.close(handles.pop())
    loader.admit(request)
    clock[0] = 901.0
    with pytest.raises(PolicyRefusal):
        loader.load_snapshot(handles[0])
    assert not loader._pending
    assert loader.admit(request)


def test_cross_thread_and_process_use_refuse(binding, monkeypatch):
    loader, request, *_ = binding
    handle = loader.admit(request)
    results = []

    def other_thread():
        with pytest.raises(PolicyRefusal) as caught:
            loader.load_snapshot(handle)
        results.append(caught.value.reason.value)

    thread = threading.Thread(target=other_thread)
    thread.start()
    thread.join()
    assert results == ["unsupported_surface"]
    monkeypatch.setattr("mnemosyne.core.host_request_binding.os.getpid", lambda: loader._process + 1)
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        loader.load_snapshot(handle)


def test_reentrant_authentication_and_async_callbacks_refuse(binding):
    loader, request, _, api, *_ = binding
    original = loader._authenticate

    def reentrant(value):
        loader.admit(value)
        return original(value)

    loader._authenticate = reentrant
    with pytest.raises(PolicyRefusal):
        loader.admit(request)

    async def asynchronous(value):
        return audience()

    with pytest.raises(TypeError):
        LocalRequestBinding(api, authority_id="a" * 32, issuer="login", authenticate=asynchronous)


@pytest.mark.parametrize("phase", ["admit", "load"])
def test_transport_change_between_authentication_checks_refuses(binding, phase):
    loader, request, _, _, *_ = binding
    real = loader._authenticate
    calls = [0]
    handle = loader.admit(request) if phase == "load" else None

    def change(actual):
        calls[0] += 1
        value = real(actual)
        return replace(value, session_epoch=2) if calls[0] > 1 else value

    loader._authenticate = change
    with pytest.raises(PolicyRefusal):
        loader.load_snapshot(handle) if phase == "load" else loader.admit(request)
    assert not loader._pending


@pytest.mark.parametrize("phase", ["admit", "load"])
def test_registry_change_between_snapshot_reads_refuses(binding, monkeypatch, phase):
    loader, request, _, api, *_ = binding
    handle = loader.admit(request) if phase == "load" else None
    real = api.current
    calls = [0]

    def change():
        calls[0] += 1
        current = real()
        if calls[0] == 1:
            api.publish((profile(),), previous=current.revision, operation_id="mid-read-revoke",
                        registry=replace(registry(), grants=()))
        return current

    monkeypatch.setattr(api, "current", change)
    with pytest.raises(PolicyRefusal):
        loader.load_snapshot(handle) if phase == "load" else loader.admit(request)
    assert not loader._pending
