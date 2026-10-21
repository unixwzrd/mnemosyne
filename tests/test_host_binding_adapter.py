"""Registry ingress through the actual reference adapter and encrypted reader."""

from dataclasses import replace

import pytest

from mnemosyne.core.host_profile import LevelDisplayMetadata, ProfileDefinition
from mnemosyne.core.host_registry import (
    AuthorizationRegistry, ConversationRegistration, DestinationRegistration,
    GrantRegistration, HOST_READ_CAPABILITY, PrincipalRegistration, StoreRegistration,
)
from mnemosyne.core.host_request_binding import AuthenticatedAudience, LocalRequestBinding
from mnemosyne.core.policy import PolicyDefinition, PolicyRefusal
from mnemosyne.core.policy_host import ProtectedHostAdapter
from mnemosyne.runtime_context import get_access_context
from tests.test_host_registry import authority as _registry_authority
from tests.test_policy_read import fixture as fixture
from tests.test_policy_evidence import evidence as evidence
from tests.test_snapshot_authority import authority as authority
from tests.test_protected_repository import repository as repository
from tests.test_protected_session import session as session

registry_authority = _registry_authority


@pytest.fixture
def registered(session, repository, registry_authority):
    owner, *_ = registry_authority
    people = tuple(PrincipalRegistration(p, "test-host", p, "actor:" + p, kind, True)
                   for p, kind in (("person:a", "human"), ("agent:a", "agent")))
    participants = frozenset(p.principal_id for p in people)
    definition = PolicyDefinition("test", 1, ("open", "team", "sealed"))
    profile = ProfileDefinition("test", 1, definition,
        tuple(LevelDisplayMetadata(level, level, level) for level in definition.levels), ())
    store = StoreRegistration("a" * 32, "domain:a", "bank:a", "test", "owner:a", 0, HOST_READ_CAPABILITY)
    destination = DestinationRegistration("channel:a", "test-host", "fixture", "route:a", 1,
                                          participants, HOST_READ_CAPABILITY)
    conversation = ConversationRegistration("context:a", "test-host", "fixture", "conversation:a", participants,
        "a" * 32, "channel:a", "sealed", "engineering", frozenset(), frozenset({"work"}),
        frozenset({"internal"}), frozenset({"read:bank"}), True)
    grants = tuple(GrantRegistration(p.principal_id, "a" * 32, "team" if p.kind == "human" else "sealed",
        owners=frozenset({"person:a"}), tenants=frozenset({"tenant:a"}), compartments=frozenset({"work"}),
        audiences=frozenset({"internal"}), purposes=frozenset({"engineering"}), operations=frozenset({"read:bank"}),
        destinations=frozenset({"channel:a"}), bank_wide=True) for p in people)
    registry = AuthorizationRegistry(people, (store,), (destination,), (conversation,), grants)
    owner.publish((profile,), previous=None, operation_id="initial", registry=registry)
    request = object()
    claim = AuthenticatedAudience("test-host", "person:a", "fixture", "conversation:a", "route:a", 1, 1,
        tuple(("test-host", p.principal_id) for p in people))
    binding = LocalRequestBinding(owner, authority_id="a" * 32, issuer="test-host",
        authenticate=lambda actual: claim if actual is request else None)
    adapter = ProtectedHostAdapter(adapter_id="registered-fixture", issuer="test-host",
        load_snapshot=binding.load_snapshot, resolve_store=lambda _: (repository[0], session[1]))
    return binding, adapter, request, owner, registry, profile, session[1]


def test_registry_to_encrypted_dispatch_excludes_denied_evidence(registered):
    binding, adapter, request, *_ = registered
    handle = binding.admit(request)
    before = get_access_context(required=True)
    seen = []
    adapter.invoke(handle, "get", {"kind": "working_memory", "record_id": "w"}, seen.append)
    assert seen[0].content == "PRIVATE-REPOSITORY-CANARY"
    seen.clear()
    adapter.invoke(handle, "get", {"kind": "working_memory", "record_id": "denied"}, seen.append)
    assert seen == [None] and get_access_context(required=True) is before
    binding.close(handle)
    binding.close(handle)


def test_registry_revocation_during_final_audit_prevents_delivery(registered, monkeypatch):
    binding, adapter, request, owner, registry, profile, audit = registered
    handle = binding.admit(request)
    real_admit = audit.admit
    observed = []

    def revoke(event, consumer):
        result = real_admit(event, consumer)
        if event.operation == "deliver":
            observed.append("deliver")
            owner.publish((profile,), previous=owner.current().revision, operation_id="revoke",
                          registry=replace(registry, grants=()))
        return result

    monkeypatch.setattr(audit, "admit", revoke)
    output = []
    with pytest.raises(PolicyRefusal):
        adapter.invoke(handle, "get", {"kind": "working_memory", "record_id": "w"}, output.append)
    assert observed == ["deliver"] and not output
    binding.close(handle)


def test_registered_path_never_accepts_model_scope_or_legacy_dispatch(registered):
    binding, adapter, request, *_ = registered
    for operation, arguments in (("get", {"context": "forged"}), ("export", {}), ("remember", {})):
        handle = binding.admit(request)
        try:
            with pytest.raises(PolicyRefusal):
                adapter.invoke(handle, operation, arguments, lambda _: pytest.fail("unexpected delivery"))
        finally:
            binding.close(handle)
