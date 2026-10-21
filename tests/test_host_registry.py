"""Synthetic registry contracts and witnessed publication, without live data."""

from dataclasses import replace
import json
import sqlite3

import pytest

from mnemosyne.core.host_configuration import HostConfigurationAuthority, _decode
from mnemosyne.core.host_administration import AdministrationSnapshot, ProfileAdministration
from mnemosyne.core.host_profile import LevelDisplayMetadata, ProfileDefinition
from mnemosyne.core.host_registry import (
    AuthorizationRegistry, ConversationRegistration, DestinationRegistration,
    GrantRegistration, HOST_READ_CAPABILITY, PrincipalRegistration, StoreRegistration,
)
from mnemosyne.core.policy import PolicyDefinition, PolicyRefusal


STORE = "c" * 32


def profile():
    return ProfileDefinition("example", 1, PolicyDefinition("example", 1, ("L0", "L1")),
                             (LevelDisplayMetadata("L0", "General", "General"),
                              LevelDisplayMetadata("L1", "Private", "Private")), ())


def registry():
    people = (
        PrincipalRegistration("human", "login", "human-subject", "actor:human", "human", True),
        PrincipalRegistration("agent", "login", "agent-subject", "actor:agent", "agent", True),
    )
    store = StoreRegistration(STORE, "example", "bank", "example", "owner:example", 0, HOST_READ_CAPABILITY)
    audience = frozenset({"human", "agent"})
    destination = DestinationRegistration("private", "login", "fixture", "route:private", 1,
                                          audience, HOST_READ_CAPABILITY)
    conversation = ConversationRegistration("context:one", "login", "fixture", "thread:one", audience,
        STORE, "private", "L1", "assist", frozenset({"notes"}), frozenset({"A"}),
        frozenset({"private"}), frozenset({"read:projects", "inject"}), True)
    grants = tuple(GrantRegistration(p.principal_id, STORE, "L1", projects=frozenset({"notes"}),
        owners=frozenset({"owner"}), tenants=frozenset({"tenant"}), compartments=frozenset({"A"}),
        audiences=frozenset({"private"}), purposes=frozenset({"assist"}),
        operations=frozenset({"read:projects", "inject"}), destinations=frozenset({"private"})) for p in people)
    return AuthorizationRegistry(people, (store,), (destination,), (conversation,), grants)


def connection(root, name):
    folder = root / name
    folder.mkdir(mode=0o700, exist_ok=True)
    path = folder / "metadata.sqlite"
    conn = sqlite3.connect(path, timeout=0)
    path.chmod(0o600)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


@pytest.fixture
def authority(tmp_path):
    conn, witness = connection(tmp_path, "owner"), connection(tmp_path, "witness")
    owner = HostConfigurationAuthority(conn, authority_id="a" * 32,
        witness_connection=witness, witness_id="b" * 32)
    owner.prepare()
    yield owner, conn, witness
    conn.close()
    witness.close()


def test_registry_roundtrip_is_canonical_and_does_not_authenticate():
    value = registry()
    assert AuthorizationRegistry.from_dict(json.loads(json.dumps(value.to_dict()))) == value
    assert replace(value, principals=tuple(reversed(value.principals)), grants=tuple(reversed(value.grants))) == value
    value.validate_profiles((profile(),))
    assert not hasattr(value, "recall") and not hasattr(value, "authenticate")
    assert "human-subject" not in repr(value) and "actor:human" not in repr(value.principals[0])


@pytest.mark.parametrize("collection", ["principals", "stores", "destinations", "conversations", "grants"])
def test_duplicate_identity_refuses(collection):
    value = registry()
    with pytest.raises(ValueError):
        replace(value, **{collection: getattr(value, collection) * 2})


@pytest.mark.parametrize("field", ["principal_id", "issuer", "subject", "separation_id"])
@pytest.mark.parametrize("bad", ["", " x", "x\n", "\ud800", "x" * 129, 12])
def test_principal_text_is_strict(field, bad):
    with pytest.raises((TypeError, ValueError)):
        replace(registry().principals[0], **{field: bad})


@pytest.mark.parametrize("collection", ["principals", "stores", "destinations", "conversations", "grants"])
def test_import_unknown_missing_and_wrong_collection_refuse(collection):
    original = registry().to_dict()
    for mutation in ("unknown", "missing", "wrong-array", "wrong-record"):
        data = json.loads(json.dumps(original))
        if mutation == "unknown":
            data[collection][0]["unexpected"] = "not accepted"
        elif mutation == "missing":
            data[collection][0].pop(next(iter(data[collection][0])))
        elif mutation == "wrong-array":
            data[collection] = {}
        else:
            data[collection][0] = None
        with pytest.raises((TypeError, ValueError, PolicyRefusal)):
            AuthorizationRegistry.from_dict(data)


@pytest.mark.parametrize("bad", [True, False, 0, 2, "1", None])
def test_unknown_registry_contract_refuses(bad):
    data = registry().to_dict()
    data["contract_version"] = bad
    with pytest.raises(ValueError):
        AuthorizationRegistry.from_dict(data)


def test_duplicate_labels_and_implicit_booleans_refuse():
    data = registry().to_dict()
    data["grants"][0]["projects"] = ["notes", "notes"]
    with pytest.raises(ValueError):
        AuthorizationRegistry.from_dict(data)
    with pytest.raises(TypeError):
        replace(registry().principals[0], enabled=1)
    with pytest.raises(TypeError):
        replace(registry().grants[0], bank_wide=1)
    with pytest.raises(ValueError):
        replace(registry().grants[0], projects={"notes"})


def test_dangling_references_and_ambiguous_identity_refuse():
    value = registry()
    mutations = [
        dict(principals=value.principals[:1]), dict(stores=()), dict(destinations=()),
        dict(conversations=(replace(value.conversations[0], participants=frozenset({"human"})),)),
        dict(conversations=(replace(value.conversations[0], issuer="other"),)),
        dict(grants=(replace(value.grants[0], principal_id="missing"),)),
        dict(grants=(replace(value.grants[0], destinations=frozenset({"missing"})),)),
        dict(principals=(value.principals[0], replace(value.principals[0], principal_id="alias"))),
    ]
    for mutation in mutations:
        with pytest.raises(ValueError):
            replace(value, **mutation)


def test_unknown_vocabulary_and_capability_refuse():
    value = registry()
    with pytest.raises(ValueError):
        value.validate_profiles(())
    with pytest.raises(ValueError):
        replace(value, grants=(replace(value.grants[0], classification_ceiling="invented"),)).validate_profiles((profile(),))
    for record in (value.stores[0], value.destinations[0]):
        with pytest.raises(ValueError):
            replace(record, capability="legacy-fallback")


@pytest.mark.parametrize("collection,maximum", [("principals", 256), ("stores", 32), ("destinations", 256),
                                                ("conversations", 256), ("grants", 4096)])
def test_collection_limits_refuse_before_processing(collection, maximum):
    value = registry()
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        replace(value, **{collection: (getattr(value, collection)[0],) * (maximum + 1)})
    data = value.to_dict()
    data[collection] = [None] * (maximum + 1)
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        AuthorizationRegistry.from_dict(data)


def test_empty_registry_has_no_defaults():
    value = AuthorizationRegistry()
    value.validate_profiles(())
    assert not any(getattr(value, name) for name in ("principals", "stores", "destinations", "conversations", "grants"))
    assert AuthorizationRegistry.from_dict(value.to_dict()) == value


def test_registry_and_profiles_publish_as_one_witnessed_revision(authority):
    api, conn, _ = authority
    before = api.publish((profile(),), previous=None, operation_id="profile-only")
    assert api.current().registry is None
    after = api.publish((profile(),), previous=before.revision, operation_id="registry", registry=registry())
    current = api.current()
    assert current.registry == registry() and current.revision == after.revision
    assert json.loads(current.canonical_bytes())["contract_version"] == 2
    assert api.publish((profile(),), previous=before.revision, operation_id="registry", registry=registry()) == after
    assert conn.execute("SELECT count(*) FROM host_configuration_revisions").fetchone() == (2,)


def test_registry_cannot_silently_downgrade_to_profile_only(authority):
    api, _, _ = authority
    old = api.publish((profile(),), previous=None, operation_id="initial", registry=registry())
    with pytest.raises(PolicyRefusal):
        api.publish((profile(),), previous=old.revision, operation_id="strip")
    empty = api.publish((profile(),), previous=old.revision, operation_id="revoke", registry=AuthorizationRegistry())
    assert api.current().registry == AuthorizationRegistry()
    with pytest.raises(PolicyRefusal):
        api.publish((profile(),), previous=empty.revision, operation_id="strip-again")


def test_unwitnessed_registry_is_not_current_and_recovery_never_grants(authority):
    api, _, _ = authority
    old = api.publish((profile(),), previous=None, operation_id="initial")
    pending = api.stage((profile(),), previous=old.revision, operation_id="pending", registry=registry())
    assert api.current().registry is None
    assert api.recover("pending") == pending
    api.advance_witness(pending)
    with pytest.raises(PolicyRefusal):
        api.current()
    api.recover("pending")
    assert api.current().registry == registry()


def test_profile_only_canonical_payload_is_unchanged(authority):
    api, _, _ = authority
    api.publish((profile(),), previous=None, operation_id="initial")
    data = {"contract_version": 1, "authority_id": "a" * 32, "generation": 1, "profiles": [profile().to_dict()]}
    assert api.current().canonical_bytes() == json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def test_malformed_registry_payload_refuses_without_identity_details():
    payload = json.dumps({"contract_version": 2, "authority_id": "a" * 32, "generation": 1,
                          "profiles": [profile().to_dict()], "registry": {"secret-field": "canary"}}).encode()
    with pytest.raises(PolicyRefusal) as caught:
        _decode("a" * 32, (1, b"a" * 64, payload, b"operation", b"committed"))
    assert "canary" not in str(caught.value) and "secret-field" not in str(caught.value)


def test_restore_cannot_reinstate_old_grants_or_legacy_mode(authority):
    api, conn, _ = authority
    api.publish((profile(),), previous=None, operation_id="profile-only")
    legacy = sqlite3.connect(":memory:")
    granted = sqlite3.connect(":memory:")
    try:
        conn.backup(legacy)
        initial = api.current()
        current = api.publish((profile(),), previous=initial.revision, operation_id="grant", registry=registry())
        conn.backup(granted)
        api.publish((profile(),), previous=current.revision, operation_id="revoke", registry=AuthorizationRegistry())
        for backup in (granted, legacy):
            backup.backup(conn)
            with pytest.raises(PolicyRefusal, match="context_unavailable"):
                api.current()
            assert not conn.in_transaction
    finally:
        legacy.close()
        granted.close()


def test_registry_publication_cannot_reuse_stale_predecessor(authority):
    api, _, _ = authority
    first = api.publish((profile(),), previous=None, operation_id="initial", registry=registry())
    api.publish((profile(),), previous=first.revision, operation_id="revoke", registry=AuthorizationRegistry())
    with pytest.raises(PolicyRefusal):
        api.publish((profile(),), previous=first.revision, operation_id="old-grants", registry=registry())
    assert api.current().registry == AuthorizationRegistry()


def test_aggregate_payload_budget_refuses_before_publication(authority):
    api, conn, witness = authority
    base = registry()
    people = tuple(replace(base.principals[0], principal_id=f"p:{i}", subject=f"s:{i}") for i in range(16))
    owners = frozenset(f"owner:{i}:" + "x" * 100 for i in range(200))
    grants = tuple(replace(base.grants[0], principal_id=p.principal_id, owners=owners) for p in people)
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        oversized = replace(base, principals=base.principals + people, grants=base.grants + grants)
        api.publish((profile(),), previous=None, operation_id="too-large", registry=oversized)
    assert conn.execute("SELECT count(*) FROM host_configuration_revisions").fetchone() == (0,)
    assert witness.execute("SELECT count(*) FROM snapshot_publications").fetchone() == (0,)


def test_profile_only_facade_cannot_strip_or_change_registry(authority):
    api, _, _ = authority
    initial = api.publish((profile(),), previous=None, operation_id="initial", registry=registry())
    claim = AdministrationSnapshot("login", "admin", "admin-actor", "a" * 32, "d" * 64,
        1, frozenset({"example"}), frozenset({"profiles:view", "profiles:labels"}))
    admin = ProfileAdministration(api, authority_id="a" * 32, issuer="login", authenticate=lambda _: claim)
    assert admin.view(object(), "example").profile == profile()
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        admin.preview(object(), "example", replace(profile(), version=2))
    assert api.current().revision == initial.revision and api.current().registry == registry()


def test_import_budget_stops_before_deserializing_the_remaining_grants(monkeypatch):
    data = registry().to_dict()
    base = data["principals"][0]
    people = [dict(base, principal_id=f"p:{i}", subject=f"s:{i}") for i in range(128)]
    data["principals"] += people
    large = [f"label:{i}:" + "x" * 112 for i in range(256)]
    grant = data["grants"][0]
    dimensions = ("projects", "owners", "tenants", "compartments", "audiences", "purposes", "operations")
    data["grants"] = [dict(grant, principal_id=p["principal_id"], **{name: large for name in dimensions})
                      for p in people]
    original, calls = GrantRegistration.from_dict, []

    def count(cls, item):
        calls.append(item["principal_id"])
        return original(item)

    monkeypatch.setattr(GrantRegistration, "from_dict", classmethod(count))
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        AuthorizationRegistry.from_dict(data)
    assert len(calls) == 2
