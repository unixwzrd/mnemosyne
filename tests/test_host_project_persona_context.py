"""Project/persona composition in native protected APIs, not live Hermes auth."""

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
from mnemosyne.core.policy_projects import PolicyProjects
from mnemosyne.core.policy_store import RecordKind
from tests.test_host_registry import authority as registry_authority
from tests.test_policy_read import add, fixture as fixture
from tests.test_policy_evidence import evidence as evidence
from tests.test_snapshot_authority import authority as authority
from tests.test_protected_repository import repository as repository
from tests.test_protected_session import session as session
from tests.test_protected_snapshot import identity


STORE = "a" * 32
PROJECTS = {"finance": "project:finance", "research": "project:research"}


@pytest.fixture
def selections(registry_authority):
    owner = registry_authority[0]
    definition = PolicyDefinition("test", 1, ("open", "team", "sealed"))
    profile = ProfileDefinition("test", 1, definition,
        tuple(LevelDisplayMetadata(level, level, level) for level in definition.levels), ())
    people = (PrincipalRegistration("person:a", "test-host", "human-subject", "actor:human", "human", True),
        *(PrincipalRegistration("agent:" + key, "test-host", "agent-subject:" + key, "actor:agent:" + key,
            "agent", True) for key in ("finance", "research", "style")))
    store = StoreRegistration(STORE, "domain:a", "bank:a", "test", "owner:a", 0, HOST_READ_CAPABILITY)
    destinations, conversations, grants = [], [], []
    for key in ("finance", "research", "style"):
        project = "finance" if key == "style" else key
        audience = frozenset({"person:a", "agent:" + key})
        destinations.append(DestinationRegistration("destination:" + key, "test-host", "fixture", "route:" + key,
            1, audience, HOST_READ_CAPABILITY))
        conversations.append(ConversationRegistration("context:" + key, "test-host", "fixture", "chat:" + key,
            audience, STORE, "destination:" + key, "sealed", "engineering", frozenset({PROJECTS[project]}),
            frozenset({"compartment:" + project}), frozenset({"internal"}), frozenset({"read:projects"}), True))
    for person in people:
        key = person.principal_id.removeprefix("agent:")
        selected = ("finance", "research") if person.kind == "human" else (("finance",) if key == "style" else (key,))
        grants.append(GrantRegistration(person.principal_id, STORE,
            "team" if person.kind == "human" else ("open" if key == "style" else "sealed"),
            projects=frozenset(PROJECTS[p] for p in selected), owners=frozenset({"person:a"}),
            tenants=frozenset({"tenant:a"}), compartments=frozenset("compartment:" + p for p in selected),
            audiences=frozenset({"internal"}), purposes=frozenset({"engineering"}), operations=frozenset({"read:projects"}),
            destinations=frozenset(d.destination_id for d in destinations)))
    registry = AuthorizationRegistry(people, (store,), tuple(destinations), tuple(conversations), tuple(grants))
    owner.publish((profile,), previous=None, operation_id="reviewed-initial-fixture", registry=registry)
    request = object()
    state = {"selected": "finance", "epoch": 1}

    def authenticate(actual):
        if actual is not request:
            raise PermissionError("untrusted selection is not an authenticated request")
        key = state["selected"]
        return AuthenticatedAudience("test-host", "human-subject", "fixture", "chat:" + key, "route:" + key,
            1, state["epoch"], (("test-host", "human-subject"), ("test-host", "agent-subject:" + key)))

    binding = LocalRequestBinding(owner, authority_id="a" * 32, issuer="test-host", authenticate=authenticate)
    return binding, request, state, owner, profile, registry


def publish(selections, registry):
    owner, profile = selections[3:5]
    owner.publish((profile,), previous=owner.current().revision,
        operation_id="reviewed-change:" + str(owner.current().revision.generation), registry=registry)


def snapshot(selections):
    binding, request, *_ = selections
    handle = binding.admit(request)
    try:
        return binding.load_snapshot(handle)
    finally:
        binding.close(handle)


@pytest.mark.parametrize("selected,ceiling,project", [("finance", "team", "finance"),
    ("research", "team", "research"), ("style", "open", "finance")])
def test_selected_project_and_persona_only_narrow_the_complete_audience(selections, selected, ceiling, project):
    selections[2]["selected"] = selected
    effective = snapshot(selections).effective()[0]
    assert effective.projects == {PROJECTS[project]}
    assert effective.compartments == {"compartment:" + project}
    assert effective.classification_ceiling == ceiling
    assert effective.principals == {"person:a", "agent:" + selected}


@pytest.mark.parametrize("ceiling", ["open", "team", "sealed"])
def test_project_chat_ceiling_remains_distinct_from_document_classification(selections, ceiling):
    value = selections[-1]
    publish(selections, replace(value, conversations=tuple(replace(c, classification_ceiling=ceiling)
        if c.conversation_id == "chat:finance" else c for c in value.conversations)))
    effective = snapshot(selections).effective()[0]
    assert effective.classification_ceiling == ("open" if ceiling == "open" else "team")


@pytest.mark.parametrize("missing", ["project", "compartment"])
@pytest.mark.parametrize("principal", ["person:a", "agent:finance"])
def test_scope_and_compartment_permissions_are_required_from_each_principal(selections, missing, principal):
    value = selections[-1]
    field = "projects" if missing == "project" else "compartments"
    publish(selections, replace(value, grants=tuple(replace(g, **{field: frozenset()})
        if g.principal_id == principal else g for g in value.grants)))
    if missing == "project":
        with pytest.raises(PolicyRefusal):
            snapshot(selections)
    else:
        assert not snapshot(selections).effective()[0].compartments


@pytest.mark.parametrize("override", ["project_id", "personality", "principal", "classification_ceiling", "participants"])
def test_model_or_ui_metadata_is_not_identity_proof(selections, override):
    binding = selections[0]
    with pytest.raises(PolicyRefusal):
        binding.admit({override: "pretend-privileged-selection"})
    assert not binding._pending


@pytest.mark.parametrize("selected", ["unregistered", "renamed-persona", "finance-copy"])
def test_new_display_selection_does_not_create_an_authorized_identity(selections, selected):
    selections[2]["selected"] = selected
    with pytest.raises(PolicyRefusal):
        snapshot(selections)


@pytest.mark.parametrize("transition", ["project", "persona"])
def test_selection_change_and_aba_cannot_reuse_old_request_handle(selections, transition):
    binding, request, state, *_ = selections
    old = binding.admit(request)
    before = binding.load_snapshot(old)
    state.update(selected="research" if transition == "project" else "style", epoch=2)
    with pytest.raises(PolicyRefusal):
        binding.load_snapshot(old)
    state.update(selected="finance", epoch=3)
    with pytest.raises(PolicyRefusal):
        binding.load_snapshot(old)
    fresh = snapshot(selections)
    assert fresh.context.fingerprint() != before.context.fingerprint()


@pytest.fixture
def native(selections, session, evidence, repository):
    store = evidence[0]
    catalog = PolicyProjects(store)
    catalog.prepare()
    for project in PROJECTS.values():
        catalog.register(project, actor="owner:fixture")
    records = (("finance-note", "team", {"compartment:finance"}, ("finance",)),
        ("finance-sealed", "sealed", {"compartment:finance"}, ("finance",)),
        ("research-note", "team", {"compartment:research"}, ("research",)),
        ("shared-relevance", "team", {"compartment:finance"}, ("finance", "research")))
    for record, level, compartments, projects in records:
        add(store, record, content="SYNTHETIC-" + record, classification=level, compartments=compartments)
        for project in projects:
            catalog.propose(RecordKind.WORKING, record, PROJECTS[project], actor="owner:fixture", origin="fixture")
            catalog.confirm(RecordKind.WORKING, record, PROJECTS[project], actor="reviewer:fixture")
    repository[0].publish(store.conn, identity(generation=3), previous=session[3].checkpoint, operation_id="project-fixtures")
    binding = selections[0]
    adapter = ProtectedHostAdapter(adapter_id="project-persona-fixture", issuer="test-host",
        load_snapshot=binding.load_snapshot, resolve_store=lambda _: (repository[0], session[1]))
    return adapter


@pytest.mark.parametrize("selected,expected", [("finance", {"finance-note", "shared-relevance"}),
    ("research", {"research-note"}), ("style", set())])
def test_actual_encrypted_reader_enforces_project_compartment_and_lowest_clearance(selections, native, selected, expected):
    binding, request, state, *_ = selections
    state["selected"] = selected
    handle = binding.admit(request)
    seen = set()
    try:
        for identity in ("finance-note", "finance-sealed", "research-note", "shared-relevance", "absent"):
            results = []
            native.invoke(handle, "get", {"kind": "working_memory", "record_id": identity}, results.append)
            assert len(results) == 1
            if results[0] is not None:
                assert results[0].content == "SYNTHETIC-" + identity
                seen.add(identity)
        assert seen == expected
    finally:
        binding.close(handle)
