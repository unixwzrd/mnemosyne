"""Metadata inheritance and absent-classification rules, without activation."""

from dataclasses import FrozenInstanceError, replace
import itertools

import pytest

from mnemosyne.core.policy import MemoryPolicy, PolicyDefinition, PolicyRefusal
from mnemosyne.core.policy_derivation import PolicyParent, derive_memory_policy, normalize_classification
from mnemosyne.core.policy_store import RecordKind
from tests.test_policy_read import fixture as fixture, read, restriction


DEFINITION = PolicyDefinition("test", 1, ("unclassified", "internal", "restricted"))


def policy(**kwargs):
    values = dict(policy_id="test", policy_version=1, classification="internal", owner="person:a", classification_source="manual",
                  audiences={"team", "staff"}, purposes={"engineering", "support"}, compartments={"project:a"}, tenant_id="tenant:a")
    values.update(kwargs)
    return MemoryPolicy(**values)


def test_strictest_inheritance_and_traversable_metadata_without_content():
    parents = [PolicyParent("binding:b", policy(classification="restricted", compartments={"project:b"}, audiences={"team"},
        purposes={"engineering"}, overlays={"legal-hold"})), PolicyParent("binding:a", policy())]
    report = derive_memory_policy(DEFINITION, parents)
    assert report.policy.classification == "restricted"
    assert report.policy.compartments == {"project:a", "project:b"}
    assert report.policy.audiences == {"team"} and report.policy.purposes == {"engineering"}
    assert report.policy.overlays == {"legal-hold"}
    assert report.policy.owner == "person:a" and report.policy.tenant_id == "tenant:a"
    assert report.policy.classification_source == "external"
    assert report.parents == tuple(reversed(parents))
    parents.clear()
    assert len(report.parents) == 2
    assert "restricted" not in repr(report) and "binding:" not in repr(report.parents[0])
    with pytest.raises(FrozenInstanceError):
        report.policy = policy()


@pytest.mark.parametrize("field", ["audiences", "purposes"])
def test_empty_permission_intersection_stays_denied(field):
    report = derive_memory_policy(DEFINITION, [PolicyParent("a", policy()), PolicyParent("b", policy(**{field: set()}))])
    assert getattr(report.policy, field) == frozenset()


@pytest.mark.parametrize("field,other", [("owner", "person:b"), ("tenant_id", "tenant:b"), ("tenant_id", None)])
def test_unsupported_owner_tenant_merge_refuses(field, other):
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        derive_memory_policy(DEFINITION, [PolicyParent("a", policy()), PolicyParent("b", policy(**{field: other}))])


@pytest.mark.parametrize("other", [policy(policy_id="other"), policy(policy_version=2), policy(classification="unknown")])
def test_policy_vocabulary_mismatch_refuses(other):
    with pytest.raises(PolicyRefusal, match="policy_mismatch"):
        derive_memory_policy(DEFINITION, [PolicyParent("a", other)])


def test_origin_context_preserved_when_shared_otherwise_parents_preserve_all_origins():
    original = policy(classification_source="context", origin_context_id="ctx:a", origin_context_epoch=1)
    shared = derive_memory_policy(DEFINITION, [PolicyParent("a", original), PolicyParent("b", original)])
    assert (shared.policy.origin_context_id, shared.policy.origin_context_epoch) == ("ctx:a", 1)
    other = replace(original, origin_context_epoch=2)
    mixed = derive_memory_policy(DEFINITION, [PolicyParent("a", original), PolicyParent("b", other)])
    assert mixed.policy.origin_context_id is None and mixed.policy.origin_context_epoch is None
    assert [parent.policy.origin_context_epoch for parent in mixed.parents] == [1, 2]


def test_deterministic_identity_retains_parent_lineage_and_every_policy_attribute():
    parents = [PolicyParent("b", policy()), PolicyParent("a", policy(classification="restricted"))]
    first = derive_memory_policy(DEFINITION, parents)
    assert first.fingerprint() == derive_memory_policy(DEFINITION, list(reversed(parents))).fingerprint()
    assert len(first.fingerprint()) == 64
    for field, value in (("owner", "person:b"), ("classification_source", "external"), ("tenant_id", "tenant:b"),
                         ("audiences", {"team"}), ("purposes", {"engineering"}), ("compartments", {"other"}),
                         ("overlays", {"other"})):
        changed = [PolicyParent(parent.reference, replace(parent.policy, **{field: value})) for parent in parents]
        assert first.fingerprint() != derive_memory_policy(DEFINITION, changed).fingerprint()
    renamed = [PolicyParent("c", parents[0].policy), parents[1]]
    assert first.fingerprint() != derive_memory_policy(DEFINITION, renamed).fingerprint()


@pytest.mark.parametrize("parents", [[], (), None, iter(()), {}, [object()], [PolicyParent("a", policy())]*2,
                                    [PolicyParent(str(i), policy()) for i in range(129)]])
def test_invalid_or_unbounded_parents_refuse(parents):
    with pytest.raises((ValueError, TypeError)):
        derive_memory_policy(DEFINITION, parents)


def test_cumulative_requirement_budget_refuses_without_truncation():
    parents = [PolicyParent("a", policy(compartments={f"a:{i}" for i in range(256)})), PolicyParent("b", policy(compartments={"extra"}))]
    with pytest.raises(ValueError):
        derive_memory_policy(DEFINITION, parents)


@pytest.mark.parametrize("reference", ["", " a", "a\0b", "x"*257, None])
def test_invalid_parent_reference(reference):
    with pytest.raises(ValueError):
        PolicyParent(reference, policy())


@pytest.mark.parametrize("explicit,inherited,label,origin", [
    (None, (), "unclassified", "default"), ("unclassified", (), "unclassified", "explicit"),
    (None, ("restricted",), "restricted", "inherited"), ("unclassified", ("restricted",), "restricted", "inherited"),
    ("restricted", ("internal",), "restricted", "explicit"), ("internal", ("internal",), "internal", "explicit"),
    (None, ("unclassified",), "unclassified", "inherited"),
])
def test_normalization_default_is_not_declassification(explicit, inherited, label, origin):
    decision = normalize_classification(DEFINITION, explicit, inherited=inherited)
    assert (decision.classification, decision.origin) == (label, origin)


@pytest.mark.parametrize("invalid", ["", "UNKNOWN", "default", " unclassified", True, 0])
def test_invalid_explicit_label_never_defaults_even_with_stricter_inheritance(invalid):
    with pytest.raises(PolicyRefusal, match="policy_mismatch"):
        normalize_classification(DEFINITION, invalid, inherited=("restricted",))


@pytest.mark.parametrize("inherited", [(None,), ("unknown",), {"internal"}, iter(("internal",)), ("internal",)*129])
def test_invalid_inherited_labels_refuse(inherited):
    with pytest.raises((ValueError, PolicyRefusal)):
        normalize_classification(DEFINITION, inherited=inherited)


def test_custom_vocabulary_does_not_default_to_its_lowest_label():
    definition = PolicyDefinition("custom", 1, ("public", "private"))
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        normalize_classification(definition)
    assert normalize_classification(definition, "public").classification == "public"


def test_small_lattice_all_combinations_never_relax_any_parent():
    for classifications in itertools.product(DEFINITION.levels, repeat=3):
        for masks in itertools.product(range(4), repeat=3):
            parents = [PolicyParent(str(i), policy(classification=classification,
                audiences={f"a:{j}" for j in range(2) if mask & (1 << j)},
                purposes={f"p:{j}" for j in range(2) if mask & (1 << j)}, compartments={f"c:{mask}"}))
                for i, (classification, mask) in enumerate(zip(classifications, masks))]
            result = derive_memory_policy(DEFINITION, parents).policy
            for parent in parents:
                assert DEFINITION.levels.index(result.classification) >= DEFINITION.levels.index(parent.policy.classification)
                assert result.audiences <= parent.policy.audiences and result.purposes <= parent.policy.purposes
                assert result.compartments >= parent.policy.compartments


@pytest.mark.parametrize("change", [{}, {"classification": "sealed"}, {"compartments": {"extra"}},
                                   {"audiences": {"other"}}, {"purposes": {"other"}}, {"overlays": {"unknown"}}])
def test_derived_metadata_remains_effective_in_existing_indexed_reader(fixture, change):
    store, _, reader = fixture
    definition = store.get_definition("test", 1)
    receipt = derive_memory_policy(definition, [PolicyParent("source:a", restriction()), PolicyParent("source:b", restriction(**change))])
    canary = "DERIVED-DENIED-CANARY" if change else "allowed-derived"
    store.conn.execute("INSERT INTO working_memory VALUES('derived',?)", (canary,))
    store.conn.commit()
    store.bind(RecordKind.WORKING, "derived", receipt.policy)
    statements = []
    store.conn.set_trace_callback(statements.append)
    result = read(reader, "derived")
    assert (result is not None) == (not change)
    if result is not None:
        assert result.content == "allowed-derived"
    assert store.get_binding(RecordKind.WORKING, "derived").policy == receipt.policy
    assert not any(s.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE", "CREATE")) for s in statements)
