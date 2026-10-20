"""Explicit metadata-only inheritance; not authorization or lifecycle storage."""

from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import json
from typing import Tuple

from mnemosyne.core.policy import MemoryPolicy, PolicyDefinition, PolicyRefusal, RefusalReason, _text


@dataclass(frozen=True, repr=False)
class ClassificationDecision:
    classification: str
    origin: str


def normalize_classification(definition, classification=None, *, inherited=()):
    """Default absence only; never lower a trusted inherited classification."""
    if not isinstance(definition, PolicyDefinition):
        raise TypeError("definition must be an explicit PolicyDefinition")
    if type(inherited) not in (tuple, list) or len(inherited) > 128:
        raise ValueError("inherited must contain at most 128 classification labels")
    labels = tuple(inherited)
    if any(type(label) is not str or label not in definition.levels for label in labels):
        raise PolicyRefusal(RefusalReason.POLICY_MISMATCH)
    if classification is not None and (type(classification) is not str or classification not in definition.levels):
        raise PolicyRefusal(RefusalReason.POLICY_MISMATCH)
    if not labels and classification is None:
        if "unclassified" not in definition.levels:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        return ClassificationDecision("unclassified", "default")
    strongest = max(labels, key=definition.levels.index) if labels else classification
    if classification is not None and definition.levels.index(classification) >= definition.levels.index(strongest):
        return ClassificationDecision(classification, "explicit")
    return ClassificationDecision(strongest, "inherited")


@dataclass(frozen=True, repr=False)
class PolicyParent:
    """Trusted caller's exact supporting binding/revision reference and policy."""

    reference: str
    policy: MemoryPolicy

    def __post_init__(self):
        _text(self.reference, "reference")
        if not isinstance(self.policy, MemoryPolicy):
            raise TypeError("policy must be an explicit MemoryPolicy")


def _policy_payload(policy):
    return {field.name: sorted(value) if isinstance(value, frozenset) else value
            for field in fields(MemoryPolicy) for value in (getattr(policy, field.name),)}


@dataclass(frozen=True, repr=False)
class DerivedPolicy:
    policy: MemoryPolicy
    parents: Tuple[PolicyParent, ...]

    def fingerprint(self):
        value = [1, _policy_payload(self.policy), [[parent.reference, _policy_payload(parent.policy)] for parent in self.parents]]
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def derive_memory_policy(definition, parents):
    """Intersect permission sets and union requirements, without declassification."""
    if not isinstance(definition, PolicyDefinition):
        raise TypeError("definition must be an explicit PolicyDefinition")
    if type(parents) not in (tuple, list) or not 1 <= len(parents) <= 128:
        raise ValueError("parents must contain 1..128 explicit PolicyParent records")
    parents = tuple(parents)
    if any(not isinstance(parent, PolicyParent) for parent in parents):
        raise TypeError("parents must be explicit PolicyParent records")
    if len({parent.reference for parent in parents}) != len(parents):
        raise ValueError("parent references must be unique")
    parents = tuple(sorted(parents, key=lambda parent: parent.reference))
    for parent in parents:
        definition.validate_binding(parent.policy)
    first = parents[0].policy
    if any((parent.policy.owner, parent.policy.tenant_id) != (first.owner, first.tenant_id) for parent in parents):
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
    classification = normalize_classification(definition, inherited=tuple(parent.policy.classification for parent in parents))
    origin = (first.origin_context_id, first.origin_context_epoch)
    if any((parent.policy.origin_context_id, parent.policy.origin_context_epoch) != origin for parent in parents):
        origin = (None, None)
    policies = [parent.policy for parent in parents]
    policy = MemoryPolicy(definition.policy_id, definition.version, classification.classification, first.owner, "external",
        compartments=frozenset().union(*(p.compartments for p in policies)),
        audiences=first.audiences.intersection(*(p.audiences for p in policies[1:])),
        purposes=first.purposes.intersection(*(p.purposes for p in policies[1:])),
        overlays=frozenset().union(*(p.overlays for p in policies)), tenant_id=first.tenant_id,
        origin_context_id=origin[0], origin_context_epoch=origin[1])
    return DerivedPolicy(policy, parents)
