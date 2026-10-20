"""Optional policy contracts; no activation, persistence or retrieval enforcement.

These records carry host-resolved claims, not credentials. Only an authenticated
adapter may supply a request context; constructing a record cannot authenticate
its creator. A trusted in-process owner can bypass these API contracts entirely.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, fields, replace
from enum import Enum
from typing import FrozenSet, Optional, Tuple


POLICY_CONTRACT_VERSION = 1


class RefusalReason(str, Enum):
    MISSING_CONTEXT = "missing_context"
    POLICY_MISMATCH = "policy_mismatch"
    INVALID_SELECTION = "invalid_selection"
    UNSUPPORTED_SURFACE = "unsupported_surface"


class PolicyRefusal(PermissionError):
    """Content-free contract refusal; never include a denied object's identity."""

    def __init__(self, reason: RefusalReason):
        if not isinstance(reason, RefusalReason):
            raise ValueError("reason must be a RefusalReason")
        self.reason = reason
        super().__init__(f"policy_refused:{reason.value}")


def _text(value: str, name: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str) or not value or value != value.strip()
        or len(value) > maximum
        or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)
    ):
        raise ValueError(f"{name} must be bounded nonblank text without surrounding whitespace or controls")
    return value


def _number(value: int, name: str, minimum: int = 1) -> int:
    if type(value) is not int or not minimum <= value <= 2**63 - 1:
        raise ValueError(f"{name} must be a bounded integer")
    return value


def _labels(value, name: str) -> FrozenSet[str]:
    if not isinstance(value, (tuple, list, set, frozenset)) or len(value) > 256:
        raise ValueError(f"{name} must be a collection of at most 256 labels")
    return frozenset(_text(item, name) for item in value)


@dataclass(frozen=True, repr=False)
class PolicyDefinition:
    """Deployment-defined ordered classification vocabulary, lowest first."""

    policy_id: str
    version: int
    levels: Tuple[str, ...]

    def __post_init__(self):
        _text(self.policy_id, "policy_id")
        _number(self.version, "version")
        if not isinstance(self.levels, (tuple, list)) or not 1 <= len(self.levels) <= 64:
            raise ValueError("levels must be an ordered collection of 1..64 labels")
        levels = tuple(_text(level, "levels", 64) for level in self.levels)
        if len(set(levels)) != len(levels):
            raise ValueError("levels must not repeat labels")
        object.__setattr__(self, "levels", levels)

    def validate_context(self, context: "AccessContext") -> None:
        """Check vocabulary/version only, not identity, freshness or access."""
        if not isinstance(context, AccessContext):
            raise PolicyRefusal(RefusalReason.MISSING_CONTEXT)
        if (
            context.policy_id != self.policy_id or context.policy_version != self.version
            or context.classification_ceiling not in self.levels
        ):
            raise PolicyRefusal(RefusalReason.POLICY_MISMATCH)

    def validate_binding(self, binding: "MemoryPolicy") -> None:
        """Check metadata against this vocabulary; do not authorize a read."""
        if not isinstance(binding, MemoryPolicy) or (
            binding.policy_id != self.policy_id or binding.policy_version != self.version
            or binding.classification not in self.levels
        ):
            raise PolicyRefusal(RefusalReason.POLICY_MISMATCH)


@dataclass(frozen=True, repr=False)
class AccessContext:
    """Effective claims resolved by a trusted host, never from tool arguments.

    All principals must already be authenticated and their grants intersected.
    Empty grant sets authorize nothing; labels have no wildcard semantics. A context
    is a snapshot, not proof that its epoch is still current.
    """

    context_id: str
    epoch: int
    policy_id: str
    policy_version: int
    issuer: str
    platform: str
    principals: FrozenSet[str]
    classification_ceiling: str
    purpose: str
    assurance: str
    banks: FrozenSet[str] = frozenset()
    projects: FrozenSet[str] = frozenset()
    compartments: FrozenSet[str] = frozenset()
    audiences: FrozenSet[str] = frozenset()
    operations: FrozenSet[str] = frozenset()
    destinations: FrozenSet[str] = frozenset()
    channel_id: Optional[str] = None
    conversation_id: Optional[str] = None

    def __post_init__(self):
        for name in ("context_id", "policy_id", "issuer", "platform", "purpose", "assurance"):
            _text(getattr(self, name), name)
        _text(self.classification_ceiling, "classification_ceiling", 64)
        _number(self.epoch, "epoch", minimum=0)
        _number(self.policy_version, "policy_version")
        for name in ("principals", "banks", "projects", "compartments", "audiences", "operations", "destinations"):
            object.__setattr__(self, name, _labels(getattr(self, name), name))
        if not self.principals:
            raise ValueError("principals must not be empty")
        for name in ("channel_id", "conversation_id"):
            if getattr(self, name) is not None:
                _text(getattr(self, name), name)

    def narrow(
        self, *, banks=None, projects=None, operations=None, destinations=None,
    ) -> "AccessContext":
        """Select exact subsets; None retains grants, an empty set selects none.

        Unknown selections refuse rather than silently broadening or turning an
        empty result into an all-projects fallback. This is not row authorization.
        """
        changes = {}
        for name, selection in (("banks", banks), ("projects", projects),
                                ("operations", operations), ("destinations", destinations)):
            if selection is not None:
                try:
                    selected = _labels(selection, name)
                except ValueError:
                    raise PolicyRefusal(RefusalReason.INVALID_SELECTION) from None
                if not selected <= getattr(self, name):
                    raise PolicyRefusal(RefusalReason.INVALID_SELECTION)
                changes[name] = selected
        return replace(self, **changes)

    def fingerprint(self) -> str:
        """Deterministic cache-key ingredient, not an access decision or secret."""
        values = {f.name: getattr(self, f.name) for f in fields(self)}
        for name, value in values.items():
            if isinstance(value, frozenset):
                values[name] = sorted(value)
        encoded = json.dumps([POLICY_CONTRACT_VERSION, values], sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True, repr=False)
class MemoryPolicy:
    """Proposed row restriction metadata; not yet stored, indexed or enforced."""

    policy_id: str
    policy_version: int
    classification: str
    owner: str
    classification_source: str
    compartments: FrozenSet[str] = frozenset()
    audiences: FrozenSet[str] = frozenset()
    purposes: FrozenSet[str] = frozenset()
    overlays: FrozenSet[str] = frozenset()
    tenant_id: Optional[str] = None
    origin_context_id: Optional[str] = None
    origin_context_epoch: Optional[int] = None

    def __post_init__(self):
        for name in ("policy_id", "owner"):
            _text(getattr(self, name), name)
        _number(self.policy_version, "policy_version")
        _text(self.classification, "classification", 64)
        if self.classification_source not in ("manual", "context", "external"):
            raise ValueError("classification_source must be manual, context or external")
        for name in ("compartments", "audiences", "purposes", "overlays"):
            object.__setattr__(self, name, _labels(getattr(self, name), name))
        if self.tenant_id is not None:
            _text(self.tenant_id, "tenant_id")
        if (self.origin_context_id is None) != (self.origin_context_epoch is None):
            raise ValueError("origin context ID and epoch must be supplied together")
        if self.origin_context_id is not None:
            _text(self.origin_context_id, "origin_context_id")
            _number(self.origin_context_epoch, "origin_context_epoch", minimum=0)
        if self.classification_source == "context" and self.origin_context_id is None:
            raise ValueError("context classification requires an origin context")


class PolicySurface(str, Enum):
    BEAM = "beam"
    VECTOR = "vector"
    LEXICAL = "lexical"
    GRAPH = "graph"
    DIRECT = "direct"
    WRITE = "write"
    DERIVE = "derive"
    MAINTENANCE = "maintenance"
    EXPORT = "export"
    IMPORT = "import"
    SYNC = "sync"
    EXPAND = "expand"
    INJECT = "inject"
    CACHE = "cache"


@dataclass(frozen=True, repr=False)
class AdapterCapabilities:
    """Explicit declarations, not a certificate that an adapter enforces them."""

    adapter_id: str
    surfaces: FrozenSet[PolicySurface] = frozenset()
    contract_version: int = POLICY_CONTRACT_VERSION

    def __post_init__(self):
        _text(self.adapter_id, "adapter_id")
        if type(self.contract_version) is not int or self.contract_version != POLICY_CONTRACT_VERSION:
            raise ValueError("unsupported policy contract version")
        if not isinstance(self.surfaces, (tuple, list, set, frozenset)) or len(self.surfaces) > 256:
            raise ValueError("surfaces must be an explicit collection of PolicySurface values")
        if any(not isinstance(surface, PolicySurface) for surface in self.surfaces):
            raise ValueError("surfaces must contain only PolicySurface values")
        object.__setattr__(self, "surfaces", frozenset(self.surfaces))

    def require(self, surface: PolicySurface) -> None:
        """Refuse undeclared paths; this helper does not guard existing APIs."""
        if not isinstance(surface, PolicySurface) or surface not in self.surfaces:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
