"""Bounded generic authorization metadata, not credentials or a domain rules engine."""

from __future__ import annotations

from dataclasses import dataclass, fields
import json
from typing import ClassVar

from .host_profile import ProfileDefinition, _bounded_text, _exact_dict
from .policy import PolicyRefusal, RefusalReason, _number
from .snapshot_authority import _store_id


REGISTRY_CONTRACT_VERSION = 1
MAX_PRINCIPALS = 256
MAX_STORES = 32
MAX_DESTINATIONS = 256
MAX_CONVERSATIONS = 256
MAX_GRANTS = 4096
MAX_REGISTRY_BYTES = 256 * 1024
HOST_READ_CAPABILITY = "native-evidence-v1"
GRANT_SET_FIELDS = (
    "projects", "owners", "tenants", "compartments", "audiences", "purposes",
    "operations", "destinations",
)


def _labels(value, name):
    if type(value) is not frozenset or len(value) > 256:
        raise ValueError("bounded exact label set required")
    for item in value:
        _bounded_text(item, name, 128)


def _enabled(value):
    if type(value) is not bool:
        raise TypeError("explicit boolean required")


class _Record:
    _sets: ClassVar[tuple[str, ...]] = ()

    def to_dict(self):
        return {field.name: sorted(getattr(self, field.name)) if field.name in self._sets
                else getattr(self, field.name) for field in fields(self)}

    @classmethod
    def from_dict(cls, data):
        values = dict(_exact_dict(data, {field.name for field in fields(cls)}, "registry record"))
        for name in cls._sets:
            value = values[name]
            if type(value) is not list or len(value) > 256 or any(type(v) is not str for v in value):
                raise ValueError("bounded exact label array required")
            if len(set(value)) != len(value):
                raise ValueError("duplicate label")
            values[name] = frozenset(value)
        return cls(**values)


@dataclass(frozen=True, repr=False)
class PrincipalRegistration(_Record):
    principal_id: str
    issuer: str
    subject: str
    separation_id: str
    kind: str
    enabled: bool

    def __post_init__(self):
        for name in ("principal_id", "issuer", "subject", "separation_id"):
            _bounded_text(getattr(self, name), name, 128)
        if type(self.kind) is not str or self.kind not in ("human", "agent", "service"):
            raise ValueError("supported principal kind required")
        _enabled(self.enabled)


@dataclass(frozen=True, repr=False)
class StoreRegistration(_Record):
    store_id: str
    domain_id: str
    bank: str
    profile_id: str
    owner_registry_key: str
    lifecycle_epoch: int
    capability: str

    def __post_init__(self):
        _store_id(self.store_id)
        for name in ("domain_id", "bank", "profile_id", "owner_registry_key"):
            _bounded_text(getattr(self, name), name, 128)
        _number(self.lifecycle_epoch, "lifecycle_epoch", minimum=0)
        if type(self.capability) is not str or self.capability != HOST_READ_CAPABILITY:
            raise ValueError("explicit supported store capability required")


@dataclass(frozen=True, repr=False)
class DestinationRegistration(_Record):
    destination_id: str
    issuer: str
    platform: str
    route_id: str
    route_revision: int
    recipients: frozenset[str]
    capability: str
    _sets: ClassVar[tuple[str, ...]] = ("recipients",)

    def __post_init__(self):
        for name in ("destination_id", "issuer", "platform", "route_id"):
            _bounded_text(getattr(self, name), name, 128)
        _number(self.route_revision, "route_revision")
        _labels(self.recipients, "recipients")
        if not self.recipients:
            raise ValueError("complete nonempty destination audience required")
        if type(self.capability) is not str or self.capability != HOST_READ_CAPABILITY:
            raise ValueError("explicit supported destination capability required")


@dataclass(frozen=True, repr=False)
class ConversationRegistration(_Record):
    context_id: str
    issuer: str
    platform: str
    conversation_id: str
    participants: frozenset[str]
    store_id: str
    destination_id: str
    classification_ceiling: str
    purpose: str
    projects: frozenset[str]
    compartments: frozenset[str]
    audiences: frozenset[str]
    operations: frozenset[str]
    enabled: bool
    _sets: ClassVar[tuple[str, ...]] = ("participants", "projects", "compartments", "audiences", "operations")

    def __post_init__(self):
        _store_id(self.store_id)
        for name in ("context_id", "issuer", "platform", "conversation_id", "destination_id", "purpose"):
            _bounded_text(getattr(self, name), name, 128)
        _bounded_text(self.classification_ceiling, "classification_ceiling", 64)
        for name in self._sets:
            _labels(getattr(self, name), name)
        if not self.participants:
            raise ValueError("complete nonempty conversation audience required")
        _enabled(self.enabled)


@dataclass(frozen=True, repr=False)
class GrantRegistration(_Record):
    principal_id: str
    store_id: str
    classification_ceiling: str
    projects: frozenset[str] = frozenset()
    owners: frozenset[str] = frozenset()
    tenants: frozenset[str] = frozenset()
    compartments: frozenset[str] = frozenset()
    audiences: frozenset[str] = frozenset()
    purposes: frozenset[str] = frozenset()
    operations: frozenset[str] = frozenset()
    destinations: frozenset[str] = frozenset()
    bank_wide: bool = False
    _sets: ClassVar[tuple[str, ...]] = GRANT_SET_FIELDS

    def __post_init__(self):
        _bounded_text(self.principal_id, "principal_id", 128)
        _store_id(self.store_id)
        _bounded_text(self.classification_ceiling, "classification_ceiling", 64)
        for name in self._sets:
            _labels(getattr(self, name), name)
        _enabled(self.bank_wide)


_COLLECTIONS = (
    ("principals", PrincipalRegistration, MAX_PRINCIPALS, lambda p: p.principal_id),
    ("stores", StoreRegistration, MAX_STORES, lambda s: s.store_id),
    ("destinations", DestinationRegistration, MAX_DESTINATIONS, lambda d: d.destination_id),
    ("conversations", ConversationRegistration, MAX_CONVERSATIONS, lambda c: c.context_id),
    ("grants", GrantRegistration, MAX_GRANTS, lambda g: (g.principal_id, g.store_id)),
)


@dataclass(frozen=True, repr=False)
class AuthorizationRegistry:
    principals: tuple[PrincipalRegistration, ...] = ()
    stores: tuple[StoreRegistration, ...] = ()
    destinations: tuple[DestinationRegistration, ...] = ()
    conversations: tuple[ConversationRegistration, ...] = ()
    grants: tuple[GrantRegistration, ...] = ()

    def __post_init__(self):
        for name, cls, maximum, key in _COLLECTIONS:
            values = getattr(self, name)
            if type(values) is not tuple or len(values) > maximum:
                raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
            if any(type(value) is not cls for value in values):
                raise TypeError("exact registry records required")
            if len({key(value) for value in values}) != len(values):
                raise ValueError("duplicate registry identity")
            object.__setattr__(self, name, tuple(sorted(values, key=key)))
        self._references()
        self._budget()

    def _budget(self):
        # Bound the aggregate before building a potentially much larger nested
        # JSON document; each individual record has already bounded its sets.
        size = len(json.dumps({"contract_version": REGISTRY_CONTRACT_VERSION,
            **{name: [] for name, *_ in _COLLECTIONS}}, sort_keys=True, separators=(",", ":")))
        for name, *_ in _COLLECTIONS:
            values = getattr(self, name)
            size += max(0, len(values) - 1)
            for value in values:
                size += len(json.dumps(value.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True))
                if size > MAX_REGISTRY_BYTES:
                    raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)

    def _references(self):
        principals = {p.principal_id for p in self.principals}
        stores = {s.store_id: s for s in self.stores}
        destinations = {d.destination_id: d for d in self.destinations}
        if len({(p.issuer, p.subject) for p in self.principals}) != len(self.principals):
            raise ValueError("duplicate issuer/subject mapping")
        routes = [(d.issuer, d.platform, d.route_id) for d in self.destinations]
        if len(set(routes)) != len(routes):
            raise ValueError("duplicate destination route")
        conversations = [(c.issuer, c.platform, c.conversation_id) for c in self.conversations]
        if len(set(conversations)) != len(conversations):
            raise ValueError("duplicate transport conversation")
        for destination in self.destinations:
            if not destination.recipients <= principals:
                raise ValueError("unregistered recipient")
        for conversation in self.conversations:
            destination = destinations.get(conversation.destination_id)
            if (conversation.store_id not in stores or destination is None
                    or conversation.participants != destination.recipients
                    or conversation.issuer != destination.issuer or conversation.platform != destination.platform):
                raise ValueError("incomplete conversation binding")
        for grant in self.grants:
            if (grant.principal_id not in principals or grant.store_id not in stores
                    or not grant.destinations <= set(destinations)):
                raise ValueError("unregistered grant reference")

    def validate_profiles(self, profiles):
        if type(profiles) is not tuple or any(type(p) is not ProfileDefinition for p in profiles):
            raise TypeError("exact profile tuple required")
        definitions = {p.profile_id: p.policy for p in profiles}
        stores = {s.store_id: s for s in self.stores}
        for store in self.stores:
            if store.profile_id not in definitions:
                raise ValueError("unregistered policy profile")
        for record in (*self.conversations, *self.grants):
            if record.classification_ceiling not in definitions[stores[record.store_id].profile_id].levels:
                raise ValueError("classification outside registered vocabulary")

    def to_dict(self):
        return {"contract_version": REGISTRY_CONTRACT_VERSION,
                **{name: [record.to_dict() for record in getattr(self, name)] for name, *_ in _COLLECTIONS}}

    @classmethod
    def from_dict(cls, data):
        values = _exact_dict(data, {"contract_version", *(name for name, *_ in _COLLECTIONS)}, "registry")
        if type(values["contract_version"]) is not int or values["contract_version"] != REGISTRY_CONTRACT_VERSION:
            raise ValueError("unsupported registry contract")
        records = {}
        for name, record, maximum, _ in _COLLECTIONS:
            items = values[name]
            if type(items) is not list or len(items) > maximum:
                raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
            records[name] = tuple(record.from_dict(item) for item in items)
        return cls(**records)
