"""Exact-target, independently approved registry edits; never content authority."""

from dataclasses import dataclass, replace
import hashlib
import inspect
import os
import threading
import time
import uuid

from .administration_audit_contract import AdministrativeActor, RegistryAdministrationIntent, _digest
from .administration_journal import AdministrationJournal
from .host_administration import AdministrationApproval, MAX_PENDING_CHANGES, _entry
from .host_configuration import ConfigurationRevision, HostConfigurationAuthority, _canonical, _snapshot
from .host_profile import _bounded_text
from .host_registry import (
    ConversationRegistration, DestinationRegistration, PrincipalRegistration, StoreRegistration,
)
from .policy import PolicyRefusal, RefusalReason, _number
from .policy_host import _synchronous
from .snapshot_authority import _store_id


REGISTRY_ADMIN_CAPABILITIES = frozenset({"registry:view", "registry:write", "registry:approve"})
_TARGETS = {
    "principals": (PrincipalRegistration, "principal_id"),
    "stores": (StoreRegistration, "store_id"),
    "destinations": (DestinationRegistration, "destination_id"),
    "conversations": (ConversationRegistration, "context_id"),
}


def _target(kind, identity):
    if type(kind) is not str or kind not in _TARGETS:
        raise ValueError("supported registry collection required")
    _bounded_text(identity, "target_id", 128)
    if kind == "stores":
        _store_id(identity)
    return kind, identity


@dataclass(frozen=True, repr=False)
class RegistryAdministrationSnapshot:
    issuer: str
    principal_id: str
    separation_id: str
    authority_id: str
    authorization_revision: str
    epoch: int
    targets: frozenset[tuple[str, str]]
    controlled_principals: frozenset[str]
    capabilities: frozenset[str]

    def __post_init__(self):
        for name in ("issuer", "principal_id", "separation_id"):
            _bounded_text(getattr(self, name), name, 128)
        _store_id(self.authority_id)
        _digest(self.authorization_revision)
        _number(self.epoch, "epoch")
        if type(self.targets) is not frozenset or not 1 <= len(self.targets) <= 256:
            raise ValueError("bounded exact registry target pairs required")
        for target in self.targets:
            if type(target) is not tuple or len(target) != 2:
                raise ValueError("exact target pair required")
            _target(*target)
        if (type(self.controlled_principals) is not frozenset
                or not 1 <= len(self.controlled_principals) <= 256
                or self.principal_id not in self.controlled_principals):
            raise ValueError("complete controlled identities including actor required")
        for identity in self.controlled_principals:
            _bounded_text(identity, "controlled_principal", 128)
        if (type(self.capabilities) is not frozenset or not self.capabilities
                or any(type(c) is not str for c in self.capabilities)
                or not self.capabilities <= REGISTRY_ADMIN_CAPABILITIES):
            raise ValueError("explicit supported registry capabilities required")

    def fingerprint(self):
        return hashlib.sha256(_canonical({
            "issuer": self.issuer, "principal_id": self.principal_id, "separation_id": self.separation_id,
            "authority_id": self.authority_id, "authorization_revision": self.authorization_revision,
            "epoch": self.epoch, "targets": sorted(self.targets),
            "controlled_principals": sorted(self.controlled_principals), "capabilities": sorted(self.capabilities),
        })).hexdigest()


@dataclass(frozen=True, repr=False)
class RegistryView:
    revision: ConfigurationRevision
    record: PrincipalRegistration | StoreRegistration | DestinationRegistration | ConversationRegistration | None


@dataclass(frozen=True, repr=False)
class RegistryAdministrationPlan:
    operation_id: str
    previous: ConfigurationRevision
    target_kind: str
    target_id: str
    prior: object
    replacement: object
    affected_principals: frozenset[str]
    digest: str


@dataclass(repr=False)
class _Pending:
    plan: RegistryAdministrationPlan
    actor: RegistryAdministrationSnapshot
    deadline: float
    approval: AdministrationApproval | None = None
    approver: RegistryAdministrationSnapshot | None = None
    approval_request: object = None


class RegistryAdministration:
    """One explicit registry target per plan; grants/profiles remain unchanged.

    Owner, authenticators and complete current control mappings stay trusted.
    This facade requires a separately witnessed attribution journal.
    """

    def __init__(self, owner, *, authority_id, issuer, authenticate, journal, lifetime_seconds=60):
        if type(owner) is not HostConfigurationAuthority:
            raise TypeError("exact owner authority required")
        _store_id(authority_id)
        _bounded_text(issuer, "issuer", 128)
        _synchronous(authenticate)
        if type(journal) is not AdministrationJournal or journal._authority_id != authority_id:
            raise TypeError("exact same-authority administration journal required")
        if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 300:
            raise ValueError("bounded preview lifetime required")
        self._owner, self._authority_id, self._issuer = owner, authority_id, issuer
        self._authenticate, self._journal, self._lifetime = authenticate, journal, lifetime_seconds
        self._pending = {}
        self._process, self._thread, self._busy = os.getpid(), threading.get_ident(), False

    def _fresh(self, request, target, capabilities, expected=None):
        claim = self._authenticate(request)
        if inspect.iscoroutine(claim) or inspect.isgenerator(claim):
            claim.close()
        if (type(claim) is not RegistryAdministrationSnapshot or claim.issuer != self._issuer
                or claim.authority_id != self._authority_id or target not in claim.targets
                or not capabilities <= claim.capabilities or (expected is not None and claim != expected)):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return claim

    def _current(self):
        current = self._owner.current()
        if current.revision.authority_id != self._authority_id:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        if current.registry is None:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        return current

    def _controlled(self, claim, registry):
        people = {p.principal_id: p for p in registry.principals}
        actor = people.get(claim.principal_id)
        if (actor is None or not actor.enabled or actor.issuer != claim.issuer
                or actor.separation_id != claim.separation_id
                or not claim.controlled_principals <= people.keys()):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return frozenset(people[key].separation_id for key in claim.controlled_principals)

    def _record(self, registry, target):
        kind, identity = target
        key = _TARGETS[kind][1]
        return next((r for r in getattr(registry, kind) if getattr(r, key) == identity), None)

    def _candidate(self, current, target, replacement):
        kind, identity = target
        cls, key = _TARGETS[kind]
        if replacement is not None and (type(replacement) is not cls or getattr(replacement, key) != identity):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        prior = self._record(current.registry, target)
        # New issuer mappings and resource IDs need independently qualified
        # provisioning/lifetime evidence, not a model-supplied replacement.
        if prior is None:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        if prior == replacement:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        # Existing identity/store bindings cannot redirect retained grants.
        if prior is not None and replacement is not None:
            if kind == "principals" and replace(prior, enabled=replacement.enabled) != replacement:
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            if kind == "stores" and (replace(prior, lifecycle_epoch=replacement.lifecycle_epoch) != replacement
                                     or replacement.lifecycle_epoch <= prior.lifecycle_epoch):
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            if kind == "destinations" and (prior.issuer != replacement.issuer or prior.platform != replacement.platform
                                           or prior.route_id != replacement.route_id or prior.recipients != replacement.recipients
                                           or replacement.route_revision <= prior.route_revision):
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            if kind == "conversations" and any(getattr(prior, k) != getattr(replacement, k)
                                               for k in ("issuer", "platform", "conversation_id", "participants", "store_id", "destination_id")):
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        values = tuple(r for r in getattr(current.registry, kind) if getattr(r, key) != identity)
        if replacement is not None:
            values += (replacement,)
        registry = replace(current.registry, **{kind: values})
        return _snapshot(self._authority_id, current.revision.generation + 1, current.profiles, registry,
                         storage_version=current.storage_version)

    def _affected(self, target, *registries):
        kind, identity = target
        affected = set()
        for registry in registries:
            record = self._record(registry, target)
            if record is None:
                continue
            if kind == "principals":
                affected.update(p.principal_id for p in registry.principals if p.separation_id == record.separation_id)
            elif kind == "stores":
                affected.update(g.principal_id for g in registry.grants if g.store_id == identity)
                for c in registry.conversations:
                    if c.store_id == identity:
                        affected.update(c.participants)
            elif kind == "destinations":
                affected.update(record.recipients)
                affected.update(g.principal_id for g in registry.grants if identity in g.destinations)
            else:
                affected.update(record.participants)
        return frozenset(affected)

    def _separated(self, claims, current, candidate, affected):
        for registry in (current.registry, candidate.registry):
            people = {p.principal_id: p for p in registry.principals}
            beneficiary_actors = {people[p].separation_id for p in affected if p in people}
            closures = [self._controlled(claim, registry) for claim in claims]
            if any(closure & beneficiary_actors for closure in closures):
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            if len(closures) == 2 and closures[0] & closures[1]:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)

    def _expire(self):
        for key in tuple(self._pending):
            if time.monotonic() >= self._pending[key].deadline:
                del self._pending[key]

    def _find(self, plan):
        if type(plan) is not RegistryAdministrationPlan:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        pending = self._pending.get(plan.operation_id)
        if pending is None or pending.plan is not plan or time.monotonic() >= pending.deadline:
            self._expire()
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return pending

    def _verify(self, request, pending):
        if time.monotonic() >= pending.deadline:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        target = pending.plan.target_kind, pending.plan.target_id
        self._fresh(request, target, frozenset({"registry:view", "registry:write"}), pending.actor)
        if pending.approval is None or pending.approver is None:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        self._fresh(pending.approval_request, target, frozenset({"registry:view", "registry:approve"}), pending.approver)
        if time.monotonic() >= pending.deadline:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)

    @_entry
    def view(self, request, kind, identity):
        target = _target(kind, identity)
        claim = self._fresh(request, target, frozenset({"registry:view"}))
        current = self._current()
        self._controlled(claim, current.registry)
        record = self._record(current.registry, target)
        self._fresh(request, target, frozenset({"registry:view"}), claim)
        return RegistryView(current.revision, record)

    @_entry
    def preview(self, request, kind, identity, replacement):
        target = _target(kind, identity)
        claim = self._fresh(request, target, frozenset({"registry:view", "registry:write"}))
        current = self._current()
        candidate = self._candidate(current, target, replacement)
        affected = self._affected(target, current.registry, candidate.registry)
        self._separated((claim,), current, candidate, affected)
        self._fresh(request, target, frozenset({"registry:view", "registry:write"}), claim)
        self._expire()
        if len(self._pending) >= MAX_PENDING_CHANGES:
            raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
        operation = "host-registry:" + uuid.uuid4().hex
        digest = hashlib.sha256(_canonical({"contract_version": 1, "operation_id": operation,
            "authority_id": self._authority_id, "previous": current.revision.sha256,
            "candidate": candidate.revision.sha256, "actor": claim.fingerprint(), "target": target})).hexdigest()
        plan = RegistryAdministrationPlan(operation, current.revision, kind, identity,
            self._record(current.registry, target), replacement, affected, digest)
        self._pending[operation] = _Pending(plan, claim, time.monotonic() + self._lifetime)
        return plan

    @_entry
    def approve(self, request, plan):
        pending = self._find(plan)
        target = plan.target_kind, plan.target_id
        claim = self._fresh(request, target, frozenset({"registry:view", "registry:approve"}))
        current = self._current()
        if (pending.approval is not None or current.revision != plan.previous
                or claim.principal_id == pending.actor.principal_id or claim.separation_id == pending.actor.separation_id
                or claim.epoch != pending.actor.epoch or claim.authorization_revision != pending.actor.authorization_revision):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        candidate = self._candidate(current, target, plan.replacement)
        self._separated((pending.actor, claim), current, candidate, plan.affected_principals)
        self._fresh(request, target, frozenset({"registry:view", "registry:approve"}), claim)
        self._find(plan)
        approval = AdministrationApproval(plan.operation_id, plan.digest)
        pending.approval, pending.approver, pending.approval_request = approval, claim, request
        return approval

    @_entry
    def cancel(self, plan):
        self._find(plan)
        del self._pending[plan.operation_id]

    @_entry
    def apply(self, request, plan, *, approval=None):
        pending = self._find(plan)
        self._verify(request, pending)
        if approval is not pending.approval:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        current = self._current()
        if current.revision != plan.previous:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        candidate = self._candidate(current, (plan.target_kind, plan.target_id), plan.replacement)
        self._separated((pending.actor, pending.approver), current, candidate, plan.affected_principals)
        self._verify(request, pending)
        del self._pending[plan.operation_id]

        def attribution(claim):
            return AdministrativeActor(claim.issuer, claim.principal_id, claim.separation_id,
                claim.authorization_revision, claim.epoch, claim.fingerprint())

        intent = RegistryAdministrationIntent(plan.operation_id, plan.digest, plan.previous, candidate.revision,
            plan.target_kind, plan.target_id, attribution(pending.actor), attribution(pending.approver))
        self._journal.append_intent(intent, owner=self._owner)
        self._verify(request, pending)
        receipt = self._owner.stage(candidate.profiles, previous=plan.previous,
                                    operation_id=plan.operation_id, registry=candidate.registry)
        self._verify(request, pending)
        self._owner.advance_witness(receipt)
        self._verify(request, pending)
        result = self._owner.finalize(receipt)
        self._journal.observe(plan.operation_id, owner=self._owner)
        self._verify(request, pending)
        return result
