"""Scoped grant proposals over trusted host claims; no transport or activation."""

from dataclasses import dataclass, replace
import hashlib
import inspect
import os
import threading
import time
import uuid

from .host_administration import AdministrationApproval, MAX_PENDING_CHANGES, _entry
from .host_configuration import ConfigurationRevision, HostConfigurationAuthority, _canonical, _snapshot
from .host_profile import _bounded_text
from .host_registry import GrantRegistration
from .policy import PolicyRefusal, RefusalReason, _number
from .policy_host import _synchronous
from .snapshot_authority import _store_id


GRANT_ADMIN_CAPABILITIES = frozenset({"grants:view", "grants:write", "grants:approve"})
MAX_ADMIN_TARGETS = 256


@dataclass(frozen=True, repr=False)
class GrantAdministrationSnapshot:
    """Fresh trusted administrative claims, not model-supplied credentials.

    targets are exact (principal_id, store_id) pairs. controlled_principals must
    include every identity controlled by this canonical actor, including itself.
    """

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
        value = self.authorization_revision
        if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("exact authorization revision required")
        _number(self.epoch, "epoch")
        if type(self.targets) is not frozenset or not 1 <= len(self.targets) <= MAX_ADMIN_TARGETS:
            raise ValueError("bounded exact target pairs required")
        for target in self.targets:
            if type(target) is not tuple or len(target) != 2:
                raise ValueError("exact principal/store pair required")
            _bounded_text(target[0], "principal_id", 128)
            _store_id(target[1])
        if (type(self.controlled_principals) is not frozenset
                or not 1 <= len(self.controlled_principals) <= 256
                or self.principal_id not in self.controlled_principals):
            raise ValueError("explicit controlled identities including actor required")
        for identity in self.controlled_principals:
            _bounded_text(identity, "controlled_principal", 128)
        if (type(self.capabilities) is not frozenset or not self.capabilities
                or any(type(c) is not str for c in self.capabilities)
                or not self.capabilities <= GRANT_ADMIN_CAPABILITIES):
            raise ValueError("explicit supported grant capabilities required")

    def fingerprint(self):
        return hashlib.sha256(_canonical({
            "issuer": self.issuer, "principal_id": self.principal_id, "separation_id": self.separation_id,
            "authority_id": self.authority_id, "authorization_revision": self.authorization_revision,
            "epoch": self.epoch, "targets": sorted(self.targets),
            "controlled_principals": sorted(self.controlled_principals), "capabilities": sorted(self.capabilities),
        })).hexdigest()


@dataclass(frozen=True, repr=False)
class GrantView:
    revision: ConfigurationRevision
    grant: GrantRegistration | None


@dataclass(frozen=True, repr=False)
class GrantAdministrationPlan:
    operation_id: str
    previous: ConfigurationRevision
    principal_id: str
    store_id: str
    prior: GrantRegistration | None
    replacement: GrantRegistration | None
    digest: str


@dataclass(repr=False)
class _Pending:
    plan: GrantAdministrationPlan
    actor: GrantAdministrationSnapshot
    deadline: float
    approval: AdministrationApproval | None = None
    approver: GrantAdministrationSnapshot | None = None
    approval_request: object = None


class GrantAdministration:
    """Grant-only facade; owner, authenticator and actor mappings stay trusted.

    It cannot provision a registry or edit identities, stores, profiles, routes,
    conversations, administrative capabilities, keys, recovery or content.
    """

    def __init__(self, owner, *, authority_id, issuer, authenticate, lifetime_seconds=60):
        if type(owner) is not HostConfigurationAuthority:
            raise TypeError("exact owner authority required")
        _store_id(authority_id)
        _bounded_text(issuer, "issuer", 128)
        _synchronous(authenticate)
        if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 300:
            raise ValueError("bounded preview lifetime required")
        self._owner, self._authority_id, self._issuer = owner, authority_id, issuer
        self._authenticate, self._lifetime, self._pending = authenticate, lifetime_seconds, {}
        self._process, self._thread, self._busy = os.getpid(), threading.get_ident(), False

    def _fresh(self, request, target, capabilities, expected=None):
        claim = self._authenticate(request)
        if inspect.iscoroutine(claim) or inspect.isgenerator(claim):
            claim.close()
        if (type(claim) is not GrantAdministrationSnapshot or claim.issuer != self._issuer
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

    def _target(self, principal_id, store_id):
        _bounded_text(principal_id, "principal_id", 128)
        _store_id(store_id)
        return principal_id, store_id

    def _controlled_actors(self, claim, registry):
        principals = {p.principal_id: p for p in registry.principals}
        actor = principals.get(claim.principal_id)
        if (actor is None or not actor.enabled or actor.issuer != claim.issuer
                or actor.separation_id != claim.separation_id
                or not claim.controlled_principals <= principals.keys()):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return frozenset(principals[key].separation_id for key in claim.controlled_principals)

    def _not_beneficiary(self, claim, principal_id, registry):
        controlled = self._controlled_actors(claim, registry)
        principal = next((p for p in registry.principals if p.principal_id == principal_id), None)
        if principal is None or principal.separation_id in controlled:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)

    def _candidate(self, current, target, replacement):
        grants = tuple(g for g in current.registry.grants if (g.principal_id, g.store_id) != target)
        if replacement is not None:
            grants += (replacement,)
        registry = replace(current.registry, grants=grants)
        return _snapshot(self._authority_id, current.revision.generation + 1, current.profiles, registry)

    def _expire(self):
        now = time.monotonic()
        for key in tuple(self._pending):
            if now >= self._pending[key].deadline:
                del self._pending[key]

    def _find(self, plan):
        if type(plan) is not GrantAdministrationPlan:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        pending = self._pending.get(plan.operation_id)
        if pending is None or pending.plan is not plan or time.monotonic() >= pending.deadline:
            self._expire()
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return pending

    def _verify(self, request, pending):
        if time.monotonic() >= pending.deadline:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        target = pending.plan.principal_id, pending.plan.store_id
        self._fresh(request, target, frozenset({"grants:view", "grants:write"}), pending.actor)
        if pending.approval is None or pending.approver is None:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        self._fresh(pending.approval_request, target, frozenset({"grants:view", "grants:approve"}), pending.approver)
        if time.monotonic() >= pending.deadline:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)

    @_entry
    def view(self, request, principal_id, store_id):
        target = self._target(principal_id, store_id)
        claim = self._fresh(request, target, frozenset({"grants:view"}))
        current = self._current()
        self._controlled_actors(claim, current.registry)
        grant = next((g for g in current.registry.grants if (g.principal_id, g.store_id) == target), None)
        self._fresh(request, target, frozenset({"grants:view"}), claim)
        return GrantView(current.revision, grant)

    @_entry
    def preview(self, request, principal_id, store_id, replacement):
        target = self._target(principal_id, store_id)
        if replacement is not None and (type(replacement) is not GrantRegistration
                or (replacement.principal_id, replacement.store_id) != target):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        claim = self._fresh(request, target, frozenset({"grants:view", "grants:write"}))
        current = self._current()
        self._not_beneficiary(claim, principal_id, current.registry)
        if not any(s.store_id == store_id for s in current.registry.stores):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        prior = next((g for g in current.registry.grants if (g.principal_id, g.store_id) == target), None)
        if prior == replacement:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        candidate = self._candidate(current, target, replacement)
        self._fresh(request, target, frozenset({"grants:view", "grants:write"}), claim)
        self._expire()
        if len(self._pending) >= MAX_PENDING_CHANGES:
            raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
        operation = "host-grant:" + uuid.uuid4().hex
        digest = hashlib.sha256(_canonical({
            "contract_version": 1, "operation_id": operation, "authority_id": self._authority_id,
            "previous": current.revision.sha256, "candidate": candidate.revision.sha256,
            "actor": claim.fingerprint(), "target": target,
        })).hexdigest()
        plan = GrantAdministrationPlan(operation, current.revision, principal_id, store_id, prior, replacement, digest)
        self._pending[operation] = _Pending(plan, claim, time.monotonic() + self._lifetime)
        return plan

    @_entry
    def approve(self, request, plan):
        pending = self._find(plan)
        target = plan.principal_id, plan.store_id
        claim = self._fresh(request, target, frozenset({"grants:view", "grants:approve"}))
        current = self._current()
        if (pending.approval is not None or current.revision != plan.previous
                or claim.principal_id == pending.actor.principal_id or claim.separation_id == pending.actor.separation_id
                or claim.epoch != pending.actor.epoch or claim.authorization_revision != pending.actor.authorization_revision):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        self._not_beneficiary(claim, plan.principal_id, current.registry)
        if self._controlled_actors(claim, current.registry) & self._controlled_actors(pending.actor, current.registry):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        self._fresh(request, target, frozenset({"grants:view", "grants:approve"}), claim)
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
        self._not_beneficiary(pending.actor, plan.principal_id, current.registry)
        self._not_beneficiary(pending.approver, plan.principal_id, current.registry)
        if (self._controlled_actors(pending.actor, current.registry)
                & self._controlled_actors(pending.approver, current.registry)):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        candidate = self._candidate(current, (plan.principal_id, plan.store_id), plan.replacement)
        self._verify(request, pending)
        # An uncertain write consumes the handle; inspect the owner receipt,
        # never blindly resend a proposal through this facade.
        del self._pending[plan.operation_id]
        receipt = self._owner.stage(candidate.profiles, previous=plan.previous,
                                    operation_id=plan.operation_id, registry=candidate.registry)
        self._verify(request, pending)
        self._owner.advance_witness(receipt)
        self._verify(request, pending)
        result = self._owner.finalize(receipt)
        self._verify(request, pending)
        return result
