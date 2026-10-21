"""Separately scoped and attributed cancellation of unwitnessed proposals."""

from dataclasses import dataclass
import hashlib
import inspect
import os
import threading
import time
import uuid

from .administration_audit_contract import AdministrativeActor, CancellationAdministrationIntent, _digest
from .administration_journal import AdministrationJournal
from .host_administration import AdministrationApproval, MAX_PENDING_CHANGES, _entry
from .host_configuration import ConfigurationReceipt, ConfigurationRevision, HostConfigurationAuthority, _canonical
from .host_profile import _bounded_text
from .policy import PolicyRefusal, RefusalReason, _number
from .policy_host import _synchronous
from .snapshot_authority import _store_id


CANCELLATION_CAPABILITIES = frozenset({"recovery:view", "recovery:cancel", "recovery:approve"})


@dataclass(frozen=True, repr=False)
class CancellationAdministrationSnapshot:
    issuer: str
    principal_id: str
    separation_id: str
    authority_id: str
    authorization_revision: str
    epoch: int
    operations: frozenset[str]
    controlled_principals: frozenset[str]
    capabilities: frozenset[str]

    def __post_init__(self):
        for name in ("issuer", "principal_id", "separation_id"):
            _bounded_text(getattr(self, name), name, 128)
        _store_id(self.authority_id)
        _digest(self.authorization_revision)
        _number(self.epoch, "epoch")
        if type(self.operations) is not frozenset or not 1 <= len(self.operations) <= 256:
            raise ValueError("bounded exact operation scope required")
        for operation in self.operations:
            _bounded_text(operation, "operation_id", 128)
        if (type(self.controlled_principals) is not frozenset
                or not 1 <= len(self.controlled_principals) <= 256
                or self.principal_id not in self.controlled_principals):
            raise ValueError("complete controlled identities including actor required")
        for identity in self.controlled_principals:
            _bounded_text(identity, "controlled_principal", 128)
        if (type(self.capabilities) is not frozenset or not self.capabilities
                or any(type(c) is not str for c in self.capabilities)
                or not self.capabilities <= CANCELLATION_CAPABILITIES):
            raise ValueError("explicit cancellation capabilities required")

    def fingerprint(self):
        return hashlib.sha256(_canonical({
            "issuer": self.issuer, "principal_id": self.principal_id, "separation_id": self.separation_id,
            "authority_id": self.authority_id, "authorization_revision": self.authorization_revision,
            "epoch": self.epoch, "operations": sorted(self.operations),
            "controlled_principals": sorted(self.controlled_principals), "capabilities": sorted(self.capabilities),
        })).hexdigest()


@dataclass(frozen=True, repr=False)
class CancellationView:
    current: ConfigurationRevision
    original: ConfigurationReceipt | None


@dataclass(frozen=True, repr=False)
class CancellationPlan:
    operation_id: str
    previous: ConfigurationRevision
    original: ConfigurationReceipt
    candidate: ConfigurationRevision
    digest: str


@dataclass(repr=False)
class _Pending:
    plan: CancellationPlan
    actor: CancellationAdministrationSnapshot
    deadline: float
    approval: AdministrationApproval | None = None
    approver: CancellationAdministrationSnapshot | None = None
    approval_request: object = None


class CancellationAdministration:
    """Exact-operation recovery role, not grant administration or key access."""

    def __init__(self, owner, *, authority_id, issuer, authenticate, journal, lifetime_seconds=60):
        if type(owner) is not HostConfigurationAuthority or owner._storage_version != 2:
            raise TypeError("explicit cancellable owner required")
        _store_id(authority_id)
        _bounded_text(issuer, "issuer", 128)
        _synchronous(authenticate)
        if type(journal) is not AdministrationJournal or journal._authority_id != authority_id:
            raise TypeError("exact same-authority journal required")
        if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 300:
            raise ValueError("bounded preview lifetime required")
        self._owner, self._authority_id, self._issuer = owner, authority_id, issuer
        self._authenticate, self._journal, self._lifetime = authenticate, journal, lifetime_seconds
        self._pending = {}
        self._process, self._thread, self._busy = os.getpid(), threading.get_ident(), False

    def _fresh(self, request, operation, capabilities, expected=None):
        claim = self._authenticate(request)
        if inspect.iscoroutine(claim) or inspect.isgenerator(claim):
            claim.close()
        if (type(claim) is not CancellationAdministrationSnapshot or claim.issuer != self._issuer
                or claim.authority_id != self._authority_id or operation not in claim.operations
                or not capabilities <= claim.capabilities or (expected is not None and claim != expected)):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return claim

    def _current(self):
        current = self._owner.current()
        if current.revision.authority_id != self._authority_id or current.registry is None:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return current

    def _controlled(self, claim, registry):
        if registry is None:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        people = {p.principal_id: p for p in registry.principals}
        actor = people.get(claim.principal_id)
        if (actor is None or not actor.enabled or actor.issuer != claim.issuer
                or actor.separation_id != claim.separation_id or not claim.controlled_principals <= people.keys()):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return frozenset(people[p].separation_id for p in claim.controlled_principals)

    def _proposal(self, original):
        owner = self._owner
        owner._ready()
        with owner._store._transaction():
            owner._schema()
            value = owner._raw_row(operation_id=original.operation_id)
            if value is None or value[1] != original:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return value[0]

    def _separated(self, claims, current, proposed):
        if proposed.registry is None:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        before = {p.principal_id: p for p in current.registry.principals}
        after = {p.principal_id: p for p in proposed.registry.principals}
        affected = {identity for identity in before.keys() | after.keys() if before.get(identity) != after.get(identity)}
        # Initial recovery authority is deliberately conservative across the
        # whole proposal, including identity changes with no content grant.
        for registry in (current.registry, proposed.registry):
            affected.update(g.principal_id for g in registry.grants)
            for conversation in registry.conversations:
                affected.update(conversation.participants)
        for registry in (current.registry, proposed.registry):
            canonical = {p.separation_id for p in registry.principals if p.principal_id in affected}
            closures = [self._controlled(claim, registry) for claim in claims]
            if any(closure & canonical for closure in closures) or (len(closures) == 2 and closures[0] & closures[1]):
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)

    def _find(self, plan):
        if type(plan) is not CancellationPlan:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        pending = self._pending.get(plan.operation_id)
        if pending is None or pending.plan is not plan or time.monotonic() >= pending.deadline:
            self._expire()
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return pending

    def _expire(self):
        for key in tuple(self._pending):
            if time.monotonic() >= self._pending[key].deadline:
                del self._pending[key]

    def _verify(self, request, pending):
        if time.monotonic() >= pending.deadline:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        operation = pending.plan.original.operation_id
        self._fresh(request, operation, frozenset({"recovery:view", "recovery:cancel"}), pending.actor)
        if pending.approval is None or pending.approver is None:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        self._fresh(pending.approval_request, operation, frozenset({"recovery:view", "recovery:approve"}), pending.approver)
        if time.monotonic() >= pending.deadline:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)

    @_entry
    def view(self, request, original_operation_id):
        _bounded_text(original_operation_id, "operation_id", 128)
        claim = self._fresh(request, original_operation_id, frozenset({"recovery:view"}))
        current = self._current()
        self._controlled(claim, current.registry)
        original = self._owner.receipt(original_operation_id)
        self._fresh(request, original_operation_id, frozenset({"recovery:view"}), claim)
        return CancellationView(current.revision, original)

    @_entry
    def preview(self, request, original_operation_id):
        _bounded_text(original_operation_id, "operation_id", 128)
        claim = self._fresh(request, original_operation_id, frozenset({"recovery:view", "recovery:cancel"}))
        current = self._current()
        original = self._owner.receipt(original_operation_id)
        candidate = self._owner.cancellation_candidate(original, previous=current.revision)
        self._separated((claim,), current, self._proposal(original))
        self._fresh(request, original_operation_id, frozenset({"recovery:view", "recovery:cancel"}), claim)
        self._expire()
        if len(self._pending) >= MAX_PENDING_CHANGES:
            raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
        operation = "host-cancel:" + uuid.uuid4().hex
        digest = hashlib.sha256(_canonical({"contract_version": 1, "operation_id": operation,
            "previous": current.revision.sha256, "candidate": candidate.revision.sha256,
            "original_operation_id": original_operation_id, "original_revision": original.revision.sha256,
            "actor": claim.fingerprint(), "authority_id": self._authority_id})).hexdigest()
        plan = CancellationPlan(operation, current.revision, original, candidate.revision, digest)
        self._pending[operation] = _Pending(plan, claim, time.monotonic() + self._lifetime)
        return plan

    @_entry
    def approve(self, request, plan):
        pending = self._find(plan)
        operation = plan.original.operation_id
        claim = self._fresh(request, operation, frozenset({"recovery:view", "recovery:approve"}))
        current = self._current()
        if (pending.approval is not None or current.revision != plan.previous
                or claim.principal_id == pending.actor.principal_id or claim.separation_id == pending.actor.separation_id
                or claim.epoch != pending.actor.epoch or claim.authorization_revision != pending.actor.authorization_revision):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        if self._owner.cancellation_candidate(plan.original, previous=plan.previous).revision != plan.candidate:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        self._separated((pending.actor, claim), current, self._proposal(plan.original))
        self._fresh(request, operation, frozenset({"recovery:view", "recovery:approve"}), claim)
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
        if self._owner.cancellation_candidate(plan.original, previous=plan.previous).revision != plan.candidate:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        self._separated((pending.actor, pending.approver), current, self._proposal(plan.original))
        self._verify(request, pending)
        del self._pending[plan.operation_id]

        def attribution(claim):
            return AdministrativeActor(claim.issuer, claim.principal_id, claim.separation_id,
                claim.authorization_revision, claim.epoch, claim.fingerprint())

        intent = CancellationAdministrationIntent(plan.operation_id, plan.digest, plan.previous, plan.candidate,
            plan.original.operation_id, plan.original.revision, attribution(pending.actor), attribution(pending.approver))
        self._journal.append_intent(intent, owner=self._owner)
        self._verify(request, pending)
        receipt = self._owner.stage_cancellation(plan.original, previous=plan.previous, operation_id=plan.operation_id)
        self._verify(request, pending)
        self._owner.advance_witness(receipt)
        self._verify(request, pending)
        result = self._owner.finalize(receipt)
        self._journal.observe(plan.operation_id, owner=self._owner)
        self._verify(request, pending)
        return result
