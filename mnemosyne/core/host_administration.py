"""Scoped profile administration over an explicitly trusted host binding.

This is not an identity provider, grant registry, data-access credential or
model tool. The raw owner authority and authentication callback stay trusted.
"""

from dataclasses import dataclass
from functools import wraps
import hashlib
import inspect
import os
import threading
import time
import uuid

from .host_configuration import (
    ConfigurationRevision, HostConfigurationAuthority, _canonical, _snapshot,
)
from .host_profile import ProfileDefinition, _bounded_text
from .policy import PolicyRefusal, RefusalReason, _number
from .policy_host import _synchronous
from .policy_read import _guard_policy_output
from .snapshot_authority import _store_id


ADMINISTRATIVE_CAPABILITIES = frozenset({
    "profiles:view", "profiles:labels", "profiles:policy", "profiles:approve",
})
MAX_PENDING_CHANGES = 64


@dataclass(frozen=True, repr=False)
class AdministrationSnapshot:
    """Fresh authenticated host claims, never credentials supplied by a model.

    separation_id identifies the canonical independent administrative actor;
    aliases/personas for the same actor must share it. The host is responsible
    for that mapping and for a revision/epoch that never silently goes back.
    """

    issuer: str
    principal_id: str
    separation_id: str
    authority_id: str
    authorization_revision: str
    epoch: int
    profiles: frozenset[str]
    capabilities: frozenset[str]

    def __post_init__(self):
        for name in ("issuer", "principal_id", "separation_id"):
            _bounded_text(getattr(self, name), name, 128)
        _store_id(self.authority_id)
        value = self.authorization_revision
        if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("exact authorization revision required")
        _number(self.epoch, "epoch")
        if type(self.profiles) is not frozenset or not 1 <= len(self.profiles) <= 32:
            raise TypeError("explicit bounded profile scope required")
        for profile in self.profiles:
            _bounded_text(profile, "profile", 128)
        if (type(self.capabilities) is not frozenset or not self.capabilities
                or any(type(value) is not str for value in self.capabilities)
                or not self.capabilities <= ADMINISTRATIVE_CAPABILITIES):
            raise ValueError("explicit supported administrative capabilities required")

    def fingerprint(self):
        return hashlib.sha256(_canonical({
            "issuer": self.issuer, "principal_id": self.principal_id,
            "separation_id": self.separation_id, "authority_id": self.authority_id,
            "authorization_revision": self.authorization_revision, "epoch": self.epoch,
            "profiles": sorted(self.profiles), "capabilities": sorted(self.capabilities),
        })).hexdigest()


@dataclass(frozen=True, repr=False)
class ProfileView:
    revision: ConfigurationRevision
    profile: ProfileDefinition | None


@dataclass(frozen=True, repr=False)
class AdministrationPlan:
    """Process-local preview; only the issuing facade can apply this object."""

    operation_id: str
    previous: ConfigurationRevision
    profile_id: str
    replacement: ProfileDefinition | None
    change_kind: str
    digest: str


@dataclass(frozen=True, repr=False)
class AdministrationApproval:
    """Opaque local approval receipt, not a transferable authorization token."""

    operation_id: str
    plan_digest: str


@dataclass(repr=False)
class _Pending:
    plan: AdministrationPlan
    actor: AdministrationSnapshot
    deadline: float
    approval: AdministrationApproval | None = None
    approver: AdministrationSnapshot | None = None
    approval_request: object = None


def _entry(method):
    @_guard_policy_output
    @wraps(method)
    def call(self, *args, **kwargs):
        if (self._process != os.getpid() or self._thread != threading.get_ident() or self._busy):
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        self._busy = True
        try:
            return method(self, *args, **kwargs)
        except PolicyRefusal:
            raise
        except Exception:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None
        finally:
            self._busy = False
    return call


class ProfileAdministration:
    """Metadata-only facade; authentication must be supplied by a trusted host.

    No principal/grant administration, content reads, activation, recovery,
    arbitrary callbacks in plans or implicit administrative superuser exist.
    Local admission checks are not atomic with an external identity authority.
    """

    def __init__(self, owner, *, authority_id, issuer, authenticate, lifetime_seconds=60):
        if type(owner) is not HostConfigurationAuthority:
            raise TypeError("exact owner authority required")
        _store_id(authority_id)
        _bounded_text(issuer, "issuer", 128)
        _synchronous(authenticate)
        if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 300:
            raise ValueError("bounded preview lifetime required")
        self._owner, self._authority_id = owner, authority_id
        self._issuer, self._authenticate = issuer, authenticate
        self._lifetime = lifetime_seconds
        self._pending = {}
        self._process, self._thread, self._busy = os.getpid(), threading.get_ident(), False

    def _fresh(self, request, *, profile_id, capabilities, expected=None):
        try:
            claim = self._authenticate(request)
            if inspect.iscoroutine(claim) or inspect.isgenerator(claim):
                claim.close()
            if (type(claim) is not AdministrationSnapshot or claim.issuer != self._issuer
                    or claim.authority_id != self._authority_id or profile_id not in claim.profiles
                    or not capabilities <= claim.capabilities or (expected is not None and claim != expected)):
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            return claim
        except PolicyRefusal:
            raise
        except Exception:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None

    def _current(self):
        current = self._owner.current()
        if current.revision.authority_id != self._authority_id:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return current

    def _find(self, plan):
        if type(plan) is not AdministrationPlan:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        pending = self._pending.get(plan.operation_id)
        if pending is None or pending.plan is not plan or time.monotonic() >= pending.deadline:
            self._expire()
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return pending

    def _expire(self):
        now = time.monotonic()
        for key in tuple(self._pending):
            if now >= self._pending[key].deadline:
                del self._pending[key]

    def _verify(self, request, pending):
        self._find(pending.plan)
        self._admit_after_stage(request, pending)

    @_entry
    def view(self, request, profile_id):
        _bounded_text(profile_id, "profile_id", 128)
        claim = self._fresh(request, profile_id=profile_id, capabilities=frozenset({"profiles:view"}))
        current = self._current()
        profile = next((p for p in current.profiles if p.profile_id == profile_id), None)
        self._fresh(request, profile_id=profile_id, capabilities=frozenset({"profiles:view"}), expected=claim)
        return ProfileView(current.revision, profile)

    @_entry
    def preview(self, request, profile_id, replacement):
        _bounded_text(profile_id, "profile_id", 128)
        if replacement is not None and (type(replacement) is not ProfileDefinition or replacement.profile_id != profile_id):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        claim = self._fresh(request, profile_id=profile_id, capabilities=frozenset({"profiles:view"}))
        current = self._current()
        prior = next((p for p in current.profiles if p.profile_id == profile_id), None)
        if replacement == prior or (prior is not None and replacement is not None and replacement.version <= prior.version):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        kind = "labels" if prior is not None and replacement is not None and replacement.policy == prior.policy else "policy"
        profiles = tuple(p for p in current.profiles if p.profile_id != profile_id)
        if replacement is not None:
            profiles += (replacement,)
        candidate = _snapshot(self._authority_id, current.revision.generation + 1, profiles)
        self._fresh(request, profile_id=profile_id,
                    capabilities=frozenset({"profiles:view", "profiles:" + kind}), expected=claim)
        self._expire()
        if len(self._pending) >= MAX_PENDING_CHANGES:
            raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
        operation = "host-admin:" + uuid.uuid4().hex
        digest = hashlib.sha256(_canonical({
            "contract_version": 1, "operation_id": operation,
            "previous": current.revision.sha256, "authority_id": self._authority_id,
            "candidate": candidate.revision.sha256, "actor": claim.fingerprint(),
            "profile_id": profile_id, "change_kind": kind,
        })).hexdigest()
        plan = AdministrationPlan(operation, current.revision, profile_id, replacement, kind, digest)
        self._pending[operation] = _Pending(plan, claim, time.monotonic() + self._lifetime)
        return plan

    @_entry
    def approve(self, request, plan):
        pending = self._find(plan)
        if plan.change_kind != "policy" or pending.approval is not None:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        claim = self._fresh(request, profile_id=plan.profile_id,
                            capabilities=frozenset({"profiles:view", "profiles:approve"}))
        if (claim.principal_id == pending.actor.principal_id
                or claim.separation_id == pending.actor.separation_id
                or claim.epoch != pending.actor.epoch
                or claim.authorization_revision != pending.actor.authorization_revision
                or self._current().revision != plan.previous):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        self._fresh(request, profile_id=plan.profile_id,
                    capabilities=frozenset({"profiles:view", "profiles:approve"}), expected=claim)
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
        if ((plan.change_kind == "policy" and approval is not pending.approval)
                or (plan.change_kind == "labels" and approval is not None)):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        current = self._current()
        if current.revision != plan.previous:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        profiles = tuple(p for p in current.profiles if p.profile_id != plan.profile_id)
        if plan.replacement is not None:
            profiles += (plan.replacement,)
        self._verify(request, pending)
        # Consume before the first write: uncertain writes require owner receipt
        # inspection, never an automatic resend through this facade.
        del self._pending[plan.operation_id]
        receipt = self._owner.stage(profiles, previous=plan.previous, operation_id=plan.operation_id)
        self._admit_after_stage(request, pending)
        self._owner.advance_witness(receipt)
        self._admit_after_stage(request, pending)
        result = self._owner.finalize(receipt)
        self._admit_after_stage(request, pending)
        return result

    def _admit_after_stage(self, request, pending):
        if time.monotonic() >= pending.deadline:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        self._fresh(request, profile_id=pending.plan.profile_id,
                    capabilities=frozenset({"profiles:view", "profiles:" + pending.plan.change_kind}), expected=pending.actor)
        if pending.plan.change_kind == "policy":
            if pending.approval is None or pending.approver is None:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            self._fresh(pending.approval_request, profile_id=pending.plan.profile_id,
                        capabilities=frozenset({"profiles:view", "profiles:approve"}), expected=pending.approver)
