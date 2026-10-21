"""Fresh registry-backed ingress over an explicit trusted authentication hook."""

from dataclasses import dataclass
from functools import wraps
import inspect
import os
import threading
import time

from .host_configuration import HostConfigurationAuthority
from .host_profile import _bounded_text
from .host_registry import GRANT_SET_FIELDS
from .policy import AccessContext, PolicyRefusal, RefusalReason, _number
from .policy_host import HostPolicySnapshot, ParticipantGrant, _synchronous
from .policy_read import _guard_policy_output
from .snapshot_authority import _store_id


MAX_PENDING_REQUESTS = 64


@dataclass(frozen=True, repr=False)
class AuthenticatedAudience:
    """Current host-attested transport facts, never model/tool parameters.

    session_epoch must advance on every relevant transport/audience change,
    including A/B/A changes which restore identical visible participants.
    """

    issuer: str
    subject: str
    platform: str
    conversation_id: str
    route_id: str
    route_revision: int
    session_epoch: int
    participants: tuple[tuple[str, str], ...]

    def __post_init__(self):
        for name in ("issuer", "subject", "platform", "conversation_id", "route_id"):
            _bounded_text(getattr(self, name), name, 128)
        _number(self.route_revision, "route_revision")
        _number(self.session_epoch, "session_epoch")
        if type(self.participants) is not tuple or not 1 <= len(self.participants) <= 256:
            raise ValueError("complete bounded audience required")
        for pair in self.participants:
            if type(pair) is not tuple or len(pair) != 2:
                raise ValueError("exact issuer/subject pairs required")
            for value in pair:
                _bounded_text(value, "participant identity", 128)
        if len(set(self.participants)) != len(self.participants):
            raise ValueError("duplicate audience identity")
        if (self.issuer, self.subject) not in self.participants:
            raise ValueError("authenticated sender must belong to the audience")
        object.__setattr__(self, "participants", tuple(sorted(self.participants)))


class RequestHandle:
    """Object-identity capability admitted only by its issuing local binding."""

    __slots__ = ()


@dataclass(repr=False)
class _PendingRequest:
    request: object
    claim: AuthenticatedAudience
    revision: object
    deadline: float


def _entry(method):
    @_guard_policy_output
    @wraps(method)
    def call(self, *args, **kwargs):
        if self._process != os.getpid() or self._thread != threading.get_ident() or self._busy:
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


def _resolve(configuration, claim):
    registry = configuration.registry
    if registry is None:
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    conversation = next((c for c in registry.conversations if
        (c.issuer, c.platform, c.conversation_id) == (claim.issuer, claim.platform, claim.conversation_id)), None)
    if conversation is None or not conversation.enabled:
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    destination = next(d for d in registry.destinations if d.destination_id == conversation.destination_id)
    if (destination.route_id != claim.route_id or destination.route_revision != claim.route_revision):
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    identities = {(p.issuer, p.subject): p for p in registry.principals}
    participants = []
    for identity in claim.participants:
        principal = identities.get(identity)
        if principal is None or not principal.enabled:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        participants.append(principal.principal_id)
    if frozenset(participants) != conversation.participants:
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    store = next(s for s in registry.stores if s.store_id == conversation.store_id)
    definition = next(p.policy for p in configuration.profiles if p.profile_id == store.profile_id)
    by_principal = {g.principal_id: g for g in registry.grants if g.store_id == store.store_id}
    grants = []
    for principal in sorted(participants):
        grant = by_principal.get(principal)
        if grant is None:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        grants.append(ParticipantGrant(principal, configuration.revision.generation, grant.classification_ceiling,
            banks=frozenset({store.bank}), bank_wide=grant.bank_wide,
            **{name: getattr(grant, name) for name in GRANT_SET_FIELDS}))
    context = AccessContext(context_id=conversation.context_id + ":transport:" + str(claim.session_epoch),
        epoch=configuration.revision.generation,
        policy_id=definition.policy_id, policy_version=definition.version, issuer=claim.issuer,
        platform=claim.platform, principals=frozenset(participants),
        classification_ceiling=conversation.classification_ceiling, purpose=conversation.purpose,
        assurance="authenticated", banks=frozenset({store.bank}), projects=conversation.projects,
        compartments=conversation.compartments, audiences=conversation.audiences,
        operations=conversation.operations, destinations=frozenset({destination.destination_id}),
        channel_id=claim.route_id, conversation_id=claim.conversation_id)
    snapshot = HostPolicySnapshot(context, definition, tuple(grants), store.store_id,
        store.domain_id, store.bank, destination.destination_id, store.lifecycle_epoch)
    snapshot.effective()
    return snapshot


class LocalRequestBinding:
    """Registry-backed load_snapshot callback; not an actual transport login.

    Authentication, complete audience attestation, session-epoch changes and
    owner-tool isolation are trusted host responsibilities. No callback can be
    imported from registry data. Nothing activates a legacy endpoint.
    """

    def __init__(self, owner, *, authority_id, issuer, authenticate, lifetime_seconds=900):
        if type(owner) is not HostConfigurationAuthority:
            raise TypeError("exact owner authority required")
        _store_id(authority_id)
        _bounded_text(issuer, "issuer", 128)
        _synchronous(authenticate)
        if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 3600:
            raise ValueError("request lifetime must be 1..3600 seconds")
        self._owner, self._authority_id = owner, authority_id
        self._issuer, self._authenticate = issuer, authenticate
        self._lifetime, self._pending = lifetime_seconds, {}
        self._process, self._thread, self._busy = os.getpid(), threading.get_ident(), False

    def _authenticate_current(self, request):
        claim = self._authenticate(request)
        if inspect.iscoroutine(claim) or inspect.isgenerator(claim):
            claim.close()
        if type(claim) is not AuthenticatedAudience or claim.issuer != self._issuer:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return claim

    def _current(self):
        snapshot = self._owner.current()
        if snapshot.revision.authority_id != self._authority_id:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return snapshot

    def _expire(self):
        now = time.monotonic()
        for handle in tuple(self._pending):
            if now >= self._pending[handle].deadline:
                del self._pending[handle]

    @_entry
    def admit(self, authenticated_request):
        self._expire()
        if len(self._pending) >= MAX_PENDING_REQUESTS:
            raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
        deadline = time.monotonic() + self._lifetime
        claim = self._authenticate_current(authenticated_request)
        current = self._current()
        _resolve(current, claim)
        if (self._authenticate_current(authenticated_request) != claim
                or self._current().revision != current.revision or time.monotonic() >= deadline):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        handle = RequestHandle()
        self._pending[handle] = _PendingRequest(authenticated_request, claim, current.revision, deadline)
        return handle

    @_entry
    def load_snapshot(self, handle):
        self._expire()
        if type(handle) is not RequestHandle or handle not in self._pending:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        pending = self._pending[handle]
        try:
            claim = self._authenticate_current(pending.request)
            current = self._current()
            if claim != pending.claim or current.revision != pending.revision:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            snapshot = _resolve(current, claim)
            if (self._authenticate_current(pending.request) != claim
                    or self._current().revision != pending.revision or time.monotonic() >= pending.deadline):
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            return snapshot
        except BaseException:
            del self._pending[handle]
            raise

    @_entry
    def close(self, handle):
        if type(handle) is not RequestHandle:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        self._pending.pop(handle, None)
