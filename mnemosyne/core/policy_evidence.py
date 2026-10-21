"""Payload-free evidence references; reuse always reloads authorized native data."""

from dataclasses import asdict, dataclass
import hashlib
import inspect
import json

from .policy import PolicyRefusal, RefusalReason, _number, _text
from .policy_read import PolicyReader, _guard_policy_output
from .policy_store import RecordKind, _identity


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _sha256(value):
    if type(value) is not str or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("expected a SHA-256 hex digest")


def _scope(context, grant, selection):
    return _digest([1, context.fingerprint(), grant.domain_id, grant.bank, grant.destination,
        sorted(grant.owners), sorted(grant.tenants), None if selection is None else sorted(selection), grant.lifecycle_epoch])


def _value(hit):
    value = asdict(hit)
    # A new decision is required on reuse; it must not change the value identity.
    value.pop("decision_id")
    value["record_kind"] = hit.record_kind.value
    return _digest(value)


def _require_consumer(consumer):
    deferred = (inspect.iscoroutinefunction, inspect.isasyncgenfunction, inspect.isgeneratorfunction)
    if not callable(consumer) or any(check(target) for check in deferred
        for target in (consumer, getattr(consumer, "__call__", None))):
        raise TypeError("consumer must be synchronous and return None")


def _consume(consumer, value):
    result = consumer(value)
    if result is not None:
        if inspect.iscoroutine(result) or inspect.isgenerator(result):
            result.close()
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)


@dataclass(frozen=True, repr=False)
class EvidenceLease:
    """Sensitive metadata, not a bearer credential or authorization decision."""

    record_kind: RecordKind
    record_id: str | int
    binding_id: str
    bank: str
    destination: str
    projects: frozenset[str] | None
    lifecycle_epoch: int
    scope_fingerprint: str
    value_fingerprint: str

    def __post_init__(self):
        _identity(self.record_kind, self.record_id)
        for name in ("binding_id", "bank", "destination"):
            _text(getattr(self, name), name)
        if self.projects is not None:
            from .policy import _labels
            object.__setattr__(self, "projects", _labels(self.projects, "projects"))
        _number(self.lifecycle_epoch, "lifecycle_epoch", minimum=0)
        _sha256(self.scope_fingerprint)
        _sha256(self.value_fingerprint)


@dataclass(frozen=True, repr=False)
class EvidenceDeliveryReceipt:
    """Sensitive completion metadata; neither a payload nor a bearer grant."""

    lease: EvidenceLease
    decision_id: str
    context_id: str
    context_epoch: int

    def __post_init__(self):
        if type(self.lease) is not EvidenceLease:
            raise TypeError("lease must be an EvidenceLease")
        _text(self.decision_id, "decision_id")
        _text(self.context_id, "context_id")
        _number(self.context_epoch, "context_epoch", minimum=0)


class PolicyEvidence:
    """Explicit v2 lease/reload boundary; no cached payloads or provider calls."""

    def __init__(self, reader):
        if not isinstance(reader, PolicyReader):
            raise TypeError("reader must be an explicit PolicyReader")
        self.reader = reader

    def issue(self, kind, record_id, *, destination, projects=None):
        _identity(kind, record_id)
        return self._read(kind, record_id, destination=destination, projects=projects, lease=None)

    def resolve(self, lease):
        if type(lease) is not EvidenceLease:
            raise TypeError("lease must be an EvidenceLease")
        return self._read(lease.record_kind, lease.record_id, destination=lease.destination, projects=lease.projects, lease=lease)

    @_guard_policy_output
    def deliver(self, lease, consumer):
        """Freshly resolve immediately before one trusted synchronous consumer.

        No retries or atomic external-delivery promise. A callback that fails or
        returns deferred work may already have had effects; never blindly resend.
        """
        _require_consumer(consumer)
        hit = self.resolve(lease)
        receipt = EvidenceDeliveryReceipt(lease, hit.decision_id, hit.context_id, hit.context_epoch)
        _consume(consumer, hit)
        return receipt

    async def stream(self, leases, producer, consumer, *, limits=None):
        """Cooperative bounded streaming; actual transports need qualification."""
        from .policy_stream import stream_evidence
        try:
            return await stream_evidence(self, leases, producer, consumer, limits=limits)
        except BaseException as error:
            from .source_expansion import _clear_traceback_frames
            _clear_traceback_frames(error)
            raise

    @_guard_policy_output
    def _read(self, kind, record_id, *, destination, projects, lease):
        store = self.reader._store
        if store.conn.in_transaction:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        context, grant, selection = self.reader._decision(destination, projects)
        if grant.lifecycle_epoch is None:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        scope = _scope(context, grant, selection)
        if lease is not None and (lease.bank != self.reader._bank or lease.scope_fingerprint != scope
                                  or lease.lifecycle_epoch != grant.lifecycle_epoch):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)

        def verify(current, **intent):
            fresh_context, fresh, fresh_selection = self.reader._decision(destination, projects)
            if _scope(fresh_context, fresh, fresh_selection) != scope:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            return fresh

        pinned = PolicyReader(store, bank=self.reader._bank, verify_context=verify)
        with store._transaction():
            if kind is RecordKind.SOURCE_REVISION:
                if selection is not None:
                    raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
                hit = pinned.get_source_revision(record_id, destination=destination)
            else:
                hit = pinned.get(kind, record_id, destination=destination, projects=projects)
            if hit is None:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            value = _value(hit)
            if lease is not None and (hit.binding_id != lease.binding_id or value != lease.value_fingerprint):
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            _, final, _ = pinned._decision(destination, projects)
        if lease is None:
            return EvidenceLease(kind, record_id, hit.binding_id, hit.bank, destination, selection,
                grant.lifecycle_epoch, scope, value)
        from dataclasses import replace
        return replace(hit, decision_id=final.decision_id)
