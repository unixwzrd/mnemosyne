"""Explicit authenticated-host contract; no identity from model arguments."""

from contextlib import contextmanager
from dataclasses import dataclass, replace
import inspect
import uuid

from .policy import (
    AccessContext,
    PolicyDefinition,
    PolicyRefusal,
    PolicySurface,
    RefusalReason,
    _labels,
    _number,
    _text,
)
from .policy_evidence import _consume, _require_consumer
from .policy_read import BankReadGrant, ProjectReadGrant, _guard_policy_output
from .policy_store import RecordKind
from .protected_session import ProtectedSession
from ..runtime_context import bind_access_context


@dataclass(frozen=True, repr=False)
class ParticipantGrant:
    """One claim in an atomic current host snapshot, not a credential."""

    principal_id: str
    authority_epoch: int
    classification_ceiling: str
    banks: frozenset[str] = frozenset()
    projects: frozenset[str] = frozenset()
    owners: frozenset[str] = frozenset()
    tenants: frozenset[str] = frozenset()
    compartments: frozenset[str] = frozenset()
    audiences: frozenset[str] = frozenset()
    purposes: frozenset[str] = frozenset()
    operations: frozenset[str] = frozenset()
    destinations: frozenset[str] = frozenset()
    bank_wide: bool = False

    def __post_init__(self):
        _text(self.principal_id, "principal_id")
        _number(self.authority_epoch, "authority_epoch", minimum=0)
        _text(self.classification_ceiling, "classification_ceiling", 64)
        for name in (
            "banks",
            "projects",
            "owners",
            "tenants",
            "compartments",
            "audiences",
            "purposes",
            "operations",
            "destinations",
        ):
            object.__setattr__(self, name, _labels(getattr(self, name), name))
        if type(self.bank_wide) is not bool:
            raise TypeError("explicit bank-wide permission required")


@dataclass(frozen=True, repr=False)
class HostPolicySnapshot:
    """Complete current roster/permissions resolved atomically by the host.

    The host authenticates the request and guarantees epoch freshness. None of
    these fields may be copied from tool arguments, titles or model claims.
    """

    context: AccessContext
    definition: PolicyDefinition
    grants: tuple[ParticipantGrant, ...]
    store_id: str
    domain_id: str
    bank: str
    destination: str
    lifecycle_epoch: int

    def __post_init__(self):
        if (
            type(self.context) is not AccessContext
            or type(self.definition) is not PolicyDefinition
        ):
            raise TypeError("exact host context and policy definition required")
        if (
            type(self.grants) not in (tuple, list)
            or not 1 <= len(self.grants) <= 256
            or any(type(g) is not ParticipantGrant for g in self.grants)
        ):
            raise TypeError("complete bounded participant grants required")
        object.__setattr__(self, "grants", tuple(self.grants))
        if (
            type(self.store_id) is not str
            or len(self.store_id) != 32
            or any(c not in "0123456789abcdef" for c in self.store_id)
        ):
            raise ValueError("explicit host store identity required")
        for name in ("domain_id", "bank", "destination"):
            _text(getattr(self, name), name)
        _number(self.lifecycle_epoch, "lifecycle_epoch", minimum=0)

    def effective(self):
        ctx, grants, definition = self.context, self.grants, self.definition
        definition.validate_context(ctx)
        if (
            ctx.assurance != "authenticated"
            or len({g.principal_id for g in grants}) != len(grants)
            or {g.principal_id for g in grants} != ctx.principals
            or any(g.authority_epoch != ctx.epoch for g in grants)
        ):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        try:
            ceiling = min(
                [
                    definition.levels.index(ctx.classification_ceiling),
                    *(
                        definition.levels.index(g.classification_ceiling)
                        for g in grants
                    ),
                ]
            )
        except ValueError:
            raise PolicyRefusal(RefusalReason.POLICY_MISMATCH) from None

        def common(name):
            return frozenset.intersection(*(getattr(g, name) for g in grants))

        if (
            self.bank not in ctx.banks
            or self.bank not in common("banks")
            or self.destination not in ctx.destinations
            or self.destination not in common("destinations")
            or ctx.purpose not in common("purposes")
        ):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        if ctx.projects:
            if not ctx.projects <= common("projects"):
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            required = "read:projects"
        else:
            if not all(g.bank_wide for g in grants):
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            required = "read:bank"
        operations = ctx.operations & common("operations")
        if required not in operations:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        effective = replace(
            ctx,
            classification_ceiling=definition.levels[ceiling],
            banks=frozenset({self.bank}),
            destinations=frozenset({self.destination}),
            compartments=ctx.compartments & common("compartments"),
            audiences=ctx.audiences & common("audiences"),
            operations=operations,
        )
        return effective, common("owners"), common("tenants")


def _synchronous(callback):
    if not callable(callback) or any(
        check(target)
        for target in (callback, getattr(callback, "__call__", None))
        for check in (
            inspect.iscoroutinefunction,
            inspect.isasyncgenfunction,
            inspect.isgeneratorfunction,
        )
    ):
        raise TypeError("explicit synchronous trusted host callback required")


class _HostBinding:
    def __init__(self, load, request, expected_issuer):
        self._load, self._request, self._issuer = load, request, expected_issuer
        self.snapshot = self._fresh()
        self.context, self._owners, self._tenants = self.snapshot.effective()

    def _fresh(self):
        try:
            snapshot = self._load(self._request)
        except PolicyRefusal:
            raise
        except Exception:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None
        if inspect.iscoroutine(snapshot) or inspect.isgenerator(snapshot):
            snapshot.close()
        if (
            type(snapshot) is not HostPolicySnapshot
            or snapshot.context.issuer != self._issuer
        ):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return snapshot

    def verify(self, context, *, bank, destination, projects=None):
        fresh = self._fresh()
        effective, owners, tenants = fresh.effective()
        if (
            fresh != self.snapshot
            or effective.fingerprint() != context.fingerprint()
            or context.fingerprint() != self.context.fingerprint()
            or bank != fresh.bank
            or destination != fresh.destination
        ):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        values = dict(
            context_fingerprint=context.fingerprint(),
            domain_id=fresh.domain_id,
            bank=bank,
            destination=destination,
            decision_id="decision:" + uuid.uuid4().hex,
            owners=owners,
            tenants=tenants,
            lifecycle_epoch=fresh.lifecycle_epoch,
        )
        if effective.projects:
            if projects != effective.projects:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            return ProjectReadGrant(**values, projects=effective.projects)
        if projects is not None:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return BankReadGrant(**values)


class ProtectedHostAdapter:
    """Reference host bridge; installing legacy adapters does not enable this.

    load_snapshot authenticates an opaque transport request and returns atomic
    current claims. resolve_store maps only its trusted store identity to owner
    repository/audit capabilities. Neither callback is a model tool argument.
    """

    def __init__(self, *, adapter_id, issuer, load_snapshot, resolve_store):
        self.adapter_id = _text(adapter_id, "adapter_id")
        self._issuer = _text(issuer, "issuer")
        _synchronous(load_snapshot)
        _synchronous(resolve_store)
        self._load, self._resolve = load_snapshot, resolve_store

    @contextmanager
    def session(self, authenticated_request):
        binding = _HostBinding(self._load, authenticated_request, self._issuer)
        snapshot = binding.snapshot
        with bind_access_context(binding.context):
            try:
                resolved = self._resolve(snapshot.store_id)
            except PolicyRefusal:
                raise
            except Exception:
                raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None
            if type(resolved) is not tuple or len(resolved) != 2:
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            repository, audit = resolved
            with ProtectedSession(
                repository,
                snapshot.store_id,
                destination=snapshot.destination,
                verify_context=binding.verify,
                audit=audit,
                projects=binding.context.projects or None,
            ) as memory:
                yield memory

    @_guard_policy_output
    def invoke(self, authenticated_request, operation, arguments, consumer):
        _require_consumer(consumer)
        if (
            type(arguments) is not dict
            or len(arguments) > 16
            or any(type(key) is not str for key in arguments)
        ):
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        # Scoping is always host-resolved, not a frontend/model parameter.
        if set(arguments) & {
            "context",
            "bank",
            "destination",
            "projects",
            "store_id",
            "key",
            "profile",
            "consumer",
            "producer",
            "count_tokens",
            "verify_context",
            "audit",
            "repository",
        }:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        arguments = dict(arguments)
        if "kind" in arguments:
            try:
                arguments["kind"] = RecordKind(arguments["kind"])
            except (TypeError, ValueError):
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE) from None
        with self.session(authenticated_request) as memory:
            if type(operation) is not str or operation not in {
                "get",
                "candidates",
                "source_metadata",
                "lexical",
                "vector",
                "hybrid",
                "issue",
                "resolve",
            }:
                memory.dispatch("frontend-unsupported")
            context, grant, selection = memory._reader._decision(
                memory._destination, memory._projects
            )
            result = memory.dispatch(operation, **arguments)
            memory._admit("deliver", PolicySurface.INJECT)
            memory._reader._release(context, grant, selection, memory._destination)
            _consume(consumer, result)
