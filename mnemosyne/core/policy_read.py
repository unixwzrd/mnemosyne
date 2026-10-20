"""Explicit authorized bank-level reads; not store-wide protected activation."""

from __future__ import annotations

import inspect
import sqlite3
from dataclasses import dataclass, field, replace
from functools import wraps
from typing import Callable, FrozenSet, Optional, Union

from mnemosyne.core.policy import (
    AccessContext, AdapterCapabilities, PolicyRefusal, PolicySurface, RefusalReason,
    _labels, _number, _text,
)
from mnemosyne.core.policy_store import (
    PolicyStore, PolicyStoreError, RecordKind, StoreErrorCode, _identity, _source_revision_schema,
)
from mnemosyne.core.policy_projects import PolicyProjects
from mnemosyne.runtime_context import get_access_context


def _guard_policy_output(operation):
    @wraps(operation)
    def guarded(*args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except BaseException as error:
            from .source_expansion import _clear_traceback_frames
            _clear_traceback_frames(error)
            raise
    return guarded


@dataclass(frozen=True, repr=False)
class BankReadGrant:
    """Host-verified bank-wide scope; constructing a grant is not authentication."""

    context_fingerprint: str
    domain_id: str
    bank: str
    destination: str
    decision_id: str
    owners: FrozenSet[str]
    tenants: FrozenSet[str] = frozenset()
    lifecycle_epoch: Optional[int] = field(default=None, kw_only=True)

    def __post_init__(self):
        fingerprint = _text(self.context_fingerprint, "context_fingerprint", 64)
        if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
            raise ValueError("context_fingerprint must be a SHA-256 hex digest")
        for name in ("domain_id", "bank", "destination", "decision_id"):
            _text(getattr(self, name), name)
        for name in ("owners", "tenants"):
            object.__setattr__(self, name, _labels(getattr(self, name), name))
        if self.lifecycle_epoch is not None:
            _number(self.lifecycle_epoch, "lifecycle_epoch", minimum=0)


@dataclass(frozen=True, repr=False)
class ProjectReadGrant(BankReadGrant):
    """Verified exact project selection, not a bank-wide authorization."""

    projects: FrozenSet[str] = frozenset()

    def __post_init__(self):
        super().__post_init__()
        object.__setattr__(self, "projects", _labels(self.projects, "projects"))


@dataclass(frozen=True, repr=False)
class AuthorizedCandidate:
    record_kind: RecordKind
    record_id: Union[str, int]
    bank: str
    binding_id: str
    policy_id: str
    policy_version: int
    classification: str
    decision_id: str
    context_id: str
    context_epoch: int
    lifecycle_epoch: Optional[int] = field(default=None, kw_only=True)


@dataclass(frozen=True, repr=False)
class AuthorizedMemory(AuthorizedCandidate):
    content: str


@dataclass(frozen=True, repr=False)
class AuthorizedSourceRevision(AuthorizedCandidate):
    """Authorized asserted metadata, not verified bytes or an expansion grant."""

    asset_id: str
    content_hash: str
    representation: str
    byte_size: Optional[int]
    digest_status: str


class PolicyReader:
    """Read-only prototype requiring a fresh trusted decision on every call.

    Legacy APIs are deliberately unchanged. The host owns authentication, current
    epochs, participant intersection and binding destinations to actual consumers.
    """

    capabilities = AdapterCapabilities("core-policy-reader", {PolicySurface.DIRECT})

    def __init__(self, store: PolicyStore, *, bank: str, verify_context: Callable):
        if not isinstance(store, PolicyStore):
            raise TypeError("store must be an explicit PolicyStore")
        if not callable(verify_context) or inspect.iscoroutinefunction(verify_context):
            raise TypeError("verify_context must be a synchronous trusted verifier")
        self._store = store
        self._bank = _text(bank, "bank")
        self._verify = verify_context
        self._projects = PolicyProjects(store)

    def _decision(self, destination: str, projects=None) -> tuple[AccessContext, BankReadGrant, Optional[FrozenSet[str]]]:
        destination = _text(destination, "destination")
        context = get_access_context(required=True)
        if (projects is None and context.projects) or context.assurance != "authenticated":
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        selection = None if projects is None else context.narrow(projects=projects).projects
        operation = "read:bank" if selection is None else "read:projects"
        if self._bank not in context.banks or destination not in context.destinations or operation not in context.operations:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        try:
            intent = {} if selection is None else {"projects": selection}
            grant = self._verify(context, bank=self._bank, destination=destination, **intent)
        except PolicyRefusal:
            raise
        except Exception:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None
        if inspect.isawaitable(grant):
            if inspect.iscoroutine(grant):
                grant.close()
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        if not isinstance(grant, BankReadGrant) or (
            grant.context_fingerprint != context.fingerprint()
            or grant.bank != self._bank or grant.destination != destination
        ):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        if selection is None:
            if isinstance(grant, ProjectReadGrant):
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        elif not isinstance(grant, ProjectReadGrant) or grant.projects != selection:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        if sum(map(len, (grant.owners, grant.tenants, context.audiences, context.compartments, selection or ()))) > 900:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        if sqlite3.sqlite_version_info < (3, 35, 0):
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        return context, grant, selection

    def _selection(self, kind, context, grant, record_id=None, projects=None):
        domain = self._store._domain(required=True)
        if domain.domain_id != grant.domain_id:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        lifecycle = ""
        if domain.schema_version == 2:
            from .policy_lifecycle import require_epoch
            require_epoch(self._store.conn, grant.lifecycle_epoch)
            self._release(context, grant, projects, grant.destination)
            lifecycle = "AND NOT EXISTS (SELECT 1 FROM main.policy_quarantine AS q WHERE q.binding_id=b.binding_id)"
        elif grant.lifecycle_epoch is not None:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        definition = self._store._definition(context.policy_id, context.policy_version)
        if definition is None:
            raise PolicyRefusal(RefusalReason.POLICY_MISMATCH)
        definition.validate_context(context)
        params = [kind.value, context.policy_id, context.policy_version,
                  definition.levels.index(context.classification_ceiling)]

        def selected(column, values):
            values = sorted(values)
            params.extend(values)
            return f"{column} IN ({','.join('?' for _ in values)})" if values else "0"

        owner = selected("b.owner", grant.owners)
        tenant = selected("b.tenant_id", grant.tenants)
        audience = selected("t.value", context.audiences)
        compartment = selected("t.value", context.compartments)
        params.append(context.purpose)
        project_filter = ""
        if projects is not None:
            self._projects._domain(required=True)
            self._projects._require_projects(projects)
            membership = selected("m.project_id", projects)
            project_filter = f"""AND EXISTS (SELECT 1 FROM main.policy_project_memberships AS m
                WHERE m.binding_id=b.binding_id AND m.confirmed_by IS NOT NULL AND m.confirmed_at IS NOT NULL
                  AND ({membership}))"""
        target = ""
        if record_id is not None:
            target = "AND b.record_id=?"
            params.append(record_id)
        # Fence the metadata-only authorized relation before joining native content.
        sql = f"""WITH eligible AS MATERIALIZED (
            SELECT b.record_id,b.binding_id,b.policy_id,b.policy_version,b.classification
            FROM main.policy_bindings AS b JOIN main.policy_levels AS l
              ON l.policy_id=b.policy_id AND l.version=b.policy_version AND l.label=b.classification
            WHERE b.record_kind=? AND b.policy_id=? AND b.policy_version=? AND l.rank<=?
              AND ({owner}) AND (b.tenant_id IS NULL OR ({tenant}))
              AND EXISTS (SELECT 1 FROM main.policy_binding_terms AS t
                  WHERE t.binding_id=b.binding_id AND t.dimension='audiences' AND ({audience}))
              AND NOT EXISTS (SELECT 1 FROM main.policy_binding_terms AS t
                  WHERE t.binding_id=b.binding_id AND t.dimension='compartments' AND NOT ({compartment}))
              AND EXISTS (SELECT 1 FROM main.policy_binding_terms AS t
                  WHERE t.binding_id=b.binding_id AND t.dimension='purposes' AND t.value=?)
              AND NOT EXISTS (SELECT 1 FROM main.policy_binding_terms AS t
                  WHERE t.binding_id=b.binding_id AND t.dimension NOT IN ('audiences','compartments','purposes'))
              {project_filter}
              {lifecycle}
              {target}
        )"""
        return sql, params

    def _release(self, context, grant, projects, destination):
        if grant.lifecycle_epoch is not None:
            current, fresh, _ = self._decision(destination, projects)
            if current.fingerprint() != context.fingerprint() or replace(fresh, decision_id=grant.decision_id) != grant:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            return fresh
        return grant

    @_guard_policy_output
    def _read(self, kind, *, destination, record_id=None, limit=100, offset=0, projects=None):
        context, grant, selection = self._decision(destination, projects)
        with self._store._transaction():
            sql, params = self._selection(kind, context, grant, record_id, selection)
            content = ",n.body" if kind is RecordKind.CANONICAL else ",n.content"
            if record_id is None:
                content = ""
            sql += f""" SELECT n.id,e.binding_id,e.policy_id,e.policy_version,e.classification{content}
                FROM eligible AS e JOIN main.{kind.value} AS n
                  ON n.id=e.record_id AND CAST(n.id AS TEXT)=e.record_id
                ORDER BY n.id LIMIT ? OFFSET ?"""
            params.extend((limit, offset))
            rows = self._store.conn.execute(sql, params).fetchall()
            grant = self._release(context, grant, selection, destination)
        result = []
        for row in rows:
            values = (kind, row[0], self._bank, *row[1:5], grant.decision_id, context.context_id, context.epoch)
            result.append(AuthorizedCandidate(*values, lifecycle_epoch=grant.lifecycle_epoch) if record_id is None
                          else AuthorizedMemory(*values, row[5], lifecycle_epoch=grant.lifecycle_epoch))
        return result

    def get(self, kind: RecordKind, record_id, *, destination: str, projects=None) -> Optional[AuthorizedMemory]:
        """Return one authorized record, or None for both absent and denied IDs."""
        identity = _identity(kind, record_id)
        if kind is RecordKind.SOURCE_REVISION:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        records = self._read(kind, destination=destination, record_id=identity, limit=1, projects=projects)
        return records[0] if records else None

    @_guard_policy_output
    def get_source_revision(self, revision_id: str, *, destination: str) -> Optional[AuthorizedSourceRevision]:
        """Read exact source metadata after indexed authorization, without I/O.

        Requires both read:bank and read:source-revision. Source bytes, locators,
        extraction history, project selections and expansion remain unsupported.
        """
        identity = _identity(RecordKind.SOURCE_REVISION, revision_id)
        context = get_access_context(required=True)
        if "read:source-revision" not in context.operations:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        context, grant, _ = self._decision(destination)
        try:
            return self._source_metadata(identity, context, grant)
        except sqlite3.DataError:
            raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE) from None

    def _source_metadata(self, identity, context, grant):
        from mnemosyne.core.media import _revision_text

        with self._store._transaction():
            sql, params = self._selection(RecordKind.SOURCE_REVISION, context, grant, identity)
            if not _source_revision_schema(self._store.conn):
                return None
            # Bound Python result allocation, not SQLite's internal page reads.
            fields = []
            for column, maximum in (("asset_id", 512), ("content_hash", 64),
                                    ("representation", 128), ("digest_status", 64)):
                fields.append(f"CASE WHEN typeof(r.{column})='text' AND length(r.{column}) BETWEEN 1 AND {maximum} "
                              f"AND instr(r.{column},char(0))=0 THEN r.{column} ELSE NULL END")
            sql += f""" SELECT e.binding_id,e.policy_id,e.policy_version,e.classification,
                    {','.join(fields)},CASE WHEN typeof(r.byte_size) IN ('null','integer') THEN r.byte_size ELSE -1 END
                FROM eligible AS e CROSS JOIN main.media_source_revisions AS r
                WHERE r.revision_id COLLATE BINARY=e.record_id COLLATE BINARY
                AND EXISTS (SELECT 1 FROM main.media_assets AS a WHERE a.asset_id COLLATE BINARY=r.asset_id COLLATE BINARY)
                LIMIT 1"""
            row = self._store.conn.execute(sql, params).fetchone()
            grant = self._release(context, grant, None, grant.destination)
        if row is None:
            return None
        try:
            asset = _revision_text(row[4], "asset_id", 512)
            digest = row[5]
            representation = _revision_text(row[6], "representation", 128)
            if (not isinstance(digest, str) or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest) or row[7] != "asserted"
                or (row[8] is not None and (type(row[8]) is not int or not 0 <= row[8] <= 2**63 - 1))):
                raise ValueError("invalid source metadata")
        except (TypeError, ValueError):
            raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE) from None
        return AuthorizedSourceRevision(RecordKind.SOURCE_REVISION, identity, self._bank, *row[:4],
                                        grant.decision_id, context.context_id, context.epoch,
                                        asset, digest, representation, row[8], row[7], lifecycle_epoch=grant.lifecycle_epoch)

    def candidate_ids(self, kind: RecordKind, *, destination: str, limit: int = 100, offset: int = 0, projects=None):
        """List authorized native IDs/provenance without reading native content."""
        if not isinstance(kind, RecordKind):
            raise ValueError("record_kind must be a supported RecordKind")
        if kind is RecordKind.SOURCE_REVISION:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        _number(limit, "limit")
        _number(offset, "offset", minimum=0)
        if limit > 1000:
            raise ValueError("limit must be at most 1000")
        return self._read(kind, destination=destination, limit=limit, offset=offset, projects=projects)
