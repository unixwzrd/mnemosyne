"""Optional owner-maintained project relevance, not authentication or activation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from mnemosyne.core.policy import PolicyRefusal, RefusalReason, _text
from mnemosyne.core.policy_store import PolicyStore, PolicyStoreError, RecordKind, StoreErrorCode, _identity


PROJECT_SCHEMA_VERSION = 1
_SCHEMA = {
    "policy_project_state": (("singleton", "INTEGER", 0, 1), ("schema_version", "INTEGER", 1, 0), ("domain_id", "TEXT", 1, 0)),
    "policy_projects": (("project_id", "TEXT", 1, 1), ("registered_by", "TEXT", 1, 0), ("registered_at", "TEXT", 1, 0)),
    "policy_project_memberships": (
        ("binding_id", "TEXT", 1, 1), ("project_id", "TEXT", 1, 2), ("origin", "TEXT", 1, 0),
        ("assigned_by", "TEXT", 1, 0), ("assigned_at", "TEXT", 1, 0),
        ("confirmed_by", "TEXT", 0, 0), ("confirmed_at", "TEXT", 0, 0),
    ),
}


@dataclass(frozen=True, repr=False)
class PreparedProjects:
    domain_id: str
    schema_version: int = PROJECT_SCHEMA_VERSION


@dataclass(frozen=True, repr=False)
class ProjectMembership:
    binding_id: str
    project_id: str
    origin: str
    assigned_by: str
    assigned_at: str
    confirmed_by: Optional[str]
    confirmed_at: Optional[str]

    @property
    def state(self):
        return "proposed" if self.confirmed_by is None else "confirmed"


class PolicyProjects:
    """Explicit optional catalog; all administrative methods are owner-mode."""

    def __init__(self, store: PolicyStore):
        if not isinstance(store, PolicyStore):
            raise TypeError("store must be an explicit PolicyStore")
        self._store = store
        self._conn = store.conn

    def _domain(self, *, required=False):
        domain = self._store._domain(required=required)
        names = {r[0] for r in self._conn.execute(
            "SELECT name FROM main.sqlite_master WHERE type='table' AND name IN (?,?,?)", tuple(_SCHEMA),
        )}
        if not names:
            if required:
                raise PolicyStoreError(StoreErrorCode.UNPREPARED)
            return None
        if domain is None or names != set(_SCHEMA):
            raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
        for table, expected in _SCHEMA.items():
            actual = tuple((r[1], r[2].upper(), r[3], r[5]) for r in self._conn.execute(f"PRAGMA main.table_info('{table}')"))
            if actual != expected:
                raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
        indexes = self._conn.execute("PRAGMA main.index_list('policy_project_memberships')").fetchall()
        found = next((r for r in indexes if r[1] == "idx_policy_project_selection"), None)
        columns = tuple(r[2] for r in self._conn.execute("PRAGMA main.index_info('idx_policy_project_selection')"))
        if found is None or found[2] or found[4] or columns != ("project_id", "confirmed_by", "binding_id"):
            raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
        rows = self._conn.execute("SELECT singleton,schema_version,domain_id FROM main.policy_project_state LIMIT 2").fetchall()
        if len(rows) != 1 or tuple(rows[0]) != (1, PROJECT_SCHEMA_VERSION, domain.domain_id):
            raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
        return PreparedProjects(domain.domain_id)

    def get_domain(self):
        with self._store._transaction():
            return self._domain()

    def prepare(self):
        with self._store._transaction(write=True):
            domain = self._store._domain(required=True)
            existing = self._domain()
            if existing is not None:
                return existing
            statements = (
                "CREATE TABLE main.policy_project_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL, domain_id TEXT NOT NULL)",
                "CREATE TABLE main.policy_projects(project_id TEXT NOT NULL PRIMARY KEY, registered_by TEXT NOT NULL, "
                "registered_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')))",
                "CREATE TABLE main.policy_project_memberships(binding_id TEXT NOT NULL, project_id TEXT NOT NULL, origin TEXT NOT NULL, "
                "assigned_by TEXT NOT NULL, assigned_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), "
                "confirmed_by TEXT, confirmed_at TEXT, PRIMARY KEY(binding_id,project_id), CHECK((confirmed_by IS NULL)=(confirmed_at IS NULL)))",
                "CREATE INDEX main.idx_policy_project_selection ON policy_project_memberships(project_id,confirmed_by,binding_id)",
            )
            for sql in statements:
                self._conn.execute(sql)
            self._conn.execute("INSERT INTO main.policy_project_state VALUES(1,?,?)", (PROJECT_SCHEMA_VERSION, domain.domain_id))
            return self._domain(required=True)

    def register(self, project_id: str, *, actor: str):
        project_id, actor = _text(project_id, "project_id"), _text(actor, "actor")
        with self._store._transaction(write=True):
            self._domain(required=True)
            row = self._conn.execute("SELECT registered_by FROM main.policy_projects WHERE project_id=?", (project_id,)).fetchone()
            if row is not None:
                if row[0] != actor:
                    raise ValueError("project registration provenance conflicts")
                return "unchanged"
            self._conn.execute("INSERT INTO main.policy_projects(project_id,registered_by) VALUES(?,?)", (project_id, actor))
            return "created"

    def _require_projects(self, projects):
        if not projects:
            return
        known = {r[0] for r in self._conn.execute(
            f"SELECT project_id FROM main.policy_projects WHERE project_id IN ({','.join('?' for _ in projects)})", sorted(projects),
        )}
        if known != set(projects):
            raise PolicyRefusal(RefusalReason.INVALID_SELECTION)

    def _binding(self, kind, identity, *, parent=False):
        if kind is RecordKind.SOURCE_REVISION:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        domain = self._store._domain(required=True)
        binding = self._store._binding(kind, identity, domain)
        if binding is None:
            raise ValueError("policy binding is required for project membership")
        if parent and self._conn.execute(
            f"SELECT 1 FROM main.{kind.value} WHERE id=? AND CAST(id AS TEXT)=?", (identity, identity),
        ).fetchone() is None:
            raise ValueError("native parent must exist for project assignment")
        return binding.binding_id

    def _membership(self, binding_id, project_id):
        row = self._conn.execute("""SELECT binding_id,project_id,origin,assigned_by,assigned_at,confirmed_by,confirmed_at
            FROM main.policy_project_memberships WHERE binding_id=? AND project_id=?""", (binding_id, project_id)).fetchone()
        if row is None:
            return None
        try:
            for name, value in zip(("binding_id", "project_id", "origin", "assigned_by", "assigned_at"), row[:5]):
                _text(value, name)
            if (row[5] is None) != (row[6] is None):
                raise ValueError("incomplete confirmation")
            if row[5] is not None:
                _text(row[5], "confirmed_by")
                _text(row[6], "confirmed_at")
        except ValueError:
            raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE) from None
        return ProjectMembership(*row)

    def get_membership(self, kind: RecordKind, record_id, project_id: str):
        identity, project_id = _identity(kind, record_id), _text(project_id, "project_id")
        if kind is RecordKind.SOURCE_REVISION:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        with self._store._transaction():
            if self._domain() is None:
                return None
            binding = self._store._binding(kind, identity, self._store._domain(required=True))
            return None if binding is None else self._membership(binding.binding_id, project_id)

    def propose(self, kind: RecordKind, record_id, project_id: str, *, origin: str, actor: str):
        identity, project_id = _identity(kind, record_id), _text(project_id, "project_id")
        origin, actor = _text(origin, "origin"), _text(actor, "actor")
        with self._store._transaction(write=True):
            self._domain(required=True)
            self._require_projects({project_id})
            binding_id = self._binding(kind, identity, parent=True)
            existing = self._membership(binding_id, project_id)
            if existing is not None:
                if (existing.origin, existing.assigned_by) != (origin, actor):
                    raise ValueError("membership proposal provenance conflicts")
                return "unchanged"
            count = self._conn.execute("SELECT COUNT(*) FROM main.policy_project_memberships WHERE binding_id=?", (binding_id,)).fetchone()[0]
            if count >= 256:
                raise ValueError("membership limit reached")
            self._conn.execute("INSERT INTO main.policy_project_memberships(binding_id,project_id,origin,assigned_by) VALUES(?,?,?,?)",
                               (binding_id, project_id, origin, actor))
            return "created"

    def confirm(self, kind: RecordKind, record_id, project_id: str, *, actor: str):
        identity, project_id = _identity(kind, record_id), _text(project_id, "project_id")
        actor = _text(actor, "actor")
        with self._store._transaction(write=True):
            self._domain(required=True)
            self._require_projects({project_id})
            binding_id = self._binding(kind, identity, parent=True)
            existing = self._membership(binding_id, project_id)
            if existing is None:
                raise ValueError("proposal required before confirmation")
            if existing.confirmed_by is not None:
                if existing.confirmed_by != actor:
                    raise ValueError("membership confirmation provenance conflicts")
                return "unchanged"
            self._conn.execute("""UPDATE main.policy_project_memberships
                SET confirmed_by=?,confirmed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE binding_id=? AND project_id=?""",
                               (actor, binding_id, project_id))
            return "confirmed"
