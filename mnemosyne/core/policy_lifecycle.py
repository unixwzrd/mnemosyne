"""Explicit owner lineage/quarantine; no legacy activation or raw-data archive."""

from dataclasses import dataclass
from enum import Enum
import hashlib
import json

from .policy import PolicyRefusal, RefusalReason, _number
from .policy_store import PolicyStore, PolicyStoreError, RecordKind, StoreErrorCode, _binding_id, _identity


LIFECYCLE_SCHEMA_VERSION = 2
MAX_DERIVATIVES = 4096
_DDL = {
    "policy_lifecycle_state": "CREATE TABLE policy_lifecycle_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), epoch INTEGER NOT NULL CHECK(epoch>=0))",
    "policy_lineage": "CREATE TABLE policy_lineage (binding_id TEXT PRIMARY KEY, parent_count INTEGER NOT NULL, receipt_digest TEXT NOT NULL)",
    "policy_lineage_edges": "CREATE TABLE policy_lineage_edges (child_binding_id TEXT NOT NULL, parent_binding_id TEXT NOT NULL, parent_digest TEXT NOT NULL, PRIMARY KEY(child_binding_id,parent_binding_id))",
    "policy_quarantine": "CREATE TABLE policy_quarantine (binding_id TEXT PRIMARY KEY, reason TEXT NOT NULL, epoch INTEGER NOT NULL)",
    "idx_policy_lineage_parent": "CREATE INDEX idx_policy_lineage_parent ON policy_lineage_edges (parent_binding_id,child_binding_id)",
}


def _present(conn):
    return bool(conn.execute("SELECT 1 FROM main.sqlite_master WHERE name IN (?,?,?,?,?) LIMIT 1", tuple(_DDL)).fetchone())


def _require_schema(conn):
    rows = conn.execute("SELECT name,sql FROM main.sqlite_master WHERE name IN (?,?,?,?,?)", tuple(_DDL)).fetchall()
    normalize = lambda sql: "".join(sql.split()).lower() if type(sql) is str else None
    if len(rows) != len(_DDL) or any(normalize(sql) != normalize(_DDL[name]) for name, sql in rows):
        raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
    rows = conn.execute("SELECT singleton,epoch FROM main.policy_lifecycle_state LIMIT 2").fetchall()
    if len(rows) != 1 or type(rows[0][0]) is not int or rows[0][0] != 1:
        raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
    try:
        return _number(rows[0][1], "lifecycle_epoch", minimum=0)
    except ValueError:
        raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE) from None


def require_epoch(conn, epoch):
    if type(epoch) is not int or epoch != _require_schema(conn):
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)


@dataclass(frozen=True, repr=False)
class PolicyRecordRef:
    record_kind: RecordKind
    record_id: str | int

    def __post_init__(self):
        _identity(self.record_kind, self.record_id)


class QuarantineReason(str, Enum):
    REVOKED = "revoked"
    CORRECTED = "corrected"
    DELETED = "deleted"


@dataclass(frozen=True, repr=False)
class LifecycleReceipt:
    epoch: int
    status: str
    transaction_state: str


def _digest(policy):
    from .policy_derivation import _policy_payload
    return hashlib.sha256(json.dumps(_policy_payload(policy), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class PolicyLifecycle:
    """Trusted owner operations; never infer identity or authorization from inputs."""

    def __init__(self, store):
        if not isinstance(store, PolicyStore):
            raise TypeError("store must be an explicit PolicyStore")
        self.store = store

    def prepare(self):
        conn = self.store.conn
        pending = conn.in_transaction
        with self.store._transaction(write=True):
            domain = self.store._domain(required=True)
            if domain.schema_version == LIFECYCLE_SCHEMA_VERSION:
                return LifecycleReceipt(_require_schema(conn), "unchanged", "pending" if pending else "committed")
            for name, ddl in _DDL.items():
                prefix = "CREATE INDEX " if ddl.startswith("CREATE INDEX ") else "CREATE TABLE "
                conn.execute(ddl.replace(prefix, prefix + "main.", 1))
            conn.execute("INSERT INTO main.policy_lifecycle_state VALUES (1,0)")
            conn.execute("UPDATE main.policy_store_state SET schema_version=? WHERE singleton=1", (LIFECYCLE_SCHEMA_VERSION,))
            self.store._domain(required=True)
        return LifecycleReceipt(0, "created", "pending" if pending else "committed")

    def _domain(self):
        domain = self.store._domain(required=True)
        if domain.schema_version != LIFECYCLE_SCHEMA_VERSION:
            raise PolicyStoreError(StoreErrorCode.UNPREPARED)
        return domain

    def epoch(self):
        with self.store._transaction():
            self._domain()
            return _require_schema(self.store.conn)

    def _bound(self, reference, domain, *, active=False):
        if not isinstance(reference, PolicyRecordRef):
            raise TypeError("record must be an explicit PolicyRecordRef")
        binding = self.store._binding(reference.record_kind, _identity(reference.record_kind, reference.record_id), domain)
        if binding is None or (active and self.store.conn.execute("SELECT 1 FROM main.policy_quarantine WHERE binding_id=?", (binding.binding_id,)).fetchone()):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        if active:
            column = "revision_id" if reference.record_kind is RecordKind.SOURCE_REVISION else "id"
            row = self.store.conn.execute(f"SELECT 1 FROM main.{reference.record_kind.value} WHERE CAST({column} AS TEXT)=? LIMIT 1",
                (_identity(reference.record_kind, reference.record_id),)).fetchone()
            if row is None:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return binding

    def bind_derivative(self, child, parents):
        from .policy_derivation import PolicyParent, derive_memory_policy
        if not isinstance(child, PolicyRecordRef):
            raise TypeError("child must be an explicit PolicyRecordRef")
        if type(parents) not in (tuple, list) or not 1 <= len(parents) <= 128 or any(not isinstance(p, PolicyRecordRef) for p in parents):
            raise ValueError("parents must contain 1..128 explicit PolicyRecordRef records")
        parents = tuple(parents)
        if len(set(parents)) != len(parents) or child in parents:
            raise ValueError("parents must be unique and exclude the child")
        conn = self.store.conn
        pending = conn.in_transaction
        with self.store._transaction(write=True):
            domain = self._domain()
            bindings = [self._bound(parent, domain, active=True) for parent in parents]
            definition = self.store._definition(bindings[0].policy.policy_id, bindings[0].policy.policy_version)
            if definition is None:
                raise PolicyRefusal(RefusalReason.POLICY_MISMATCH)
            receipt = derive_memory_policy(definition, [PolicyParent(b.binding_id, b.policy) for b in bindings])
            child_id = _identity(child.record_kind, child.record_id)
            binding_id = _binding_id(domain.domain_id, child.record_kind, child_id)
            if conn.execute("SELECT 1 FROM main.policy_quarantine WHERE binding_id=?", (binding_id,)).fetchone():
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            existing = conn.execute("SELECT parent_count,receipt_digest FROM main.policy_lineage WHERE binding_id=?", (binding_id,)).fetchone()
            edges = tuple(sorted((b.binding_id, _digest(b.policy)) for b in bindings))
            if existing is not None:
                stored = conn.execute("SELECT parent_binding_id,parent_digest FROM main.policy_lineage_edges WHERE child_binding_id=? ORDER BY parent_binding_id", (binding_id,)).fetchall()
                binding = self.store._binding(child.record_kind, child_id, domain)
                if tuple(existing) != (len(parents), receipt.fingerprint()) or tuple(map(tuple, stored)) != edges or binding is None or binding.policy != receipt.policy:
                    raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
                status = "unchanged"
            else:
                if self.store._binding(child.record_kind, child_id, domain) is not None:
                    raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
                if conn.execute("SELECT count(*) FROM main.policy_lineage").fetchone()[0] >= MAX_DERIVATIVES:
                    raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
                self.store.bind(child.record_kind, child.record_id, receipt.policy)
                conn.execute("INSERT INTO main.policy_lineage VALUES (?,?,?)", (binding_id, len(parents), receipt.fingerprint()))
                conn.executemany("INSERT INTO main.policy_lineage_edges VALUES (?,?,?)", [(binding_id, parent, digest) for parent, digest in edges])
                status = "created"
            epoch = _require_schema(conn)
        return LifecycleReceipt(epoch, status, "pending" if pending else "committed")

    def quarantine(self, record, reason=QuarantineReason.REVOKED):
        if not isinstance(reason, QuarantineReason):
            raise ValueError("reason must be an explicit QuarantineReason")
        conn = self.store.conn
        pending = conn.in_transaction
        with self.store._transaction(write=True):
            domain = self._domain()
            root = self._bound(record, domain)
            rows = conn.execute("""WITH RECURSIVE descendants(binding_id) AS (
                SELECT ? UNION SELECT e.child_binding_id FROM main.policy_lineage_edges AS e
                JOIN descendants AS d ON e.parent_binding_id=d.binding_id)
                SELECT d.binding_id FROM descendants AS d
                WHERE NOT EXISTS (SELECT 1 FROM main.policy_quarantine AS q WHERE q.binding_id=d.binding_id)
                LIMIT ?""", (root.binding_id, MAX_DERIVATIVES+2)).fetchall()
            if len(rows) > MAX_DERIVATIVES+1:
                raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
            epoch = _require_schema(conn)
            if rows:
                if epoch == 2**63-1:
                    raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
                epoch += 1
                conn.executemany("INSERT INTO main.policy_quarantine VALUES (?,?,?)", [(row[0], reason.value, epoch) for row in rows])
                conn.execute("UPDATE main.policy_lifecycle_state SET epoch=? WHERE singleton=1", (epoch,))
            status = "quarantined" if rows else "unchanged"
        return LifecycleReceipt(epoch, status, "pending" if pending else "committed")
