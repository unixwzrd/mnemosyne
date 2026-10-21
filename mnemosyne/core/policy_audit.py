"""Bounded owner audit journal; administrative reads require fresh authority."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import inspect
import json
import sqlite3

from .policy import AccessContext, PolicyRefusal, PolicySurface, RefusalReason, _labels, _number, _text
from .policy_evidence import _consume, _require_consumer, _sha256
from .policy_lifecycle import PolicyRecordRef
from .policy_read import _guard_policy_output
from .policy_store import PolicyStore, PolicyStoreError, RecordKind, StoreErrorCode
from ..runtime_context import get_access_context


MAX_EVENT_BYTES = 65536
MAX_EVENTS = 16384
_OPERATIONS = {
    PolicySurface.DIRECT: {"get", "candidates", "source_metadata", "issue", "resolve"},
    PolicySurface.LEXICAL: {"lexical"}, PolicySurface.VECTOR: {"vector"}, PolicySurface.HYBRID: {"hybrid"},
    PolicySurface.WRITE: {"create"}, PolicySurface.DERIVE: {"derive"}, PolicySurface.EXPAND: {"expand"},
    PolicySurface.INJECT: {"deliver", "stream"}, PolicySurface.CACHE: {"resolve"},
    PolicySurface.MAINTENANCE: {"quarantine", "maintenance"}, PolicySurface.EXPORT: {"export"},
    PolicySurface.IMPORT: {"import"}, PolicySurface.SYNC: {"sync"},
}
_DDL = {
    "policy_audit_state": "CREATE TABLE policy_audit_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL, domain_id TEXT NOT NULL, bank TEXT NOT NULL, max_events INTEGER NOT NULL)",
    "policy_audit_events": "CREATE TABLE policy_audit_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, recorded_at TEXT NOT NULL, payload TEXT NOT NULL, digest TEXT NOT NULL)",
    "policy_audit_no_update": "CREATE TRIGGER policy_audit_no_update BEFORE UPDATE ON policy_audit_events BEGIN SELECT RAISE(ABORT,'immutable_audit'); END",
    "policy_audit_no_delete": "CREATE TRIGGER policy_audit_no_delete BEFORE DELETE ON policy_audit_events BEGIN SELECT RAISE(ABORT,'immutable_audit'); END",
}


@dataclass(frozen=True, repr=False)
class PolicyAuditEvent:
    event_id: str
    decision_id: str
    surface: PolicySurface
    context_id: str
    context_epoch: int
    context_fingerprint: str
    principals: frozenset[str]
    policy_id: str
    policy_version: int
    bank: str
    destination: str
    lifecycle_epoch: int
    result: str
    operation: str = "get"
    reason: RefusalReason | None = None
    requested: tuple[PolicyRecordRef, ...] = ()
    returned: tuple[PolicyRecordRef, ...] = ()

    def __post_init__(self):
        for name in ("event_id", "decision_id", "context_id", "policy_id", "bank", "destination"):
            _text(getattr(self, name), name)
        _sha256(self.context_fingerprint)
        for name, minimum in (("context_epoch", 0), ("policy_version", 1), ("lifecycle_epoch", 0)):
            _number(getattr(self, name), name, minimum=minimum)
        object.__setattr__(self, "principals", _labels(self.principals, "principals"))
        if (not self.principals or type(self.surface) is not PolicySurface
            or type(self.operation) is not str or self.operation not in _OPERATIONS.get(self.surface, ())):
            raise ValueError("explicit principals and policy surface required")
        if (type(self.result) is not str or self.result not in ("allow", "deny") or (self.result == "allow" and self.reason is not None)
            or (self.result == "deny" and type(self.reason) is not RefusalReason)):
            raise ValueError("invalid audit result and reason")
        for name in ("requested", "returned"):
            values = getattr(self, name)
            if type(values) not in (tuple, list) or len(values) > 256 or any(type(value) is not PolicyRecordRef for value in values):
                raise ValueError("bounded explicit record references required")
            if len(set(values)) != len(values):
                raise ValueError("duplicate audit references")
            object.__setattr__(self, name, tuple(values))
        if self.result == "deny" and self.returned:
            raise ValueError("denied event cannot return records")

    @classmethod
    def from_context(cls, context, **values):
        if type(context) is not AccessContext:
            raise TypeError("trusted AccessContext required")
        return cls(context_id=context.context_id, context_epoch=context.epoch,
            context_fingerprint=context.fingerprint(), principals=context.principals,
            policy_id=context.policy_id, policy_version=context.policy_version, **values)


@dataclass(frozen=True, repr=False)
class AuditReadGrant:
    context_fingerprint: str
    domain_id: str
    bank: str
    destination: str
    decision_id: str
    authority_epoch: int

    def __post_init__(self):
        _sha256(self.context_fingerprint)
        for name in ("domain_id", "bank", "destination", "decision_id"):
            _text(getattr(self, name), name)
        _number(self.authority_epoch, "authority_epoch", minimum=0)


@dataclass(frozen=True, repr=False)
class AuditWriteReceipt:
    sequence: int
    status: str
    transaction_state: str


@dataclass(frozen=True, repr=False)
class AuditRecord:
    sequence: int
    recorded_at: str
    event: PolicyAuditEvent


def _payload(event):
    if type(event) is not PolicyAuditEvent:
        raise TypeError("explicit PolicyAuditEvent required")
    values = asdict(event)
    values["surface"] = event.surface.value
    values["reason"] = None if event.reason is None else event.reason.value
    values["principals"] = sorted(event.principals)
    for name in ("requested", "returned"):
        values[name] = [[ref.record_kind.value, ref.record_id] for ref in getattr(event, name)]
    payload = json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(payload.encode("ascii")) > MAX_EVENT_BYTES:
        raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
    return payload


def _stored_text(value, maximum, *, encoding="ascii"):
    if type(value) is not bytes or len(value) > maximum:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
    try:
        return value.decode(encoding)
    except UnicodeError:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE) from None


def _decode(raw, digest):
    digest = _stored_text(digest, 64)
    if type(raw) is not bytes or len(raw) > MAX_EVENT_BYTES or hashlib.sha256(raw).hexdigest() != digest:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
    try:
        values = json.loads(raw)
        values["surface"] = PolicySurface(values["surface"])
        values["reason"] = None if values["reason"] is None else RefusalReason(values["reason"])
        for name in ("requested", "returned"):
            values[name] = tuple(PolicyRecordRef(RecordKind(kind), identity) for kind, identity in values[name])
        event = PolicyAuditEvent(**values)
        if _payload(event).encode("ascii") != raw:
            raise ValueError("noncanonical audit metadata")
        return event
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError, PolicyRefusal):
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE) from None


class PolicyAudit:
    """Explicit owner append API; read authority covers the entire journal bank.

    Own this separate metadata connection in trusted host code. Do not expose
    prepare/append/raw SQL or the verifier to a model or ordinary journal reader.
    """

    def __init__(self, conn, *, domain_id, bank, verify_read):
        if not isinstance(conn, sqlite3.Connection):
            raise TypeError("explicit metadata connection required")
        self._store = PolicyStore(conn)
        self._domain_id = _text(domain_id, "domain_id")
        self._bank = _text(bank, "bank")
        if not callable(verify_read) or inspect.iscoroutinefunction(verify_read):
            raise TypeError("synchronous trusted audit verifier required")
        self._verify = verify_read

    def _schema(self):
        conn = self._store.conn
        rows = conn.execute("SELECT name,sql FROM main.sqlite_master WHERE name IN (?,?,?,?)", tuple(_DDL)).fetchall()
        normalize = lambda value: "".join(value.split()) if type(value) is str else None
        if len(rows) != len(_DDL) or any(normalize(sql) != normalize(_DDL[name]) for name, sql in rows):
            raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
        for schema in ("main", "temp"):
            triggers = conn.execute(f"SELECT name FROM {schema}.sqlite_master WHERE type='trigger' AND tbl_name IN ('policy_audit_events','policy_audit_state')").fetchall()
            if any(schema != "main" or row[0] not in ("policy_audit_no_update", "policy_audit_no_delete") for row in triggers):
                raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
        rows = conn.execute("SELECT singleton,schema_version,domain_id,bank,max_events FROM main.policy_audit_state LIMIT 2").fetchall()
        if (len(rows) != 1 or tuple(rows[0][:4]) != (1, 1, self._domain_id, self._bank)
            or type(rows[0][4]) is not int or not 1 <= rows[0][4] <= MAX_EVENTS):
            raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
        return rows[0][4]

    def prepare(self, *, max_events=4096):
        if type(max_events) is not int or not 1 <= max_events <= MAX_EVENTS:
            raise ValueError("invalid audit capacity")
        conn = self._store.conn
        with self._store._transaction(write=True):
            present = conn.execute("SELECT 1 FROM main.sqlite_master WHERE name IN (?,?,?,?) LIMIT 1", tuple(_DDL)).fetchone()
            if present is None:
                if conn.execute("SELECT 1 FROM main.sqlite_master WHERE substr(name,1,7)!='sqlite_' LIMIT 1").fetchone():
                    raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
                for ddl in _DDL.values():
                    prefix = "CREATE TRIGGER " if ddl.startswith("CREATE TRIGGER ") else "CREATE TABLE "
                    conn.execute(ddl.replace(prefix, prefix + "main.", 1))
                conn.execute("INSERT INTO main.policy_audit_state VALUES(1,1,?,?,?)", (self._domain_id, self._bank, max_events))
            if self._schema() != max_events:
                raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)

    @_guard_policy_output
    def append(self, event):
        payload = _payload(event)
        if event.bank != self._bank:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        conn = self._store.conn
        pending = conn.in_transaction
        with self._store._transaction(write=True):
            capacity = self._schema()
            previous = conn.execute("""SELECT sequence,
                CASE WHEN length(CAST(digest AS BLOB))=64 THEN CAST(digest AS BLOB) ELSE NULL END,
                CASE WHEN length(CAST(payload AS BLOB))<=? THEN CAST(payload AS BLOB) ELSE NULL END
                FROM main.policy_audit_events WHERE event_id=?""", (MAX_EVENT_BYTES, event.event_id)).fetchone()
            digest = hashlib.sha256(payload.encode("ascii")).hexdigest()
            if previous is not None:
                if _stored_text(previous[1], 64) != digest or _decode(previous[2], previous[1]) != event:
                    raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
                sequence, status = previous[0], "unchanged"
            else:
                if conn.execute("SELECT count(*) FROM main.policy_audit_events").fetchone()[0] >= capacity:
                    raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
                recorded_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                cursor = conn.execute("INSERT INTO main.policy_audit_events(event_id,recorded_at,payload,digest) VALUES(?,?,?,?)",
                    (event.event_id, recorded_at, payload, digest))
                sequence, status = cursor.lastrowid, "created"
        return AuditWriteReceipt(sequence, status, "pending" if pending else "committed")

    def _grant(self, destination):
        context = get_access_context(required=True)
        if (context.assurance != "authenticated" or "audit:read" not in context.operations
            or self._bank not in context.banks or destination not in context.destinations):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        try:
            grant = self._verify(context, bank=self._bank, destination=destination)
        except PolicyRefusal:
            raise
        except Exception:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None
        if inspect.iscoroutine(grant):
            grant.close()
        if (type(grant) is not AuditReadGrant or grant.context_fingerprint != context.fingerprint()
            or grant.domain_id != self._domain_id or grant.bank != self._bank or grant.destination != destination
            or get_access_context(required=True).fingerprint() != context.fingerprint()):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return grant

    @_guard_policy_output
    def admit(self, event, consumer):
        """Commit an owner-reported decision before one trusted consumer.

        This records a decision, not completion or an authorization service.
        The host must authenticate/authorize before constructing an allow event.
        """
        _require_consumer(consumer)
        conn = self._store.conn
        if conn.in_transaction:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        main = next(row for row in conn.execute("PRAGMA database_list") if row[1] == "main")
        synchronous = conn.execute("PRAGMA main.synchronous").fetchone()[0]
        mode = conn.execute("PRAGMA main.journal_mode").fetchone()[0]
        if not main[2] or not ((mode == "wal" and synchronous in (2,3)) or (mode == "delete" and synchronous == 3)):
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        receipt = self.append(event)
        if event.result != "allow":
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        if receipt.transaction_state != "committed":
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        _consume(consumer, event)
        return receipt

    @_guard_policy_output
    def read(self, *, destination, after_sequence=0, limit=100):
        destination = _text(destination, "destination")
        _number(after_sequence, "after_sequence", minimum=0)
        _number(limit, "limit")
        if limit > 1000 or after_sequence > 2**63 - 1:
            raise ValueError("invalid audit page bounds")
        conn = self._store.conn
        grant = self._grant(destination)
        if conn.in_transaction:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        def recheck():
            current = self._grant(destination)
            if (current.context_fingerprint, current.domain_id, current.bank, current.destination, current.authority_epoch) != (
                grant.context_fingerprint, grant.domain_id, grant.bank, grant.destination, grant.authority_epoch):
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        with self._store._transaction():
            self._schema()
            recheck()
            rows = conn.execute("""SELECT sequence,
                CASE WHEN length(CAST(recorded_at AS BLOB))<=40 THEN CAST(recorded_at AS BLOB) ELSE NULL END,
                CASE WHEN length(CAST(payload AS BLOB))<=? THEN CAST(payload AS BLOB) ELSE NULL END,
                CASE WHEN length(CAST(digest AS BLOB))=64 THEN CAST(digest AS BLOB) ELSE NULL END,
                CASE WHEN length(CAST(event_id AS BLOB))<=1024 THEN CAST(event_id AS BLOB) ELSE NULL END
                FROM main.policy_audit_events WHERE sequence>? ORDER BY sequence LIMIT ?""",
                (MAX_EVENT_BYTES, after_sequence, limit)).fetchall()
            records = []
            for sequence, stored_at, raw, digest, event_id in rows:
                recorded_at = _stored_text(stored_at, 40)
                try:
                    _number(sequence, "sequence")
                    _text(recorded_at, "recorded_at", 40)
                    if not recorded_at.endswith("Z"):
                        raise ValueError("UTC audit time required")
                    datetime.fromisoformat(recorded_at[:-1] + "+00:00")
                except (TypeError, ValueError):
                    raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE) from None
                event = _decode(raw, digest)
                if event.bank != self._bank or event.event_id != _stored_text(event_id, 1024, encoding="utf-8"):
                    raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
                records.append(AuditRecord(sequence, recorded_at, event))
        recheck()
        return tuple(records)
