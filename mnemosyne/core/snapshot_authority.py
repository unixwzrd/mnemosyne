"""Explicit independent owner authority; never inferred from a restored snapshot."""

from dataclasses import dataclass
import sqlite3

from .policy import PolicyRefusal, RefusalReason, _text
from .policy_read import _guard_policy_output
from .policy_store import PolicyStore, PolicyStoreError, StoreErrorCode
from .protected_snapshot import SnapshotCheckpoint, SnapshotIdentity


MAX_PUBLICATIONS = 65536


def _store_id(value):
    if (
        type(value) is not str
        or len(value) != 32
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise ValueError("explicit store identity required")
    return value


_DDL = {
    "snapshot_authority_state": "CREATE TABLE snapshot_authority_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL, authority_id TEXT NOT NULL)",
    "snapshot_publications": "CREATE TABLE snapshot_publications (store_id TEXT NOT NULL, generation INTEGER NOT NULL, bank TEXT NOT NULL, domain_id TEXT NOT NULL, lifecycle_epoch INTEGER NOT NULL, envelope_sha256 TEXT NOT NULL, operation_id TEXT NOT NULL, PRIMARY KEY(store_id,generation), UNIQUE(store_id,operation_id))",
    "snapshot_publications_no_update": "CREATE TRIGGER snapshot_publications_no_update BEFORE UPDATE ON snapshot_publications BEGIN SELECT RAISE(ABORT,'immutable_authority'); END",
    "snapshot_publications_no_delete": "CREATE TRIGGER snapshot_publications_no_delete BEFORE DELETE ON snapshot_publications BEGIN SELECT RAISE(ABORT,'immutable_authority'); END",
}


@dataclass(frozen=True, repr=False)
class PublicationReceipt:
    checkpoint: SnapshotCheckpoint
    operation_id: str
    status: str


def _text_column(value, maximum=1024, *, ascii_only=False):
    if type(value) is not bytes or len(value) > maximum:
        raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
    try:
        return value.decode("ascii" if ascii_only else "utf-8")
    except UnicodeError:
        raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None


def _row(row):
    try:
        identity = SnapshotIdentity(
            _text_column(row[0], 32, ascii_only=True),
            _text_column(row[2]),
            _text_column(row[3]),
            row[1],
            row[4],
        )
        checkpoint = SnapshotCheckpoint(
            identity, _text_column(row[5], 64, ascii_only=True)
        )
        operation_id = _text(_text_column(row[6]), "operation_id")
        return checkpoint, operation_id
    except (TypeError, ValueError):
        raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None


_PROJECTION = """SELECT
    CASE WHEN length(CAST(store_id AS BLOB))=32 THEN CAST(store_id AS BLOB) ELSE NULL END,
    generation,
    CASE WHEN length(CAST(bank AS BLOB))<=1024 THEN CAST(bank AS BLOB) ELSE NULL END,
    CASE WHEN length(CAST(domain_id AS BLOB))<=1024 THEN CAST(domain_id AS BLOB) ELSE NULL END,
    lifecycle_epoch,
    CASE WHEN length(CAST(envelope_sha256 AS BLOB))=64 THEN CAST(envelope_sha256 AS BLOB) ELSE NULL END,
    CASE WHEN length(CAST(operation_id AS BLOB))<=1024 THEN CAST(operation_id AS BLOB) ELSE NULL END
    FROM main.snapshot_publications"""


class SnapshotAuthority:
    """Trusted host metadata authority outside the memory restore domain.

    The owner pins authority_id independently, provisions only explicitly, and
    protects this connection/root. Co-restoring the authority is not detectable
    by a software marker inside it and is forbidden by the host contract.
    """

    def __init__(self, conn, *, authority_id):
        if not isinstance(conn, sqlite3.Connection):
            raise TypeError("explicit independent metadata connection required")
        if (
            type(authority_id) is not str
            or len(authority_id) != 32
            or any(c not in "0123456789abcdef" for c in authority_id)
        ):
            raise ValueError(
                "authority_id must be an independently pinned 128-bit hex identity"
            )
        self._store = PolicyStore(conn)
        self._authority_id = authority_id

    def _schema(self):
        conn = self._store.conn
        rows = conn.execute(
            "SELECT name,sql FROM main.sqlite_master WHERE name IN (?,?,?,?)",
            tuple(_DDL),
        ).fetchall()
        normalize = lambda value: "".join(value.split()) if type(value) is str else None
        if len(rows) != len(_DDL) or any(
            normalize(sql) != normalize(_DDL[name]) for name, sql in rows
        ):
            raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
        for schema in ("main", "temp"):
            rows = conn.execute(
                f"SELECT name FROM {schema}.sqlite_master WHERE type='trigger' AND tbl_name IN ('snapshot_authority_state','snapshot_publications')"
            ).fetchall()
            if any(
                schema != "main"
                or row[0]
                not in (
                    "snapshot_publications_no_update",
                    "snapshot_publications_no_delete",
                )
                for row in rows
            ):
                raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
        rows = conn.execute(
            "SELECT singleton,schema_version,CASE WHEN length(CAST(authority_id AS BLOB))=32 THEN CAST(authority_id AS BLOB) ELSE NULL END FROM main.snapshot_authority_state LIMIT 2"
        ).fetchall()
        if len(rows) != 1 or tuple(rows[0]) != (
            1,
            1,
            self._authority_id.encode("ascii"),
        ):
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)

    def _write_ready(self):
        conn = self._store.conn
        if conn.in_transaction:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        main = next(
            row for row in conn.execute("PRAGMA database_list") if row[1] == "main"
        )
        mode = conn.execute("PRAGMA main.journal_mode").fetchone()[0]
        sync = conn.execute("PRAGMA main.synchronous").fetchone()[0]
        if not main[2] or not (
            (mode == "wal" and sync in (2, 3)) or (mode == "delete" and sync == 3)
        ):
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)

    def prepare(self):
        self._write_ready()
        conn = self._store.conn
        with self._store._transaction(write=True):
            present = conn.execute(
                "SELECT 1 FROM main.sqlite_master WHERE name IN (?,?,?,?) LIMIT 1",
                tuple(_DDL),
            ).fetchone()
            if present is None:
                if conn.execute(
                    "SELECT 1 FROM main.sqlite_master WHERE substr(name,1,7)!='sqlite_' LIMIT 1"
                ).fetchone():
                    raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
                for ddl in _DDL.values():
                    prefix = (
                        "CREATE TRIGGER "
                        if ddl.startswith("CREATE TRIGGER ")
                        else "CREATE TABLE "
                    )
                    conn.execute(ddl.replace(prefix, prefix + "main.", 1))
                conn.execute(
                    "INSERT INTO main.snapshot_authority_state VALUES(1,1,?)",
                    (self._authority_id,),
                )
            self._schema()

    def _head(self, store_id):
        rows = self._store.conn.execute(
            _PROJECTION + " WHERE store_id=? ORDER BY generation DESC LIMIT 1",
            (store_id,),
        ).fetchall()
        return None if not rows else _row(rows[0])

    @_guard_policy_output
    def current(self, store_id):
        _store_id(store_id)
        if self._store.conn.in_transaction:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        with self._store._transaction():
            self._schema()
            head = self._head(store_id)
        if head is None:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return head[0]

    @_guard_policy_output
    def publication(self, store_id, operation_id):
        _store_id(store_id)
        _text(operation_id, "operation_id")
        if self._store.conn.in_transaction:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        with self._store._transaction():
            self._schema()
            rows = self._store.conn.execute(
                _PROJECTION + " WHERE store_id=? AND operation_id=? LIMIT 1",
                (store_id, operation_id),
            ).fetchall()
            result = None if not rows else _row(rows[0])
        return (
            None
            if result is None
            else PublicationReceipt(result[0], result[1], "recorded")
        )

    def provision(self, checkpoint, *, operation_id):
        return self._publish(None, checkpoint, operation_id)

    def publish(self, previous, checkpoint, *, operation_id):
        if type(previous) is not SnapshotCheckpoint:
            raise TypeError("exact previous checkpoint required")
        return self._publish(previous, checkpoint, operation_id)

    @_guard_policy_output
    def _publish(self, previous, checkpoint, operation_id):
        if type(checkpoint) is not SnapshotCheckpoint:
            raise TypeError("exact proposed checkpoint required")
        _text(operation_id, "operation_id")
        self._write_ready()
        identity = checkpoint.identity
        if previous is None:
            if identity.generation != 1:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        else:
            old = previous.identity
            if (
                (identity.store_id, identity.bank, identity.domain_id)
                != (old.store_id, old.bank, old.domain_id)
                or identity.generation != old.generation + 1
                or identity.lifecycle_epoch < old.lifecycle_epoch
            ):
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        conn = self._store.conn
        with self._store._transaction(write=True):
            self._schema()
            head = self._head(identity.store_id)
            if head is not None and head == (checkpoint, operation_id):
                return PublicationReceipt(checkpoint, operation_id, "unchanged")
            if (None if head is None else head[0]) != previous:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            if conn.execute(
                "SELECT 1 FROM main.snapshot_publications WHERE store_id=? AND operation_id=? LIMIT 1",
                (identity.store_id, operation_id),
            ).fetchone():
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            if (
                conn.execute(
                    "SELECT count(*) FROM main.snapshot_publications"
                ).fetchone()[0]
                >= MAX_PUBLICATIONS
            ):
                raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
            conn.execute(
                "INSERT INTO main.snapshot_publications VALUES(?,?,?,?,?,?,?)",
                (
                    identity.store_id,
                    identity.generation,
                    identity.bank,
                    identity.domain_id,
                    identity.lifecycle_epoch,
                    checkpoint.envelope_sha256,
                    operation_id,
                ),
            )
        return PublicationReceipt(checkpoint, operation_id, "published")
