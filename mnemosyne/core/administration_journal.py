"""Independent-witness administrative journal; owner writes and scoped reads."""

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import inspect
import json
import os
import sqlite3
import stat
import threading

from .administration_audit_contract import (
    AdministrationIntent, RegistryAdministrationIntent, AdministrationJournalRead, AdministrationJournalRecord,
    _digest, _intent, _revision,
)
from .host_administration import _entry
from .host_configuration import HostConfigurationAuthority, _canonical
from .host_profile import _bounded_text, _exact_dict
from .policy import PolicyRefusal, RefusalReason, _number
from .policy_host import _synchronous
from .policy_store import PolicyStore, PolicyStoreError, StoreErrorCode
from .protected_snapshot import SnapshotCheckpoint, SnapshotIdentity
from .snapshot_authority import SnapshotAuthority, _store_id


MAX_OPERATIONS = 4096
MAX_EVENT_BYTES = 8192
_DOMAIN = "administration-journal-v1"
_DDL = {
    "administration_journal_state": "CREATE TABLE administration_journal_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL, authority_id TEXT NOT NULL, journal_id TEXT NOT NULL, max_operations INTEGER NOT NULL)",
    "administration_journal_events": "CREATE TABLE administration_journal_events (sequence INTEGER PRIMARY KEY, operation_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('intent','prepared','committed')), payload BLOB NOT NULL, digest TEXT NOT NULL, publication_state TEXT NOT NULL CHECK(publication_state IN ('prepared','committed')), UNIQUE(operation_id,kind))",
    "administration_journal_state_no_update": "CREATE TRIGGER administration_journal_state_no_update BEFORE UPDATE ON administration_journal_state BEGIN SELECT RAISE(ABORT,'immutable_journal'); END",
    "administration_journal_state_no_delete": "CREATE TRIGGER administration_journal_state_no_delete BEFORE DELETE ON administration_journal_state BEGIN SELECT RAISE(ABORT,'immutable_journal'); END",
    "administration_journal_events_no_delete": "CREATE TRIGGER administration_journal_events_no_delete BEFORE DELETE ON administration_journal_events BEGIN SELECT RAISE(ABORT,'immutable_journal'); END",
    "administration_journal_finalize_only": "CREATE TRIGGER administration_journal_finalize_only BEFORE UPDATE ON administration_journal_events WHEN NOT (OLD.publication_state='prepared' AND NEW.publication_state='committed' AND NEW.sequence=OLD.sequence AND NEW.operation_id=OLD.operation_id AND NEW.kind=OLD.kind AND NEW.payload=OLD.payload AND NEW.digest=OLD.digest) BEGIN SELECT RAISE(ABORT,'immutable_journal'); END",
}
_SELECT = """SELECT sequence,
 CASE WHEN length(CAST(operation_id AS BLOB))<=512 THEN CAST(operation_id AS BLOB) ELSE NULL END,
 CASE WHEN length(CAST(kind AS BLOB))<=16 THEN CAST(kind AS BLOB) ELSE NULL END,
 CASE WHEN length(CAST(payload AS BLOB))<=8192 THEN CAST(payload AS BLOB) ELSE NULL END,
 CASE WHEN length(CAST(digest AS BLOB))=64 THEN CAST(digest AS BLOB) ELSE NULL END,
 CASE WHEN length(CAST(publication_state AS BLOB))<=16 THEN CAST(publication_state AS BLOB) ELSE NULL END
 FROM main.administration_journal_events"""


class AdministrationJournal:
    """Trusted metadata owner, not an authentication provider or grant authority."""

    def __init__(self, conn, *, witness_connection, authority_id, journal_id, witness_id, issuer, authenticate_read):
        if type(conn) is not sqlite3.Connection or type(witness_connection) is not sqlite3.Connection:
            raise TypeError("exact explicit metadata connections required")
        for identity in (authority_id, journal_id, witness_id):
            _store_id(identity)
        _bounded_text(issuer, "issuer", 128)
        _synchronous(authenticate_read)
        self._store, self._witness_conn = PolicyStore(conn), witness_connection
        self._witness = SnapshotAuthority(witness_connection, authority_id=witness_id)
        self._authority_id, self._journal_id = authority_id, journal_id
        self._issuer, self._authenticate_read = issuer, authenticate_read
        self._process, self._thread, self._busy = os.getpid(), threading.get_ident(), False
        self._ready()

    def _ready(self, *, write=False):
        if not hasattr(os, "geteuid"):
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        identities = []
        for conn in (self._store.conn, self._witness_conn):
            if conn.in_transaction or conn.row_factory is not None or conn.text_factory is not str:
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            databases = conn.execute("PRAGMA database_list").fetchall()
            if any(row[1] not in ("main", "temp") for row in databases):
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            path = next(row[2] for row in databases if row[1] == "main")
            if not path:
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            try:
                info, parent = os.lstat(path), os.stat(os.path.dirname(path))
            except OSError:
                raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
                    or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700):
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            identities.append((info.st_dev, info.st_ino))
            if write:
                mode = conn.execute("PRAGMA main.journal_mode").fetchone()[0]
                sync = conn.execute("PRAGMA main.synchronous").fetchone()[0]
                if not ((mode == "wal" and sync in (2, 3)) or (mode == "delete" and sync == 3)):
                    raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        if identities[0] == identities[1]:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        if hasattr(self, "_identities") and identities != self._identities:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        self._identities = identities

    def _schema(self):
        conn = self._store.conn
        rows = conn.execute("SELECT CASE WHEN length(CAST(name AS BLOB))<=256 THEN name ELSE NULL END,CASE WHEN length(CAST(sql AS BLOB))<=16384 THEN sql ELSE NULL END FROM main.sqlite_master WHERE substr(name,1,7)!='sqlite_' LIMIT ?", (len(_DDL) + 1,)).fetchall()
        normalize = lambda value: "".join(value.split()) if type(value) is str else None
        if (len(rows) != len(_DDL) or any(name not in _DDL or normalize(sql) != normalize(_DDL[name]) for name, sql in rows)
                or conn.execute("SELECT 1 FROM temp.sqlite_master LIMIT 1").fetchone() is not None):
            raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
        rows = conn.execute("SELECT singleton,schema_version,CASE WHEN length(CAST(authority_id AS BLOB))=32 THEN authority_id ELSE NULL END,CASE WHEN length(CAST(journal_id AS BLOB))=32 THEN journal_id ELSE NULL END,max_operations FROM main.administration_journal_state LIMIT 2").fetchall()
        if (len(rows) != 1 or tuple(rows[0][:4]) != (1, 1, self._authority_id, self._journal_id)
                or type(rows[0][4]) is not int or not 1 <= rows[0][4] <= MAX_OPERATIONS):
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        return rows[0][4]

    def _checkpoint(self, sequence, digest):
        return SnapshotCheckpoint(SnapshotIdentity(self._journal_id, self._authority_id, _DOMAIN,
                                                   sequence + 1, sequence + 1), digest)

    def _root(self):
        return self._checkpoint(0, hashlib.sha256(_canonical({"contract_version": 1, "authority_id": self._authority_id,
            "journal_id": self._journal_id, "max_operations": self._schema()})).hexdigest())

    @_entry
    def prepare(self, *, max_operations=1024):
        if type(max_operations) is not int or not 1 <= max_operations <= MAX_OPERATIONS:
            raise ValueError("bounded operation capacity required")
        self._ready(write=True)
        self._witness.prepare()
        self._dedicated()
        conn = self._store.conn
        with self._store._transaction(write=True):
            if not conn.execute("SELECT 1 FROM main.sqlite_master WHERE substr(name,1,7)!='sqlite_' LIMIT 1").fetchone():
                for ddl in _DDL.values():
                    prefix = "CREATE TRIGGER " if ddl.startswith("CREATE TRIGGER ") else "CREATE TABLE "
                    conn.execute(ddl.replace(prefix, prefix + "main.", 1))
                conn.execute("INSERT INTO main.administration_journal_state VALUES(1,1,?,?,?)",
                             (self._authority_id, self._journal_id, max_operations))
            if self._schema() != max_operations:
                raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
            root = self._root()
        if self._witness.publication(self._journal_id, "admin-journal:root") is None:
            if self._store.conn.execute("SELECT 1 FROM main.administration_journal_events LIMIT 1").fetchone():
                raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
            self._witness.provision(root, operation_id="admin-journal:root")
        with self._store._transaction():
            self._head()

    def _row(self, *, sequence=None, operation_id=None, kind=None):
        if sequence is not None:
            sql, args = " WHERE sequence=?", (sequence,)
        elif operation_id is not None:
            sql, args = " WHERE operation_id=? AND kind=?", (operation_id, kind)
        else:
            sql, args = " ORDER BY sequence DESC LIMIT 1", ()
        row = self._store.conn.execute(_SELECT + sql, args).fetchone()
        if row is None:
            return None
        try:
            number, operation, kind, payload, digest, state = row
            _number(number, "sequence")
            if number > MAX_OPERATIONS * 3 or any(type(value) is not bytes for value in row[1:]):
                raise ValueError("bounded journal row required")
            operation = operation.decode("utf-8")
            kind, digest, state = (value.decode("ascii") for value in (kind, digest, state))
            _digest(digest)
            decoded = _exact_dict(json.loads(payload), {"sequence", "recorded_at", "body"}, "journal record")
            _number(decoded["sequence"], "sequence")
            if decoded["sequence"] != number or _canonical(decoded) != payload or hashlib.sha256(payload).hexdigest() != digest:
                raise ValueError("journal identity mismatch")
            timestamp = decoded["recorded_at"]
            _bounded_text(timestamp, "recorded_at", 40)
            if not timestamp.endswith("Z"):
                raise ValueError("UTC time required")
            datetime.fromisoformat(timestamp[:-1] + "+00:00")
            body = decoded["body"]
            expected = {"authority_id", "journal_id", "operation_id", "kind", "candidate", "intent" if kind == "intent" else "intent_sha256"}
            body = _exact_dict(body, expected, "journal body")
            if (body["authority_id"] != self._authority_id or body["journal_id"] != self._journal_id
                    or body["operation_id"] != operation or body["kind"] != kind or kind not in ("intent", "prepared", "committed")
                    or state not in ("prepared", "committed")):
                raise ValueError("journal binding mismatch")
            candidate = _revision(body["candidate"])
            if candidate.authority_id != self._authority_id:
                raise ValueError("foreign candidate authority")
            intent = _intent(body["intent"]) if kind == "intent" else None
            if intent is not None and (intent.operation_id != operation or intent.candidate != candidate):
                raise ValueError("intent mismatch")
            intent_digest = digest if intent is not None else _digest(body["intent_sha256"])
            return AdministrationJournalRecord(number, timestamp, operation, kind, candidate, intent_digest, intent), body, digest, state
        except (ValueError, TypeError, UnicodeError, KeyError):
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None

    def _dedicated(self):
        if self._witness_conn.execute("SELECT 1 FROM main.snapshot_publications WHERE store_id!=? LIMIT 1", (self._journal_id,)).fetchone():
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)

    def _head(self, *, allow_prepared=False):
        capacity = self._schema()
        self._dedicated()
        root = self._witness.publication(self._journal_id, "admin-journal:root")
        if root is None or root.checkpoint != self._root():
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        row = self._row()
        count, minimum = self._store.conn.execute("SELECT count(*),min(sequence) FROM main.administration_journal_events").fetchone()
        if count > 3 * capacity or count != (row[0].sequence if row else 0) or (count and minimum != 1):
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        checkpoint = self._checkpoint(row[0].sequence, row[2]) if row else self._root()
        if not allow_prepared or row is None or row[3] == "committed":
            if (row is not None and row[3] != "committed") or self._witness.current(self._journal_id) != checkpoint:
                raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        return row, checkpoint

    def _anchored(self, row):
        if row is None or row[3] != "committed":
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        expected = self._checkpoint(row[0].sequence, row[2])
        receipt = self._witness.publication(self._journal_id, "admin-journal:" + str(row[0].sequence))
        if receipt is None or receipt.checkpoint != expected:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        self._reference(row)

    def _reference(self, row):
        if row[0].kind != "intent":
            intent = self._row(operation_id=row[0].operation_id, kind="intent")
            if (intent is None or intent[0].sequence >= row[0].sequence
                    or row[0].intent_sha256 != intent[2] or row[0].candidate != intent[0].candidate):
                raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
            self._anchored(intent)
            committed = self._row(operation_id=row[0].operation_id, kind="committed")
            if row[0].kind == "prepared" and committed is not None and committed[0].sequence < row[0].sequence:
                raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)

    def _finish(self):
        with self._store._transaction():
            row, checkpoint = self._head(allow_prepared=True)
            if row is None or row[3] == "committed":
                if row is not None:
                    self._anchored(row)
                return None if row is None else row[0]
            self._reference(row)
            prior = self._row(sequence=row[0].sequence - 1) if row[0].sequence > 1 else None
            if prior is not None:
                self._anchored(prior)
            previous = self._checkpoint(prior[0].sequence, prior[2]) if prior else self._root()
        current = self._witness.current(self._journal_id)
        if current == previous:
            self._witness.publish(previous, checkpoint, operation_id="admin-journal:" + str(row[0].sequence))
        elif current != checkpoint:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        with self._store._transaction(write=True):
            head, actual = self._head(allow_prepared=True)
            if head != row or actual != checkpoint or self._witness.current(self._journal_id) != checkpoint:
                raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
            self._reference(head)
            self._store.conn.execute("UPDATE main.administration_journal_events SET publication_state='committed' WHERE sequence=?",
                                     (row[0].sequence,))
        return row[0]

    @_entry
    def recover(self):
        """Finish only the exact journal tail; never replay configuration writes."""
        self._ready(write=True)
        return self._finish()

    def _owner(self, owner):
        if type(owner) is not HostConfigurationAuthority:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        current = owner.current()
        if current.revision.authority_id != self._authority_id or set(owner._file_identities) & set(self._identities):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return current

    def _append(self, body):
        self._ready(write=True)
        conn = self._store.conn
        with self._store._transaction(write=True):
            head, _ = self._head()
            existing = self._row(operation_id=body["operation_id"], kind=body["kind"])
            if existing is not None:
                self._anchored(existing)
                if existing[1] != body:
                    raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
                return existing[0]
            if body["kind"] == "intent":
                count = conn.execute("SELECT count(*) FROM main.administration_journal_events WHERE kind='intent'").fetchone()[0]
                if count >= self._schema():
                    raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
            else:
                intent = self._row(operation_id=body["operation_id"], kind="intent")
                self._anchored(intent)
                if body["intent_sha256"] != intent[2] or _revision(body["candidate"]) != intent[0].candidate:
                    raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
                if body["kind"] == "prepared" and self._row(operation_id=body["operation_id"], kind="committed") is not None:
                    raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
            number = 1 if head is None else head[0].sequence + 1
            payload = _canonical({"sequence": number, "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "body": body})
            if len(payload) > MAX_EVENT_BYTES:
                raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
            conn.execute("INSERT INTO main.administration_journal_events VALUES(?,?,?,?,?,'prepared')",
                (number, body["operation_id"], body["kind"], payload, hashlib.sha256(payload).hexdigest()))
        return self._finish()

    @_entry
    def append_intent(self, intent, *, owner):
        self._ready(write=True)
        if type(intent) not in (AdministrationIntent, RegistryAdministrationIntent) or self._owner(owner).revision != intent.previous:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return self._append({"authority_id": self._authority_id, "journal_id": self._journal_id,
            "operation_id": intent.operation_id, "kind": "intent", "candidate": asdict(intent.candidate), "intent": intent.to_dict()})

    @_entry
    def observe(self, operation_id, *, owner):
        self._ready(write=True)
        _bounded_text(operation_id, "operation_id", 128)
        with self._store._transaction():
            self._head()
            intent = self._row(operation_id=operation_id, kind="intent")
            self._anchored(intent)
        current = self._owner(owner)
        receipt = owner.receipt(operation_id)
        if self._owner(owner) != current:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        with self._store._transaction():
            self._head()
            committed = self._row(operation_id=operation_id, kind="committed")
            prepared = self._row(operation_id=operation_id, kind="prepared")
        if receipt is None:
            if committed is not None or prepared is not None:
                raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
            return None
        if receipt.phase == "prepared" and committed is not None:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        if (receipt.revision != intent[0].candidate
                or (receipt.phase == "committed" and current.revision.generation < receipt.revision.generation)
                or (receipt.phase == "prepared" and current.revision != intent[0].intent.previous)):
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        return self._append({"authority_id": self._authority_id, "journal_id": self._journal_id,
            "operation_id": operation_id, "kind": receipt.phase, "candidate": asdict(receipt.revision), "intent_sha256": intent[2]})

    def _read_claim(self, request, destination, expected=None):
        claim = self._authenticate_read(request)
        if inspect.iscoroutine(claim) or inspect.isgenerator(claim):
            claim.close()
        if (type(claim) is not AdministrationJournalRead or claim.issuer != self._issuer
                or claim.authority_id != self._authority_id or claim.journal_id != self._journal_id
                or claim.destination != destination or (expected is not None and claim != expected)):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return claim

    @_entry
    def read(self, request, *, destination, after_sequence=0, limit=100):
        _bounded_text(destination, "destination", 128)
        _number(after_sequence, "after_sequence", minimum=0)
        _number(limit, "limit")
        if after_sequence > MAX_OPERATIONS * 3 or limit > 1000:
            raise ValueError("bounded journal page required")
        claim = self._read_claim(request, destination)
        self._ready()
        with self._store._transaction():
            _, checkpoint = self._head()
            numbers = self._store.conn.execute("SELECT sequence FROM main.administration_journal_events WHERE sequence>? ORDER BY sequence LIMIT ?",
                                              (after_sequence, limit)).fetchall()
            records = []
            for number, in numbers:
                row = self._row(sequence=number)
                self._anchored(row)
                records.append(row[0])
        self._read_claim(request, destination, claim)
        with self._store._transaction():
            if self._head()[1] != checkpoint:
                raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        self._read_claim(request, destination, claim)
        return tuple(records)
