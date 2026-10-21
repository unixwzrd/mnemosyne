"""Opt-in encrypted owner snapshots; never an implicit legacy-store upgrade."""

from dataclasses import dataclass
import hashlib
import inspect
import sqlite3

from .policy import PolicyRefusal, RefusalReason, _number, _text
from .policy_evidence import _sha256
from .policy_lifecycle import PolicyLifecycle
from .policy_read import _guard_policy_output
from .policy_store import PolicyStore


MAGIC = b"MNEMOSYNE-PROTECTED-1\x00"
MAX_DATABASE_BYTES = 64 * 1024 * 1024
MAX_ENVELOPE_BYTES = 90 * 1024 * 1024
_DDL = "CREATE TABLE protected_snapshot_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), format_version INTEGER NOT NULL, store_id TEXT NOT NULL, bank TEXT NOT NULL, domain_id TEXT NOT NULL, generation INTEGER NOT NULL, lifecycle_epoch INTEGER NOT NULL)"


@dataclass(frozen=True, repr=False)
class SnapshotIdentity:
    store_id: str
    bank: str
    domain_id: str
    generation: int
    lifecycle_epoch: int

    def __post_init__(self):
        if type(self.store_id) is not str or len(self.store_id) != 32 or any(c not in "0123456789abcdef" for c in self.store_id):
            raise ValueError("store_id must be an explicit 128-bit hex identity")
        _text(self.bank, "bank")
        _text(self.domain_id, "domain_id")
        for name, minimum in (("generation", 1), ("lifecycle_epoch", 0)):
            value = _number(getattr(self, name), name, minimum=minimum)
            if value > 2**63 - 1:
                raise ValueError("snapshot counter exceeds supported bounds")


@dataclass(frozen=True, repr=False)
class SnapshotCheckpoint:
    identity: SnapshotIdentity
    envelope_sha256: str

    def __post_init__(self):
        if type(self.identity) is not SnapshotIdentity:
            raise TypeError("identity must be a SnapshotIdentity")
        _sha256(self.envelope_sha256)


@dataclass(frozen=True, repr=False)
class SealedSnapshot:
    envelope: bytes
    checkpoint: SnapshotCheckpoint

    def __post_init__(self):
        if type(self.envelope) is not bytes or type(self.checkpoint) is not SnapshotCheckpoint:
            raise TypeError("explicit envelope and checkpoint required")
        if (len(self.envelope) > MAX_ENVELOPE_BYTES or not self.envelope.startswith(MAGIC)
            or hashlib.sha256(self.envelope).hexdigest() != self.checkpoint.envelope_sha256):
            raise ValueError("inconsistent protected snapshot")


def _cipher(key):
    # Reuse the existing optional dependency, not a bespoke cipher or KDF.
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE) from None
    if type(key) is not bytes or len(key) != 44:
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    try:
        return Fernet(key)
    except (ValueError, TypeError):
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED) from None


def _supported():
    if not all(hasattr(sqlite3.Connection, method) for method in ("serialize", "deserialize")):
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)


def _identity(conn, *, match_epoch=True):
    row = conn.execute("SELECT sql FROM main.sqlite_master WHERE name='protected_snapshot_state' AND type='table'").fetchone()
    if row is None or row[0] != _DDL:
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    rows = conn.execute("SELECT singleton,format_version,store_id,bank,domain_id,generation,lifecycle_epoch FROM main.protected_snapshot_state LIMIT 2").fetchall()
    if len(rows) != 1 or tuple(rows[0][:2]) != (1, 1):
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    try:
        identity = SnapshotIdentity(*rows[0][2:])
    except (TypeError, ValueError):
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED) from None
    store = PolicyStore(conn)
    domain = store.get_domain()
    if domain is None or domain.domain_id != identity.domain_id or (match_epoch and PolicyLifecycle(store).epoch() != identity.lifecycle_epoch):
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    return identity


def _current(verify_current, expected):
    if not callable(verify_current) or inspect.iscoroutinefunction(verify_current):
        raise TypeError("verify_current must be an independent synchronous authority")
    try:
        observed = verify_current(expected.identity.store_id)
    except PolicyRefusal:
        raise
    except Exception:
        raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None
    if inspect.iscoroutine(observed):
        observed.close()
    if type(observed) is not SnapshotCheckpoint or observed != expected:
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)


@_guard_policy_output
def seal_snapshot(conn, identity, *, key):
    """Produce an unpublished owner artifact without changing the source DB.

    The host must durably store the immutable envelope BEFORE atomically
    advancing its independent current-checkpoint authority. This does neither.
    """
    _supported()
    if not isinstance(conn, sqlite3.Connection) or type(identity) is not SnapshotIdentity:
        raise TypeError("explicit connection and SnapshotIdentity required")
    if conn.in_transaction:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
    cipher = _cipher(key)
    page_count = conn.execute("PRAGMA main.page_count").fetchone()[0]
    page_size = conn.execute("PRAGMA main.page_size").fetchone()[0]
    if page_count * page_size > MAX_DATABASE_BYTES:
        raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
    memory = sqlite3.connect(":memory:")
    try:
        memory.execute("PRAGMA temp_store=MEMORY")
        conn.backup(memory, name="main")
        memory.execute("PRAGMA journal_mode=MEMORY")
        store = PolicyStore(memory)
        domain = store.get_domain()
        if domain is None or domain.domain_id != identity.domain_id or PolicyLifecycle(store).epoch() != identity.lifecycle_epoch:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        existing = memory.execute("SELECT 1 FROM main.sqlite_master WHERE name='protected_snapshot_state'").fetchone()
        if existing:
            previous = _identity(memory, match_epoch=False)
            if ((previous.store_id, previous.bank, previous.domain_id) != (identity.store_id, identity.bank, identity.domain_id)
                or identity.generation <= previous.generation or identity.lifecycle_epoch < previous.lifecycle_epoch):
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            memory.execute("DELETE FROM main.protected_snapshot_state")
        else:
            memory.execute(_DDL)
        memory.execute("INSERT INTO main.protected_snapshot_state VALUES (1,1,?,?,?,?,?)",
            (identity.store_id, identity.bank, identity.domain_id, identity.generation, identity.lifecycle_epoch))
        memory.commit()
        raw = memory.serialize(name="main")
        if len(raw) > MAX_DATABASE_BYTES:
            raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
        if raw[:16] != b"SQLite format 3\x00" or raw[18:20] not in (b"\x01\x01", b"\x02\x02"):
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        # SQLite documents this exact WAL-header conversion for deserialize().
        # VACUUM would also convert it but can change vector-referenced rowids.
        if raw[18:20] == b"\x02\x02":
            raw = raw[:18] + b"\x01\x01" + raw[20:]
        envelope = MAGIC + cipher.encrypt(raw)
        checkpoint = SnapshotCheckpoint(identity, hashlib.sha256(envelope).hexdigest())
        return SealedSnapshot(envelope, checkpoint)
    finally:
        memory.close()


@_guard_policy_output
def open_snapshot(envelope, checkpoint, *, key, verify_current):
    """Open an exact current encrypted snapshot into a trusted owner's RAM.

    This read-only connection is not an agent capability. All per-record reads
    still need the explicit policy APIs and fresh authenticated host grants.
    """
    _supported()
    if type(checkpoint) is not SnapshotCheckpoint or type(envelope) is not bytes:
        raise TypeError("explicit envelope and SnapshotCheckpoint required")
    if len(envelope) > MAX_ENVELOPE_BYTES:
        raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
    if not envelope.startswith(MAGIC) or hashlib.sha256(envelope).hexdigest() != checkpoint.envelope_sha256:
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    _current(verify_current, checkpoint)
    cipher = _cipher(key)
    from cryptography.fernet import InvalidToken
    try:
        raw = cipher.decrypt(envelope[len(MAGIC):])
    except InvalidToken:
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED) from None
    if len(raw) > MAX_DATABASE_BYTES:
        raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
    if raw[:16] != b"SQLite format 3\x00" or raw[18:20] != b"\x01\x01":
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    memory = sqlite3.connect(":memory:")
    try:
        memory.execute("PRAGMA temp_store=MEMORY")
        memory.execute("PRAGMA trusted_schema=OFF")
        memory.deserialize(raw, name="main")
        memory.execute("PRAGMA query_only=ON")
        if _identity(memory) != checkpoint.identity:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        _current(verify_current, checkpoint)
        return memory
    except BaseException:
        memory.close()
        raise
