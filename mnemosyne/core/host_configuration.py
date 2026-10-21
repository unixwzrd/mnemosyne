"""Explicit owner-only profile history and independently witnessed publication.

No authentication, administration role, content grant, profile default or
protected frontend activation is supplied by these metadata APIs.
"""

from dataclasses import asdict, dataclass
import hashlib
import json
import sqlite3

from .host_profile import ProfileDefinition, _exact_dict
from .host_registry import AuthorizationRegistry
from .policy import PolicyRefusal, RefusalReason, _number, _text
from .policy_read import _guard_policy_output
from .policy_store import PolicyStore, PolicyStoreError, StoreErrorCode
from .protected_snapshot import SnapshotCheckpoint, SnapshotIdentity
from .snapshot_authority import SnapshotAuthority, _store_id


MAX_PROFILES = 32
MAX_CONFIGURATION_BYTES = 256 * 1024
MAX_CONFIGURATION_REVISIONS = 1024
_WITNESS_BANK = "host-configuration"
_WITNESS_DOMAIN = "host-configuration-v1"
_DDL = {
    "host_configuration_state": "CREATE TABLE host_configuration_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL, authority_id TEXT NOT NULL)",
    "host_configuration_revisions": "CREATE TABLE host_configuration_revisions (generation INTEGER PRIMARY KEY, digest TEXT NOT NULL, payload BLOB NOT NULL, operation_id TEXT NOT NULL UNIQUE, phase TEXT NOT NULL CHECK(phase IN ('prepared','committed')))",
    "host_profile_versions": "CREATE TABLE host_profile_versions (profile_id TEXT NOT NULL, version INTEGER NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(profile_id,version))",
    "host_policy_versions": "CREATE TABLE host_policy_versions (policy_id TEXT NOT NULL, version INTEGER NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(policy_id,version))",
    "host_configuration_no_delete": "CREATE TRIGGER host_configuration_no_delete BEFORE DELETE ON host_configuration_revisions BEGIN SELECT RAISE(ABORT,'immutable_configuration'); END",
    "host_configuration_finalize_only": "CREATE TRIGGER host_configuration_finalize_only BEFORE UPDATE ON host_configuration_revisions WHEN NOT (OLD.phase='prepared' AND NEW.phase='committed' AND NEW.generation=OLD.generation AND NEW.digest=OLD.digest AND NEW.payload=OLD.payload AND NEW.operation_id=OLD.operation_id) BEGIN SELECT RAISE(ABORT,'immutable_configuration'); END",
}
for _table in ("host_profile_versions", "host_policy_versions"):
    for _action in ("UPDATE", "DELETE"):
        _name = _table + "_no_" + _action.lower()
        _DDL[_name] = f"CREATE TRIGGER {_name} BEFORE {_action} ON {_table} BEGIN SELECT RAISE(ABORT,'immutable_configuration'); END"
_PROJECTION = """SELECT generation,
 CASE WHEN length(CAST(digest AS BLOB))=64 THEN CAST(digest AS BLOB) ELSE NULL END,
 CASE WHEN typeof(payload)='blob' AND length(payload)<=262144 THEN payload ELSE NULL END,
 CASE WHEN length(CAST(operation_id AS BLOB))<=1024 THEN CAST(operation_id AS BLOB) ELSE NULL END,
 CASE WHEN phase IN ('prepared','committed') THEN CAST(phase AS BLOB) ELSE NULL END
 FROM main.host_configuration_revisions"""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _profiles(values):
    if type(values) is not tuple or len(values) > MAX_PROFILES:
        raise ValueError("bounded exact tuple of profiles required")
    if any(type(profile) is not ProfileDefinition for profile in values):
        raise TypeError("exact profile definitions required")
    if len({profile.profile_id for profile in values}) != len(values):
        raise ValueError("duplicate profile identity")
    definitions = {}
    for profile in values:
        key = profile.policy.policy_id, profile.policy.version
        previous = definitions.setdefault(key, profile.policy)
        if previous != profile.policy:
            raise ValueError("conflicting policy vocabulary")
    return tuple(sorted(values, key=lambda profile: profile.profile_id))


@dataclass(frozen=True, repr=False)
class ConfigurationRevision:
    authority_id: str
    generation: int
    sha256: str

    def __post_init__(self):
        _store_id(self.authority_id)
        _number(self.generation, "generation")
        if type(self.sha256) is not str or len(self.sha256) != 64 or any(c not in "0123456789abcdef" for c in self.sha256):
            raise ValueError("exact SHA-256 required")


@dataclass(frozen=True, repr=False)
class CancellationReference:
    operation_id: str
    revision: ConfigurationRevision

    def __post_init__(self):
        _text(self.operation_id, "operation_id")
        if type(self.revision) is not ConfigurationRevision:
            raise TypeError("exact abandoned revision required")


@dataclass(frozen=True, repr=False)
class ConfigurationSnapshot:
    revision: ConfigurationRevision
    profiles: tuple[ProfileDefinition, ...]
    registry: AuthorizationRegistry | None = None
    storage_version: int = 1
    abandoned: CancellationReference | None = None

    def __post_init__(self):
        if type(self.revision) is not ConfigurationRevision:
            raise TypeError("exact configuration revision required")
        if type(self.storage_version) is not int or self.storage_version not in (1, 2):
            raise ValueError("supported owner storage version required")
        if self.abandoned is not None and (self.storage_version != 2 or type(self.abandoned) is not CancellationReference
                or self.abandoned.revision.authority_id != self.revision.authority_id
                or self.abandoned.revision.generation != self.revision.generation):
            raise ValueError("same-generation explicit cancellation reference required")
        object.__setattr__(self, "profiles", _profiles(self.profiles))
        if self.registry is not None:
            if type(self.registry) is not AuthorizationRegistry:
                raise TypeError("exact authorization registry required")
            self.registry.validate_profiles(self.profiles)
        payload = self.canonical_bytes()
        if len(payload) > MAX_CONFIGURATION_BYTES:
            raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
        if hashlib.sha256(payload).hexdigest() != self.revision.sha256:
            raise ValueError("configuration digest mismatch")

    def canonical_bytes(self):
        return _configuration_bytes(self.revision.authority_id, self.revision.generation, self.profiles, self.registry,
                                    storage_version=self.storage_version, abandoned=self.abandoned)


@dataclass(frozen=True, repr=False)
class ConfigurationReceipt:
    revision: ConfigurationRevision
    operation_id: str
    phase: str

    def __post_init__(self):
        if type(self.revision) is not ConfigurationRevision:
            raise TypeError("exact configuration revision required")
        _text(self.operation_id, "operation_id")
        if self.phase not in ("prepared", "committed", "cancelled"):
            raise ValueError("unsupported receipt phase")


def _checkpoint(revision):
    return SnapshotCheckpoint(SnapshotIdentity(revision.authority_id, _WITNESS_BANK,
        _WITNESS_DOMAIN, revision.generation, revision.generation), revision.sha256)


def _configuration_bytes(authority_id, generation, profiles, registry, *, storage_version=1, abandoned=None):
    document = {"contract_version": 3 if storage_version == 2 else (1 if registry is None else 2), "authority_id": authority_id,
                "generation": generation, "profiles": [profile.to_dict() for profile in profiles]}
    if registry is not None or storage_version == 2:
        document["registry"] = None if registry is None else registry.to_dict()
    if storage_version == 2:
        document.update(storage_version=2, abandoned=None if abandoned is None else asdict(abandoned))
    return _canonical(document)


def _snapshot(authority_id, generation, profiles, registry=None, *, storage_version=1, abandoned=None):
    profiles = _profiles(profiles)
    if registry is not None:
        if type(registry) is not AuthorizationRegistry:
            raise TypeError("exact authorization registry required")
        registry.validate_profiles(profiles)
    payload = _configuration_bytes(authority_id, generation, profiles, registry, storage_version=storage_version, abandoned=abandoned)
    if len(payload) > MAX_CONFIGURATION_BYTES:
        raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
    revision = ConfigurationRevision(authority_id, generation, hashlib.sha256(payload).hexdigest())
    return ConfigurationSnapshot(revision, profiles, registry, storage_version, abandoned)


def _decode(authority_id, row):
    try:
        generation, digest, payload, operation, phase = row
        if (type(payload) is not bytes or len(payload) > MAX_CONFIGURATION_BYTES
                or type(digest) is not bytes or type(operation) is not bytes or type(phase) is not bytes):
            raise ValueError("invalid row")
        decoded = json.loads(payload)
        if type(decoded) is not dict:
            raise ValueError("invalid document")
        version = decoded.get("contract_version")
        expected = {"contract_version", "authority_id", "generation", "profiles"}
        if type(version) is int and version == 2:
            expected.add("registry")
        if type(version) is int and version == 3:
            expected.update({"registry", "storage_version", "abandoned"})
        if (set(decoded) != expected or type(version) is not int or version not in (1, 2, 3)
                or decoded["authority_id"] != authority_id or type(decoded["generation"]) is not int
                or decoded["generation"] != generation or type(decoded["profiles"]) is not list
                or len(decoded["profiles"]) > MAX_PROFILES):
            raise ValueError("invalid document")
        registry = AuthorizationRegistry.from_dict(decoded["registry"]) if version >= 2 and decoded["registry"] is not None else None
        if version == 2 and registry is None:
            raise ValueError("legacy registry envelope cannot omit registry")
        abandoned = None
        if version == 3:
            if type(decoded["storage_version"]) is not int or decoded["storage_version"] != 2:
                raise ValueError("explicit cancellable owner format required")
            if decoded["abandoned"] is not None:
                value = _exact_dict(decoded["abandoned"], {"operation_id", "revision"}, "cancellation")
                revision = ConfigurationRevision(**_exact_dict(value["revision"], {"authority_id", "generation", "sha256"}, "revision"))
                abandoned = CancellationReference(value["operation_id"], revision)
        snapshot = _snapshot(authority_id, generation, tuple(ProfileDefinition.from_dict(item) for item in decoded["profiles"]), registry,
                             storage_version=2 if version == 3 else 1, abandoned=abandoned)
        if phase not in (b"prepared", b"committed"):
            raise ValueError("physical rows cannot invent cancellation disposition")
        if snapshot.canonical_bytes() != payload or snapshot.revision.sha256 != digest.decode("ascii"):
            raise ValueError("noncanonical document")
        return snapshot, ConfigurationReceipt(snapshot.revision, operation.decode("utf-8"), phase.decode("ascii"))
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None


class HostConfigurationAuthority:
    """Trusted owner metadata API, not a configuration-administrator credential.

    The explicit witness is a separately pinned SnapshotAuthority, used only as
    a compare-and-advance journal for exact configuration digests. Both databases
    and raw owner capabilities must stay outside ordinary/model tools.
    """

    def __init__(self, conn, *, authority_id, witness_connection, witness_id, storage_version=1):
        if not isinstance(conn, sqlite3.Connection) or not isinstance(witness_connection, sqlite3.Connection):
            raise TypeError("explicit owner and witness connections required")
        _store_id(authority_id)
        _store_id(witness_id)
        if type(storage_version) is not int or storage_version not in (1, 2):
            raise ValueError("explicit supported owner format required")
        if conn is witness_connection or authority_id == witness_id:
            raise ValueError("independent witness connection and identity required")
        self._store = PolicyStore(conn)
        self._witness = SnapshotAuthority(witness_connection, authority_id=witness_id)
        self._witness_connection = witness_connection
        self._authority_id = authority_id
        self._storage_version, self._ddl = storage_version, _DDL
        if storage_version == 2:
            from .cancellable_configuration import definitions
            self._ddl = definitions()
        self._separate_files()

    def _separate_files(self):
        import os
        import stat

        if not hasattr(os, "geteuid"):
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        identities = []
        for conn in (self._store.conn, self._witness_connection):
            if conn.row_factory is not None or conn.text_factory is not str:
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            path = next(row[2] for row in conn.execute("PRAGMA database_list") if row[1] == "main")
            if not path:
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            try:
                info = os.lstat(path)
                parent = os.stat(os.path.dirname(path))
            except OSError:
                raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
                    or stat.S_IMODE(parent.st_mode) != 0o700):
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            identities.append((info.st_dev, info.st_ino))
        if identities[0] == identities[1]:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        if hasattr(self, "_file_identities") and self._file_identities != identities:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        self._file_identities = identities

    def _ready(self, *, write=False):
        self._separate_files()
        if self._store.conn.in_transaction or self._witness_connection.in_transaction:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        if write:
            self._witness._write_ready()
            conn = self._store.conn
            mode = conn.execute("PRAGMA main.journal_mode").fetchone()[0]
            sync = conn.execute("PRAGMA main.synchronous").fetchone()[0]
            if not ((mode == "wal" and sync in (2, 3)) or (mode == "delete" and sync == 3)):
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)

    def _schema(self):
        conn = self._store.conn
        ddl = self._ddl
        rows = conn.execute("SELECT CASE WHEN length(CAST(name AS BLOB))<=256 THEN name ELSE NULL END,CASE WHEN length(CAST(sql AS BLOB))<=16384 THEN sql ELSE NULL END FROM main.sqlite_master WHERE substr(name,1,7)!='sqlite_' AND type IN ('table','trigger','view','index') LIMIT ?", (len(ddl) + 1,)).fetchall()
        normalize = lambda value: "".join(value.split()) if type(value) is str else None
        if (len(rows) != len(ddl) or any(name not in ddl or normalize(sql) != normalize(ddl[name]) for name, sql in rows)
                or conn.execute("SELECT 1 FROM temp.sqlite_master LIMIT 1").fetchone() is not None):
            raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
        state = conn.execute("SELECT singleton,schema_version,CASE WHEN length(CAST(authority_id AS BLOB))=32 THEN CAST(authority_id AS BLOB) ELSE NULL END FROM main.host_configuration_state LIMIT 2").fetchall()
        if state != [(1, self._storage_version, self._authority_id.encode("ascii"))]:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)

    @_guard_policy_output
    def prepare(self):
        """Explicit provisioning only; creates no current profile or grant."""
        self._ready(write=True)
        self._witness.prepare()
        conn = self._store.conn
        with self._store._transaction(write=True):
            if not conn.execute("SELECT 1 FROM main.sqlite_master WHERE substr(name,1,7)!='sqlite_' LIMIT 1").fetchone():
                for ddl in self._ddl.values():
                    prefix = "CREATE TRIGGER " if ddl.startswith("CREATE TRIGGER ") else "CREATE TABLE "
                    conn.execute(ddl.replace(prefix, prefix + "main.", 1))
                conn.execute("INSERT INTO main.host_configuration_state VALUES(1,?,?)", (self._storage_version, self._authority_id))
            self._schema()

    def _row(self, *, operation_id=None, generation=None):
        if self._storage_version == 2:
            from .cancellable_configuration import row
            return row(self, operation_id=operation_id, generation=generation)
        return self._raw_row(operation_id=operation_id, generation=generation)

    def _raw_row(self, *, operation_id=None, generation=None):
        sql, parameters = _PROJECTION, ()
        if operation_id is not None:
            sql += " WHERE operation_id=?"
            parameters = (operation_id,)
        elif generation is not None:
            sql += " WHERE generation=?"
            parameters = (generation,)
        sql += " ORDER BY generation DESC LIMIT 1"
        row = self._store.conn.execute(sql, parameters).fetchone()
        return None if row is None else _decode(self._authority_id, row)

    def _require_witness(self, revision):
        if self._witness.current(self._authority_id) != _checkpoint(revision):
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)

    def _register_versions(self, profiles, *, record=True):
        if self._storage_version == 2:
            from .cancellable_configuration import register_versions
            return register_versions(self, profiles, record=record)
        conn = self._store.conn
        for profile in profiles:
            records = (
                ("host_profile_versions", "profile_id", profile.profile_id, profile.version, profile.canonical_bytes()),
                ("host_policy_versions", "policy_id", profile.policy.policy_id, profile.policy.version,
                 _canonical({"policy_id": profile.policy.policy_id, "version": profile.policy.version, "levels": list(profile.policy.levels)})),
            )
            for table, column, identity, version, payload in records:
                digest = hashlib.sha256(payload).hexdigest()
                prior = conn.execute(f"SELECT version,CASE WHEN length(CAST(digest AS BLOB))=64 THEN CAST(digest AS BLOB) ELSE NULL END FROM main.{table} WHERE {column}=? ORDER BY version DESC LIMIT 1", (identity,)).fetchone()
                if prior is not None and (type(prior[0]) is not int or prior[0] < 1 or type(prior[1]) is not bytes
                        or len(prior[1]) != 64 or any(c not in b"0123456789abcdef" for c in prior[1])):
                    raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
                if prior is not None and (version < prior[0] or (version == prior[0] and digest.encode("ascii") != prior[1])):
                    raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
                if prior is None or version > prior[0]:
                    conn.execute(f"INSERT INTO main.{table} VALUES(?,?,?)", (identity, version, digest))

    @_guard_policy_output
    def current(self):
        self._ready()
        with self._store._transaction():
            self._schema()
            head = self._row()
            if head is None:
                raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
            if head[1].phase == "prepared":
                head = self._row(generation=head[0].revision.generation - 1)
            if head is None or head[1].phase != "committed":
                raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
            self._require_witness(head[0].revision)
        self._require_witness(head[0].revision)
        if head[0].storage_version != self._storage_version:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        return head[0]

    @_guard_policy_output
    def receipt(self, operation_id):
        self._ready()
        _text(operation_id, "operation_id")
        with self._store._transaction():
            self._schema()
            row = self._row(operation_id=operation_id)
        return None if row is None else row[1]

    @_guard_policy_output
    def stage(self, profiles, *, previous, operation_id, registry=None):
        self._ready(write=True)
        _text(operation_id, "operation_id")
        if previous is not None and (type(previous) is not ConfigurationRevision or previous.authority_id != self._authority_id):
            raise TypeError("exact same-authority predecessor required")
        generation = 1 if previous is None else previous.generation + 1
        snapshot = _snapshot(self._authority_id, generation, profiles, registry, storage_version=self._storage_version)
        conn = self._store.conn
        with self._store._transaction(write=True):
            self._schema()
            head = self._row()
            if head is not None and head[0].storage_version != self._storage_version:
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            if head is not None and head[0].registry is not None and registry is None:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            existing = self._row(operation_id=operation_id)
            if existing is not None:
                if existing != head or existing[0] != snapshot:
                    raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
                return existing[1]
            if previous is None:
                if head is not None:
                    raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            else:
                if head is None or head[1].phase != "committed" or head[0].revision != previous:
                    raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
                self._require_witness(previous)
            if generation > MAX_CONFIGURATION_REVISIONS:
                raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
            self._register_versions(snapshot.profiles, record=self._storage_version == 1)
            conn.execute("INSERT INTO main.host_configuration_revisions VALUES(?,?,?,?,?)",
                         (generation, snapshot.revision.sha256, snapshot.canonical_bytes(), operation_id, "prepared"))
        return ConfigurationReceipt(snapshot.revision, operation_id, "prepared")

    def _stored(self, receipt):
        if type(receipt) is not ConfigurationReceipt or receipt.revision.authority_id != self._authority_id:
            raise TypeError("exact same-authority receipt required")
        stored = self._row(operation_id=receipt.operation_id)
        if stored is None or stored[0].revision != receipt.revision or stored != self._row():
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return stored

    @_guard_policy_output
    def advance_witness(self, receipt):
        """Explicit owner admission of a durable prepared successor."""
        if self._storage_version == 2:
            from .cancellable_configuration import advance_witness
            return advance_witness(self, receipt)
        self._ready(write=True)
        with self._store._transaction():
            self._schema()
            snapshot, _ = self._stored(receipt)
            old = self._row(generation=snapshot.revision.generation - 1)
        target = _checkpoint(snapshot.revision)
        operation_id = "host-config:" + hashlib.sha256(receipt.operation_id.encode("utf-8")).hexdigest()
        if snapshot.revision.generation == 1:
            self._witness.provision(target, operation_id=operation_id)
        else:
            if old is None or old[1].phase != "committed":
                raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
            self._witness.publish(_checkpoint(old[0].revision), target, operation_id=operation_id)
        return receipt

    @_guard_policy_output
    def finalize(self, receipt):
        if self._storage_version == 2:
            from .cancellable_configuration import finalize
            return finalize(self, receipt)
        self._ready(write=True)
        with self._store._transaction(write=True):
            self._schema()
            snapshot, stored = self._stored(receipt)
            self._require_witness(snapshot.revision)
            if stored.phase == "prepared":
                self._store.conn.execute("UPDATE main.host_configuration_revisions SET phase='committed' WHERE generation=?", (snapshot.revision.generation,))
        self._require_witness(snapshot.revision)
        return ConfigurationReceipt(snapshot.revision, receipt.operation_id, "committed")

    @_guard_policy_output
    def publish(self, profiles, *, previous, operation_id, registry=None):
        receipt = self.stage(profiles, previous=previous, operation_id=operation_id, registry=registry)
        self.advance_witness(receipt)
        return self.finalize(receipt)

    @_guard_policy_output
    def recover(self, operation_id):
        """Inspect uncertain outcomes; never advance an unwitnessed proposal."""
        receipt = self.receipt(operation_id)
        if receipt is None:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        self._ready()
        witness = self._witness.current(self._authority_id)
        if witness == _checkpoint(receipt.revision):
            return self.finalize(receipt)
        if receipt.phase == "prepared" and receipt.revision.generation > 1:
            with self._store._transaction():
                self._schema()
                old = self._row(generation=receipt.revision.generation - 1)
            if old is not None and old[1].phase == "committed" and witness == _checkpoint(old[0].revision):
                return receipt
        raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)

    @_guard_policy_output
    def cancellation_candidate(self, receipt, *, previous):
        from .cancellable_configuration import cancellation_candidate
        return cancellation_candidate(self, receipt, previous=previous)

    @_guard_policy_output
    def stage_cancellation(self, receipt, *, previous, operation_id):
        from .cancellable_configuration import stage_cancellation
        return stage_cancellation(self, receipt, previous=previous, operation_id=operation_id)

    @_guard_policy_output
    def migrate_cancellable(self, *, operation_id):
        from .cancellable_configuration import migrate
        return migrate(self, operation_id=operation_id)

    @_guard_policy_output
    def resume_cancellable_migration(self, operation_id):
        from .cancellable_configuration import resume_migration
        return resume_migration(self, operation_id)
