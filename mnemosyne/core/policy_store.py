"""Opt-in, prepared policy metadata. This module does not protect retrieval.

Only explicit owner-mode calls create schema. No default database, activation,
backfill, content mutation or authorization is supplied by this catalog.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union
from uuid import uuid4

from mnemosyne.core.policy import (
    POLICY_CONTRACT_VERSION, MemoryPolicy, PolicyDefinition, _number, _text,
)


POLICY_SCHEMA_VERSION = 1


class RecordKind(str, Enum):
    WORKING = "working_memory"
    EPISODIC = "episodic_memory"
    CANONICAL = "canonical_facts"


class StoreErrorCode(str, Enum):
    UNPREPARED = "unprepared"
    INCOMPATIBLE = "incompatible"


class PolicyStoreError(RuntimeError):
    """Content-free refusal of absent, incomplete or unsupported catalogs."""

    def __init__(self, code: StoreErrorCode):
        if not isinstance(code, StoreErrorCode):
            raise ValueError("code must be a StoreErrorCode")
        self.code = code
        super().__init__(f"policy_store:{code.value}")


@dataclass(frozen=True, repr=False)
class PreparedDomain:
    domain_id: str
    schema_version: int = POLICY_SCHEMA_VERSION
    contract_version: int = POLICY_CONTRACT_VERSION
    mode: str = "prepared"


@dataclass(frozen=True, repr=False)
class PolicyBindingWrite:
    binding_id: str
    status: str


@dataclass(frozen=True, repr=False)
class PolicyBindingRecord:
    binding_id: str
    record_kind: RecordKind
    record_id: Union[str, int]
    policy: MemoryPolicy
    registered_at: str


_COLUMNS = {
    "policy_store_state": ("singleton", "schema_version", "contract_version", "domain_id", "mode"),
    "policy_definitions": ("policy_id", "version", "registered_at"),
    "policy_levels": ("policy_id", "version", "rank", "label"),
    "policy_bindings": ("binding_id", "record_kind", "record_id", "policy_id", "policy_version", "classification",
                        "classification_source", "owner", "tenant_id", "origin_context_id", "origin_context_epoch", "registered_at"),
    "policy_binding_terms": ("binding_id", "dimension", "value"),
}
_PRIMARY = {
    "policy_store_state": ("singleton",), "policy_definitions": ("policy_id", "version"),
    "policy_levels": ("policy_id", "version", "label"), "policy_bindings": ("binding_id",),
    "policy_binding_terms": ("binding_id", "dimension", "value"),
}
_INDEXES = {
    "idx_policy_binding_classification": ("policy_bindings", ("policy_id", "policy_version", "classification", "record_kind", "record_id")),
    "idx_policy_binding_owner": ("policy_bindings", ("owner", "record_kind", "record_id")),
    "idx_policy_binding_tenant": ("policy_bindings", ("tenant_id", "record_kind", "record_id")),
    "idx_policy_terms_reverse": ("policy_binding_terms", ("dimension", "value", "binding_id")),
}
_DIMENSIONS = ("compartments", "audiences", "purposes", "overlays")
_BINDING_COLUMNS = ", ".join(_COLUMNS["policy_bindings"])
_INTEGER_COLUMNS = frozenset({"singleton", "schema_version", "contract_version", "version", "rank", "policy_version", "origin_context_epoch"})
_NULLABLE_COLUMNS = frozenset({"singleton", "binding_id", "tenant_id", "origin_context_id", "origin_context_epoch"})
_UNIQUE = {"policy_levels": ("policy_id", "version", "rank"), "policy_bindings": ("record_kind", "record_id")}


def _identity(kind: RecordKind, record_id) -> str:
    if not isinstance(kind, RecordKind):
        raise ValueError("record_kind must be a supported RecordKind")
    if kind is RecordKind.CANONICAL:
        return str(_number(record_id, "record_id"))
    return _text(record_id, "record_id", 512)


def _binding_id(domain_id: str, kind: RecordKind, record_id: str) -> str:
    encoded = json.dumps(["v1", domain_id, kind.value, record_id], separators=(",", ":"))
    return "binding:sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class PolicyStore:
    """Prepared owner-mode catalog over an explicitly supplied connection."""

    def __init__(self, conn: sqlite3.Connection):
        if not isinstance(conn, sqlite3.Connection):
            raise TypeError("conn must be an explicit sqlite3.Connection")
        self.conn = conn

    @contextmanager
    def _transaction(self, *, write=False):
        owns = not self.conn.in_transaction
        if owns and write:
            self.conn.execute("BEGIN IMMEDIATE")
        started = False
        savepoint = "policy_catalog_" + uuid4().hex
        try:
            self.conn.execute(f"SAVEPOINT {savepoint}")
            started = True
            yield
            self.conn.execute(f"RELEASE SAVEPOINT {savepoint}")
            if owns and write:
                self.conn.execute("COMMIT")
        except BaseException:
            if started:
                with suppress(sqlite3.Error):
                    self.conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                    self.conn.execute(f"RELEASE SAVEPOINT {savepoint}")
            if owns:
                with suppress(sqlite3.Error):
                    self.conn.execute("ROLLBACK")
            raise

    def _domain(self, *, required=False) -> Optional[PreparedDomain]:
        names = {row[0] for row in self.conn.execute(
            "SELECT name FROM main.sqlite_master WHERE type='table' AND name IN (?, ?, ?, ?, ?)", tuple(_COLUMNS),
        )}
        if not names:
            if required:
                raise PolicyStoreError(StoreErrorCode.UNPREPARED)
            return None
        if names != set(_COLUMNS):
            raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
        for table, columns in _COLUMNS.items():
            info = self.conn.execute(f"PRAGMA main.table_info('{table}')").fetchall()
            primary = tuple(row[1] for row in sorted((r for r in info if r[5]), key=lambda r: r[5]))
            if tuple(row[1] for row in info) != columns or primary != _PRIMARY[table]:
                raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
            for row in info:
                expected_type = "INTEGER" if row[1] in _INTEGER_COLUMNS else "TEXT"
                nullable = row[1] in _NULLABLE_COLUMNS and (table == "policy_store_state" or table == "policy_bindings")
                if row[2].upper() != expected_type or row[3] != int(not nullable):
                    raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
            if table in _UNIQUE:
                unique = self.conn.execute(f"PRAGMA main.index_list('{table}')").fetchall()
                found = False
                for index in unique:
                    if index[2] and not index[4]:
                        indexed = self.conn.execute("SELECT name FROM main.pragma_index_info(?, 'main') ORDER BY seqno", (index[1],)).fetchall()
                        if tuple(r[0] for r in indexed) == _UNIQUE[table]:
                            found = True
                if not found:
                    raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
        for name, (table, columns) in _INDEXES.items():
            listed = self.conn.execute(f"PRAGMA main.index_list('{table}')").fetchall()
            record = next((row for row in listed if row[1] == name), None)
            actual = tuple(row[2] for row in self.conn.execute(f"PRAGMA main.index_info('{name}')"))
            if record is None or record[2] or record[4] or actual != columns:
                raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
        rows = self.conn.execute(
            "SELECT singleton, schema_version, contract_version, domain_id, mode FROM main.policy_store_state LIMIT 2"
        ).fetchall()
        if len(rows) != 1 or tuple(rows[0][:3]) != (1, POLICY_SCHEMA_VERSION, POLICY_CONTRACT_VERSION) or rows[0][4] != "prepared":
            raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
        try:
            return PreparedDomain(_text(rows[0][3], "domain_id"))
        except ValueError:
            raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE) from None

    def get_domain(self) -> Optional[PreparedDomain]:
        """Read a persistent preparation marker; it is not protected activation."""
        with self._transaction():
            return self._domain()

    def prepare(self, domain_id: str) -> PreparedDomain:
        """Atomically prepare metadata only; never backfill or enable protection."""
        domain_id = _text(domain_id, "domain_id")
        with self._transaction(write=True):
            existing = self._domain()
            if existing is not None:
                if existing.domain_id != domain_id:
                    raise ValueError("catalog already belongs to a different domain")
                return existing
            statements = (
                "CREATE TABLE main.policy_store_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
                "schema_version INTEGER NOT NULL, contract_version INTEGER NOT NULL, domain_id TEXT NOT NULL, "
                "mode TEXT NOT NULL CHECK(mode='prepared'))",
                "CREATE TABLE main.policy_definitions (policy_id TEXT NOT NULL, version INTEGER NOT NULL, "
                "registered_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), PRIMARY KEY(policy_id, version))",
                "CREATE TABLE main.policy_levels (policy_id TEXT NOT NULL, version INTEGER NOT NULL, rank INTEGER NOT NULL, "
                "label TEXT NOT NULL, PRIMARY KEY(policy_id,version,label), UNIQUE(policy_id,version,rank))",
                "CREATE TABLE main.policy_bindings (binding_id TEXT PRIMARY KEY, record_kind TEXT NOT NULL, record_id TEXT NOT NULL, "
                "policy_id TEXT NOT NULL, policy_version INTEGER NOT NULL, classification TEXT NOT NULL, "
                "classification_source TEXT NOT NULL, owner TEXT NOT NULL, tenant_id TEXT, origin_context_id TEXT, "
                "origin_context_epoch INTEGER, registered_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), "
                "UNIQUE(record_kind,record_id))",
                "CREATE TABLE main.policy_binding_terms (binding_id TEXT NOT NULL, dimension TEXT NOT NULL, "
                "value TEXT NOT NULL, PRIMARY KEY(binding_id,dimension,value))",
            )
            for statement in statements:
                self.conn.execute(statement)
            for name, (table, columns) in _INDEXES.items():
                self.conn.execute(f"CREATE INDEX main.{name} ON {table} ({', '.join(columns)})")
            self.conn.execute("INSERT INTO main.policy_store_state VALUES (1, ?, ?, ?, 'prepared')",
                              (POLICY_SCHEMA_VERSION, POLICY_CONTRACT_VERSION, domain_id))
            return self._domain(required=True)

    def _definition(self, policy_id: str, version: int) -> Optional[PolicyDefinition]:
        exists = self.conn.execute(
            "SELECT 1 FROM main.policy_definitions WHERE policy_id=? AND version=?", (policy_id, version),
        ).fetchone()
        if exists is None:
            return None
        levels = self.conn.execute(
            "SELECT rank,label FROM main.policy_levels WHERE policy_id=? AND version=? ORDER BY rank LIMIT 65", (policy_id, version),
        ).fetchall()
        try:
            if [row[0] for row in levels] != list(range(len(levels))):
                raise ValueError("noncontiguous vocabulary")
            return PolicyDefinition(policy_id, version, tuple(row[1] for row in levels))
        except ValueError:
            raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE) from None

    def get_definition(self, policy_id: str, version: int) -> Optional[PolicyDefinition]:
        policy_id, version = _text(policy_id, "policy_id"), _number(version, "version")
        with self._transaction():
            if self._domain() is None:
                return None
            return self._definition(policy_id, version)

    def register_definition(self, definition: PolicyDefinition) -> str:
        """Register immutable vocabulary, not a current policy selection."""
        if not isinstance(definition, PolicyDefinition):
            raise TypeError("definition must be a PolicyDefinition")
        with self._transaction(write=True):
            self._domain(required=True)
            existing = self._definition(definition.policy_id, definition.version)
            if existing is not None:
                if existing != definition:
                    raise ValueError("policy version already names a different vocabulary")
                return "unchanged"
            self.conn.execute("INSERT INTO main.policy_definitions (policy_id,version) VALUES (?,?)",
                              (definition.policy_id, definition.version))
            self.conn.executemany("INSERT INTO main.policy_levels (policy_id,version,rank,label) VALUES (?,?,?,?)",
                                  [(definition.policy_id, definition.version, rank, label) for rank, label in enumerate(definition.levels)])
            return "created"

    def _binding(self, kind: RecordKind, identity: str, domain: PreparedDomain) -> Optional[PolicyBindingRecord]:
        row = self.conn.execute(f"SELECT {_BINDING_COLUMNS} FROM main.policy_bindings WHERE record_kind=? AND record_id=?",
                                (kind.value, identity)).fetchone()
        if row is None:
            return None
        binding_id, record_kind, record_id, policy_id, version, classification, source, owner, tenant, context_id, epoch, registered_at = row
        terms = {name: set() for name in _DIMENSIONS}
        rows = self.conn.execute("SELECT dimension,value FROM main.policy_binding_terms WHERE binding_id=? LIMIT 1025", (binding_id,)).fetchall()
        try:
            if len(rows) > 1024 or binding_id != _binding_id(domain.domain_id, kind, identity) or record_kind != kind.value or record_id != identity:
                raise ValueError("invalid binding identity")
            for dimension, value in rows:
                if dimension not in terms:
                    raise ValueError("unsupported restriction dimension")
                terms[dimension].add(value)
            policy = MemoryPolicy(policy_id=policy_id, policy_version=version, classification=classification, owner=owner,
                                  classification_source=source, tenant_id=tenant, origin_context_id=context_id,
                                  origin_context_epoch=epoch, **terms)
            definition = self._definition(policy_id, version)
            if definition is None or classification not in definition.levels:
                raise ValueError("missing vocabulary")
            _text(registered_at, "registered_at", 64)
        except (ValueError, TypeError):
            raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE) from None
        return PolicyBindingRecord(binding_id, kind, int(identity) if kind is RecordKind.CANONICAL else identity, policy, registered_at)

    def get_binding(self, record_kind: RecordKind, record_id) -> Optional[PolicyBindingRecord]:
        """Read owner-mode metadata, not an authorized memory result."""
        identity = _identity(record_kind, record_id)
        with self._transaction():
            domain = self._domain()
            return None if domain is None else self._binding(record_kind, identity, domain)

    def bind(self, record_kind: RecordKind, record_id, policy: MemoryPolicy) -> PolicyBindingWrite:
        """Bind an existing native parent once; changed restrictions conflict."""
        identity = _identity(record_kind, record_id)
        if not isinstance(policy, MemoryPolicy):
            raise TypeError("policy must be a MemoryPolicy")
        with self._transaction(write=True):
            domain = self._domain(required=True)
            definition = self._definition(policy.policy_id, policy.policy_version)
            if definition is None:
                raise ValueError("policy definition must be registered before binding")
            definition.validate_binding(policy)
            # Enum-only identifiers and explicit main schema defeat both SQL
            # injection and connection-local temp-table shadowing.
            table = record_kind.value
            exists = self.conn.execute("SELECT 1 FROM main.sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            if exists is None or self.conn.execute(f'SELECT 1 FROM main."{table}" WHERE id=?', (record_id,)).fetchone() is None:
                raise ValueError("native parent must exist before binding")
            existing = self._binding(record_kind, identity, domain)
            if existing is not None:
                if existing.policy != policy:
                    raise ValueError("native record already has a different immutable policy binding")
                return PolicyBindingWrite(existing.binding_id, "unchanged")
            binding_id = _binding_id(domain.domain_id, record_kind, identity)
            self.conn.execute("""INSERT INTO main.policy_bindings (
                binding_id,record_kind,record_id,policy_id,policy_version,classification,
                classification_source,owner,tenant_id,origin_context_id,origin_context_epoch
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                              (binding_id, record_kind.value, identity, policy.policy_id, policy.policy_version,
                               policy.classification, policy.classification_source, policy.owner, policy.tenant_id,
                               policy.origin_context_id, policy.origin_context_epoch))
            self.conn.executemany("INSERT INTO main.policy_binding_terms (binding_id,dimension,value) VALUES (?,?,?)",
                                  [(binding_id, name, label) for name in _DIMENSIONS for label in sorted(getattr(policy, name))])
            return PolicyBindingWrite(binding_id, "created")
