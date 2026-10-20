"""Explicit atomic native creation; no legacy write retrofit or activation."""

from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from mnemosyne.core.policy import (
    AdapterCapabilities, MemoryPolicy, PolicyRefusal, PolicySurface,
    RefusalReason, _number, _text,
)
from mnemosyne.core.policy_store import PolicyStore, PolicyStoreError, RecordKind, StoreErrorCode, _identity
from mnemosyne.runtime_context import get_access_context


MAX_CONTENT_CHARACTERS = 16384


def _digest(value, name):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"{name} must be a SHA-256 hex digest")


@dataclass(frozen=True, repr=False)
class MemoryWriteIntent:
    """Bounded request identity; a digest is not anonymization or authorization."""

    record_kind: RecordKind
    record_id: str
    content_sha256: str
    content_characters: int
    conversation_id: str

    def __post_init__(self):
        if self.record_kind not in (RecordKind.WORKING, RecordKind.EPISODIC) or not isinstance(self.record_kind, RecordKind):
            raise ValueError("record_kind must be working or episodic")
        _identity(self.record_kind, self.record_id)
        _digest(self.content_sha256, "content_sha256")
        if _number(self.content_characters, "content_characters") > MAX_CONTENT_CHARACTERS:
            raise ValueError("content exceeds supported bound")
        _text(self.conversation_id, "conversation_id")

    def fingerprint(self):
        value = [1, "create", self.record_kind.value, self.record_id, self.content_sha256,
                 self.content_characters, self.conversation_id]
        return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True, repr=False)
class MemoryWriteGrant:
    """Host decision bound to one intent; constructing this is not authentication."""

    context_fingerprint: str
    intent_fingerprint: str
    domain_id: str
    bank: str
    destination: str
    decision_id: str
    policy: MemoryPolicy

    def __post_init__(self):
        _digest(self.context_fingerprint, "context_fingerprint")
        _digest(self.intent_fingerprint, "intent_fingerprint")
        for name in ("domain_id", "bank", "destination", "decision_id"):
            _text(getattr(self, name), name)
        if not isinstance(self.policy, MemoryPolicy):
            raise TypeError("policy must be an explicit MemoryPolicy")


@dataclass(frozen=True, repr=False)
class AuthorizedCreation:
    record_kind: RecordKind
    record_id: str
    bank: str
    binding_id: str
    decision_id: str
    context_id: str
    context_epoch: int
    intent_fingerprint: str
    transaction_state: str


def _native_surface(conn, kind):
    required = {"id", "content", "source", "timestamp", "session_id", "scope", "author_id", "channel_id"}
    columns = {r[1]: r for r in conn.execute(f"PRAGMA main.table_xinfo('{kind.value}')")}
    if not required <= columns.keys() or any(columns[n][2].upper() != "TEXT" or columns[n][6] != 0 for n in required):
        raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
    fts, trigger = ("fts_working", "wm_ai") if kind is RecordKind.WORKING else ("fts_episodes", "em_ai")
    expected = (("id", 0), ("content", 0), (fts, 1), ("rank", 1)) if kind is RecordKind.WORKING else (("content", 0), (fts, 1), ("rank", 1))
    if tuple((r[1], r[6]) for r in conn.execute(f"PRAGMA main.table_xinfo('{fts}')")) != expected:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
    row = conn.execute("SELECT tbl_name,sql FROM main.sqlite_master WHERE type='trigger' AND name=?", (trigger,)).fetchone()
    keys, values = ("id, content", "new.id, new.content") if kind is RecordKind.WORKING else ("rowid, content", "new.rowid, new.content")
    expected_trigger = f"CREATE TRIGGER {trigger} AFTER INSERT ON {kind.value} BEGIN INSERT INTO {fts}({keys}) VALUES ({values}); END"
    normalize = lambda s: "".join(s.split()).lower()
    if row is None or row[0] != kind.value or row[1] is None or normalize(row[1]) != normalize(expected_trigger):
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)


class PolicyWriter:
    """Creation-only explicit API; trusted host owns input policy and freshness."""

    capabilities = AdapterCapabilities("core-policy-create", {PolicySurface.WRITE})

    def __init__(self, store: PolicyStore, *, bank: str, verify_context: Callable):
        if not isinstance(store, PolicyStore):
            raise TypeError("store must be an explicit PolicyStore")
        if not callable(verify_context) or inspect.iscoroutinefunction(verify_context):
            raise TypeError("verify_context must be a synchronous trusted verifier")
        self._store = store
        self._bank = _text(bank, "bank")
        self._verify = verify_context

    def create(self, beam, content, *, record_kind, record_id, destination):
        from mnemosyne.core.beam import BeamMemory

        if not isinstance(beam, BeamMemory) or self._store.conn is not beam.conn:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        if record_kind not in (RecordKind.WORKING, RecordKind.EPISODIC) or not isinstance(record_kind, RecordKind):
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        identity = _identity(record_kind, record_id)
        if type(content) is not str or not 1 <= len(content) <= MAX_CONTENT_CHARACTERS or not content.strip() or "\0" in content:
            raise ValueError("content must be bounded nonblank text without NUL")
        try:
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        except UnicodeError:
            raise ValueError("content must be valid UTF-8 text") from None
        destination = _text(destination, "destination")
        context = get_access_context(required=True)
        if context.assurance != "authenticated" or context.projects:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        if context.conversation_id != beam.session_id or self._bank not in context.banks or destination not in context.destinations or f"create:{record_kind.value}" not in context.operations:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        intent = MemoryWriteIntent(record_kind, identity, digest, len(content), context.conversation_id)
        try:
            grant = self._verify(context, bank=self._bank, destination=destination, intent=intent)
        except PolicyRefusal:
            raise
        except Exception:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None
        if inspect.isawaitable(grant):
            if inspect.iscoroutine(grant):
                grant.close()
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        if not isinstance(grant, MemoryWriteGrant) or (grant.context_fingerprint, grant.intent_fingerprint, grant.bank, grant.destination) != (
            context.fingerprint(), intent.fingerprint(), self._bank, destination
        ) or beam.conn is not self._store.conn or beam.session_id != intent.conversation_id:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        policy = grant.policy
        if policy.classification_source != "context" or (policy.origin_context_id, policy.origin_context_epoch) != (context.context_id, context.epoch) or policy.owner not in context.principals:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        if policy.overlays:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        conn = self._store.conn
        caller_owned = conn.in_transaction
        with self._store._transaction(write=True):
            domain = self._store._domain(required=True)
            if domain.domain_id != grant.domain_id:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            definition = self._store._definition(context.policy_id, context.policy_version)
            if definition is None:
                raise PolicyRefusal(RefusalReason.POLICY_MISMATCH)
            definition.validate_context(context)
            definition.validate_binding(policy)
            if (definition.levels.index(policy.classification) > definition.levels.index(context.classification_ceiling)
                or not policy.compartments <= context.compartments or not policy.audiences & context.audiences or context.purpose not in policy.purposes):
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            _native_surface(conn, record_kind)
            # Never deduplicate content, disclose a prior row or replace an ID.
            occupied = conn.execute(f"SELECT 1 FROM main.{record_kind.value} WHERE id=? LIMIT 1", (identity,)).fetchone()
            bound = conn.execute("SELECT 1 FROM main.policy_bindings WHERE record_kind=? AND record_id=?", (record_kind.value, identity)).fetchone()
            if occupied or bound:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            conn.execute(f"""INSERT INTO main.{record_kind.value}
                (id,content,source,timestamp,session_id,scope,author_id,channel_id)
                VALUES(?,?,'conversation',?,?,'session',?,?)""",
                (identity, content, datetime.now(timezone.utc).isoformat(), intent.conversation_id, policy.owner,
                 context.channel_id or intent.conversation_id))
            binding = self._store.bind(record_kind, identity, policy)
            native = conn.execute(f"""SELECT 1 FROM main.{record_kind.value}
                WHERE id=? AND content=? AND session_id=? AND scope='session'
                  AND author_id=? AND channel_id=?""", (identity, content, intent.conversation_id, policy.owner,
                                                        context.channel_id or intent.conversation_id)).fetchone()
            persisted = self._store._binding(record_kind, identity, domain)
            if native is None or persisted is None or persisted.policy != policy:
                raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
        return AuthorizedCreation(record_kind, identity, self._bank, binding.binding_id, grant.decision_id,
                                  context.context_id, context.epoch, intent.fingerprint(), "pending" if caller_owned else "committed")


def create_authorized(beam, content, *, writer, record_kind, record_id, destination):
    if not isinstance(writer, PolicyWriter):
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    return writer.create(beam, content, record_kind=record_kind, record_id=record_id, destination=destination)
