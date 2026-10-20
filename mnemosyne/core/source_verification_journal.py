"""Optional owner-reported verification history, not attestation or authorization."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field, fields
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import uuid4

from .resolvers import scheme_of
from .source_verification import SourceVerification

if TYPE_CHECKING:
    from .media import MediaStore

__all__ = [
    "SourceVerificationJournal", "VerificationJournalError", "VerificationRecord", "VerificationWrite",
]

_TABLE = "media_source_verification_events"
_INDEX = "idx_source_verification_revision"
_DDL = """CREATE TABLE media_source_verification_events (
    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
    event_id TEXT PRIMARY KEY NOT NULL,
    event_key TEXT NOT NULL,
    producer TEXT NOT NULL,
    recorded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    revision_id TEXT NOT NULL,
    locator TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    representation TEXT NOT NULL,
    expected_sha256 TEXT NOT NULL,
    expected_byte_size INTEGER,
    observed_sha256 TEXT,
    observed_byte_size INTEGER,
    UNIQUE(revision_id, event_key)
)"""
_INDEX_DDL = """CREATE INDEX idx_source_verification_revision
ON media_source_verification_events(revision_id, recorded_at, event_id)"""
_OBS_COLUMNS = tuple(item.name for item in fields(SourceVerification))
_META_COLUMNS = ("schema_version", "event_id", "event_key", "producer", "recorded_at")
_COLUMNS = _META_COLUMNS + _OBS_COLUMNS
_SELECT = ", ".join(_COLUMNS)
_REASONS = {
    "verified": {"bytes_match"},
    "changed": {"bytes_mismatch"},
    "missing": {"source_missing"},
    "inaccessible": {"source_inaccessible"},
    "unavailable": {"source_unavailable", "resolver_unconfigured"},
    "unverified": {"unsupported_representation", "unsupported_scheme", "invalid_stream", "resolver_failure", "close_failed"},
    "limit_exceeded": {"expected_size_exceeds_budget", "stream_exceeds_budget"},
}


class VerificationJournalError(RuntimeError):
    """Fixed-code refusal; raw SQLite failures still propagate to the owner."""

    def __init__(self, code):
        if code not in {"incompatible_schema", "invalid_record", "revision_mismatch", "event_conflict"}:
            raise ValueError("unsupported verification journal error")
        self.code = code
        super().__init__(f"verification_journal:{code}")


@dataclass(frozen=True)
class VerificationWrite:
    event_id: str = field(repr=False)
    status: str
    transaction_state: str


@dataclass(frozen=True, repr=False)
class VerificationRecord:
    event_id: str
    event_key: str
    producer: str
    recorded_at: str
    observation: SourceVerification


def _text(value, maximum):
    if (
        type(value) is not str or not value.strip() or len(value) > maximum
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("invalid verification journal text")
    return value


def _utc(value):
    if type(value) is not str or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", value,
    ) is None:
        raise ValueError("invalid verification journal UTC timestamp")
    datetime.fromisoformat(value[:-1] + "+00:00")


def _digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _validate(observation):
    if type(observation) is not SourceVerification:
        raise ValueError("a SourceVerification observation is required")
    values = {name: getattr(observation, name) for name in _OBS_COLUMNS}
    _text(values["revision_id"], 256)
    _text(values["asset_id"], 512)
    _text(values["representation"], 128)
    _text(values["locator"], 4096)
    scheme = scheme_of(values["locator"])
    if scheme is None or scheme in {"data", "javascript"}:
        raise ValueError("invalid verification journal locator")
    _utc(values["checked_at"])
    status, reason = values["status"], values["reason"]
    if type(status) is not str or type(reason) is not str or reason not in _REASONS.get(status, ()):
        raise ValueError("invalid verification journal outcome")
    if not _digest(values["expected_sha256"]):
        raise ValueError("invalid verification journal expected digest")
    expected_size = values["expected_byte_size"]
    observed_size = values["observed_byte_size"]
    if expected_size is not None and (type(expected_size) is not int or not 0 <= expected_size <= 2**63 - 1):
        raise ValueError("invalid verification journal expected size")
    if observed_size is not None and (type(observed_size) is not int or not 0 <= observed_size <= 1073741825):
        raise ValueError("invalid verification journal observed size")
    complete = status in {"verified", "changed"}
    if complete:
        if not _digest(values["observed_sha256"]) or observed_size is None:
            raise ValueError("complete verification requires digest and size")
        matches = values["expected_sha256"] == values["observed_sha256"] and (
            expected_size is None or expected_size == observed_size
        )
        if matches != (status == "verified") or values["representation"] != "original-bytes":
            raise ValueError("inconsistent complete verification")
    elif values["observed_sha256"] is not None:
        raise ValueError("partial verification cannot carry a digest")
    if reason in {"unsupported_representation", "unsupported_scheme", "resolver_unconfigured", "expected_size_exceeds_budget"}:
        if observed_size is not None:
            raise ValueError("unopened source cannot carry an observed size")
    if (reason == "unsupported_representation") != (values["representation"] != "original-bytes"):
        raise ValueError("inconsistent verification representation")
    if reason == "stream_exceeds_budget" and (observed_size is None or observed_size == 0):
        raise ValueError("stream overflow requires an observed byte")
    if reason == "expected_size_exceeds_budget" and (expected_size is None or expected_size == 0):
        raise ValueError("expected overflow requires an asserted size")
    return values


def _event_id(revision_id, event_key):
    payload = json.dumps(["v1", revision_id, event_key], separators=(",", ":"))
    return "verification:sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _sql_shape(value):
    return " ".join(value.split()) if isinstance(value, str) else None


class SourceVerificationJournal:
    """Explicit connection-owned journal; construction never prepares schema."""

    def __init__(self, store: "MediaStore"):
        if not isinstance(store.conn, sqlite3.Connection):
            raise TypeError("an existing MediaStore connection is required")
        self.conn = store.conn

    @contextmanager
    def _transaction(self, *, write=False):
        owns = not self.conn.in_transaction
        if owns and write:
            self.conn.execute("BEGIN IMMEDIATE")
        started = False
        savepoint = "source_verification_" + uuid4().hex
        try:
            self.conn.execute(f"SAVEPOINT {savepoint}")
            started = True
            yield owns
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

    def _schema(self, *, create=False):
        existing = self.conn.execute(
            "SELECT type, sql FROM main.sqlite_master WHERE name = ?", (_TABLE,),
        ).fetchone()
        index = self.conn.execute(
            "SELECT type, sql FROM main.sqlite_master WHERE name = ?", (_INDEX,),
        ).fetchone()
        if existing is None and index is None:
            if not create:
                return False
            self.conn.execute(_DDL.replace("CREATE TABLE ", "CREATE TABLE main.", 1))
            self.conn.execute(_INDEX_DDL.replace("CREATE INDEX ", "CREATE INDEX main.", 1))
            return self._schema()
        if (
            existing is None or index is None or existing[0] != "table" or index[0] != "index"
            or _sql_shape(existing[1]) != _sql_shape(_DDL)
            or _sql_shape(index[1]) != _sql_shape(_INDEX_DDL)
            or self.conn.execute(
                "SELECT 1 FROM main.sqlite_master WHERE type = 'trigger' AND tbl_name = ? LIMIT 1", (_TABLE,),
            ).fetchone() is not None
        ):
            raise VerificationJournalError("incompatible_schema")
        return True

    def _decode(self, row):
        values = dict(zip(_COLUMNS, row))
        try:
            if values["schema_version"] != 1:
                raise ValueError("unknown schema version")
            _text(values["event_key"], 256)
            _text(values["producer"], 256)
            _utc(values["recorded_at"])
            observation = SourceVerification(**{name: values[name] for name in _OBS_COLUMNS})
            _validate(observation)
            if values["event_id"] != _event_id(observation.revision_id, values["event_key"]):
                raise ValueError("incorrect event identity")
        except (KeyError, TypeError, ValueError):
            raise VerificationJournalError("invalid_record") from None
        return VerificationRecord(
            values["event_id"], values["event_key"], values["producer"], values["recorded_at"], observation,
        )

    def record(self, observation, *, event_key, producer):
        """Append an owner report or return an exact retry; never verify a source."""
        payload = _validate(observation)
        event_key, producer = _text(event_key, 256), _text(producer, 256)
        event_id = _event_id(observation.revision_id, event_key)
        with self._transaction(write=True) as owns:
            self._schema(create=True)
            source = self.conn.execute(
                "SELECT asset_id, representation, content_hash, byte_size, digest_status "
                "FROM main.media_source_revisions WHERE revision_id = ?", (observation.revision_id,),
            ).fetchone()
            expected = (observation.asset_id, observation.representation, observation.expected_sha256,
                        observation.expected_byte_size, "asserted")
            if source is None or tuple(source) != expected:
                raise VerificationJournalError("revision_mismatch")
            columns = ("schema_version", "event_id", "event_key", "producer") + _OBS_COLUMNS
            cursor = self.conn.execute(
                f"INSERT INTO main.{_TABLE} ({', '.join(columns)}) "
                f"VALUES ({', '.join('?' for _ in columns)}) "
                "ON CONFLICT(revision_id, event_key) DO NOTHING",
                (1, event_id, event_key, producer, *(payload[name] for name in _OBS_COLUMNS)),
            )
            # count_changes can make INSERT return a row until stepped to EOF.
            cursor.fetchall()
            if cursor.rowcount not in (0, 1):
                raise VerificationJournalError("invalid_record")
            row = self.conn.execute(
                f"SELECT {_SELECT} FROM main.{_TABLE} WHERE revision_id = ? AND event_key = ?",
                (observation.revision_id, event_key),
            ).fetchone()
            if row is None:
                raise VerificationJournalError("invalid_record")
            actual = self._decode(row)
            if actual.event_id != event_id or actual.producer != producer or actual.observation != observation:
                raise VerificationJournalError("event_conflict")
            receipt = VerificationWrite(event_id, "created" if cursor.rowcount == 1 else "unchanged",
                                        "committed" if owns else "pending")
        return receipt

    def get(self, revision_id, *, event_key):
        """Read an exact caller-snapshot event, not a source-freshness guarantee."""
        revision_id, event_key = _text(revision_id, 256), _text(event_key, 256)
        with self._transaction():
            if not self._schema():
                return None
            row = self.conn.execute(
                f"SELECT {_SELECT} FROM main.{_TABLE} WHERE revision_id = ? AND event_key = ?",
                (revision_id, event_key),
            ).fetchone()
            return self._decode(row) if row is not None else None

    def list(self, revision_id, *, limit=100, offset=0):
        """Return a bounded deterministic page; never create missing schema."""
        revision_id = _text(revision_id, 256)
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be an integer in 1..1000")
        if type(offset) is not int or not 0 <= offset <= 2**63 - 1:
            raise ValueError("offset must be a nonnegative SQLite integer")
        with self._transaction():
            if not self._schema():
                return []
            return [self._decode(row) for row in self.conn.execute(
                f"SELECT {_SELECT} FROM main.{_TABLE} WHERE revision_id = ? "
                "ORDER BY recorded_at, event_id LIMIT ? OFFSET ?", (revision_id, limit, offset),
            ).fetchall()]
