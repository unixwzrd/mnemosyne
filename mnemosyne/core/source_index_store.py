"""Optional owner-mode durable excerpts; not protected or legacy ingestion."""

from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
import hashlib
import re
import sqlite3
from uuid import uuid4

from .media import compute_asset_id, normalize_ref
from .source_indexing import (
    MAX_EXTRACTION_BYTES, ExcerptLimits, SourceExcerpt, SourceIndexPlan, SourceSpan,
    _external_locator, _plan_fingerprint, plan_source_index,
)


_GROUPS = "media_source_index_groups"
_ASSETS = "media_source_index_assets"
_PLANS = "media_source_index_plans"
_EXCERPTS = "media_source_index_excerpts"
_DDL = {
    _GROUPS: f"""CREATE TABLE {_GROUPS} (
        source_key TEXT PRIMARY KEY NOT NULL,
        per_excerpt_bytes INTEGER NOT NULL,
        retained_bytes INTEGER NOT NULL,
        excerpt_count INTEGER NOT NULL,
        byte_ceiling INTEGER
    )""",
    _ASSETS: f"""CREATE TABLE {_ASSETS} (
        asset_id TEXT PRIMARY KEY NOT NULL,
        source_key TEXT NOT NULL REFERENCES {_GROUPS}(source_key)
    )""",
    _PLANS: f"""CREATE TABLE {_PLANS} (
        fingerprint TEXT PRIMARY KEY NOT NULL,
        source_key TEXT NOT NULL REFERENCES {_GROUPS}(source_key),
        source_revision_id TEXT NOT NULL,
        extraction_sha256 TEXT NOT NULL,
        output_locator TEXT NOT NULL,
        source_utf8_bytes INTEGER NOT NULL
    )""",
    _EXCERPTS: f"""CREATE TABLE {_EXCERPTS} (
        fingerprint TEXT NOT NULL REFERENCES {_PLANS}(fingerprint),
        ordinal INTEGER NOT NULL,
        char_start INTEGER NOT NULL,
        char_end INTEGER NOT NULL,
        text TEXT NOT NULL,
        utf8_bytes INTEGER NOT NULL,
        text_sha256 TEXT NOT NULL,
        PRIMARY KEY(fingerprint, ordinal)
    )""",
}
_INDEX_DDL = {
    "idx_source_index_assets_group": f"CREATE INDEX idx_source_index_assets_group ON {_ASSETS}(source_key)",
    "idx_source_index_plans_group": f"CREATE INDEX idx_source_index_plans_group ON {_PLANS}(source_key)",
}


class SourceIndexStoreError(RuntimeError):
    """Content-free owner-mode refusal; raw SQLite failures remain explicit."""

    def __init__(self, code):
        self.code = code
        super().__init__("source_index_store:" + code)


@dataclass(frozen=True)
class SourceRegistration:
    asset_id: str = field(repr=False)
    status: str
    transaction_state: str


@dataclass(frozen=True)
class SourceIndexWrite:
    fingerprint: str = field(repr=False)
    status: str
    transaction_state: str


@dataclass(frozen=True)
class SourceIndexUsage:
    retained_bytes: int
    excerpt_count: int
    plan_count: int
    alias_count: int
    byte_ceiling: int | None
    limits: ExcerptLimits


def _key(value):
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None:
        raise SourceIndexStoreError("invalid-source-key")
    return value


def _shape(sql):
    return " ".join(sql.split()) if isinstance(sql, str) else None


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _sql_text(column, maximum):
    return f"CASE WHEN typeof({column})='text' AND length(CAST({column} AS BLOB))<={maximum} THEN CAST({column} AS BLOB) END"


def _decode_text(value):
    if value is None:
        return None
    if type(value) is bytes:
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            pass
    raise SourceIndexStoreError("invalid-record")


def _sql_int(column):
    return f"CASE WHEN typeof({column})='integer' THEN {column} END"


class SourceIndexStore:
    """Explicit catalogue on an existing connection. No constructor migration."""

    def __init__(self, conn):
        if not isinstance(conn, sqlite3.Connection):
            raise TypeError("an existing SQLite connection is required")
        self.conn = conn

    @contextmanager
    def _transaction(self, *, write=False):
        owns = not self.conn.in_transaction
        savepoint = "source_index_" + uuid4().hex
        started = False
        try:
            if owns and write:
                self.conn.execute("BEGIN IMMEDIATE")
            started = True
            self.conn.execute(f"SAVEPOINT {savepoint}")
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
        encoding = self.conn.execute("PRAGMA main.encoding").fetchone()
        if encoding is None or encoding[0] != "UTF-8":
            raise SourceIndexStoreError("unsupported-encoding")
        expected = {**_DDL, **_INDEX_DDL}
        rows = self.conn.execute("SELECT name, type, sql, tbl_name FROM main.sqlite_master").fetchall()
        present = {row[0]: row for row in rows if row[0] in expected}
        if not present:
            if not create:
                return False
            for sql in _DDL.values():
                self.conn.execute(sql.replace("CREATE TABLE ", "CREATE TABLE main.", 1))
            for sql in _INDEX_DDL.values():
                self.conn.execute(sql.replace("CREATE INDEX ", "CREATE INDEX main.", 1))
            return self._schema()
        if set(present) != set(expected):
            raise SourceIndexStoreError("incompatible-schema")
        for name, sql in expected.items():
            if present[name][1] != ("table" if name in _DDL else "index") or _shape(present[name][2]) != _shape(sql):
                raise SourceIndexStoreError("incompatible-schema")
        for name, kind, sql, table in rows + self.conn.execute(
            "SELECT name, type, sql, tbl_name FROM temp.sqlite_master"
        ).fetchall():
            if (
                kind == "trigger" and table in _DDL
                or kind == "index" and table in _DDL and sql is not None and name not in _INDEX_DDL
            ):
                raise SourceIndexStoreError("incompatible-schema")
        if self.conn.execute(
            "SELECT 1 FROM temp.sqlite_master WHERE name IN (" + ",".join("?" for _ in expected) + ") LIMIT 1",
            tuple(expected),
        ).fetchone():
            raise SourceIndexStoreError("incompatible-schema")
        # Check even when this caller left foreign_keys disabled. No catalogue
        # API creates detached rows; unknown retention must not become zero.
        for child, column, parent, key in (
            (_ASSETS, "source_key", _GROUPS, "source_key"),
            (_PLANS, "source_key", _GROUPS, "source_key"),
            (_EXCERPTS, "fingerprint", _PLANS, "fingerprint"),
        ):
            if self.conn.execute(f"SELECT 1 FROM main.{child} c WHERE NOT EXISTS "
                f"(SELECT 1 FROM main.{parent} p WHERE p.{key}=c.{column}) LIMIT 1").fetchone():
                raise SourceIndexStoreError("invalid-record")
        return True

    def _native_table(self, table, pk, columns):
        row = self.conn.execute("SELECT type, sql FROM main.sqlite_master WHERE name=?", (table,)).fetchone()
        if row is None or row[0] != "table" or "VIRTUAL TABLE" in row[1].upper():
            raise SourceIndexStoreError("incompatible-native-schema")
        info = self.conn.execute(f"PRAGMA main.table_info({table})").fetchall()
        if not columns <= {row[1] for row in info}:
            raise SourceIndexStoreError("incompatible-native-schema")
        if pk:
            keys = [row for row in info if row[5]]
            indexes = [row[1] for row in self.conn.execute(f"PRAGMA main.index_list({table})") if row[3] == "pk"]
            if len(keys) != 1 or keys[0][1] != pk or keys[0][2].upper() != "TEXT" or len(indexes) != 1:
                raise SourceIndexStoreError("incompatible-native-schema")
            index = indexes[0].replace('"', '""')
            index_keys = [row for row in self.conn.execute(f'PRAGMA main.index_xinfo("{index}")') if row[5]]
            if len(index_keys) != 1 or index_keys[0][2] != pk or index_keys[0][4] != "BINARY":
                raise SourceIndexStoreError("incompatible-native-schema")

    def _assets(self, source_key):
        self._native_table("media_assets", "asset_id", {"asset_id", "ref_kind", "ref_value", "metadata", "title", "source", "provider", "provider_model"})
        self._native_table("media_moments", "moment_id", {"moment_id", "asset_id"})
        assets = self.conn.execute(f"SELECT {_sql_text('asset_id', 512)} FROM main.{_ASSETS} WHERE source_key=? LIMIT 33", (source_key,)).fetchall()
        assets = [(_decode_text(row[0]),) for row in assets]
        if not 1 <= len(assets) <= 32:
            raise SourceIndexStoreError("invalid-record")
        for (asset_id,) in assets:
            if type(asset_id) is not str or re.fullmatch(r"ref:[0-9a-f]{64}", asset_id) is None:
                raise SourceIndexStoreError("invalid-record")
            row = self.conn.execute(f"""SELECT CASE WHEN typeof(ref_kind)='text' AND ref_kind='url' THEN 'url' END,
                {_sql_text('ref_value', 4096)},
                COALESCE(metadata, '{{}}')='{{}}', title IS NULL AND source IS NULL AND provider IS NULL AND provider_model IS NULL
                FROM main.media_assets WHERE asset_id=?""", (asset_id,)).fetchone()
            if row is None or row[0] != "url" or not row[2] or not row[3]:
                raise SourceIndexStoreError("unaccounted-legacy-state")
            locator = _decode_text(row[1])
            _external_locator(locator)
            if compute_asset_id("url", locator) != asset_id:
                raise SourceIndexStoreError("invalid-record")
            if self.conn.execute("SELECT 1 FROM main.media_moments WHERE asset_id=? LIMIT 1", (asset_id,)).fetchone():
                raise SourceIndexStoreError("unaccounted-legacy-state")
        for table in ("working_memory", "episodic_memory"):
            if self.conn.execute("SELECT 1 FROM main.sqlite_master WHERE name=?", (table,)).fetchone():
                self._native_table(table, None, {"metadata_json"})
                placeholders = ",".join("?" for _ in assets)
                if self.conn.execute(f"""SELECT 1 FROM main.{table}
                    WHERE metadata_json IS NOT NULL AND (NOT json_valid(metadata_json)
                    OR CASE WHEN json_valid(metadata_json) THEN json_extract(metadata_json, '$.media.asset_id') END IN ({placeholders}))
                    LIMIT 1""", tuple(row[0] for row in assets)).fetchone():
                    raise SourceIndexStoreError("unaccounted-legacy-state")
        return {row[0] for row in assets}

    def _audit(self, source_key):
        group = self.conn.execute(f"""SELECT {_sql_int('per_excerpt_bytes')}, {_sql_int('retained_bytes')},
            {_sql_int('excerpt_count')}, CASE WHEN typeof(byte_ceiling) IN ('null','integer') THEN byte_ceiling ELSE -1 END
            FROM main.{_GROUPS} WHERE source_key=?""", (source_key,)).fetchone()
        if group is None:
            return None
        try:
            limits = ExcerptLimits(*group[:3])
            ceiling = group[3]
            if ceiling is not None and not _integer(ceiling, 0, limits.retained_bytes):
                raise ValueError
            assets = self._assets(source_key)
            rows = self.conn.execute(f"""SELECT
                {_sql_text('fingerprint', 64)}, {_sql_text('source_revision_id', 256)},
                {_sql_text('extraction_sha256', 64)}, {_sql_text('output_locator', 4096)},
                {_sql_int('source_utf8_bytes')} FROM main.{_PLANS} WHERE source_key=? LIMIT 129""", (source_key,)).fetchall()
            if len(rows) > 128:
                raise ValueError
            plans, used_bytes, used_count = {}, 0, 0
            if rows:
                self._native_table("media_source_revisions", "revision_id", {"revision_id", "asset_id"})
            for fingerprint, revision, digest, locator, source_size in rows:
                fingerprint, revision, digest, locator = map(_decode_text, (fingerprint, revision, digest, locator))
                _external_locator(locator)
                if (
                    type(revision) is not str or re.fullmatch(r"revision:sha256:[0-9a-f]{64}", revision) is None
                    or type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                    or not _integer(source_size, 0, MAX_EXTRACTION_BYTES)
                ):
                    raise ValueError
                native = self.conn.execute(f"SELECT {_sql_text('asset_id', 512)} FROM main.media_source_revisions WHERE revision_id=?", (revision,)).fetchone()
                if native is None or _decode_text(native[0]) not in assets:
                    raise ValueError
                excerpts = []
                retained = previous_end = 0
                for ordinal, start, end, text, size, text_hash in self.conn.execute(f"""SELECT {_sql_int('ordinal')}, {_sql_int('char_start')}, {_sql_int('char_end')},
                    {_sql_text('text', 4096)}, {_sql_int('utf8_bytes')}, {_sql_text('text_sha256', 64)}
                    FROM main.{_EXCERPTS} WHERE fingerprint=? ORDER BY ordinal LIMIT 129""", (fingerprint,)).fetchall():
                    text, text_hash = _decode_text(text), _decode_text(text_hash)
                    if (
                        ordinal != len(excerpts) or type(text) is not str or not _integer(start, previous_end, MAX_EXTRACTION_BYTES)
                        or not _integer(end, start + 1, source_size) or end-start != len(text)
                        or not _integer(size, 1, limits.per_excerpt_bytes) or len(text.encode("utf-8")) != size
                        or hashlib.sha256(text.encode("utf-8")).hexdigest() != text_hash
                    ):
                        raise ValueError
                    excerpts.append(SourceExcerpt(SourceSpan(start, end), text, size))
                    previous_end, retained = end, retained + size
                if len(excerpts) > limits.excerpt_count or retained * 4 > source_size:
                    raise ValueError
                if fingerprint != _plan_fingerprint(revision, digest, locator, source_size, limits, tuple(e.span for e in excerpts)):
                    raise ValueError
                if excerpts and (ceiling is None or ceiling > source_size // 4):
                    raise ValueError
                plans[fingerprint] = SourceIndexPlan(revision, digest, locator, source_size, retained, limits,
                    "excerpts" if excerpts else "reference-only", tuple(excerpts), fingerprint)
                used_bytes, used_count = used_bytes + retained, used_count + len(excerpts)
            if used_count > limits.excerpt_count or used_bytes > limits.retained_bytes or used_bytes > (ceiling or 0):
                raise ValueError
        except (TypeError, ValueError, UnicodeError):
            raise SourceIndexStoreError("invalid-record") from None
        return SourceIndexUsage(used_bytes, used_count, len(plans), len(assets), ceiling, limits), plans

    def register_source(self, source_key, source_locator, *, limits=ExcerptLimits()):
        source_key = _key(source_key)
        _external_locator(source_locator)
        if type(limits) is not ExcerptLimits:
            raise SourceIndexStoreError("invalid-limits")
        limits.__post_init__()
        _, locator = normalize_ref("url", source_locator)
        asset_id = compute_asset_id("url", locator)
        with self._transaction(write=True) as owns:
            self._schema(create=True)
            self._native_table("media_assets", "asset_id", {"asset_id", "ref_kind", "ref_value", "modality"})
            for schema in ("main", "temp"):
                if self.conn.execute(f"SELECT 1 FROM {schema}.sqlite_master WHERE type='trigger' AND tbl_name='media_assets' LIMIT 1").fetchone():
                    raise SourceIndexStoreError("incompatible-native-schema")
            current = self._audit(source_key)
            if current and current[0].limits != limits:
                raise SourceIndexStoreError("limits-conflict")
            existing = self.conn.execute(f"SELECT {_sql_text('asset_id', 512)} FROM main.media_assets WHERE asset_id=? OR (ref_kind='url' AND ref_value=?)", (asset_id, locator)).fetchall()
            existing = [(_decode_text(row[0]),) for row in existing]
            if existing:
                mapped = self.conn.execute(f"SELECT {_sql_text('source_key', 128)} FROM main.{_ASSETS} WHERE asset_id=?", (asset_id,)).fetchone()
                if len(existing) != 1 or existing[0][0] != asset_id or mapped is None or _decode_text(mapped[0]) != source_key or current is None:
                    raise SourceIndexStoreError("existing-asset-refused")
                return SourceRegistration(asset_id, "unchanged", "committed" if owns else "pending")
            if current and current[0].alias_count >= 32:
                raise SourceIndexStoreError("alias-limit-exceeded")
            if current is None:
                self.conn.execute(f"INSERT INTO main.{_GROUPS} VALUES(?,?,?,?,NULL)", (source_key, limits.per_excerpt_bytes, limits.retained_bytes, limits.excerpt_count)).fetchall()
            self.conn.execute("INSERT INTO main.media_assets(asset_id, ref_kind, ref_value, modality) VALUES(?, 'url', ?, 'document')", (asset_id, locator)).fetchall()
            self.conn.execute(f"INSERT INTO main.{_ASSETS} VALUES(?,?)", (asset_id, source_key)).fetchall()
            self._audit(source_key)
            result = SourceRegistration(asset_id, "created", "committed" if owns else "pending")
        return result

    def write(self, source_key, source_revision_id, extracted_text, *, extraction_sha256, output_locator, spans):
        source_key = _key(source_key)
        with self._transaction(write=True) as owns:
            if not self._schema() or (current := self._audit(source_key)) is None:
                raise SourceIndexStoreError("source-not-registered")
            usage, plans = current
            plan = plan_source_index(source_revision_id, extracted_text, extraction_sha256=extraction_sha256,
                output_locator=output_locator, spans=spans, limits=usage.limits)
            self._native_table("media_source_revisions", "revision_id", {"revision_id", "asset_id"})
            native = self.conn.execute(f"SELECT 1 FROM main.media_source_revisions r JOIN main.{_ASSETS} a ON a.asset_id=r.asset_id WHERE r.revision_id=? AND a.source_key=?", (source_revision_id, source_key)).fetchone()
            if native is None:
                raise SourceIndexStoreError("revision-mismatch")
            state = "committed" if owns else "pending"
            if plan.fingerprint in plans:
                if plans[plan.fingerprint] != plan:
                    raise SourceIndexStoreError("plan-conflict")
                return SourceIndexWrite(plan.fingerprint, "unchanged", state)
            if usage.plan_count >= 128:
                raise SourceIndexStoreError("plan-limit-exceeded")
            ceiling = usage.byte_ceiling
            if plan.excerpts:
                proposed = min(usage.limits.retained_bytes, plan.source_utf8_bytes // 4)
                ceiling = proposed if ceiling is None else min(ceiling, proposed)
                if usage.retained_bytes + plan.retained_utf8_bytes > ceiling or usage.excerpt_count + len(plan.excerpts) > usage.limits.excerpt_count:
                    raise SourceIndexStoreError("source-budget-exceeded")
            self.conn.execute(f"INSERT INTO main.{_PLANS} VALUES(?,?,?,?,?,?)", (plan.fingerprint, source_key,
                plan.source_revision_id, plan.extraction_sha256, plan.output_locator, plan.source_utf8_bytes)).fetchall()
            for ordinal, excerpt in enumerate(plan.excerpts):
                self.conn.execute(f"INSERT INTO main.{_EXCERPTS} VALUES(?,?,?,?,?,?,?)", (plan.fingerprint, ordinal,
                    excerpt.span.start, excerpt.span.end, excerpt.text, excerpt.utf8_bytes,
                    hashlib.sha256(excerpt.text.encode('utf-8')).hexdigest())).fetchall()
            self.conn.execute(f"UPDATE main.{_GROUPS} SET byte_ceiling=? WHERE source_key=?", (ceiling, source_key)).fetchall()
            self._audit(source_key)
            result = SourceIndexWrite(plan.fingerprint, "created", state)
        return result

    def usage(self, source_key):
        source_key = _key(source_key)
        with self._transaction():
            if not self._schema() or (current := self._audit(source_key)) is None:
                return None
            return current[0]

    def get_plan(self, fingerprint):
        if type(fingerprint) is not str or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
            raise SourceIndexStoreError("invalid-fingerprint")
        with self._transaction():
            if not self._schema():
                return None
            group = self.conn.execute(f"SELECT {_sql_text('source_key', 128)} FROM main.{_PLANS} WHERE fingerprint=?", (fingerprint,)).fetchone()
            if group is None:
                return None
            source_key = _key(_decode_text(group[0]))
            current = self._audit(source_key)
            if current is None or fingerprint not in current[1]:
                raise SourceIndexStoreError("invalid-record")
            return current[1][fingerprint]
