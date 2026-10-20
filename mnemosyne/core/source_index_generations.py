"""Optional owner-mode manifest checkpoints; no retrieval or protected activation."""

from dataclasses import dataclass, field
import hashlib
import json
import re

from .source_index_store import SourceIndexStore, SourceIndexStoreError, _key, _shape, _sql_int


_GENERATIONS = "media_source_index_generations"
_ITEMS = "media_source_index_generation_items"
_HEADS = "media_source_index_heads"
_DDL = {
    _GENERATIONS: f"""CREATE TABLE {_GENERATIONS} (
        generation_id TEXT PRIMARY KEY NOT NULL,
        source_key TEXT NOT NULL REFERENCES media_source_index_groups(source_key),
        generation_key TEXT NOT NULL,
        parent_id TEXT REFERENCES {_GENERATIONS}(generation_id),
        state TEXT NOT NULL
    )""",
    _ITEMS: f"""CREATE TABLE {_ITEMS} (
        generation_id TEXT NOT NULL REFERENCES {_GENERATIONS}(generation_id),
        ordinal INTEGER NOT NULL,
        fingerprint TEXT NOT NULL,
        state TEXT NOT NULL,
        reason TEXT,
        PRIMARY KEY(generation_id, ordinal)
    )""",
    _HEADS: f"""CREATE TABLE {_HEADS} (
        source_key TEXT PRIMARY KEY NOT NULL REFERENCES media_source_index_groups(source_key),
        generation_id TEXT REFERENCES {_GENERATIONS}(generation_id)
    )""",
}
_INDEX_DDL = {
    "idx_source_index_generation_key": f"CREATE UNIQUE INDEX idx_source_index_generation_key ON {_GENERATIONS}(source_key, generation_key)",
}
_REASONS = {
    "planned": (None,), "completed": (None,),
    "failed": ("unavailable", "changed", "invalid", "interrupted"),
    "excluded": ("not-selected", "unsupported", "awaiting-preparation"),
}


def _digest(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise SourceIndexStoreError("invalid-generation-input")
    return value


def _identity(source_key, generation_key, parent, fingerprints):
    payload = ["source-index-generation:v1", source_key, generation_key, parent, fingerprints]
    return hashlib.sha256(json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest()


def _sql_ascii(column, maximum):
    # Return bounded bytes, not SQLite TEXT: malformed UTF-8 TEXT would otherwise
    # enter sqlite3's decoder exception, which includes the offending payload.
    return f"CASE WHEN typeof({column})='text' AND length(CAST({column} AS BLOB))<={maximum} THEN CAST({column} AS BLOB) END"


def _decode(value):
    if type(value) is bytes:
        try:
            return value.decode("ascii")
        except UnicodeDecodeError:
            pass
    return None


@dataclass(frozen=True)
class GenerationItem:
    fingerprint: str = field(repr=False)
    state: str
    reason: str | None


@dataclass(frozen=True)
class IndexGeneration:
    generation_id: str = field(repr=False)
    source_key: str = field(repr=False)
    generation_key: str = field(repr=False)
    parent_id: str | None = field(repr=False)
    state: str
    items: tuple[GenerationItem, ...] = field(repr=False)

    @property
    def coverage(self):
        return {"total": len(self.items), **{
            state: sum(item.state == state for item in self.items) for state in _REASONS
        }}


@dataclass(frozen=True)
class GenerationWrite:
    generation_id: str = field(repr=False)
    status: str
    transaction_state: str


class SourceIndexGenerations:
    """Additive bounded catalogue on the owner's existing SQLite connection."""

    def __init__(self, conn):
        self.store = SourceIndexStore(conn)
        self.conn = conn

    def _schema(self, *, create=False):
        if not self.store._schema():
            if self.conn.execute("SELECT 1 FROM main.sqlite_master WHERE name IN (?,?,?) LIMIT 1",
                                 (_GENERATIONS, _ITEMS, _HEADS)).fetchone():
                raise SourceIndexStoreError("invalid-generation-record")
            return False
        expected = {**_DDL, **_INDEX_DDL}
        rows = self.conn.execute("SELECT name,type,sql,tbl_name FROM main.sqlite_master").fetchall()
        present = {row[0]: row for row in rows if row[0] in expected}
        if not present:
            if not create:
                return False
            for sql in _DDL.values():
                self.conn.execute(sql.replace("CREATE TABLE ", "CREATE TABLE main.", 1))
            for sql in _INDEX_DDL.values():
                self.conn.execute(sql.replace("CREATE UNIQUE INDEX ", "CREATE UNIQUE INDEX main.", 1))
            return self._schema()
        if set(present) != set(expected):
            raise SourceIndexStoreError("incompatible-generation-schema")
        for name, sql in expected.items():
            if present[name][1] != ("table" if name in _DDL else "index") or _shape(present[name][2]) != _shape(sql):
                raise SourceIndexStoreError("incompatible-generation-schema")
        for name, kind, sql, table in rows + self.conn.execute(
            "SELECT name,type,sql,tbl_name FROM temp.sqlite_master"
        ).fetchall():
            if (kind == "trigger" and table in _DDL
                or kind == "index" and table in _DDL and sql is not None and name not in _INDEX_DDL):
                raise SourceIndexStoreError("incompatible-generation-schema")
        if self.conn.execute(
            "SELECT 1 FROM temp.sqlite_master WHERE name IN (" + ",".join("?" for _ in expected) + ") LIMIT 1",
            tuple(expected),
        ).fetchone():
            raise SourceIndexStoreError("incompatible-generation-schema")
        for child, column, parent, key in (
            (_GENERATIONS, "source_key", "media_source_index_groups", "source_key"),
            (_GENERATIONS, "parent_id", _GENERATIONS, "generation_id"),
            (_ITEMS, "generation_id", _GENERATIONS, "generation_id"),
            (_HEADS, "source_key", "media_source_index_groups", "source_key"),
            (_HEADS, "generation_id", _GENERATIONS, "generation_id"),
        ):
            if self.conn.execute(f"SELECT 1 FROM main.{child} c WHERE c.{column} IS NOT NULL AND NOT EXISTS "
                f"(SELECT 1 FROM main.{parent} p WHERE p.{key}=c.{column}) LIMIT 1").fetchone():
                raise SourceIndexStoreError("invalid-generation-record")
        return True

    def _audit(self, source_key):
        catalogue = self.store._audit(source_key)
        if catalogue is None:
            raise SourceIndexStoreError("source-not-registered")
        plans = catalogue[1]
        rows = self.conn.execute(f"""SELECT {_sql_ascii('generation_id', 64)},
            {_sql_ascii('generation_key', 128)}, {_sql_ascii('parent_id', 64)},
            parent_id IS NULL, {_sql_ascii('state', 16)} FROM main.{_GENERATIONS}
            WHERE source_key=? LIMIT 65""", (source_key,)).fetchall()
        result = {}
        keys = set()
        try:
            if len(rows) > 64:
                raise ValueError
            for generation_id, key, parent, parent_null, state in rows:
                generation_id, key, parent, state = map(_decode, (generation_id, key, parent, state))
                _digest(generation_id)
                _key(key)
                if not parent_null:
                    _digest(parent)
                if state not in ("staging", "published") or key in keys:
                    raise ValueError
                keys.add(key)
                items = []
                fingerprints = set()
                for ordinal, fingerprint, item_state, reason, reason_null in self.conn.execute(f"""SELECT
                    {_sql_int('ordinal')}, {_sql_ascii('fingerprint', 64)}, {_sql_ascii('state', 16)},
                    {_sql_ascii('reason', 32)}, reason IS NULL FROM main.{_ITEMS}
                    WHERE generation_id=? ORDER BY ordinal LIMIT 129""", (generation_id,)).fetchall():
                    fingerprint, item_state, reason = map(_decode, (fingerprint, item_state, reason))
                    _digest(fingerprint)
                    if (type(ordinal) is not int or ordinal != len(items) or len(items) >= 128
                        or fingerprint in fingerprints or item_state not in _REASONS
                        or reason not in _REASONS[item_state] or (reason is None and not reason_null)):
                        raise ValueError
                    if item_state == "completed" and fingerprint not in plans:
                        raise ValueError
                    if state == "published" and item_state not in ("completed", "excluded"):
                        raise ValueError
                    fingerprints.add(fingerprint)
                    items.append(GenerationItem(fingerprint, item_state, reason))
                if generation_id != _identity(source_key, key, parent, tuple(i.fingerprint for i in items)):
                    raise ValueError
                result[generation_id] = IndexGeneration(generation_id, source_key, key, parent, state, tuple(items))
            for generation in result.values():
                if generation.parent_id is not None:
                    parent = result.get(generation.parent_id)
                    if parent is None or parent.state != "published":
                        raise ValueError
                seen, ancestor = set(), generation
                while ancestor is not None:
                    if ancestor.generation_id in seen:
                        raise ValueError
                    seen.add(ancestor.generation_id)
                    ancestor = result.get(ancestor.parent_id)
            head = self.conn.execute(f"SELECT {_sql_ascii('generation_id', 64)}, generation_id IS NULL FROM main.{_HEADS} WHERE source_key=?", (source_key,)).fetchone()
            if head is None:
                if result:
                    raise ValueError
                return None, result
            current = _decode(head[0])
            if not head[1] and (current not in result or result[current].state != "published"):
                raise ValueError
            # Every published generation must belong to the current ancestry.
            lineage, ancestor = set(), result.get(current)
            while ancestor is not None:
                lineage.add(ancestor.generation_id)
                ancestor = result.get(ancestor.parent_id)
            if {g.generation_id for g in result.values() if g.state == "published"} != lineage:
                raise ValueError
            return current, result
        except (TypeError, ValueError, SourceIndexStoreError):
            raise SourceIndexStoreError("invalid-generation-record") from None

    def _locate(self, generation_id):
        row = self.conn.execute(f"SELECT {_sql_ascii('source_key', 128)} FROM main.{_GENERATIONS} WHERE generation_id=?", (generation_id,)).fetchone()
        if row is None:
            raise SourceIndexStoreError("generation-not-found")
        try:
            source_key = _key(_decode(row[0]))
        except SourceIndexStoreError:
            raise SourceIndexStoreError("invalid-generation-record") from None
        current, generations = self._audit(source_key)
        return source_key, current, generations[generation_id]

    def begin(self, source_key, generation_key, fingerprints):
        source_key, generation_key = _key(source_key), _key(generation_key)
        if type(fingerprints) is not tuple or len(fingerprints) > 128:
            raise SourceIndexStoreError("invalid-generation-input")
        for fingerprint in fingerprints:
            _digest(fingerprint)
        if len(set(fingerprints)) != len(fingerprints):
            raise SourceIndexStoreError("invalid-generation-input")
        with self.store._transaction(write=True) as owns:
            if not self.store._schema() or self.store._audit(source_key) is None:
                raise SourceIndexStoreError("source-not-registered")
            self._schema(create=True)
            current, generations = self._audit(source_key)
            for generation in generations.values():
                if generation.generation_key == generation_key:
                    if tuple(item.fingerprint for item in generation.items) != fingerprints:
                        raise SourceIndexStoreError("generation-conflict")
                    return GenerationWrite(generation.generation_id, "unchanged", "committed" if owns else "pending")
            if len(generations) >= 64:
                raise SourceIndexStoreError("generation-limit-exceeded")
            generation_id = _identity(source_key, generation_key, current, fingerprints)
            self.conn.execute(f"INSERT OR IGNORE INTO main.{_HEADS} VALUES(?,NULL)", (source_key,)).fetchall()
            self.conn.execute(f"INSERT INTO main.{_GENERATIONS} VALUES(?,?,?,?, 'staging')", (generation_id, source_key, generation_key, current)).fetchall()
            for ordinal, fingerprint in enumerate(fingerprints):
                self.conn.execute(f"INSERT INTO main.{_ITEMS} VALUES(?,?,?,'planned',NULL)", (generation_id, ordinal, fingerprint)).fetchall()
            self._audit(source_key)
            return GenerationWrite(generation_id, "created", "committed" if owns else "pending")

    def checkpoint(self, generation_id, fingerprint, *, state="completed", reason=None):
        generation_id, fingerprint = _digest(generation_id), _digest(fingerprint)
        if type(state) is not str or state not in _REASONS or type(reason) not in (str, type(None)) or reason not in _REASONS[state]:
            raise SourceIndexStoreError("invalid-generation-input")
        with self.store._transaction(write=True) as owns:
            if not self._schema():
                raise SourceIndexStoreError("generation-not-found")
            source_key, _, generation = self._locate(generation_id)
            found = [(n, item) for n, item in enumerate(generation.items) if item.fingerprint == fingerprint]
            if not found:
                raise SourceIndexStoreError("item-not-planned")
            ordinal, item = found[0]
            receipt_state = "committed" if owns else "pending"
            if (item.state, item.reason) == (state, reason):
                return GenerationWrite(generation_id, "unchanged", receipt_state)
            if generation.state == "published" or item.state in ("completed", "excluded"):
                raise SourceIndexStoreError("terminal-checkpoint")
            if state == "completed" and fingerprint not in self.store._audit(source_key)[1]:
                raise SourceIndexStoreError("evidence-not-ready")
            self.conn.execute(f"UPDATE main.{_ITEMS} SET state=?,reason=? WHERE generation_id=? AND ordinal=?", (state, reason, generation_id, ordinal)).fetchall()
            self._audit(source_key)
            return GenerationWrite(generation_id, "updated", receipt_state)

    def publish(self, generation_id):
        generation_id = _digest(generation_id)
        with self.store._transaction(write=True) as owns:
            if not self._schema():
                raise SourceIndexStoreError("generation-not-found")
            source_key, current, generation = self._locate(generation_id)
            receipt_state = "committed" if owns else "pending"
            if current == generation_id:
                return GenerationWrite(generation_id, "unchanged", receipt_state)
            if generation.state == "published" or current != generation.parent_id:
                raise SourceIndexStoreError("stale-generation-parent")
            if any(item.state not in ("completed", "excluded") for item in generation.items):
                raise SourceIndexStoreError("incomplete-generation")
            self.conn.execute(f"UPDATE main.{_GENERATIONS} SET state='published' WHERE generation_id=?", (generation_id,)).fetchall()
            self.conn.execute(f"UPDATE main.{_HEADS} SET generation_id=? WHERE source_key=?", (generation_id, source_key)).fetchall()
            self._audit(source_key)
            return GenerationWrite(generation_id, "published", receipt_state)

    def get(self, generation_id):
        generation_id = _digest(generation_id)
        with self.store._transaction():
            if not self._schema():
                return None
            if self.conn.execute(f"SELECT 1 FROM main.{_GENERATIONS} WHERE generation_id=?", (generation_id,)).fetchone() is None:
                return None
            return self._locate(generation_id)[2]

    def current(self, source_key):
        source_key = _key(source_key)
        with self.store._transaction():
            if not self._schema():
                return None
            if self.conn.execute("SELECT 1 FROM main.media_source_index_groups WHERE source_key=?", (source_key,)).fetchone() is None:
                return None
            current, generations = self._audit(source_key)
            return generations.get(current)
