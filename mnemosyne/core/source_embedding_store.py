"""Explicit owner-mode source embedding artifacts, not protected retrieval."""

from dataclasses import dataclass, field
import hashlib
import json
import math
import re
import struct

from .source_index_generations import _decode, _sql_ascii
from .source_index_store import SourceIndexStore, SourceIndexStoreError, _key, _shape, _sql_int


_CACHE = "media_source_embedding_artifacts"
_BINDINGS = "media_source_embedding_bindings"
_DDL = {
    _CACHE: f"""CREATE TABLE {_CACHE} (
        cache_id TEXT PRIMARY KEY NOT NULL,
        source_key TEXT NOT NULL REFERENCES media_source_index_groups(source_key),
        sharing_domain TEXT NOT NULL,
        model_identity TEXT NOT NULL,
        dimensions INTEGER NOT NULL,
        preprocessing_sha256 TEXT NOT NULL,
        text_sha256 TEXT NOT NULL,
        vector BLOB NOT NULL,
        vector_sha256 TEXT NOT NULL
    )""",
    _BINDINGS: f"""CREATE TABLE {_BINDINGS} (
        fingerprint TEXT NOT NULL,
        ordinal INTEGER NOT NULL,
        cache_id TEXT NOT NULL REFERENCES {_CACHE}(cache_id),
        PRIMARY KEY(fingerprint, ordinal, cache_id),
        FOREIGN KEY(fingerprint, ordinal) REFERENCES media_source_index_excerpts(fingerprint, ordinal)
    )""",
}
_INDEX_DDL = {"idx_source_embeddings_group": f"CREATE INDEX idx_source_embeddings_group ON {_CACHE}(source_key)"}


def _digest(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise SourceIndexStoreError("invalid-embedding-input")
    return value


@dataclass(frozen=True, repr=False)
class EmbeddingContract:
    sharing_domain: str
    model_identity: str
    dimensions: int
    preprocessing_sha256: str

    def __post_init__(self):
        _key(self.sharing_domain)
        _digest(self.preprocessing_sha256)
        if (type(self.model_identity) is not str or re.fullmatch(r"[!-~]{1,256}", self.model_identity) is None
            or type(self.dimensions) is not int or not 1 <= self.dimensions <= 4096):
            raise SourceIndexStoreError("invalid-embedding-input")


def _contract(value):
    if type(value) is not EmbeddingContract:
        raise SourceIndexStoreError("invalid-embedding-input")
    value.__post_init__()
    return value


def _identity(source_key, contract, text_hash):
    value = ["source-embedding:v1", source_key, contract.sharing_domain, contract.model_identity,
             contract.dimensions, contract.preprocessing_sha256, text_hash]
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest()


def _pack(values, dimensions):
    if type(values) not in (list, tuple) or len(values) != dimensions:
        raise SourceIndexStoreError("invalid-embedding-vector")
    if any(type(value) not in (float, int) or abs(value) > 3.4028234663852886e38 or not math.isfinite(value) for value in values):
        raise SourceIndexStoreError("invalid-embedding-vector")
    blob = struct.pack(f"<{dimensions}f", *values)
    if not any(struct.unpack(f"<{dimensions}f", blob)):
        raise SourceIndexStoreError("invalid-embedding-vector")
    return blob


@dataclass(frozen=True)
class SourceEmbedding:
    cache_id: str = field(repr=False)
    values: tuple[float, ...] = field(repr=False)
    status: str
    transaction_state: str


class SourceEmbeddingStore:
    """Bounded artifact reuse with durable source-excerpt provenance."""

    def __init__(self, conn):
        self.store = SourceIndexStore(conn)
        self.conn = conn

    def _schema(self, *, create=False):
        expected = {**_DDL, **_INDEX_DDL}
        if self.conn.execute("SELECT 1 FROM temp.sqlite_master WHERE name IN (?,?,?) LIMIT 1", tuple(expected)).fetchone():
            raise SourceIndexStoreError("incompatible-embedding-schema")
        if not self.store._schema():
            if self.conn.execute("SELECT 1 FROM main.sqlite_master WHERE name IN (?,?,?) LIMIT 1", tuple(expected)).fetchone():
                raise SourceIndexStoreError("invalid-embedding-record")
            return False
        rows = self.conn.execute("SELECT name,type,sql,tbl_name FROM main.sqlite_master").fetchall()
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
            raise SourceIndexStoreError("incompatible-embedding-schema")
        for name, sql in expected.items():
            if present[name][1] != ("table" if name in _DDL else "index") or _shape(present[name][2]) != _shape(sql):
                raise SourceIndexStoreError("incompatible-embedding-schema")
        for name, kind, sql, table in rows + self.conn.execute("SELECT name,type,sql,tbl_name FROM temp.sqlite_master").fetchall():
            if (kind == "trigger" and table in _DDL
                or kind == "index" and table in _DDL and sql is not None and name not in _INDEX_DDL):
                raise SourceIndexStoreError("incompatible-embedding-schema")
        if self.conn.execute(f"SELECT 1 FROM main.{_CACHE} c WHERE NOT EXISTS "
            "(SELECT 1 FROM main.media_source_index_groups g WHERE g.source_key=c.source_key) LIMIT 1").fetchone():
            raise SourceIndexStoreError("invalid-embedding-record")
        if self.conn.execute(f"SELECT 1 FROM main.{_BINDINGS} b WHERE NOT EXISTS "
            f"(SELECT 1 FROM main.{_CACHE} c WHERE c.cache_id=b.cache_id) OR NOT EXISTS "
            "(SELECT 1 FROM main.media_source_index_excerpts e WHERE e.fingerprint=b.fingerprint AND e.ordinal=b.ordinal) LIMIT 1").fetchone():
            raise SourceIndexStoreError("invalid-embedding-record")
        return True

    def _plans(self, source_key):
        if not self.store._schema() or (catalogue := self.store._audit(source_key)) is None:
            raise SourceIndexStoreError("source-not-registered")
        return catalogue[1]

    def _target(self, source_key, fingerprint, ordinal, contract, plans):
        _key(source_key)
        _digest(fingerprint)
        _contract(contract)
        plan = plans.get(fingerprint)
        if type(ordinal) is not int or ordinal < 0 or plan is None or ordinal >= len(plan.excerpts):
            raise SourceIndexStoreError("embedding-evidence-not-ready")
        excerpt = plan.excerpts[ordinal]
        text_hash = hashlib.sha256(excerpt.text.encode("utf-8")).hexdigest()
        return excerpt, text_hash, _identity(source_key, contract, text_hash)

    def _audit(self, source_key, plans):
        rows = self.conn.execute(f"""SELECT {_sql_ascii('cache_id', 64)}, {_sql_ascii('sharing_domain', 128)},
            {_sql_ascii('model_identity', 256)}, {_sql_int('dimensions')}, {_sql_ascii('preprocessing_sha256', 64)},
            {_sql_ascii('text_sha256', 64)}, CASE WHEN typeof(vector)='blob' AND length(vector)<=16384 THEN vector END,
            {_sql_ascii('vector_sha256', 64)} FROM main.{_CACHE} WHERE source_key=? LIMIT 1025""", (source_key,)).fetchall()
        caches, specs, byte_count = {}, set(), 0
        try:
            if len(rows) > 1024:
                raise ValueError
            for cache_id, domain, model, dimensions, preprocessing, text_hash, blob, vector_hash in rows:
                cache_id, domain, model, preprocessing, text_hash, vector_hash = map(_decode,
                    (cache_id, domain, model, preprocessing, text_hash, vector_hash))
                contract = EmbeddingContract(domain, model, dimensions, preprocessing)
                _digest(text_hash)
                if (cache_id != _identity(source_key, contract, text_hash) or type(blob) is not bytes
                    or len(blob) != 4 * dimensions or hashlib.sha256(blob).hexdigest() != vector_hash):
                    raise ValueError
                nonzero = False
                for (value,) in struct.iter_unpack("<f", blob):
                    if not math.isfinite(value):
                        raise ValueError
                    nonzero = nonzero or value != 0
                if not nonzero:
                    raise ValueError
                specs.add(contract)
                caches[cache_id] = (contract, text_hash, blob)
                byte_count += len(blob)
            if len(specs) > 8 or byte_count > 16 * 1024 * 1024:
                raise ValueError
            bindings, texts = set(), {}
            linked = set()
            for fingerprint, ordinal, cache_id in self.conn.execute(f"""SELECT {_sql_ascii('b.fingerprint', 64)},
                {_sql_int('b.ordinal')}, {_sql_ascii('b.cache_id', 64)} FROM main.{_BINDINGS} b
                JOIN main.{_CACHE} c ON c.cache_id=b.cache_id WHERE c.source_key=? LIMIT 1025""", (source_key,)).fetchall():
                fingerprint, cache_id = _decode(fingerprint), _decode(cache_id)
                if cache_id not in caches or len(bindings) >= 1024:
                    raise ValueError
                contract, text_hash, _ = caches[cache_id]
                excerpt, expected_text, expected_id = self._target(source_key, fingerprint, ordinal, contract, plans)
                if text_hash != expected_text or cache_id != expected_id:
                    raise ValueError
                if cache_id in texts and texts[cache_id] != excerpt.text:
                    raise ValueError
                texts[cache_id] = excerpt.text
                bindings.add((fingerprint, ordinal, cache_id))
                linked.add(cache_id)
            if set(caches) != linked:
                raise ValueError
        except (TypeError, ValueError, SourceIndexStoreError, struct.error):
            raise SourceIndexStoreError("invalid-embedding-record") from None
        return caches, bindings, texts

    def get(self, source_key, fingerprint, ordinal, *, contract):
        source_key = _key(source_key)
        with self.store._transaction():
            exists = self._schema()
            plans = self._plans(source_key)
            excerpt, _, cache_id = self._target(source_key, fingerprint, ordinal, contract, plans)
            if not exists:
                return None
            caches, _, texts = self._audit(source_key, plans)
            if cache_id not in caches:
                return None
            if texts[cache_id] != excerpt.text:
                raise SourceIndexStoreError("embedding-conflict")
            return SourceEmbedding(cache_id, struct.unpack(f"<{contract.dimensions}f", caches[cache_id][2]), "available", "snapshot")

    def _write(self, source_key, fingerprint, ordinal, contract, blob, *, expected_text=None):
        source_key = _key(source_key)
        with self.store._transaction(write=True) as owns:
            exists = self._schema()
            plans = self._plans(source_key)
            excerpt, text_hash, cache_id = self._target(source_key, fingerprint, ordinal, contract, plans)
            if expected_text is not None and excerpt.text != expected_text:
                raise SourceIndexStoreError("embedding-evidence-changed")
            if not exists:
                if blob is None:
                    return None
                self._schema(create=True)
            caches, bindings, texts = self._audit(source_key, plans)
            found = caches.get(cache_id)
            if found is None:
                if blob is None:
                    return None
                specs = {row[0] for row in caches.values()} | {contract}
                if len(specs) > 8 or len(caches) >= 1024 or sum(len(row[2]) for row in caches.values()) + len(blob) > 16 * 1024 * 1024:
                    raise SourceIndexStoreError("embedding-budget-exceeded")
                self.conn.execute(f"INSERT INTO main.{_CACHE} VALUES(?,?,?,?,?,?,?,?,?)", (cache_id, source_key,
                    contract.sharing_domain, contract.model_identity, contract.dimensions, contract.preprocessing_sha256,
                    text_hash, blob, hashlib.sha256(blob).hexdigest())).fetchall()
                values, status = struct.unpack(f"<{contract.dimensions}f", blob), "created"
            else:
                if texts[cache_id] != excerpt.text or blob is not None and blob != found[2]:
                    raise SourceIndexStoreError("embedding-conflict")
                values, status = struct.unpack(f"<{contract.dimensions}f", found[2]), "reused"
            if (fingerprint, ordinal, cache_id) not in bindings:
                if len(bindings) >= 1024:
                    raise SourceIndexStoreError("embedding-budget-exceeded")
                self.conn.execute(f"INSERT INTO main.{_BINDINGS} VALUES(?,?,?)", (fingerprint, ordinal, cache_id)).fetchall()
            self._audit(source_key, plans)
            return SourceEmbedding(cache_id, values, status, "committed" if owns else "pending")

    def reuse(self, source_key, fingerprint, ordinal, *, contract):
        return self._write(source_key, fingerprint, ordinal, _contract(contract), None)

    def put(self, source_key, fingerprint, ordinal, values, *, contract):
        contract = _contract(contract)
        return self._write(source_key, fingerprint, ordinal, contract, _pack(values, contract.dimensions))

    def materialize(self, source_key, fingerprint, ordinal, *, contract, compute):
        if self.conn.in_transaction:
            raise SourceIndexStoreError("embedding-callback-in-transaction")
        if not callable(compute):
            raise SourceIndexStoreError("invalid-embedding-input")
        contract = _contract(contract)
        found = self.reuse(source_key, fingerprint, ordinal, contract=contract)
        if found is not None:
            return found
        with self.store._transaction():
            excerpt, _, _ = self._target(source_key, fingerprint, ordinal, contract, self._plans(source_key))
        values = compute(excerpt.text, contract)
        if self.conn.in_transaction:
            raise SourceIndexStoreError("embedding-callback-in-transaction")
        contract = _contract(contract)
        return self._write(source_key, fingerprint, ordinal, contract, _pack(values, contract.dimensions), expected_text=excerpt.text)
