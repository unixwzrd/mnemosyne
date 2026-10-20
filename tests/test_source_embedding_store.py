"""Synthetic durable embedding reuse; no live models, providers or stores."""

from dataclasses import FrozenInstanceError, replace
import hashlib
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys

import pytest

from mnemosyne.core.media import MediaStore
from mnemosyne.core.source_embedding_store import EmbeddingContract, SourceEmbeddingStore
from mnemosyne.core.source_index_generations import SourceIndexGenerations
from mnemosyne.core.source_index_store import SourceIndexStore, SourceIndexStoreError
from mnemosyne.core.source_indexing import SourceSpan


SPEC = EmbeddingContract("domain:a", "synthetic/model@revision-one", 4, "a" * 64)
VALUES = (1.0, 0.0, 0.0, 0.0)
TEXT = "SELECTED EXCERPT" + "OMITTED-EMBEDDING-SOURCE" * 100


class Fixture:
    def __init__(self, root):
        self.path = root / "embedding.db"
        self.media = MediaStore(db_path=self.path)
        self.conn = self.media.conn
        self.store = SourceIndexStore(self.conn)
        self.embeddings = SourceEmbeddingStore(self.conn)
        self.asset = self.store.register_source("source:a", "archive://synthetic/original").asset_id
        self.revision = self.media.register_source_revision(self.asset, revision_key="one", content_hash="a" * 64).revision_id
        self.plan = self.write()

    def write(self, revision=None, start=0):
        return self.store.write("source:a", revision or self.revision, TEXT,
            extraction_sha256=hashlib.sha256(TEXT.encode()).hexdigest(), output_locator="archive://synthetic/extraction",
            spans=(SourceSpan(start, start + 16),))

    def put(self, values=VALUES, spec=SPEC, plan=None):
        return self.embeddings.put("source:a", (plan or self.plan).fingerprint, 0, values, contract=spec)

    def get(self, spec=SPEC, plan=None):
        return self.embeddings.get("source:a", (plan or self.plan).fingerprint, 0, contract=spec)


@pytest.fixture
def fx(tmp_path):
    value = Fixture(tmp_path)
    yield value
    value.conn.close()


def refused(code):
    return pytest.raises(SourceIndexStoreError, match="^source_index_store:" + code + "$")


def test_constructor_and_missing_get_reuse_do_not_create_schema_or_commit(fx):
    fx.conn.execute("CREATE TABLE unrelated(value)")
    fx.conn.execute("INSERT INTO unrelated VALUES(1)")
    assert fx.get() is None
    assert fx.embeddings.reuse("source:a", fx.plan.fingerprint, 0, contract=SPEC) is None
    assert fx.conn.in_transaction
    assert not fx.conn.execute("SELECT 1 FROM sqlite_master WHERE name='media_source_embedding_artifacts'").fetchone()
    fx.conn.rollback()
    assert fx.conn.execute("SELECT count(*) FROM unrelated").fetchone()[0] == 0


def test_put_roundtrip_retry_is_immutable_and_does_not_duplicate(fx):
    first = fx.put()
    assert (first.status, first.transaction_state) == ("created", "committed")
    before = fx.conn.total_changes
    assert fx.put().status == "reused"
    assert fx.embeddings.reuse("source:a", fx.plan.fingerprint, 0, contract=SPEC).values == VALUES
    assert fx.conn.total_changes == before
    assert fx.get().values == VALUES
    assert "domain:a" not in repr(SPEC)
    assert first.cache_id not in repr(first) and "1.0" not in repr(first)
    with pytest.raises(FrozenInstanceError):
        first.values = ()
    with refused("embedding-conflict"):
        fx.put((0.0, 1.0, 0.0, 0.0))
    assert fx.get().values == VALUES


def test_clone_revision_relocation_and_new_span_reuse_with_new_lineage(fx):
    original = fx.put()
    alias = fx.store.register_source("source:a", "archive://synthetic/moved").asset_id
    revision = fx.media.register_source_revision(alias, revision_key="two", content_hash="b" * 64).revision_id
    plan = fx.write(revision)
    before = fx.store.usage("source:a")
    assert fx.get(plan=plan).cache_id == original.cache_id
    assert fx.conn.execute("SELECT count(*) FROM media_source_embedding_bindings").fetchone()[0] == 1
    reused = fx.embeddings.reuse("source:a", plan.fingerprint, 0, contract=SPEC)
    assert reused.cache_id == original.cache_id
    assert fx.conn.execute("SELECT count(*) FROM media_source_embedding_artifacts").fetchone()[0] == 1
    assert fx.conn.execute("SELECT count(*) FROM media_source_embedding_bindings").fetchone()[0] == 2
    assert fx.store.usage("source:a") == before


@pytest.mark.parametrize("changes", (
    {"sharing_domain": "domain:b"}, {"model_identity": "synthetic/model@revision-two"},
    {"dimensions": 5}, {"preprocessing_sha256": "b" * 64},
))
def test_contract_changes_miss(fx, changes):
    fx.put()
    spec = replace(SPEC, **changes)
    assert fx.get(spec=spec) is None
    assert fx.embeddings.reuse("source:a", fx.plan.fingerprint, 0, contract=spec) is None


def test_changed_excerpt_misses_and_unrelated_group_never_shares(fx):
    fx.put()
    assert fx.get(plan=fx.write(start=1)) is None
    asset = fx.store.register_source("source:b", "archive://synthetic/unrelated").asset_id
    revision = fx.media.register_source_revision(asset, revision_key="one", content_hash="a" * 64).revision_id
    plan = fx.store.write("source:b", revision, TEXT, extraction_sha256=hashlib.sha256(TEXT.encode()).hexdigest(),
                          output_locator="archive://synthetic/extraction", spans=(SourceSpan(0, 16),))
    assert fx.embeddings.get("source:b", plan.fingerprint, 0, contract=SPEC) is None
    with refused("embedding-evidence-not-ready"):
        fx.embeddings.put("source:a", plan.fingerprint, 0, VALUES, contract=SPEC)


def test_materialize_compute_once_then_reuse_after_reopen_and_generation_change(fx):
    calls = []

    def compute(text, spec):
        assert not fx.conn.in_transaction
        assert text == TEXT[:16] and spec == SPEC
        calls.append(text)
        return VALUES

    first = fx.embeddings.materialize("source:a", fx.plan.fingerprint, 0, contract=SPEC, compute=compute)
    generations = SourceIndexGenerations(fx.conn)
    for key in ("one", "two"):
        generation = generations.begin("source:a", key, (fx.plan.fingerprint,)).generation_id
        fx.embeddings.materialize("source:a", fx.plan.fingerprint, 0, contract=SPEC, compute=compute)
        generations.checkpoint(generation, fx.plan.fingerprint)
        generations.publish(generation)
    fx.conn.close()
    fx.conn = sqlite3.connect(fx.path)
    fx.embeddings = SourceEmbeddingStore(fx.conn)
    assert fx.embeddings.materialize("source:a", fx.plan.fingerprint, 0, contract=SPEC, compute=compute).cache_id == first.cache_id
    assert len(calls) == 1


@pytest.mark.parametrize("failure", (RuntimeError, KeyboardInterrupt))
def test_failed_callback_does_not_change_current_generation_or_create_cache(fx, failure):
    generations = SourceIndexGenerations(fx.conn)
    generation = generations.begin("source:a", "old", ()).generation_id
    generations.publish(generation)

    def compute(text, spec):
        raise failure("synthetic callback interruption")

    with pytest.raises(failure):
        fx.embeddings.materialize("source:a", fx.plan.fingerprint, 0, contract=SPEC, compute=compute)
    assert generations.current("source:a").generation_id == generation
    assert not fx.conn.in_transaction
    assert not fx.conn.execute("SELECT 1 FROM sqlite_master WHERE name='media_source_embedding_artifacts'").fetchone()


def test_materialize_refuses_caller_transaction_before_callback(fx):
    fx.conn.execute("BEGIN")
    calls = []
    with refused("embedding-callback-in-transaction"):
        fx.embeddings.materialize("source:a", fx.plan.fingerprint, 0, contract=SPEC, compute=lambda *args: calls.append(1))
    assert fx.conn.in_transaction and calls == []
    fx.conn.rollback()


def test_callback_opening_transaction_is_not_silently_committed(fx):
    def compute(text, spec):
        fx.conn.execute("BEGIN")
        return VALUES

    with refused("embedding-callback-in-transaction"):
        fx.embeddings.materialize("source:a", fx.plan.fingerprint, 0, contract=SPEC, compute=compute)
    assert fx.conn.in_transaction
    fx.conn.rollback()
    assert fx.get() is None


def test_callback_interval_changed_evidence_refuses_before_persisting_vector(fx):
    def compute(text, spec):
        changed = "different source"
        assert len(changed) == 16
        fx.conn.execute("UPDATE media_source_index_excerpts SET text=?,text_sha256=? WHERE fingerprint=?",
                        (changed, hashlib.sha256(changed.encode()).hexdigest(), fx.plan.fingerprint))
        fx.conn.commit()
        return VALUES

    with refused("embedding-evidence-changed"):
        fx.embeddings.materialize("source:a", fx.plan.fingerprint, 0, contract=SPEC, compute=compute)
    assert not fx.conn.execute("SELECT 1 FROM sqlite_master WHERE name='media_source_embedding_artifacts'").fetchone()


def test_callback_none_is_failure_not_a_successful_empty_result(fx):
    with refused("invalid-embedding-vector"):
        fx.embeddings.materialize("source:a", fx.plan.fingerprint, 0, contract=SPEC, compute=lambda *args: None)
    assert fx.get() is None


def test_materialize_bad_evidence_never_calls_compute(fx):
    calls = []
    with refused("embedding-evidence-not-ready"):
        fx.embeddings.materialize("source:a", "a" * 64, 0, contract=SPEC, compute=lambda *args: calls.append(1))
    assert calls == []


@pytest.mark.parametrize("count_changes", (False, True))
def test_caller_plan_vector_binding_and_generation_rollback(fx, count_changes):
    fx.conn.execute(f"PRAGMA count_changes={int(count_changes)}")
    fx.conn.execute("BEGIN")
    result = fx.put()
    assert result.transaction_state == "pending"
    assert fx.get().cache_id == result.cache_id
    fx.conn.rollback()
    assert fx.get() is None
    assert not fx.conn.execute("SELECT 1 FROM sqlite_master WHERE name='media_source_embedding_artifacts'").fetchone()
    assert fx.store.usage("source:a").retained_bytes == 16


@pytest.mark.parametrize("values", (None, (), (1, 0), (True, 0, 0, 0), (float("nan"), 0, 0, 0),
                                  (float("inf"), 0, 0, 0), (10**1000, 0, 0, 0), (1e-50, 0, 0, 0),
                                  (0, 0, 0, 0), ("1", 0, 0, 0)))
def test_invalid_vectors_refuse_without_schema_or_text(fx, values):
    with refused("invalid-embedding-vector"):
        fx.put(values)
    assert fx.get() is None
    assert not fx.conn.execute("SELECT 1 FROM sqlite_master WHERE name='media_source_embedding_artifacts'").fetchone()


@pytest.mark.parametrize("changes", ({"dimensions": True}, {"dimensions": 0}, {"dimensions": 4097},
                                    {"model_identity": ""}, {"model_identity": "has space"},
                                    {"model_identity": "é"}, {"preprocessing_sha256": "X" * 64}))
def test_invalid_contract(changes):
    with refused("invalid-embedding-input"):
        replace(SPEC, **changes)


@pytest.mark.parametrize("sql", (
    "UPDATE media_source_embedding_artifacts SET vector=zeroblob(100000)",
    "UPDATE media_source_embedding_artifacts SET vector=zeroblob(16)",
    "UPDATE media_source_embedding_artifacts SET vector_sha256='a'",
    "UPDATE media_source_embedding_artifacts SET model_identity=CAST(x'50524956415445ff' AS TEXT)",
    "UPDATE media_source_embedding_artifacts SET dimensions=zeroblob(100000)",
    "UPDATE media_source_embedding_bindings SET ordinal=8",
    "DELETE FROM media_source_embedding_bindings",
))
def test_corrupt_records_refuse_content_free(fx, sql):
    fx.put()
    fx.conn.execute(sql)
    fx.conn.commit()
    with refused("invalid-embedding-record") as caught:
        fx.get()
    assert "PRIVATE" not in str(caught.value)
    assert not fx.conn.in_transaction


@pytest.mark.parametrize("registered", (False, True))
@pytest.mark.parametrize("name", ("media_source_embedding_artifacts", "media_source_embedding_bindings", "idx_source_embeddings_group"))
def test_temp_only_reserved_objects_refuse_before_missing_schema(tmp_path, registered, name):
    conn = sqlite3.connect(tmp_path / "temp.db")
    if registered:
        MediaStore(conn=conn)
    conn.execute(f"CREATE TEMP TABLE {name}(value)")
    store = SourceEmbeddingStore(conn)
    with refused("incompatible-embedding-schema"):
        store.get("source:a", "a" * 64, 0, contract=SPEC)
    assert not conn.in_transaction
    conn.close()


@pytest.mark.parametrize("sql", (
    "DROP TABLE media_source_embedding_bindings",
    "CREATE INDEX extra ON media_source_embedding_artifacts(model_identity)",
    "CREATE TRIGGER changed AFTER INSERT ON media_source_embedding_bindings BEGIN SELECT 1; END",
))
def test_unknown_schema_refuses_without_repair(fx, sql):
    fx.put()
    fx.conn.execute(sql)
    fx.conn.commit()
    with refused("incompatible-embedding-schema"):
        fx.get()


def test_contract_budget_does_not_reset_by_new_generation(fx):
    for number in range(8):
        fx.put(spec=replace(SPEC, model_identity=f"synthetic/model@{number}"))
    generations = SourceIndexGenerations(fx.conn)
    generation = generations.begin("source:a", "empty", ()).generation_id
    generations.publish(generation)
    with refused("embedding-budget-exceeded"):
        fx.put(spec=replace(SPEC, model_identity="synthetic/model@nine"))
    assert fx.conn.execute("SELECT count(*) FROM media_source_embedding_artifacts").fetchone()[0] == 8


def test_float32_bytes_checksums_and_no_original_sidecar(fx):
    result = fx.put((0.1, 0, 0, 0))
    blob, digest = fx.conn.execute("SELECT vector,vector_sha256 FROM media_source_embedding_artifacts").fetchone()
    assert blob == struct.pack("<4f", 0.1, 0, 0, 0)
    assert hashlib.sha256(blob).hexdigest() == digest
    assert result.values[0] == struct.unpack("<f", struct.pack("<f", 0.1))[0]
    assert fx.conn.execute("SELECT count(*) FROM media_moments").fetchone()[0] == 0
    for path in fx.path.parent.glob("embedding.db*"):
        assert b"OMITTED-EMBEDDING-SOURCE" not in path.read_bytes()


def test_1024_dimensions_are_explicit_and_do_not_change_runtime_identity(fx):
    spec = replace(SPEC, dimensions=1024)
    result = fx.put((1.0,) + (0.0,) * 1023, spec=spec)
    assert len(result.values) == 1024
    assert fx.get(spec=spec).cache_id == result.cache_id
    assert fx.get() is None


def test_actual_process_exit_leaves_no_partial_vector(fx):
    script = """
import os, sqlite3, sys
from mnemosyne.core.source_embedding_store import SourceEmbeddingStore, EmbeddingContract
c=sqlite3.connect(sys.argv[1]); c.execute('BEGIN IMMEDIATE')
s=SourceEmbeddingStore(c)
r=s.put('source:a',sys.argv[2],0,(1.,0.,0.,0.),contract=EmbeddingContract('domain:a','synthetic/model@revision-one',4,'a'*64))
assert r.transaction_state=='pending'
os._exit(73)
"""
    child = subprocess.run([sys.executable, "-c", script, str(fx.path), fx.plan.fingerprint],
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}, capture_output=True, text=True)
    assert child.returncode == 73, child.stderr
    assert fx.get() is None
    assert fx.put().status == "created"


def test_readonly_and_busy_connections_preserve_owner(fx):
    fx.put()
    readonly = sqlite3.connect(f"file:{fx.path}?mode=ro", uri=True)
    conn = sqlite3.connect(fx.path, timeout=0)
    try:
        assert SourceEmbeddingStore(readonly).get("source:a", fx.plan.fingerprint, 0, contract=SPEC).values == VALUES
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            SourceEmbeddingStore(readonly).put("source:a", fx.plan.fingerprint, 0, VALUES,
                                             contract=replace(SPEC, sharing_domain="domain:b"))
        assert not readonly.in_transaction
        fx.conn.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            SourceEmbeddingStore(conn).reuse("source:a", fx.plan.fingerprint, 0, contract=SPEC)
        assert not conn.in_transaction
        fx.conn.rollback()
    finally:
        readonly.close()
        conn.close()


@pytest.mark.parametrize("encoding", ("UTF-16le", "UTF-16be"))
def test_utf16_store_refuses_before_embedding_schema(tmp_path, encoding):
    conn = sqlite3.connect(tmp_path / "encoding.db")
    conn.execute(f"PRAGMA encoding='{encoding}'")
    MediaStore(conn=conn)
    with refused("unsupported-encoding"):
        SourceEmbeddingStore(conn).get("source:a", "a" * 64, 0, contract=SPEC)
    assert not conn.execute("SELECT 1 FROM sqlite_master WHERE name LIKE 'media_source_embedding_%'").fetchone()
    conn.close()


def test_exact_retry_after_lost_commit_acknowledgement(fx):
    class LostAck(sqlite3.Connection):
        armed = True

        def execute(self, sql, *args, **kwargs):
            result = super().execute(sql, *args, **kwargs)
            if self.armed and sql == "COMMIT":
                self.armed = False
                raise sqlite3.OperationalError("synthetic lost commit acknowledgement")
            return result

    conn = sqlite3.connect(fx.path, factory=LostAck)
    cache = SourceEmbeddingStore(conn)
    try:
        with pytest.raises(sqlite3.OperationalError, match="lost commit"):
            cache.put("source:a", fx.plan.fingerprint, 0, VALUES, contract=SPEC)
        assert not conn.in_transaction
        assert cache.put("source:a", fx.plan.fingerprint, 0, VALUES, contract=SPEC).status == "reused"
        assert conn.execute("SELECT count(*) FROM media_source_embedding_artifacts").fetchone()[0] == 1
    finally:
        conn.close()


def test_pinned_previous_source_can_still_read_write_without_touching_cache(fx):
    prior = Path(__file__).resolve().parents[2] / "mnemosyne-s4a"
    if not prior.is_dir():
        pytest.skip("pinned prior S4a source not available")
    pin = subprocess.run(["git", "rev-parse", "HEAD"], cwd=prior, capture_output=True, text=True, check=True)
    assert pin.stdout.strip() == "7ddfeba961d7228e5ec84f2d6e8a765f49579f0e"
    fx.put()
    generations = SourceIndexGenerations(fx.conn)
    generation = generations.begin("source:a", "old", (fx.plan.fingerprint,)).generation_id
    generations.checkpoint(generation, fx.plan.fingerprint)
    generations.publish(generation)
    script = """
import hashlib, sqlite3, sys
from mnemosyne.core.source_index_generations import SourceIndexGenerations
from mnemosyne.core.source_index_store import SourceIndexStore
from mnemosyne.core.source_indexing import SourceSpan
c=sqlite3.connect(sys.argv[1]); s=SourceIndexStore(c)
assert SourceIndexGenerations(c).current('source:a').generation_id==sys.argv[3]
text='SELECTED EXCERPT'+'OMITTED-EMBEDDING-SOURCE'*100
assert s.write('source:a',sys.argv[2],text,extraction_sha256=hashlib.sha256(text.encode()).hexdigest(),
output_locator='archive://synthetic/extraction',spans=(SourceSpan(1,17),)).status=='created'
assert c.execute('SELECT count(*) FROM media_source_embedding_artifacts').fetchone()[0]==1
c.close()
"""
    child = subprocess.run([sys.executable, "-c", script, str(fx.path), fx.revision, generation], cwd=prior,
        env={**os.environ, "PYTHONPATH": str(prior)}, capture_output=True, text=True)
    assert child.returncode == 0, child.stderr
    assert fx.get().values == VALUES


def test_bounded_read_does_not_materialize_float_tuples_for_other_artifacts(fx, monkeypatch):
    for number in range(8):
        fx.put(spec=replace(SPEC, model_identity=f"synthetic/model@{number}"))
    original = struct.unpack
    calls = []

    def tracked(*args):
        calls.append(args[0])
        return original(*args)

    monkeypatch.setattr(struct, "unpack", tracked)
    assert fx.get(spec=replace(SPEC, model_identity="synthetic/model@0")).values == VALUES
    assert calls == ["<4f"]
