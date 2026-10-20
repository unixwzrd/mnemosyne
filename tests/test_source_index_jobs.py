"""Synthetic model-bound owner import jobs, never real providers or stores."""

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from mnemosyne.core.media import MediaStore
from mnemosyne.core.source_embedding_store import EmbeddingContract
from mnemosyne.core.source_index_generations import SourceIndexGenerations
from mnemosyne.core.source_index_jobs import SourceIndexJobs
from mnemosyne.core.source_index_store import SourceIndexStore, SourceIndexStoreError
from mnemosyne.core.source_indexing import SourceSpan


SPEC = EmbeddingContract("domain:a", "synthetic/model@one", 4, "a" * 64)
TEXT = "A" * 32 + "B" * 32 + "C" * 32 + "OMITTED-JOB-SOURCE" * 300


class Fixture:
    def __init__(self, root):
        self.path = root / "jobs.db"
        self.media = MediaStore(db_path=self.path)
        self.conn = self.media.conn
        self.store = SourceIndexStore(self.conn)
        self.jobs = SourceIndexJobs(self.conn)
        asset = self.store.register_source("source:a", "archive://synthetic/original").asset_id
        self.revision = self.media.register_source_revision(asset, revision_key="one", content_hash="a" * 64).revision_id
        self.plans = tuple(self.store.write("source:a", self.revision, TEXT,
            extraction_sha256=hashlib.sha256(TEXT.encode()).hexdigest(), output_locator="archive://synthetic/extraction",
            spans=(SourceSpan(start, start + 16),)).fingerprint for start in (0, 32, 64))
        self.calls = []

    def compute(self, text, spec):
        assert not self.conn.in_transaction
        self.calls.append((text, spec))
        return (1.0,) + (0.0,) * (spec.dimensions - 1)

    def begin(self, key="one", plans=None, spec=SPEC):
        return self.jobs.begin("source:a", key, self.plans if plans is None else plans, contract=spec).job.generation.generation_id

    def run(self, generation, compute=None):
        return self.jobs.run(generation, compute=compute or self.compute)


@pytest.fixture
def fx(tmp_path):
    value = Fixture(tmp_path)
    yield value
    value.conn.close()


def refused(code):
    return pytest.raises(SourceIndexStoreError, match="^source_index_store:" + code + "$")


def test_constructor_and_missing_reads_do_not_create_optional_schema(fx):
    fx.conn.execute("CREATE TABLE unrelated(value)")
    fx.conn.execute("INSERT INTO unrelated VALUES(1)")
    assert fx.jobs.get("a" * 64) is None
    assert fx.jobs.current("source:a") is None
    assert fx.conn.in_transaction
    assert not fx.conn.execute("SELECT 1 FROM sqlite_master WHERE name='media_source_index_embedding_jobs'").fetchone()
    fx.conn.rollback()


def test_complete_job_records_model_and_publishes_only_embedding_readiness(fx):
    generation = fx.begin()
    assert not fx.jobs.get(generation).embedding_ready
    result = fx.run(generation)
    assert result.embedding_ready and result.generation.state == "published"
    assert result.contract == SPEC
    assert result.generation.coverage == dict(total=3, planned=0, completed=3, failed=0, excluded=0)
    assert len(fx.calls) == 3
    assert fx.jobs.current("source:a").generation.generation_id == generation
    assert fx.run(generation).embedding_ready
    assert len(fx.calls) == 3
    assert fx.begin() == generation
    assert not fx.jobs.get(generation).embedding_ready


@pytest.mark.parametrize("failure", (RuntimeError, KeyboardInterrupt))
def test_partial_failure_preserves_usable_predecessor_and_resumes(fx, failure):
    old = fx.begin("old", (fx.plans[0],))
    fx.run(old)
    new = fx.begin("new", fx.plans[1:])
    before = len(fx.calls)

    def compute(text, spec):
        if text == "C" * 16:
            raise failure("synthetic provider interruption")
        return fx.compute(text, spec)

    with pytest.raises(failure):
        fx.run(new, compute)
    assert fx.jobs.current("source:a").generation.generation_id == old
    coverage = fx.jobs.get(new).generation.coverage
    assert coverage == dict(total=2, planned=0, completed=1, failed=1, excluded=0)
    fx.conn.close()
    fx.conn = sqlite3.connect(fx.path)
    fx.jobs = SourceIndexJobs(fx.conn)
    result = fx.run(new)
    assert result.embedding_ready and result.generation.generation_id == new
    assert len(fx.calls) == before + 2
    assert fx.jobs.get(old).generation.state == "published"


@pytest.mark.parametrize("change", ({"model_identity": "synthetic/model@two"}, {"dimensions": 1024},
                                    {"sharing_domain": "domain:b"}, {"preprocessing_sha256": "b" * 64}))
def test_model_contract_change_creates_new_generation_and_recomputes(fx, change):
    old = fx.begin(plans=(fx.plans[0],))
    fx.run(old)
    spec = replace(SPEC, **change)
    new = fx.begin(plans=(fx.plans[0],), spec=spec)
    assert new != old
    assert fx.run(new).contract == spec
    assert len(fx.calls) == 2
    assert fx.jobs.current("source:a").contract == spec


def test_one_changed_excerpt_recomputes_only_that_artifact(fx):
    old = fx.begin("old", (fx.plans[0], fx.plans[1]))
    fx.run(old)
    new = fx.begin("new", (fx.plans[0], fx.plans[2]))
    fx.run(new)
    assert [text for text, _ in fx.calls] == ["A" * 16, "B" * 16, "C" * 16]
    assert fx.conn.execute("SELECT count(*) FROM media_source_embedding_artifacts").fetchone()[0] == 3


def test_excluded_preparation_is_explicit_and_does_not_block_readable_plan(fx):
    missing = "f" * 64
    generation = fx.begin(plans=(fx.plans[0], missing))
    receipt = fx.jobs.exclude(generation, missing, reason="awaiting-preparation")
    assert receipt.transaction_state == "committed"
    ready = fx.run(generation)
    assert ready.embedding_ready and ready.generation.coverage["excluded"] == 1
    assert len(fx.calls) == 1
    assert fx.jobs.current("source:a").generation.coverage["excluded"] == 1


def test_legacy_evidence_only_generation_is_not_embedding_index(fx):
    generations = SourceIndexGenerations(fx.conn)
    legacy = generations.begin("source:a", "legacy", (fx.plans[0],)).generation_id
    generations.checkpoint(legacy, fx.plans[0])
    generations.publish(legacy)
    assert fx.jobs.current("source:a") is None


def test_old_owner_api_cannot_forge_embedding_readiness_with_completion_only(fx):
    generation = fx.begin(plans=(fx.plans[0],))
    generations = SourceIndexGenerations(fx.conn)
    generations.checkpoint(generation, fx.plans[0])
    generations.publish(generation)
    with refused("index-job-incomplete"):
        fx.jobs.current("source:a")
    assert len(fx.calls) == 0


@pytest.mark.parametrize("sql", ("DELETE FROM media_source_index_embedding_jobs", "DROP TABLE media_source_index_embedding_jobs"))
def test_missing_job_metadata_cannot_downgrade_or_be_silently_recreated(fx, sql):
    generation = fx.begin(plans=(fx.plans[0],))
    fx.run(generation)
    fx.conn.execute(sql)
    fx.conn.commit()
    for operation in (lambda: fx.jobs.get(generation), lambda: fx.jobs.current("source:a"),
                      lambda: fx.begin(plans=(fx.plans[0],))):
        with refused("invalid-index-job-record"):
            operation()
    assert not fx.conn.in_transaction


def test_readiness_requires_new_lineage_not_just_matching_cached_text(fx):
    old = fx.begin("old", (fx.plans[0],))
    fx.run(old)
    revision = fx.media.register_source_revision(
        fx.conn.execute("SELECT asset_id FROM media_source_index_assets LIMIT 1").fetchone()[0],
        revision_key="two", content_hash="b" * 64).revision_id
    moved = fx.store.write("source:a", revision, TEXT, extraction_sha256=hashlib.sha256(TEXT.encode()).hexdigest(),
                           output_locator="archive://synthetic/extraction", spans=(SourceSpan(0, 16),)).fingerprint
    new = fx.begin("new", (moved,))
    generations = SourceIndexGenerations(fx.conn)
    generations.checkpoint(new, moved)
    generations.publish(new)
    with refused("index-job-incomplete"):
        fx.jobs.current("source:a")


def test_stale_parent_refuses_before_compute(fx):
    old = fx.begin("old", (fx.plans[0],))
    fx.run(old)
    stale = fx.begin("stale", (fx.plans[1],))
    winner = fx.begin("winner", (fx.plans[2],))
    fx.run(winner)
    before = len(fx.calls)
    with refused("stale-generation-parent"):
        fx.run(stale)
    assert len(fx.calls) == before
    assert fx.jobs.current("source:a").generation.generation_id == winner
    with refused("stale-generation-parent"):
        fx.run(old)


def test_competing_publication_during_callback_cannot_replace_winner(fx):
    old = fx.begin("old", (fx.plans[0],))
    fx.run(old)
    loser = fx.begin("loser", (fx.plans[1],))
    winner = fx.begin("winner", ())

    def compute(text, spec):
        fx.run(winner)
        return fx.compute(text, spec)

    with refused("stale-generation-parent"):
        fx.run(loser, compute)
    assert fx.jobs.current("source:a").generation.generation_id == winner


@pytest.mark.parametrize("count_changes", (False, True))
def test_begin_and_exclude_respect_outer_transaction(fx, count_changes):
    fx.conn.execute(f"PRAGMA count_changes={int(count_changes)}")
    fx.conn.execute("BEGIN")
    receipt = fx.jobs.begin("source:a", "pending", ("a" * 64,), contract=SPEC)
    assert receipt.transaction_state == "pending"
    generation = receipt.job.generation.generation_id
    assert fx.jobs.exclude(generation, "a" * 64, reason="unsupported").transaction_state == "pending"
    assert fx.conn.in_transaction
    with refused("index-job-callback-in-transaction"):
        fx.run(generation)
    fx.conn.rollback()
    assert fx.jobs.get(generation) is None
    assert not fx.calls


def test_callback_opening_and_raising_does_not_mutate_its_transaction(fx):
    generation = fx.begin(plans=(fx.plans[0],))

    def compute(text, spec):
        fx.conn.execute("BEGIN")
        raise RuntimeError("synthetic callback owns this transaction")

    with pytest.raises(RuntimeError, match="owns this transaction"):
        fx.run(generation, compute)
    assert fx.conn.in_transaction
    assert fx.jobs.get(generation).generation.coverage["planned"] == 1
    fx.conn.rollback()


@pytest.mark.parametrize("column", ("job_key", "sharing_domain", "model_identity", "preprocessing_sha256"))
def test_malformed_job_text_refuses_without_decoder_payload(fx, column):
    generation = fx.begin()
    fx.conn.execute(f"UPDATE media_source_index_embedding_jobs SET {column}=CAST(x'50524956415445ff' AS TEXT)")
    fx.conn.commit()
    with refused("invalid-index-job-record") as caught:
        fx.jobs.get(generation)
    assert "PRIVATE" not in str(caught.value)
    assert not fx.conn.in_transaction


@pytest.mark.parametrize("sql", (
    "UPDATE media_source_index_embedding_jobs SET dimensions=zeroblob(100000)",
    "UPDATE media_source_index_embedding_jobs SET model_identity='other/model'",
    "UPDATE media_source_index_embedding_jobs SET job_key='other-key'",
))
def test_contract_or_type_corruption_refuses(fx, sql):
    generation = fx.begin()
    fx.conn.execute(sql)
    fx.conn.commit()
    with refused("invalid-index-job-record"):
        fx.jobs.get(generation)


@pytest.mark.parametrize("sql", (
    "CREATE INDEX extra ON media_source_index_embedding_jobs(job_key)",
    "CREATE TRIGGER changed AFTER INSERT ON media_source_index_embedding_jobs BEGIN SELECT 1; END",
    "CREATE TEMP TABLE media_source_index_embedding_jobs(value)",
))
def test_unknown_job_schema_refuses(fx, sql):
    generation = fx.begin()
    fx.conn.execute(sql)
    fx.conn.commit()
    with refused("incompatible-index-job-schema"):
        fx.jobs.get(generation)


def test_temp_only_job_schema_refuses_clean_missing_reads(tmp_path):
    conn = sqlite3.connect(tmp_path / "temp.db")
    conn.execute("CREATE TEMP TABLE media_source_index_embedding_jobs(value)")
    with refused("incompatible-index-job-schema"):
        SourceIndexJobs(conn).current("source:a")
    assert not conn.in_transaction
    conn.close()


def test_empty_and_reference_only_jobs_are_explicit_ready_without_compute(fx):
    empty = fx.begin("empty", ())
    assert fx.run(empty).embedding_ready
    reference = fx.store.write("source:a", fx.revision, TEXT, extraction_sha256=hashlib.sha256(TEXT.encode()).hexdigest(),
                               output_locator="archive://synthetic/extraction", spans=()).fingerprint
    job = fx.begin("reference", (reference,))
    assert fx.run(job).embedding_ready
    assert fx.calls == []
    assert fx.jobs.current("source:a").generation.coverage["completed"] == 1


def test_actual_process_exit_retains_prior_and_reuses_completed_artifact(fx):
    old = fx.begin("old", (fx.plans[0],))
    fx.run(old)
    new = fx.begin("new", fx.plans[1:])
    script = """
import os, sqlite3, sys
from mnemosyne.core.source_index_jobs import SourceIndexJobs
c=sqlite3.connect(sys.argv[1]); j=SourceIndexJobs(c)
def compute(text,spec):
    if text=='C'*16: os._exit(73)
    return (1.,0.,0.,0.)
j.run(sys.argv[2],compute=compute)
"""
    child = subprocess.run([sys.executable, "-c", script, str(fx.path), new],
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}, capture_output=True, text=True)
    assert child.returncode == 73, child.stderr
    assert fx.jobs.current("source:a").generation.generation_id == old
    assert fx.jobs.get(new).generation.coverage == dict(total=2, planned=1, completed=1, failed=0, excluded=0)
    assert fx.run(new).embedding_ready
    assert [text for text, _ in fx.calls] == ["A" * 16, "C" * 16]
    assert fx.conn.execute("SELECT count(*) FROM media_source_embedding_artifacts").fetchone()[0] == 3
    for path in fx.path.parent.glob("jobs.db*"):
        assert b"OMITTED-JOB-SOURCE" not in path.read_bytes()
