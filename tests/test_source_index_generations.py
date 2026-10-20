"""Synthetic owner-mode generation recovery; never live stores or providers."""

import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from mnemosyne.core.media import MediaStore
from mnemosyne.core.source_index_generations import SourceIndexGenerations
from mnemosyne.core.source_index_store import SourceIndexStore, SourceIndexStoreError
from mnemosyne.core.source_indexing import SourceSpan, plan_source_index


TEXT = "synthetic evidence " * 100


class Fixture:
    def __init__(self, root):
        self.path = root / "generation.db"
        self.media = MediaStore(db_path=self.path)
        self.conn = self.media.conn
        self.store = SourceIndexStore(self.conn)
        self.generations = SourceIndexGenerations(self.conn)
        asset = self.store.register_source("source:a", "archive://synthetic/original").asset_id
        self.revision = self.media.register_source_revision(asset, revision_key="one", content_hash="a" * 64).revision_id

    def options(self, start=0):
        return dict(extraction_sha256=hashlib.sha256(TEXT.encode()).hexdigest(),
                    output_locator="archive://synthetic/extraction", spans=(SourceSpan(start, start + 10),))

    def fingerprint(self, start=0):
        return plan_source_index(self.revision, TEXT, **self.options(start)).fingerprint

    def write(self, start=0):
        return self.store.write("source:a", self.revision, TEXT, **self.options(start))

    def begin(self, key="one", starts=(0,)):
        return self.generations.begin("source:a", key, tuple(self.fingerprint(n) for n in starts)).generation_id

    def publish(self, key="one", starts=(0,)):
        generation = self.begin(key, starts)
        for start in starts:
            self.write(start)
            self.generations.checkpoint(generation, self.fingerprint(start))
        self.generations.publish(generation)
        return generation


@pytest.fixture
def fx(tmp_path):
    value = Fixture(tmp_path)
    yield value
    value.conn.close()


def error(code):
    return pytest.raises(SourceIndexStoreError, match="^source_index_store:" + code + "$")


def test_missing_reads_and_constructor_preserve_caller_and_schema(tmp_path):
    conn = sqlite3.connect(tmp_path / "empty.db")
    conn.execute("CREATE TABLE unrelated(value)")
    conn.execute("INSERT INTO unrelated VALUES(1)")
    generations = SourceIndexGenerations(conn)
    assert generations.get("a" * 64) is None
    assert generations.current("source:a") is None
    assert conn.in_transaction
    assert [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")] == ["unrelated"]
    with error("source-not-registered"):
        generations.begin("source:a", "one", ())
    conn.rollback()
    assert conn.execute("SELECT count(*) FROM unrelated").fetchone()[0] == 0
    conn.close()


def test_coverage_resume_after_reopen_preserves_current(fx):
    old = fx.publish()
    new = fx.begin("two", (10, 20, 30))
    fx.write(10)
    fx.generations.checkpoint(new, fx.fingerprint(10))
    fx.generations.checkpoint(new, fx.fingerprint(20), state="failed", reason="unavailable")
    fx.generations.checkpoint(new, fx.fingerprint(30), state="excluded", reason="awaiting-preparation")
    assert fx.generations.get(new).coverage == dict(total=3, planned=0, completed=1, failed=1, excluded=1)
    with error("incomplete-generation"):
        fx.generations.publish(new)
    fx.conn.close()
    fx.conn = sqlite3.connect(fx.path)
    fx.store = SourceIndexStore(fx.conn)
    fx.generations = SourceIndexGenerations(fx.conn)
    assert fx.generations.current("source:a").generation_id == old
    assert fx.begin("two", (10, 20, 30)) == new
    fx.write(20)
    fx.generations.checkpoint(new, fx.fingerprint(20))
    assert fx.generations.publish(new).status == "published"
    assert fx.generations.get(old).state == "published"
    assert fx.generations.current("source:a").generation_id == new


def test_exact_retries_and_generation_reuse_do_not_copy_text(fx):
    old = fx.publish()
    usage = fx.store.usage("source:a")
    assert fx.generations.publish(old).status == "unchanged"
    assert fx.generations.checkpoint(old, fx.fingerprint()).status == "unchanged"
    new = fx.publish("two")
    assert fx.store.usage("source:a") == usage
    assert fx.generations.current("source:a").parent_id == old
    assert fx.generations.current("source:a").generation_id == new
    assert fx.begin() == old
    with error("stale-generation-parent"):
        fx.generations.publish(old)
    assert fx.conn.execute("SELECT count(*) FROM media_source_index_excerpts").fetchone()[0] == 1


def test_immutable_manifest_and_terminal_checkpoints(fx):
    generation = fx.begin()
    with error("generation-conflict"):
        fx.begin(starts=(10,))
    with error("evidence-not-ready"):
        fx.generations.checkpoint(generation, fx.fingerprint())
    with error("item-not-planned"):
        fx.generations.checkpoint(generation, fx.fingerprint(10))
    fx.generations.checkpoint(generation, fx.fingerprint(), state="excluded", reason="not-selected")
    with error("terminal-checkpoint"):
        fx.generations.checkpoint(generation, fx.fingerprint(), state="planned")
    fx.generations.publish(generation)
    assert fx.generations.get(generation).coverage["excluded"] == 1


def test_failed_can_resume_without_rewriting_complete_items(fx):
    generation = fx.begin()
    fx.generations.checkpoint(generation, fx.fingerprint(), state="failed", reason="interrupted")
    fx.generations.checkpoint(generation, fx.fingerprint(), state="planned")
    fx.write()
    fx.generations.checkpoint(generation, fx.fingerprint())
    with error("terminal-checkpoint"):
        fx.generations.checkpoint(generation, fx.fingerprint(), state="failed", reason="changed")


def test_competing_connections_publish_once_and_refuse_stale_parent(fx):
    old = fx.publish()
    left = fx.begin("left", ())
    right = fx.begin("right", ())
    conn = sqlite3.connect(fx.path)
    try:
        other = SourceIndexGenerations(conn)
        other.publish(right)
        with error("stale-generation-parent"):
            fx.generations.publish(left)
        assert not fx.conn.in_transaction
        assert fx.generations.current("source:a").generation_id == right
        assert other.get(old).state == "published"
    finally:
        conn.close()


@pytest.mark.parametrize("count_changes", (False, True))
def test_atomic_plan_checkpoint_and_publish_obey_outer_rollback(fx, count_changes):
    old = fx.publish()
    fx.conn.execute(f"PRAGMA count_changes={int(count_changes)}")
    fx.conn.execute("CREATE TABLE unrelated(value)")
    before = fx.store.usage("source:a")
    fx.conn.execute("INSERT INTO unrelated VALUES(7)")
    generation = fx.begin("two", (10,))
    assert fx.write(10).transaction_state == "pending"
    assert fx.generations.checkpoint(generation, fx.fingerprint(10)).transaction_state == "pending"
    assert fx.generations.publish(generation).transaction_state == "pending"
    assert fx.generations.current("source:a").generation_id == generation
    fx.conn.rollback()
    assert fx.generations.current("source:a").generation_id == old
    assert fx.generations.get(generation) is None
    assert fx.store.usage("source:a") == before
    assert fx.conn.execute("SELECT count(*) FROM unrelated").fetchone()[0] == 0


def test_caller_commit_persists_pending_receipt(fx):
    fx.conn.execute("BEGIN")
    receipt = fx.generations.begin("source:a", "empty", ())
    assert receipt.transaction_state == "pending"
    fx.generations.publish(receipt.generation_id)
    fx.conn.commit()
    assert fx.generations.current("source:a").generation_id == receipt.generation_id


@pytest.mark.parametrize("stage", ("begin", "checkpoint", "publish"))
def test_process_exit_discards_uncommitted_change_keeps_previous(fx, stage):
    old = fx.publish()
    pending = fx.begin("two", (10,))
    fx.write(10)
    script = """
import os, sqlite3, sys
from mnemosyne.core.source_index_generations import SourceIndexGenerations
c=sqlite3.connect(sys.argv[1]); g=SourceIndexGenerations(c); c.execute('BEGIN IMMEDIATE')
stage=sys.argv[2]
if stage=='begin': g.begin('source:a', 'crashed', ())
if stage=='checkpoint': g.checkpoint(sys.argv[3], sys.argv[4])
if stage=='publish':
    g.checkpoint(sys.argv[3], sys.argv[4]); g.publish(sys.argv[3])
os._exit(73)
"""
    result = subprocess.run([sys.executable, "-c", script, str(fx.path), stage, pending, fx.fingerprint(10)],
                            env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}, capture_output=True)
    assert result.returncode == 73, result.stderr.decode()
    assert fx.generations.current("source:a").generation_id == old
    assert fx.generations.get(pending).coverage["planned"] == 1
    assert fx.begin("crashed", ()) is not None
    fx.generations.checkpoint(pending, fx.fingerprint(10))
    fx.generations.publish(pending)


@pytest.mark.parametrize("failure", (RuntimeError, KeyboardInterrupt))
@pytest.mark.parametrize("outer", (False, True))
def test_failed_publish_rolls_back_pointer_and_keeps_caller(fx, failure, outer):
    old = fx.publish()
    generation = fx.begin("two", ())
    if outer:
        fx.conn.execute("BEGIN")
    original = fx.generations._audit
    calls = 0

    def injected(key):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise failure("synthetic interruption")
        return original(key)

    fx.generations._audit = injected
    with pytest.raises(failure):
        fx.generations.publish(generation)
    fx.generations._audit = original
    assert fx.conn.in_transaction == outer
    assert fx.generations.current("source:a").generation_id == old
    assert fx.generations.get(generation).state == "staging"
    fx.conn.rollback()


def test_completed_requires_same_group_not_merely_matching_fingerprint(fx):
    asset = fx.store.register_source("source:b", "archive://synthetic/other").asset_id
    revision = fx.media.register_source_revision(asset, revision_key="one", content_hash="b" * 64).revision_id
    plan = fx.store.write("source:b", revision, TEXT, **fx.options())
    generation = fx.generations.begin("source:a", "foreign", (plan.fingerprint,)).generation_id
    with error("evidence-not-ready"):
        fx.generations.checkpoint(generation, plan.fingerprint)


@pytest.mark.parametrize("fingerprints", (["a" * 64], ("A" * 64,), ("a" * 64,) * 2, tuple(f"{n:064x}" for n in range(129)), (True,)))
def test_invalid_manifest_does_not_create_generation_schema(fx, fingerprints):
    with error("invalid-generation-input"):
        fx.generations.begin("source:a", "one", fingerprints)
    assert not fx.conn.execute("SELECT 1 FROM sqlite_master WHERE name='media_source_index_generations'").fetchone()


@pytest.mark.parametrize("state,reason", (("failed", None), ("completed", "private text"), ("excluded", "unknown"), ("unknown", None), (True, None), ("planned", b"")))
def test_invalid_checkpoint_codes_refuse_without_mutation(fx, state, reason):
    generation = fx.begin()
    with error("invalid-generation-input"):
        fx.generations.checkpoint(generation, fx.fingerprint(), state=state, reason=reason)
    assert fx.generations.get(generation).coverage["planned"] == 1


@pytest.mark.parametrize("change", (
    "UPDATE media_source_index_generation_items SET ordinal=2",
    "UPDATE media_source_index_generation_items SET state='completed'",
    "UPDATE media_source_index_generation_items SET reason=zeroblob(100000)",
    "UPDATE media_source_index_generation_items SET fingerprint='a'||char(0)||printf('%100000s','')",
    "UPDATE media_source_index_generations SET generation_key=zeroblob(100000) WHERE generation_key='two'",
    "UPDATE media_source_index_generations SET state='published'",
    "UPDATE media_source_index_heads SET generation_id=NULL",
))
def test_corrupt_records_refuse_without_returning_content(fx, change):
    fx.publish()
    fx.begin("two", (10,))
    fx.conn.execute(change)
    fx.conn.commit()
    with error("invalid-generation-record"):
        fx.generations.current("source:a")
    assert not fx.conn.in_transaction


@pytest.mark.parametrize("sql", (
    "CREATE TEMP TABLE media_source_index_heads(value)",
    "CREATE TRIGGER changed AFTER UPDATE ON media_source_index_heads BEGIN SELECT 1; END",
    "CREATE INDEX extra ON media_source_index_generations(state)",
    "DROP TABLE media_source_index_generation_items",
))
def test_unknown_schema_refuses_without_repair(fx, sql):
    generation = fx.publish()
    fx.conn.execute(sql)
    fx.conn.commit()
    with error("incompatible-generation-schema"):
        fx.generations.get(generation)


def test_orphan_items_refuse_even_with_foreign_keys_disabled(fx):
    fx.publish()
    fx.conn.execute("INSERT INTO media_source_index_generation_items VALUES(?,0,?,'planned',NULL)", ("c" * 64, "d" * 64))
    fx.conn.commit()
    with error("invalid-generation-record"):
        fx.generations.current("source:a")


def test_history_limit_is_explicit_not_silent_eviction(fx):
    first = fx.publish("generation:0", ())
    for number in range(1, 64):
        fx.publish(f"generation:{number}", ())
    with error("generation-limit-exceeded"):
        fx.begin("generation:64", ())
    assert fx.generations.get(first).state == "published"
    assert fx.generations.current("source:a").generation_key == "generation:63"


def test_legacy_catalogue_remains_usable_without_generation_rewrite(fx):
    fx.publish()
    before = fx.conn.execute("SELECT sql FROM sqlite_master WHERE name='media_source_index_plans'").fetchone()[0]
    fx.write(10)
    assert fx.store.get_plan(fx.fingerprint()).excerpts[0].text == TEXT[:10]
    assert fx.store.usage("source:a").plan_count == 2
    assert fx.conn.execute("SELECT sql FROM sqlite_master WHERE name='media_source_index_plans'").fetchone()[0] == before
    assert fx.conn.execute("SELECT count(*) FROM media_moments").fetchone()[0] == 0


def test_new_generation_cannot_reset_source_retention(fx):
    fx.publish()
    before = fx.store.usage("source:a")
    for number in range(1, 5):
        fx.publish(f"empty:{number}", ())
    assert fx.store.usage("source:a") == before


def test_removed_underlying_catalogue_is_not_treated_as_empty(fx):
    fx.publish()
    for table in ("media_source_index_excerpts", "media_source_index_plans", "media_source_index_assets", "media_source_index_groups"):
        fx.conn.execute(f"DROP TABLE {table}")
    fx.conn.commit()
    with error("invalid-generation-record"):
        fx.generations.current("source:a")


def test_failed_initial_begin_rolls_back_optional_schema(fx):
    original = fx.generations._audit
    calls = 0

    def injected(key):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt("synthetic initial schema interruption")
        return original(key)

    fx.generations._audit = injected
    with pytest.raises(KeyboardInterrupt):
        fx.begin()
    fx.generations._audit = original
    assert not fx.conn.in_transaction
    assert not fx.conn.execute("SELECT 1 FROM sqlite_master WHERE name='media_source_index_generations'").fetchone()
    assert fx.store.usage("source:a").plan_count == 0
    assert fx.begin() is not None


@pytest.mark.parametrize("operation", ("begin", "checkpoint", "publish"))
def test_lost_commit_acknowledgement_recovers_by_exact_retry(fx, operation):
    fx.write()
    generation = fx.begin()
    if operation == "publish":
        fx.generations.checkpoint(generation, fx.fingerprint())

    class LostAck(sqlite3.Connection):
        armed = True

        def execute(self, sql, *args, **kwargs):
            result = super().execute(sql, *args, **kwargs)
            if self.armed and sql == "COMMIT":
                self.armed = False
                raise sqlite3.OperationalError("synthetic lost commit acknowledgement")
            return result

    conn = sqlite3.connect(fx.path, factory=LostAck)
    generations = SourceIndexGenerations(conn)
    actions = {
        "begin": lambda: generations.begin("source:a", "ack", (fx.fingerprint(),)),
        "checkpoint": lambda: generations.checkpoint(generation, fx.fingerprint()),
        "publish": lambda: generations.publish(generation),
    }
    try:
        with pytest.raises(sqlite3.OperationalError, match="lost commit"):
            actions[operation]()
        assert not conn.in_transaction
        receipt = actions[operation]()
        assert receipt.status == "unchanged"
        assert receipt.transaction_state == "committed"
        assert fx.store.usage("source:a").plan_count == 1
    finally:
        conn.close()


@pytest.mark.parametrize("encoding", ("UTF-16le", "UTF-16be"))
def test_unsupported_encoding_refuses_before_schema_creation(tmp_path, encoding):
    conn = sqlite3.connect(tmp_path / "encoding.db")
    conn.execute(f"PRAGMA encoding='{encoding}'")
    MediaStore(conn=conn)
    generations = SourceIndexGenerations(conn)
    with error("unsupported-encoding"):
        generations.current("source:a")
    assert not conn.execute("SELECT 1 FROM sqlite_master WHERE name LIKE 'media_source_index_%'").fetchone()
    conn.close()


def test_lock_and_readonly_errors_are_explicit_without_owned_lock_leak(fx):
    old = fx.publish()
    conn = sqlite3.connect(fx.path, timeout=0)
    other = SourceIndexGenerations(conn)
    fx.conn.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            other.begin("source:a", "blocked", ())
        assert not conn.in_transaction
    finally:
        fx.conn.rollback()
        conn.close()
    readonly = sqlite3.connect(f"file:{fx.path}?mode=ro", uri=True)
    try:
        reader = SourceIndexGenerations(readonly)
        assert reader.current("source:a").generation_id == old
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            reader.begin("source:a", "readonly", ())
        assert not readonly.in_transaction
    finally:
        readonly.close()


def test_maximum_manifest_and_explicit_exclusions_are_bounded(fx):
    fingerprints = tuple(f"{n:064x}" for n in range(128))
    generation = fx.generations.begin("source:a", "maximum", fingerprints).generation_id
    for fingerprint in fingerprints:
        fx.generations.checkpoint(generation, fingerprint, state="excluded", reason="unsupported")
    fx.generations.publish(generation)
    assert fx.generations.current("source:a").coverage == dict(total=128, planned=0, completed=0, failed=0, excluded=128)


def test_completed_catalogue_corruption_cannot_be_published(fx):
    old = fx.publish()
    generation = fx.begin("two", (10,))
    fx.write(10)
    fx.generations.checkpoint(generation, fx.fingerprint(10))
    fx.conn.execute("UPDATE media_source_index_excerpts SET text='different!' WHERE fingerprint=?", (fx.fingerprint(10),))
    fx.conn.commit()
    with error("invalid-record"):
        fx.generations.publish(generation)
    assert fx.conn.execute("SELECT generation_id FROM media_source_index_heads WHERE source_key='source:a'").fetchone()[0] == old


def test_retained_s3b_checkout_reads_writes_with_optional_generation_tables(fx):
    prior = Path(__file__).resolve().parents[2] / "mnemosyne-s3b"
    if not prior.is_dir():
        pytest.skip("pinned prior S3b source not available")
    import_result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=prior, capture_output=True, text=True, check=True)
    assert import_result.stdout.strip() == "03bbfb6d8541901cc1468add48627bf1f51101cc"
    generation = fx.publish()
    before = fx.conn.execute("SELECT * FROM media_source_index_heads").fetchall()
    script = """
import hashlib, sqlite3, sys
from mnemosyne.core.source_index_store import SourceIndexStore
from mnemosyne.core.source_indexing import SourceSpan
c=sqlite3.connect(sys.argv[1]); s=SourceIndexStore(c)
assert s.get_plan(sys.argv[2]).excerpts
text='synthetic evidence '*100
assert s.write('source:a', sys.argv[3], text, extraction_sha256=hashlib.sha256(text.encode()).hexdigest(),
output_locator='archive://synthetic/extraction', spans=(SourceSpan(10,20),)).status=='created'
assert s.usage('source:a').plan_count==2
c.close()
"""
    run = subprocess.run([sys.executable, "-c", script, str(fx.path), fx.fingerprint(), fx.revision], cwd=prior,
                         env={**os.environ, "PYTHONPATH": str(prior)}, capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert fx.conn.execute("SELECT * FROM media_source_index_heads").fetchall() == before
    assert fx.generations.current("source:a").generation_id == generation
