"""Disposable owner-mode S3b catalogue, never live memory or protected activation."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import sqlite3
import subprocess
import sys

import pytest

from mnemosyne.core.media import MediaStore, MomentDraft
from mnemosyne.core.source_index_store import SourceIndexStore, SourceIndexStoreError
from mnemosyne.core.source_indexing import ExcerptLimits, SourceIndexError, SourceSpan


TEXT = "x" * 1000


class Fixture:
    def __init__(self, root, limits=ExcerptLimits(), conn=None):
        self.path = root / "catalogue.db"
        self.media = MediaStore(db_path=self.path, conn=conn)
        self.conn = self.media.conn
        self.store = SourceIndexStore(self.conn)
        self.asset = self.store.register_source("source:a", "archive://synthetic/original", limits=limits).asset_id
        self.revision = self.revise(self.asset, "one")

    def revise(self, asset, key):
        return self.media.register_source_revision(asset, revision_key=key, content_hash=hashlib.sha256(key.encode()).hexdigest()).revision_id

    def write(self, *, revision=None, text=TEXT, spans=(SourceSpan(0, 100),), **changes):
        options = dict(extraction_sha256=hashlib.sha256(text.encode()).hexdigest(),
                       output_locator="archive://synthetic/extraction", spans=spans)
        options.update(changes)
        return self.store.write("source:a", revision or self.revision, text, **options)


@pytest.fixture
def fx(tmp_path):
    value = Fixture(tmp_path)
    yield value
    value.conn.close()


def error(code):
    return pytest.raises(SourceIndexStoreError, match="^source_index_store:" + code + "$")


def test_constructor_and_missing_reads_do_not_migrate_or_commit(tmp_path):
    conn = sqlite3.connect(tmp_path / "empty.db")
    conn.execute("CREATE TABLE unrelated(value)")
    conn.execute("INSERT INTO unrelated VALUES(1)")
    store = SourceIndexStore(conn)
    assert store.usage("source:a") is None
    assert store.get_plan("a" * 64) is None
    assert conn.in_transaction
    assert [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")] == ["unrelated"]
    conn.rollback()
    assert conn.execute("SELECT count(*) FROM unrelated").fetchone()[0] == 0
    conn.close()


def test_exact_retry_and_roundtrip_after_reopen(fx):
    first = fx.write()
    assert (first.status, first.transaction_state) == ("created", "committed")
    assert fx.write().status == "unchanged"
    usage = fx.store.usage("source:a")
    assert (usage.retained_bytes, usage.excerpt_count, usage.plan_count, usage.byte_ceiling) == (100, 1, 1, 250)
    fx.conn.close()
    fx.conn = sqlite3.connect(fx.path)
    fx.store = SourceIndexStore(fx.conn)
    record = fx.store.get_plan(first.fingerprint)
    assert record.excerpts[0].text == "x" * 100
    assert record.fingerprint == first.fingerprint
    assert "archive://" not in repr(record)
    assert "x" * 100 not in repr(record)


def test_aliases_and_revisions_share_lifetime_budget(fx):
    alias = fx.store.register_source("source:a", "archive://synthetic/relocated").asset_id
    later = fx.revise(alias, "later")
    assert fx.write().status == "created"
    assert fx.write(revision=later, spans=(SourceSpan(100, 200),)).status == "created"
    with error("source-budget-exceeded"):
        fx.write(revision=later, spans=(SourceSpan(200, 251),))
    assert fx.store.usage("source:a").retained_bytes == 200
    assert fx.store.usage("source:a").alias_count == 2


def test_larger_extraction_cannot_raise_ceiling_and_smaller_one_can_lower(fx):
    fx.write()
    fx.write(text="x" * 2000, spans=(SourceSpan(100, 200),))
    assert fx.store.usage("source:a").byte_ceiling == 250
    with error("source-budget-exceeded"):
        fx.write(text="x" * 2000, spans=(SourceSpan(200, 251),))
    with error("source-budget-exceeded"):
        fx.write(text="x" * 400, spans=(SourceSpan(200, 201),))
    assert fx.store.usage("source:a").byte_ceiling == 250


def test_smaller_ceiling_persists_and_reference_only_does_not_change_it(fx):
    fx.write(spans=(SourceSpan(0, 10),))
    fx.write(text="x" * 400, spans=(SourceSpan(10, 20),))
    fx.write(text="", spans=())
    assert fx.store.usage("source:a").byte_ceiling == 100
    with error("source-budget-exceeded"):
        fx.write(spans=(SourceSpan(20, 101),))


def test_registration_retry_conflicts_and_existing_assets_not_adopted(fx):
    assert fx.store.register_source("source:a", "ARCHIVE://SYNTHETIC/original").status == "unchanged"
    with error("limits-conflict"):
        fx.store.register_source("source:a", "archive://synthetic/other", limits=ExcerptLimits(retained_bytes=100))
    with error("existing-asset-refused"):
        fx.store.register_source("source:b", "archive://synthetic/original")
    old = fx.media.upsert_asset(ref_kind="url", ref_value="archive://synthetic/existing", modality="document")
    with error("existing-asset-refused"):
        fx.store.register_source("source:b", "archive://synthetic/existing")
    assert fx.media.get_asset(old.asset_id)
    assert fx.store.usage("source:b") is None


def test_revision_must_belong_to_group(fx):
    asset = fx.store.register_source("source:b", "archive://synthetic/unrelated").asset_id
    other = fx.revise(asset, "other")
    with error("revision-mismatch"):
        fx.write(revision=other)
    with error("revision-mismatch"):
        fx.write(revision="revision:sha256:" + "0" * 64)
    assert fx.store.usage("source:a").plan_count == 0


@pytest.mark.parametrize("change", [
    {"extraction_sha256": "0" * 64}, {"output_locator": "https://bad host/path"},
    {"spans": (SourceSpan(0, 1001),)}, {"spans": (SourceSpan(0, 251),)},
])
def test_raw_inputs_revalidated_and_failure_leaves_no_rows(fx, change):
    with pytest.raises(SourceIndexError):
        fx.write(**change)
    assert fx.store.usage("source:a").plan_count == 0
    assert not fx.conn.in_transaction


def test_caller_transaction_success_pending_and_failure_preserves_unrelated_work(fx):
    fx.conn.execute("CREATE TABLE unrelated(value)")
    fx.conn.execute("INSERT INTO unrelated VALUES(7)")
    assert fx.write().transaction_state == "pending"
    assert fx.conn.in_transaction
    with error("source-budget-exceeded"):
        fx.write(spans=(SourceSpan(100, 251),))
    assert fx.conn.execute("SELECT value FROM unrelated").fetchone()[0] == 7
    assert fx.store.usage("source:a").retained_bytes == 100
    fx.conn.rollback()
    assert fx.store.usage("source:a").retained_bytes == 0
    assert fx.conn.execute("SELECT count(*) FROM unrelated").fetchone()[0] == 0


def test_registration_in_caller_transaction_does_not_commit_native_asset(tmp_path):
    media = MediaStore(db_path=tmp_path / "registration.db")
    media.conn.execute("BEGIN")
    result = SourceIndexStore(media.conn).register_source("source:a", "archive://synthetic/new")
    assert result.transaction_state == "pending"
    media.conn.rollback()
    assert media.get_asset(result.asset_id) is None
    assert not media.conn.execute("SELECT 1 FROM sqlite_master WHERE name='media_source_index_groups'").fetchone()
    media.conn.close()


def test_count_changes_and_foreign_keys_do_not_leave_active_cursors(fx):
    fx.conn.execute("PRAGMA count_changes=ON")
    fx.conn.execute("PRAGMA foreign_keys=ON")
    assert fx.write().transaction_state == "committed"
    assert fx.write().status == "unchanged"
    assert not fx.conn.in_transaction


def test_alias_count_limit_and_cross_group_reference_refusal(fx):
    for index in range(31):
        fx.store.register_source("source:a", f"archive://synthetic/alias-{index}")
    assert fx.store.usage("source:a").alias_count == 32
    with error("alias-limit-exceeded"):
        fx.store.register_source("source:a", "archive://synthetic/alias-overflow")
    assert fx.store.register_source("source:a", "archive://synthetic/original").status == "unchanged"


def test_reference_only_plans_are_bounded_and_retry_is_free(fx):
    first = None
    for index in range(128):
        current = fx.write(text="", spans=(), output_locator=f"archive://synthetic/empty-{index}")
        first = current if first is None else first
    assert fx.store.usage("source:a").plan_count == 128
    assert fx.write(text="", spans=(), output_locator="archive://synthetic/empty-0").fingerprint == first.fingerprint
    with error("plan-limit-exceeded"):
        fx.write(text="", spans=(), output_locator="archive://synthetic/empty-overflow")
    assert fx.store.usage("source:a").retained_bytes == 0


def test_aggregate_count_is_not_reset_by_another_revision(tmp_path):
    fx = Fixture(tmp_path, ExcerptLimits(excerpt_count=2))
    fx.write(spans=(SourceSpan(0, 1), SourceSpan(2, 3)))
    later = fx.revise(fx.asset, "another")
    with error("source-budget-exceeded"):
        fx.write(revision=later, spans=(SourceSpan(4, 5),))
    fx.conn.close()


@pytest.mark.parametrize("target", ["media_source_index_plans", "media_source_index_groups"])
def test_orphaned_retention_refuses_even_with_foreign_keys_disabled(fx, target):
    fx.write()
    fx.conn.execute("PRAGMA foreign_keys=OFF")
    fx.conn.execute(f"DELETE FROM {target}")
    fx.conn.commit()
    with error("invalid-record"):
        fx.store.usage("source:a")


@pytest.mark.parametrize("autocommit", [True, False])
def test_explicit_autocommit_modes_preserve_ownership(tmp_path, autocommit):
    if sys.version_info < (3, 12):
        pytest.skip("sqlite3 autocommit parameter requires Python 3.12")
    conn = sqlite3.connect(tmp_path / "catalogue.db", autocommit=autocommit)
    fx = Fixture(tmp_path, conn=conn)
    result = fx.write()
    assert result.transaction_state == ("committed" if autocommit else "pending")
    if not autocommit:
        conn.rollback()
        assert fx.store.usage("source:a") is None
    conn.close()


@pytest.mark.parametrize("legacy", ["moment", "metadata", "title", "working", "episodic", "invalid-json"])
def test_known_legacy_retention_refuses_reads_and_new_writes(fx, legacy):
    receipt = fx.write()
    if legacy == "moment":
        fx.media.add_moments(fx.asset, [MomentDraft("caption", "legacy text")])
    elif legacy in {"metadata", "title"}:
        value = '{"unknown":"legacy text"}' if legacy == "metadata" else "legacy text"
        fx.conn.execute(f"UPDATE media_assets SET {legacy}=? WHERE asset_id=?", (value, fx.asset))
    else:
        table = "episodic_memory" if legacy == "episodic" else "working_memory"
        fx.conn.execute(f"CREATE TABLE {table}(metadata_json TEXT)")
        value = "invalid" if legacy == "invalid-json" else json.dumps({"media": {"asset_id": fx.asset}})
        fx.conn.execute(f"INSERT INTO {table} VALUES(?)", (value,))
    fx.conn.commit()
    for call in (lambda: fx.store.usage("source:a"), lambda: fx.store.get_plan(receipt.fingerprint), lambda: fx.write(spans=())):
        with error("unaccounted-legacy-state"):
            call()


@pytest.mark.parametrize("kind", ["extra-index", "main-trigger", "temp-trigger", "temp-shadow", "partial-schema"])
def test_incompatible_optional_schema_refuses_without_repair(fx, kind):
    if kind == "extra-index":
        fx.conn.execute("CREATE INDEX extra ON media_source_index_excerpts(text)")
    elif kind in {"main-trigger", "temp-trigger"}:
        prefix = "TEMP " if kind == "temp-trigger" else ""
        fx.conn.execute(f"CREATE {prefix}TRIGGER bad AFTER INSERT ON main.media_source_index_excerpts BEGIN SELECT 1; END")
    elif kind == "temp-shadow":
        fx.conn.execute("CREATE TEMP TABLE media_source_index_groups(value)")
    else:
        fx.conn.execute("DROP TABLE media_source_index_plans")
    before = fx.conn.total_changes
    with error("incompatible-schema"):
        fx.write()
    assert fx.conn.total_changes == before


@pytest.mark.parametrize("corruption", ["bytes", "text", "equal-text", "ordinal", "span", "locator", "ceiling", "limits"])
def test_corrupt_accounting_refuses_not_reset_to_zero(fx, corruption):
    receipt = fx.write()
    sql = {
        "bytes": "UPDATE media_source_index_excerpts SET utf8_bytes=1",
        "text": "UPDATE media_source_index_excerpts SET text='changed'",
        "equal-text": "UPDATE media_source_index_excerpts SET text=replace(text, 'x', 'y')",
        "ordinal": "UPDATE media_source_index_excerpts SET ordinal=9",
        "span": "UPDATE media_source_index_excerpts SET char_end=1000000",
        "locator": "UPDATE media_source_index_plans SET output_locator='data:text/plain,hidden'",
        "ceiling": "UPDATE media_source_index_groups SET byte_ceiling=99999",
        "limits": "UPDATE media_source_index_groups SET retained_bytes=99999",
    }[corruption]
    fx.conn.execute(sql)
    fx.conn.commit()
    with error("invalid-record"):
        fx.store.get_plan(receipt.fingerprint)


def test_source_budget_race_never_overbooks(fx):
    def worker(start):
        conn = sqlite3.connect(fx.path, timeout=10)
        try:
            return SourceIndexStore(conn).write("source:a", fx.revision, TEXT,
                extraction_sha256=hashlib.sha256(TEXT.encode()).hexdigest(), output_locator="archive://synthetic/race",
                spans=(SourceSpan(start, start + 200),)).status
        except SourceIndexStoreError as exc:
            return exc.code
        finally:
            conn.close()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(worker, [0, 200]))
    assert sorted(results) == ["created", "source-budget-exceeded"]
    assert fx.store.usage("source:a").retained_bytes == 200


def test_omitted_source_text_never_enters_database_or_wal(fx, tmp_path):
    fx.conn.execute("PRAGMA journal_mode=WAL")
    text = "SELECTED EXCERPT" + "\nOMITTED-DENIED-CANARY-12345" * 1000
    original = tmp_path / "original.txt"
    original.write_text(text)
    before = original.read_bytes()
    fx.write(text=text, spans=(SourceSpan(0, 16),))
    assert original.read_bytes() == before
    for path in tmp_path.glob("catalogue.db*"):
        assert b"OMITTED-DENIED-CANARY-12345" not in path.read_bytes()
    for table in ("media_moments",):
        assert fx.conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
    assert not fx.conn.execute("SELECT 1 FROM sqlite_master WHERE name LIKE 'fts_%' OR name='working_memory'").fetchone()


def test_process_abort_leaves_no_partial_plan(fx):
    program = """
import hashlib, os, sqlite3, sys
from mnemosyne.core.source_index_store import SourceIndexStore
from mnemosyne.core.source_indexing import SourceSpan
c=sqlite3.connect(sys.argv[1]); c.execute('BEGIN IMMEDIATE')
SourceIndexStore(c).write('source:a',sys.argv[2],'x'*1000,extraction_sha256=hashlib.sha256(b'x'*1000).hexdigest(),output_locator='archive://synthetic/crash',spans=(SourceSpan(0,100),))
os._exit(73)
"""
    result = subprocess.run([sys.executable, "-c", program, str(fx.path), fx.revision], env=os.environ.copy(), capture_output=True)
    assert result.returncode == 73, result.stderr.decode()
    assert fx.store.usage("source:a").plan_count == 0
    assert fx.write().status == "created"


class FailingConnection(sqlite3.Connection):
    failure = None

    def execute(self, sql, parameters=()):
        if self.failure and sql.startswith(self.failure):
            self.failure = None
            raise sqlite3.OperationalError("synthetic injected failure")
        return super().execute(sql, parameters)


@pytest.mark.parametrize("prefix", ["INSERT INTO main.media_source_index_excerpts", "UPDATE main.media_source_index_groups", "RELEASE SAVEPOINT", "COMMIT"])
def test_failed_owned_writes_roll_back_and_release_lock(tmp_path, prefix):
    conn = sqlite3.connect(tmp_path / "catalogue.db", factory=FailingConnection)
    fx = Fixture(tmp_path, conn=conn)
    conn.failure = prefix
    with pytest.raises(sqlite3.OperationalError, match="synthetic injected failure"):
        fx.write()
    assert not conn.in_transaction
    assert fx.store.usage("source:a").plan_count == 0
    assert fx.write().status == "created"
    conn.close()


@pytest.mark.parametrize("prefix", ["CREATE TABLE main.media_source_index_assets", "INSERT INTO main.media_assets", "INSERT INTO main.media_source_index_assets", "COMMIT"])
def test_failed_registration_rolls_back_schema_and_native_asset(tmp_path, prefix):
    conn = sqlite3.connect(tmp_path / "new.db", factory=FailingConnection)
    media = MediaStore(conn=conn)
    store = SourceIndexStore(conn)
    conn.failure = prefix
    with pytest.raises(sqlite3.OperationalError, match="synthetic injected failure"):
        store.register_source("source:a", "archive://synthetic/new")
    assert not conn.in_transaction
    assert media.conn.execute("SELECT count(*) FROM media_assets").fetchone()[0] == 0
    assert not conn.execute("SELECT 1 FROM sqlite_master WHERE name='media_source_index_groups'").fetchone()
    assert store.register_source("source:a", "archive://synthetic/new").status == "created"
    conn.close()


def test_failed_caller_write_only_rolls_back_this_invocation(tmp_path):
    conn = sqlite3.connect(tmp_path / "catalogue.db", factory=FailingConnection)
    fx = Fixture(tmp_path, conn=conn)
    conn.execute("CREATE TABLE unrelated(value)")
    conn.execute("INSERT INTO unrelated VALUES(11)")
    conn.failure = "INSERT INTO main.media_source_index_excerpts"
    with pytest.raises(sqlite3.OperationalError):
        fx.write()
    assert conn.in_transaction
    assert conn.execute("SELECT value FROM unrelated").fetchone()[0] == 11
    assert fx.store.usage("source:a").plan_count == 0
    conn.rollback()
    conn.close()


def test_busy_begin_does_not_strand_a_transaction(fx):
    fx.conn.execute("BEGIN IMMEDIATE")
    other = sqlite3.connect(fx.path, timeout=0)
    with pytest.raises(sqlite3.OperationalError, match="locked"):
        SourceIndexStore(other).write("source:a", fx.revision, TEXT,
            extraction_sha256=hashlib.sha256(TEXT.encode()).hexdigest(), output_locator="archive://synthetic/other", spans=())
    assert not other.in_transaction
    fx.conn.rollback()
    other.close()
    assert fx.write().status == "created"


class LostCommitAcknowledgement(sqlite3.Connection):
    armed = False

    def execute(self, sql, parameters=()):
        result = super().execute(sql, parameters)
        if self.armed and sql == "COMMIT":
            self.armed = False
            raise sqlite3.OperationalError("synthetic lost commit acknowledgement")
        return result


def test_lost_commit_acknowledgement_is_recoverable_without_double_charge(tmp_path):
    conn = sqlite3.connect(tmp_path / "catalogue.db", factory=LostCommitAcknowledgement)
    fx = Fixture(tmp_path, conn=conn)
    conn.armed = True
    with pytest.raises(sqlite3.OperationalError, match="lost commit acknowledgement"):
        fx.write()
    assert not conn.in_transaction
    assert fx.store.usage("source:a").retained_bytes == 100
    assert fx.write().status == "unchanged"
    assert fx.store.usage("source:a").retained_bytes == 100
    conn.close()


class LostBeginAcknowledgement(sqlite3.Connection):
    armed = False

    def execute(self, sql, parameters=()):
        result = super().execute(sql, parameters)
        if self.armed and sql == "BEGIN IMMEDIATE":
            self.armed = False
            raise sqlite3.OperationalError("synthetic lost begin acknowledgement")
        return result


def test_begin_failure_after_lock_acquisition_releases_owned_transaction(tmp_path):
    conn = sqlite3.connect(tmp_path / "catalogue.db", factory=LostBeginAcknowledgement)
    fx = Fixture(tmp_path, conn=conn)
    conn.armed = True
    with pytest.raises(sqlite3.OperationalError, match="lost begin acknowledgement"):
        fx.write()
    assert not conn.in_transaction
    assert fx.write().status == "created"
    conn.close()


def test_savepoint_name_failure_does_not_leak_a_write_lock(fx, monkeypatch):
    def failed_name():
        raise MemoryError("synthetic name allocation failure")
    with monkeypatch.context() as patch:
        patch.setattr("mnemosyne.core.source_index_store.uuid4", failed_name)
        with pytest.raises(MemoryError, match="synthetic name allocation failure"):
            fx.write()
    assert not fx.conn.in_transaction
    assert fx.write().status == "created"


class LostSavepointAcknowledgement(sqlite3.Connection):
    armed = False
    attempted_name = None

    def execute(self, sql, parameters=()):
        result = super().execute(sql, parameters)
        if self.armed and sql.startswith("SAVEPOINT source_index_"):
            self.armed = False
            self.attempted_name = sql.split()[1]
            raise sqlite3.OperationalError("synthetic lost savepoint acknowledgement")
        return result


def test_savepoint_creation_ack_failure_preserves_caller_without_leaking_savepoint(tmp_path):
    conn = sqlite3.connect(tmp_path / "catalogue.db", factory=LostSavepointAcknowledgement)
    fx = Fixture(tmp_path, conn=conn)
    conn.execute("CREATE TABLE unrelated(value)")
    conn.execute("INSERT INTO unrelated VALUES(13)")
    conn.armed = True
    with pytest.raises(sqlite3.OperationalError, match="lost savepoint acknowledgement"):
        fx.write()
    assert conn.in_transaction
    assert conn.execute("SELECT value FROM unrelated").fetchone()[0] == 13
    with pytest.raises(sqlite3.OperationalError, match="no such savepoint"):
        conn.execute("RELEASE SAVEPOINT " + conn.attempted_name)
    conn.rollback()
    conn.close()


@pytest.mark.parametrize("kind", ["asset-view", "revision-view", "nocase-key", "working-schema"])
def test_native_schema_incompatibility_does_not_migrate(fx, kind):
    if kind == "asset-view":
        fx.conn.execute("ALTER TABLE media_assets RENAME TO previous_assets")
        fx.conn.execute("CREATE VIEW media_assets AS SELECT * FROM previous_assets")
    elif kind == "revision-view":
        fx.conn.execute("ALTER TABLE media_source_revisions RENAME TO previous_revisions")
        fx.conn.execute("CREATE VIEW media_source_revisions AS SELECT * FROM previous_revisions")
    elif kind == "nocase-key":
        fx.conn.execute("ALTER TABLE media_source_revisions RENAME TO previous_revisions")
        fx.conn.execute("CREATE TABLE media_source_revisions(revision_id TEXT PRIMARY KEY COLLATE NOCASE, asset_id TEXT)")
    else:
        fx.conn.execute("CREATE TABLE working_memory(unrelated TEXT)")
    fx.conn.commit()
    with error("incompatible-native-schema"):
        fx.write()
    assert not fx.conn.in_transaction


@pytest.mark.parametrize("table,column,numeric", [
    ("media_source_index_groups", "per_excerpt_bytes", True),
    ("media_source_index_groups", "retained_bytes", True),
    ("media_source_index_groups", "excerpt_count", True),
    ("media_source_index_groups", "byte_ceiling", True),
    ("media_source_index_plans", "source_utf8_bytes", True),
    ("media_source_index_excerpts", "ordinal", True),
    ("media_source_index_excerpts", "char_start", True),
    ("media_source_index_excerpts", "char_end", True),
    ("media_source_index_excerpts", "utf8_bytes", True),
    ("media_source_index_excerpts", "text", False),
    ("media_source_index_excerpts", "text_sha256", False),
    ("media_source_index_plans", "output_locator", False),
    ("media_source_index_plans", "source_revision_id", False),
    ("media_source_index_plans", "extraction_sha256", False),
    ("media_source_index_assets", "asset_id", False),
    ("media_assets", "ref_value", False),
    ("media_assets", "ref_kind", False),
])
def test_corrupt_values_are_bounded_before_python_materialization(fx, table, column, numeric):
    fx.write()
    payload = b"X" * 92000 if numeric else "x\0" + "X" * 92000
    fx.conn.execute(f"UPDATE {table} SET {column}=?", (payload,))
    fx.conn.commit()
    def bounded_rows(cursor, row):
        assert all(not isinstance(value, (str, bytes)) or len(value) <= 4096 for value in row), "oversize corrupt value materialized"
        return row
    fx.conn.row_factory = bounded_rows
    with pytest.raises(SourceIndexStoreError):
        fx.store.usage("source:a")


def test_valid_nul_and_multibyte_excerpts_roundtrip(fx):
    text = "x\0🧭" + "padding " * 100
    receipt = fx.write(text=text, spans=(SourceSpan(0, 3),))
    result = fx.store.get_plan(receipt.fingerprint)
    assert result.excerpts[0].text == "x\0🧭"
    assert result.retained_utf8_bytes == 6


@pytest.mark.parametrize("encoding", ["UTF-16le", "UTF-16be"])
@pytest.mark.parametrize("caller_owned", [False, True])
def test_utf16_refuses_before_catalogue_or_content_without_converting_legacy(tmp_path, encoding, caller_owned):
    conn = sqlite3.connect(tmp_path / "utf16.db")
    conn.execute(f"PRAGMA encoding='{encoding}'")
    media = MediaStore(conn=conn)
    conn.execute("CREATE TABLE unrelated(value)")
    conn.commit()
    if caller_owned:
        conn.execute("INSERT INTO unrelated VALUES(19)")
    store = SourceIndexStore(conn)
    for call in (
        lambda: store.register_source("source:a", "archive://synthetic/new"),
        lambda: store.usage("source:a"),
        lambda: store.get_plan("a" * 64),
        lambda: store.write("source:a", "revision:sha256:" + "a" * 64, TEXT,
            extraction_sha256=hashlib.sha256(TEXT.encode()).hexdigest(), output_locator="archive://synthetic/extract", spans=()),
    ):
        with error("unsupported-encoding"):
            call()
        assert conn.in_transaction == caller_owned
        assert not conn.execute("SELECT 1 FROM sqlite_master WHERE name LIKE 'media_source_index_%'").fetchone()
        assert conn.execute("SELECT count(*) FROM media_assets").fetchone()[0] == 0
    assert conn.execute("PRAGMA encoding").fetchone()[0] == encoding
    if caller_owned:
        assert conn.execute("SELECT value FROM unrelated").fetchone()[0] == 19
        conn.rollback()
    old = media.upsert_asset(ref_kind="url", ref_value="archive://synthetic/legacy", modality="document")
    assert media.get_asset(old.asset_id)["ref_value"] == "archive://synthetic/legacy"
    conn.close()
