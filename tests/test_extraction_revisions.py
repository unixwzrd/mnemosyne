"""Synthetic extraction lineage; legacy recall and live stores are not modified."""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from mnemosyne.core.media import MediaStore, MomentDraft


@pytest.fixture
def store(tmp_path):
    instance = MediaStore(db_path=tmp_path / "extractions.db")
    yield instance
    instance.conn.close()


def parents(store, suffix="one"):
    asset = store.upsert_asset(ref_kind="url", ref_value=f"https://example.invalid/{suffix}", modality="audio").asset_id
    moment = store.add_moments(asset, [MomentDraft(
        kind="transcript", text="synthetic original excerpt", span_kind="time",
        t_start_ms=1000, t_end_ms=2000, speaker="Speaker A",
    )]).moment_ids[0]
    revision = store.register_source_revision(asset, revision_key="bytes-one", content_hash="a" * 64).revision_id
    return asset, revision, moment


def register(store, source, moment, key="extract-one", **kwargs):
    values = dict(extractor="synthetic-asr", extractor_version="1.0", config_hash="b" * 64, output_hash="c" * 64)
    values.update(kwargs)
    return store.register_extraction_revision(source, moment, revision_key=key, **values)


def schema(store):
    return [tuple(row) for row in store.conn.execute("SELECT name, sql FROM sqlite_master ORDER BY name")]


def test_missing_schema_reads_do_not_migrate(store):
    before = schema(store)
    assert store.get_extraction_revision("absent") is None
    assert store.list_extraction_revisions("absent", "absent") == []
    assert schema(store) == before
    assert not store.conn.in_transaction


def test_source_registration_alone_does_not_create_extraction_schema(store):
    parents(store)
    assert not store._has_extraction_revision_schema()


def test_idempotency_identity_and_asserted_not_verified(store):
    _, source, moment = parents(store)
    first = register(store, source, moment, output_hash="C" * 64)
    before = store.get_extraction_revision(first.extraction_revision_id)
    second = register(store, source, moment)
    assert second.extraction_revision_id == first.extraction_revision_id
    assert (first.status, second.status) == ("created", "unchanged")
    assert before == store.get_extraction_revision(second.extraction_revision_id)
    identity = json.dumps(["v1", source, moment, "extract-one"], separators=(",", ":"))
    assert first.extraction_revision_id == "extraction:sha256:" + hashlib.sha256(identity.encode()).hexdigest()
    assert before["digest_status"] == "asserted"
    assert before["registered_at"].endswith("Z")


def test_same_span_correction_preserves_legacy_text_and_byte_revision(store):
    asset, source, moment = parents(store)
    legacy = store.get_moments(asset)
    byte_revision = store.get_source_revision(source)
    first = register(store, source, moment, output_locator="archive:transcript-original")
    second = register(store, source, moment, "human-correction", output_hash="d" * 64,
                      output_locator="archive:transcript-corrected",
                      predecessor_extraction_revision_id=first.extraction_revision_id)
    assert first.extraction_revision_id != second.extraction_revision_id
    assert store.get_moments(asset) == legacy
    assert store.get_source_revision(source) == byte_revision
    rows = store.list_extraction_revisions(source, moment)
    assert {row["output_hash"] for row in rows} == {"c" * 64, "d" * 64}
    assert store.get_extraction_revision(second.extraction_revision_id)["predecessor_extraction_revision_id"] == first.extraction_revision_id
    repeat = store.add_moments(asset, [MomentDraft(kind="transcript", text="would be ignored by legacy ingest",
                              span_kind="time", t_start_ms=1000, t_end_ms=2000, speaker="Speaker A")])
    assert repeat.duplicate == 1
    assert store.get_moments(asset) == legacy


@pytest.mark.parametrize("changed", [
    {"extractor": "another"}, {"extractor_version": "2"}, {"config_hash": "d" * 64},
    {"output_hash": "d" * 64}, {"output_locator": "archive:other"},
])
def test_immutable_conflict_never_overwrites(store, changed):
    _, source, moment = parents(store)
    first = register(store, source, moment)
    before = store.get_extraction_revision(first.extraction_revision_id)
    with pytest.raises(ValueError, match="different immutable extraction"):
        register(store, source, moment, **changed)
    assert store.list_extraction_revisions(source, moment) == [before]


def test_equal_outputs_have_distinct_event_identity_and_branches(store):
    _, source, moment = parents(store)
    first = register(store, source, moment)
    for key in ("correction-a", "correction-b"):
        register(store, source, moment, key, predecessor_extraction_revision_id=first.extraction_revision_id)
    rows = store.list_extraction_revisions(source, moment)
    assert len({row["extraction_revision_id"] for row in rows}) == 3
    assert {row["output_hash"] for row in rows} == {"c" * 64}


@pytest.mark.parametrize("which", ["source", "moment", "cross-asset", "asset-deleted"])
def test_invalid_parent_relationships_roll_back_schema(store, which):
    asset, source, moment = parents(store)
    if which == "source":
        source = "absent"
    elif which == "moment":
        moment = "absent"
    elif which == "cross-asset":
        _, _, moment = parents(store, "other")
    else:
        store.conn.execute("DELETE FROM media_assets WHERE asset_id=?", (asset,))
        store.conn.commit()
    before = schema(store)
    with pytest.raises(ValueError, match="same asset"):
        register(store, source, moment)
    assert schema(store) == before
    assert not store.conn.in_transaction


def test_absent_source_schema_is_a_validation_error_without_migration(store):
    before = schema(store)
    with pytest.raises(ValueError, match="same asset"):
        register(store, "absent", "absent")
    assert schema(store) == before
    assert not store.conn.in_transaction


def test_predecessor_cannot_cross_byte_revision_or_span(store):
    asset, source, moment = parents(store)
    first = register(store, source, moment)
    other_source = store.register_source_revision(asset, revision_key="bytes-two", content_hash="d" * 64).revision_id
    other_moment = store.add_moments(asset, [MomentDraft(kind="transcript", text="other", span_kind="time", t_start_ms=3000)]).moment_ids[0]
    for parent, span, predecessor in ((source, moment, "absent"),
                                     (other_source, moment, first.extraction_revision_id),
                                     (source, other_moment, first.extraction_revision_id)):
        with pytest.raises(ValueError, match="predecessor"):
            register(store, parent, span, "bad-child", predecessor_extraction_revision_id=predecessor)
    assert len(store.list_extraction_revisions(source, moment)) == 1


def test_predecessor_is_immutable_and_cannot_reference_self(store):
    _, source, moment = parents(store)
    first = register(store, source, moment)
    with pytest.raises(ValueError, match="own predecessor"):
        register(store, source, moment, predecessor_extraction_revision_id=first.extraction_revision_id)
    second = register(store, source, moment, "second")
    with pytest.raises(ValueError, match="different immutable extraction"):
        register(store, source, moment, "second", predecessor_extraction_revision_id=first.extraction_revision_id)
    assert store.get_extraction_revision(second.extraction_revision_id)["predecessor_extraction_revision_id"] is None


@pytest.mark.parametrize("arguments", [
    {"extractor": ""}, {"extractor": "x" * 129}, {"extractor_version": None},
    {"extractor_version": "bad\nversion"}, {"config_hash": b"b" * 64},
    {"config_hash": "bad"}, {"output_hash": " " + "c" * 64},
    {"output_locator": "data:text/plain,full-transcript"}, {"output_locator": "JaVaScRiPt:payload"},
    {"output_locator": "x" * 4097}, {"output_locator": "bad\0handle"},
    {"predecessor_extraction_revision_id": ""},
])
def test_invalid_metadata_does_not_create_schema(store, arguments):
    _, source, moment = parents(store)
    before = schema(store)
    with pytest.raises(ValueError):
        register(store, source, moment, **arguments)
    assert schema(store) == before


def test_payload_arguments_are_not_supported(store):
    _, source, moment = parents(store)
    with pytest.raises(TypeError):
        register(store, source, moment, text="full-transcript")
    assert not store._has_extraction_revision_schema()


@pytest.mark.parametrize("field,value", [
    ("source_revision_id", ""), ("moment_id", "x" * 257),
    ("revision_key", ""), ("revision_key", "x" * 257), ("revision_key", "bad\nkey"),
])
def test_invalid_identity_is_rejected_before_schema(store, field, value):
    _, source, moment = parents(store)
    arguments = dict(source_revision_id=source, moment_id=moment, revision_key="event",
                     extractor="synthetic", extractor_version="1", config_hash="b" * 64, output_hash="c" * 64)
    arguments[field] = value
    before = schema(store)
    with pytest.raises(ValueError):
        store.register_extraction_revision(**arguments)
    assert schema(store) == before


def test_reads_reopen_pagination_and_no_payload_schema(store):
    _, source, moment = parents(store)
    for index in range(5):
        register(store, source, moment, f"event-{index}")
    other = MediaStore(db_path=store.db_path)
    try:
        before = other.conn.total_changes
        rows = other.list_extraction_revisions(source, moment)
        assert len(rows) == 5
        assert other.list_extraction_revisions(source, moment, limit=2) == rows[:2]
        assert other.list_extraction_revisions(source, moment, limit=3, offset=2) == rows[2:]
        assert other.get_extraction_revision(rows[0]["extraction_revision_id"]) == rows[0]
        assert other.conn.total_changes == before
        columns = {row[1]: row[2] for row in other.conn.execute("PRAGMA table_info(media_extraction_revisions)")}
        assert set(columns) == {"extraction_revision_id", "source_revision_id", "moment_id", "revision_key",
                                "extractor", "extractor_version", "config_hash", "output_hash", "output_locator",
                                "predecessor_extraction_revision_id", "digest_status", "registered_at"}
        assert "BLOB" not in columns.values()
        assert other.conn.execute("PRAGMA foreign_key_list(media_extraction_revisions)").fetchall() == []
        for kwargs in ({"limit": 0}, {"limit": 1001}, {"limit": True}, {"offset": -1}, {"offset": 2**63}):
            with pytest.raises(ValueError):
                other.list_extraction_revisions(source, moment, **kwargs)
    finally:
        other.conn.close()


@pytest.mark.parametrize("preexisting", [False, True])
def test_independent_connections_register_concurrently_once(store, preexisting):
    _, source, moment = parents(store)
    if preexisting:
        register(store, source, moment, "previous")
    instances = [MediaStore(db_path=store.db_path) for _ in range(4)]
    barrier = Barrier(4)

    def worker(instance):
        barrier.wait(timeout=10)
        return register(instance, source, moment)

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(worker, instances))
        assert len({r.extraction_revision_id for r in results}) == 1
        assert sorted(r.status for r in results) == ["created", "unchanged", "unchanged", "unchanged"]
    finally:
        for instance in instances:
            instance.conn.close()


def test_caller_transaction_is_not_committed_on_success_or_failure(store):
    asset, source, moment = parents(store)
    store.conn.execute("BEGIN")
    store.conn.execute("UPDATE media_assets SET title='outer' WHERE asset_id=?", (asset,))
    first = register(store, source, moment)
    assert store.conn.in_transaction
    with pytest.raises(ValueError, match="predecessor"):
        register(store, source, moment, "bad", predecessor_extraction_revision_id="absent")
    assert store.conn.in_transaction
    assert store.get_asset(asset)["title"] == "outer"
    assert len(store.list_extraction_revisions(source, moment)) == 1
    assert store.get_extraction_revision(first.extraction_revision_id) is not None
    store.conn.rollback()
    assert not store._has_extraction_revision_schema()
    assert store.get_asset(asset)["title"] is None


@pytest.mark.parametrize("failure", ["CREATE INDEX", "INSERT INTO media_extraction_revisions", "RELEASE SAVEPOINT", "COMMIT"])
def test_injected_failure_is_atomic_and_retryable(tmp_path, failure):
    class FailingConnection(sqlite3.Connection):
        fail = False

        def execute(self, sql, parameters=()):
            if self.fail and failure in sql:
                raise sqlite3.OperationalError("synthetic interruption")
            return super().execute(sql, parameters)

    connection = sqlite3.connect(tmp_path / "failure.db", factory=FailingConnection)
    connection.row_factory = sqlite3.Row
    try:
        instance = MediaStore(conn=connection)
        _, source, moment = parents(instance)
        before = schema(instance)
        connection.fail = True
        with pytest.raises(sqlite3.OperationalError, match="interruption"):
            register(instance, source, moment)
        assert not connection.in_transaction
        assert schema(instance) == before
        connection.fail = False
        assert register(instance, source, moment).status == "created"
    finally:
        connection.close()


@pytest.mark.skipif(sys.version_info < (3, 12), reason="sqlite3 autocommit parameter requires Python 3.12+")
@pytest.mark.parametrize("autocommit", [False, True])
def test_explicit_transaction_modes_preserve_ownership(tmp_path, autocommit):
    path = tmp_path / "modes.db"
    connection = sqlite3.connect(path, autocommit=autocommit)
    connection.row_factory = sqlite3.Row
    try:
        instance = MediaStore(conn=connection)
        _, source, moment = parents(instance)
        connection.commit()
        result = register(instance, source, moment)
        assert connection.in_transaction is not autocommit
        if not autocommit:
            with sqlite3.connect(path) as observer:
                assert observer.execute("SELECT name FROM sqlite_master WHERE name='media_extraction_revisions'").fetchone() is None
            connection.commit()
        with sqlite3.connect(path) as observer:
            assert observer.execute("SELECT extraction_revision_id FROM media_extraction_revisions").fetchone() == (result.extraction_revision_id,)
        with pytest.raises(ValueError, match="predecessor"):
            register(instance, source, moment, "bad", predecessor_extraction_revision_id="absent")
        assert connection.in_transaction is not autocommit
    finally:
        connection.close()


def test_no_fetch_or_inference(store, monkeypatch):
    import socket
    from mnemosyne.core import embeddings, local_llm

    def forbidden(*args, **kwargs):
        pytest.fail("extraction registration attempted IO or inference")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(embeddings, "embed", forbidden)
    monkeypatch.setattr(embeddings, "_embed_api", forbidden)
    monkeypatch.setattr(local_llm, "summarize_memories", forbidden)
    _, source, moment = parents(store)
    result = register(store, source, moment, output_locator="https://example.invalid/must-not-fetch")
    assert store.get_extraction_revision(result.extraction_revision_id)["digest_status"] == "asserted"


def test_pinned_upstream_reader_writer_preserves_extraction_records(store, tmp_path):
    configured = os.environ.get("MNEMOSYNE_S1_LEGACY_SOURCE")
    if not configured:
        pytest.skip("set pinned legacy source/revision for old-reader qualification")
    source = Path(configured).resolve()
    expected = os.environ.get("MNEMOSYNE_S1_LEGACY_REVISION", "")
    assert len(expected) == 40
    assert subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip() == expected
    subprocess.run(["git", "-C", str(source), "diff", "--quiet", "HEAD"], check=True)
    asset, revision, moment = parents(store)
    result = register(store, revision, moment)
    before = store.get_extraction_revision(result.extraction_revision_id)
    script = '''
import json, os, sys
from pathlib import Path
import mnemosyne.core.media as module
assert Path(module.__file__).resolve().is_relative_to(Path(os.environ["PYTHONPATH"]))
assert not hasattr(module.MediaStore, "register_extraction_revision")
path, asset, moments = json.load(sys.stdin)
store = module.MediaStore(db_path=Path(path))
try:
    assert store.get_moments(asset) == moments
    store.upsert_asset(ref_kind="url", ref_value="https://example.invalid/old-writer", modality="document")
finally:
    store.conn.close()
'''
    env = {"PATH": os.defpath, "HOME": str(tmp_path), "PYTHONPATH": str(source),
           "HERMES_HOME": str(tmp_path / ".hermes"), "MNEMOSYNE_DATA_DIR": str(tmp_path / "unused"),
           "MNEMOSYNE_NO_EMBEDDINGS": "1", "MNEMOSYNE_LLM_ENABLED": "false"}
    completed = subprocess.run([sys.executable, "-c", script], cwd=tmp_path, env=env,
                               input=json.dumps([str(store.db_path), asset, store.get_moments(asset)]),
                               capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert store.get_extraction_revision(result.extraction_revision_id) == before
    assert store.find_asset_by_ref("url", "https://example.invalid/old-writer") is not None


def test_process_abort_does_not_publish_caller_extraction(store, tmp_path):
    asset, source, moment = parents(store)
    code = '''
import json, os, sys
from pathlib import Path
from mnemosyne.core.media import MediaStore
path, source, moment = json.load(sys.stdin)
store = MediaStore(db_path=Path(path))
store.conn.execute("BEGIN")
store.register_extraction_revision(source, moment, revision_key="interrupted",
    extractor="synthetic", extractor_version="1", config_hash="b"*64, output_hash="c"*64)
os._exit(17)
'''
    env = {"PATH": os.defpath, "HOME": str(tmp_path), "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
           "HERMES_HOME": str(tmp_path / ".hermes"), "MNEMOSYNE_DATA_DIR": str(tmp_path / "unused"),
           "MNEMOSYNE_NO_EMBEDDINGS": "1", "MNEMOSYNE_LLM_ENABLED": "false"}
    completed = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, env=env,
                               input=json.dumps([str(store.db_path), source, moment]),
                               capture_output=True, text=True, timeout=30)
    assert completed.returncode == 17, completed.stdout + completed.stderr
    assert not store._has_extraction_revision_schema()
    assert store.get_moments(asset)[0]["moment_id"] == moment
    assert register(store, source, moment).status == "created"
