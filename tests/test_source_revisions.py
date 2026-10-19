"""Synthetic S1a evidence; no original files, models or protected-mode claims."""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from pathlib import Path

import pytest

from mnemosyne.core.media import MediaStore, MomentDraft


@pytest.fixture
def store(tmp_path):
    instance = MediaStore(db_path=tmp_path / "media.db")
    yield instance
    instance.conn.close()


def asset(store, reference="https://example.invalid/source", **kwargs):
    return store.upsert_asset(ref_kind="url", ref_value=reference, modality="document", **kwargs).asset_id


def register(store, parent, key="version-1", **kwargs):
    values = {"content_hash": "a" * 64, **kwargs}
    return store.register_source_revision(parent, revision_key=key, **values)


def schema(store):
    return store.conn.execute("SELECT name, sql FROM sqlite_master ORDER BY name").fetchall()


def test_legacy_open_and_revision_reads_do_not_migrate_or_write(store):
    parent = asset(store)
    store.add_moments(parent, [MomentDraft(kind="page", text="bounded synthetic excerpt")])
    before = [tuple(row) for row in schema(store)]
    changes = store.conn.total_changes
    assert store.get_source_revision("not-registered") is None
    assert store.list_source_revisions(parent) == []
    assert [tuple(row) for row in schema(store)] == before
    assert store.conn.total_changes == changes
    assert all("source_revisions" not in row[0] for row in before)
    assert store.get_moments(parent)[0]["text"] == "bounded synthetic excerpt"


def test_repeat_is_immutable_idempotent_and_does_not_verify_bytes(store):
    parent = asset(store)
    first = register(store, parent, content_hash="A" * 64, byte_size=42)
    before = store.get_source_revision(first.revision_id)
    second = register(store, parent, byte_size=42)
    assert first.revision_id == second.revision_id
    assert (first.status, second.status) == ("created", "unchanged")
    assert store.get_source_revision(first.revision_id) == before
    assert before["content_hash"] == "a" * 64
    assert before["digest_status"] == "asserted"
    assert before["registered_at"].endswith("Z")
    identity = json.dumps(["v1", parent, "version-1"], separators=(",", ":"))
    assert first.revision_id == "revision:sha256:" + hashlib.sha256(identity.encode()).hexdigest()


@pytest.mark.parametrize("changed", [
    {"content_hash": "b" * 64}, {"representation": "http-response"},
    {"byte_size": 99}, {"archive_locator": "archive:another"},
])
def test_conflicts_never_overwrite_or_add_rows(store, changed):
    parent = asset(store)
    original = register(store, parent)
    before = store.get_source_revision(original.revision_id)
    with pytest.raises(ValueError, match="different immutable metadata"):
        register(store, parent, **changed)
    assert store.list_source_revisions(parent) == [before]


def test_changed_bytes_keep_legacy_asset_and_moment_identity(store):
    parent = asset(store, content_hash="a" * 64)
    moment = store.add_moments(parent, [MomentDraft(kind="page", text="original bounded excerpt")])
    legacy_asset, legacy_moments = store.get_asset(parent), store.get_moments(parent)
    first = register(store, parent)
    second = register(store, parent, "version-2", content_hash="b" * 64, predecessor_revision_id=first.revision_id)
    assert first.revision_id != second.revision_id
    assert store.get_asset(parent) == legacy_asset
    assert store.get_moments(parent) == legacy_moments
    assert legacy_moments[0]["moment_id"] == moment.moment_ids[0]
    assert store.get_source_revision(first.revision_id)["content_hash"] == "a" * 64
    assert store.get_source_revision(second.revision_id)["content_hash"] == "b" * 64


def test_identical_bytes_in_independent_revision_events_are_not_conflated(store):
    parent = asset(store)
    first = register(store, parent, "occurrence-a")
    second = register(store, parent, "occurrence-b", predecessor_revision_id=first.revision_id)
    assert first.revision_id != second.revision_id
    assert len(store.list_source_revisions(parent)) == 2


def test_location_alias_does_not_change_registered_revision_or_id(store):
    parent = asset(store, content_hash="a" * 64)
    first = register(store, parent, archive_locator="archive:stable-handle")
    before = store.get_source_revision(first.revision_id)
    moved = store.upsert_asset(ref_kind="file", ref_value="/synthetic/moved/document", modality="document", content_hash="a" * 64)
    assert moved.asset_id == parent
    assert register(store, moved.asset_id, archive_locator="archive:stable-handle").status == "unchanged"
    assert store.get_source_revision(first.revision_id) == before


def test_missing_parent_rolls_back_new_optional_schema(store):
    before = [tuple(row) for row in schema(store)]
    with pytest.raises(ValueError, match="no media_assets row"):
        register(store, "absent")
    assert [tuple(row) for row in schema(store)] == before
    assert not store.conn.in_transaction


def test_predecessor_must_exist_and_belong_to_same_asset(store):
    first_parent, second_parent = asset(store), asset(store, "https://example.invalid/other")
    first = register(store, first_parent)
    for predecessor in ("absent", first.revision_id):
        with pytest.raises(ValueError, match="same asset"):
            register(store, second_parent, predecessor_revision_id=predecessor)
    assert store.list_source_revisions(second_parent) == []
    assert register(store, second_parent).status == "created"


def test_self_predecessor_and_predecessor_changes_are_refused(store):
    parent = asset(store)
    first = register(store, parent)
    with pytest.raises(ValueError, match="own predecessor"):
        register(store, parent, predecessor_revision_id=first.revision_id)
    second = register(store, parent, "version-2")
    with pytest.raises(ValueError, match="different immutable metadata"):
        register(store, parent, "version-2", predecessor_revision_id=first.revision_id)
    assert store.get_source_revision(second.revision_id)["predecessor_revision_id"] is None


@pytest.mark.parametrize("arguments", [
    {"content_hash": "deadbeef"}, {"content_hash": b"a" * 64},
    {"content_hash": " " + "a" * 64}, {"byte_size": -1}, {"byte_size": True},
    {"byte_size": 2**63}, {"representation": ""}, {"representation": "x" * 129},
    {"archive_locator": "x" * 4097}, {"archive_locator": "bad\nhandle"},
    {"predecessor_revision_id": ""},
])
def test_invalid_metadata_does_not_create_schema(store, arguments):
    parent = asset(store)
    before = [tuple(row) for row in schema(store)]
    with pytest.raises(ValueError):
        register(store, parent, **arguments)
    assert [tuple(row) for row in schema(store)] == before


@pytest.mark.parametrize("key", ["", "  ", "x" * 257, "bad\0key", None])
def test_invalid_keys_are_rejected(store, key):
    with pytest.raises(ValueError):
        register(store, asset(store), key)


def test_reads_and_registration_preserve_caller_transaction(store):
    parent = asset(store)
    store.conn.execute("BEGIN")
    store.conn.execute("UPDATE media_assets SET title='outer-write' WHERE asset_id=?", (parent,))
    revision = register(store, parent)
    assert store.conn.in_transaction
    assert store.get_source_revision(revision.revision_id) is not None
    assert store.conn.in_transaction
    store.conn.rollback()
    assert store.get_asset(parent)["title"] is None
    assert store.get_source_revision(revision.revision_id) is None
    assert not store._has_source_revision_schema()


def test_failure_preserves_outer_work_and_earlier_revisions(store):
    parent = asset(store)
    first = register(store, parent)
    store.conn.execute("BEGIN")
    store.conn.execute("UPDATE media_assets SET title='outer-write' WHERE asset_id=?", (parent,))
    with pytest.raises(ValueError):
        register(store, parent, "bad-child", predecessor_revision_id="absent")
    assert store.conn.in_transaction
    assert store.get_asset(parent)["title"] == "outer-write"
    assert [row["revision_id"] for row in store.list_source_revisions(parent)] == [first.revision_id]
    store.conn.rollback()


@pytest.mark.parametrize("failure", ["CREATE INDEX", "INSERT INTO media_source_revisions"])
def test_interrupted_first_registration_restores_schema_and_retries(tmp_path, failure):
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
        parent = asset(instance)
        before = [tuple(row) for row in schema(instance)]
        connection.fail = True
        with pytest.raises(sqlite3.OperationalError, match="synthetic interruption"):
            register(instance, parent)
        assert [tuple(row) for row in schema(instance)] == before
        assert not connection.in_transaction
        connection.fail = False
        assert register(instance, parent).status == "created"
    finally:
        connection.close()


@pytest.mark.parametrize("initialized", [False, True])
def test_concurrent_independent_connections_have_one_idempotent_write(store, initialized):
    parent = asset(store)
    if initialized:
        register(store, parent, "seed")
    barrier = Barrier(2)
    others = [MediaStore(db_path=store.db_path) for _ in range(2)]

    def write(instance):
        barrier.wait(timeout=10)
        return register(instance, parent)

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(write, others))
        assert len({result.revision_id for result in results}) == 1
        assert sorted(result.status for result in results) == ["created", "unchanged"]
        assert len(store.list_source_revisions(parent)) == 1 + initialized
    finally:
        for instance in others:
            instance.conn.close()


def test_reopen_and_bounded_page_reads_do_not_change_registration(store):
    parent = asset(store)
    for index in range(4):
        register(store, parent, f"version-{index}")
    second = MediaStore(db_path=store.db_path)
    try:
        all_rows = second.list_source_revisions(parent)
        changes = second.conn.total_changes
        assert len(all_rows) == 4
        assert second.list_source_revisions(parent, limit=2) == all_rows[:2]
        assert second.list_source_revisions(parent, limit=2, offset=2) == all_rows[2:]
        assert second.conn.total_changes == changes
        for kwargs in ({"limit": 0}, {"limit": 1001}, {"limit": True}, {"offset": -1}, {"offset": 2**63}):
            with pytest.raises(ValueError):
                second.list_source_revisions(parent, **kwargs)
    finally:
        second.conn.close()


def test_revision_schema_has_no_payload_or_foreign_key_columns(store):
    parent = asset(store)
    register(store, parent)
    columns = {row[1]: row[2].upper() for row in store.conn.execute("PRAGMA table_info(media_source_revisions)")}
    assert set(columns) == {
        "revision_id", "asset_id", "revision_key", "content_hash", "representation",
        "byte_size", "predecessor_revision_id", "archive_locator", "digest_status", "registered_at",
    }
    assert not any("BLOB" in value for value in columns.values())
    assert store.conn.execute("PRAGMA foreign_key_list(media_source_revisions)").fetchall() == []


def test_registration_never_fetches_or_invokes_models(store, monkeypatch):
    import socket
    from mnemosyne.core import embeddings, local_llm

    def forbidden(*args, **kwargs):
        pytest.fail("metadata registration attempted IO or inference")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(embeddings, "embed", forbidden)
    monkeypatch.setattr(embeddings, "_embed_api", forbidden)
    monkeypatch.setattr(local_llm, "summarize_memories", forbidden)
    result = register(store, asset(store), archive_locator="https://example.invalid/must-not-fetch")
    assert store.get_source_revision(result.revision_id)["digest_status"] == "asserted"


def test_legacy_beam_paths_stay_usable_without_automatic_revision_schema(tmp_path):
    from mnemosyne.core.beam import BeamMemory

    beam = BeamMemory(db_path=tmp_path / "legacy-beam.db", session_id="synthetic")
    try:
        media = MediaStore(conn=beam.conn)
        first = beam.remember("Synthetic legacy memory before revisions.", scope="global")
        assert first is not None
        assert not media._has_source_revision_schema()
        revision = register(media, asset(media))
        second = beam.remember("Synthetic legacy memory after explicit registration.", scope="global")
        assert second is not None
        rows = beam.conn.execute("SELECT content FROM working_memory WHERE id IN (?, ?)", (first, second)).fetchall()
        assert {row[0] for row in rows} == {
            "Synthetic legacy memory before revisions.", "Synthetic legacy memory after explicit registration.",
        }
        assert media.get_source_revision(revision.revision_id)["digest_status"] == "asserted"
        assert beam.conn.execute("SELECT COUNT(*) FROM media_source_revisions").fetchone()[0] == 1
    finally:
        beam.conn.close()


def test_pinned_unchanged_upstream_can_read_and_write_candidate_store(store, tmp_path):
    configured = os.environ.get("MNEMOSYNE_S1_LEGACY_SOURCE")
    if not configured:
        pytest.skip("set MNEMOSYNE_S1_LEGACY_SOURCE and MNEMOSYNE_S1_LEGACY_REVISION for old-reader qualification")
    source = Path(configured).resolve()
    expected = os.environ.get("MNEMOSYNE_S1_LEGACY_REVISION", "")
    assert len(expected) == 40
    actual = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    assert actual == expected
    subprocess.run(["git", "-C", str(source), "diff", "--quiet", "HEAD"], check=True)
    parent = asset(store, title="synthetic legacy title")
    store.add_moments(parent, [MomentDraft(kind="page", text="synthetic legacy excerpt")])
    revision = register(store, parent)
    before = store.get_source_revision(revision.revision_id)
    payload = {"path": str(store.db_path), "asset": store.get_asset(parent), "moments": store.get_moments(parent)}
    script = '''
import json, os, sys
from pathlib import Path
import mnemosyne.core.media as module
assert Path(module.__file__).resolve().is_relative_to(Path(os.environ["PYTHONPATH"]))
assert not hasattr(module.MediaStore, "register_source_revision"), "reader is not the unchanged baseline"
payload = json.load(sys.stdin)
store = module.MediaStore(db_path=Path(payload["path"]))
try:
    assert store.get_asset(payload["asset"]["asset_id"]) == payload["asset"]
    assert store.get_moments(payload["asset"]["asset_id"]) == payload["moments"]
    store.upsert_asset(ref_kind="url", ref_value="https://example.invalid/legacy-writer", modality="document")
    print("legacy_reader_writer_verified")
finally:
    store.conn.close()
'''
    env = {
        "PATH": os.environ.get("PATH", os.defpath), "HOME": str(tmp_path),
        "HERMES_HOME": str(tmp_path / ".hermes"), "MNEMOSYNE_DATA_DIR": str(tmp_path / "unused"),
        "MNEMOSYNE_NO_EMBEDDINGS": "1", "MNEMOSYNE_LLM_ENABLED": "false",
        "MNEMOSYNE_HOST_LLM_ENABLED": "false", "PYTHONPATH": str(source),
    }
    completed = subprocess.run(
        [sys.executable, "-c", script], cwd=tmp_path, env=env, input=json.dumps(payload),
        text=True, capture_output=True, timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout.strip() == "legacy_reader_writer_verified"
    assert store.get_source_revision(revision.revision_id) == before
    assert store.find_asset_by_ref("url", "https://example.invalid/legacy-writer") is not None


@pytest.mark.skipif(sys.version_info < (3, 12), reason="sqlite3 autocommit parameter requires Python 3.12+")
@pytest.mark.parametrize("succeeds", [False, True])
def test_explicit_transactions_finalize_on_autocommit_connections(tmp_path, succeeds):
    path = tmp_path / "autocommit.db"
    connection = sqlite3.connect(path, autocommit=True)
    connection.row_factory = sqlite3.Row
    try:
        instance = MediaStore(conn=connection)
        parent = asset(instance)
        if succeeds:
            result = register(instance, parent)
            assert not connection.in_transaction
            with sqlite3.connect(path) as observer:
                row = observer.execute("SELECT revision_id FROM media_source_revisions").fetchone()
            assert row == (result.revision_id,)
        else:
            with pytest.raises(ValueError, match="predecessor"):
                register(instance, parent, predecessor_revision_id="absent")
            assert not connection.in_transaction
            with sqlite3.connect(path) as observer:
                row = observer.execute("SELECT name FROM sqlite_master WHERE name='media_source_revisions'").fetchone()
            assert row is None
            assert register(instance, parent).status == "created"
    finally:
        connection.close()


@pytest.mark.skipif(sys.version_info < (3, 12), reason="sqlite3 autocommit parameter requires Python 3.12+")
def test_pep249_transaction_mode_remains_caller_owned(tmp_path):
    path = tmp_path / "caller-owned.db"
    connection = sqlite3.connect(path, autocommit=False)
    connection.row_factory = sqlite3.Row
    try:
        instance = MediaStore(conn=connection)
        parent = asset(instance)
        result = register(instance, parent)
        assert connection.in_transaction
        assert connection.autocommit is False
        assert instance.get_source_revision(result.revision_id) is not None
        with sqlite3.connect(path) as observer:
            assert observer.execute("SELECT name FROM sqlite_master WHERE name='media_source_revisions'").fetchone() is None
        connection.commit()
        with sqlite3.connect(path) as observer:
            assert observer.execute("SELECT revision_id FROM media_source_revisions").fetchone() == (result.revision_id,)
    finally:
        connection.close()


def test_process_abort_does_not_commit_a_caller_owned_revision(store, tmp_path):
    parent = asset(store)
    source = Path(__file__).resolve().parents[1]
    env = {
        "PATH": os.environ.get("PATH", os.defpath), "HOME": str(tmp_path),
        "HERMES_HOME": str(tmp_path / ".hermes"), "MNEMOSYNE_DATA_DIR": str(tmp_path / "unused"),
        "MNEMOSYNE_NO_EMBEDDINGS": "1", "MNEMOSYNE_LLM_ENABLED": "false",
        "MNEMOSYNE_HOST_LLM_ENABLED": "false", "PYTHONPATH": str(source),
    }
    script = '''
import json, os, sys
from pathlib import Path
from mnemosyne.core.media import MediaStore
path, parent = json.load(sys.stdin)
store = MediaStore(db_path=Path(path))
store.conn.execute("BEGIN")
store.register_source_revision(parent, revision_key="interrupted", content_hash="a" * 64)
os._exit(17)
'''
    completed = subprocess.run(
        [sys.executable, "-c", script], cwd=tmp_path, env=env,
        input=json.dumps([str(store.db_path), parent]), text=True, capture_output=True, timeout=30,
    )
    assert completed.returncode == 17, completed.stdout + completed.stderr
    assert store.get_asset(parent) is not None
    assert not store._has_source_revision_schema()
    assert register(store, parent, "interrupted").status == "created"
