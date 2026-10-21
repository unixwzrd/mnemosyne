"""Independent authority records in disposable owner databases only."""

from dataclasses import replace
import sqlite3

import pytest

from mnemosyne.core.policy import PolicyRefusal
from mnemosyne.core.policy_store import PolicyStoreError
from mnemosyne.core.protected_snapshot import SnapshotCheckpoint, SnapshotIdentity
from mnemosyne.core.snapshot_authority import SnapshotAuthority


def checkpoint(generation=1, **changes):
    values = dict(
        store_id="a" * 32,
        bank="bank:a",
        domain_id="domain:a",
        generation=generation,
        lifecycle_epoch=0,
    )
    values.update(changes)
    return SnapshotCheckpoint(SnapshotIdentity(**values), str(generation % 10) * 64)


@pytest.fixture
def authority(tmp_path):
    conn = sqlite3.connect(tmp_path / "authority.sqlite")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    api = SnapshotAuthority(conn, authority_id="b" * 32)
    api.prepare()
    yield api, conn
    conn.close()


def test_explicit_preparation_and_persisted_identity(authority):
    api, conn = authority
    api.prepare()
    api.provision(checkpoint(), operation_id="first")
    assert api.current("a" * 32) == checkpoint()
    assert api.publication("a" * 32, "first").status == "recorded"
    assert api.publication("a" * 32, "missing") is None
    with pytest.raises(PolicyRefusal, match="context_unavailable"):
        SnapshotAuthority(conn, authority_id="c" * 32).current("a" * 32)


def test_compare_swap_monotonicity_and_exact_retry(authority):
    api, conn = authority
    assert api.provision(checkpoint(), operation_id="first").status == "published"
    assert api.provision(checkpoint(), operation_id="first").status == "unchanged"
    second = checkpoint(2)
    api.publish(checkpoint(), second, operation_id="second")
    assert (
        api.publish(checkpoint(), second, operation_id="second").status == "unchanged"
    )
    with pytest.raises(PolicyRefusal):
        api.provision(checkpoint(), operation_id="first")
    with pytest.raises(PolicyRefusal):
        api.publish(
            checkpoint(), checkpoint(2, lifecycle_epoch=1), operation_id="racing"
        )
    with pytest.raises(PolicyRefusal):
        api.publish(second, checkpoint(3), operation_id="first")
    assert conn.execute("SELECT count(*) FROM snapshot_publications").fetchone()[0] == 2


@pytest.mark.parametrize(
    "changes",
    [
        dict(generation=3),
        dict(bank="other"),
        dict(domain_id="other"),
        dict(store_id="c" * 32),
        dict(lifecycle_epoch=0),
    ],
)
def test_invalid_successor_never_advances(authority, changes):
    api, _ = authority
    old = checkpoint(lifecycle_epoch=2)
    api.provision(old, operation_id="first")
    values = dict(generation=2, lifecycle_epoch=2)
    values.update(changes)
    with pytest.raises(PolicyRefusal):
        api.publish(old, checkpoint(**values), operation_id="bad")
    assert api.current("a" * 32) == old


@pytest.mark.parametrize("name", ["unrelated", "sqliteOther", "sqliteXcache"])
def test_prepare_refuses_existing_logical_objects(tmp_path, name):
    conn = sqlite3.connect(tmp_path / "dirty.sqlite")
    conn.execute("PRAGMA synchronous=EXTRA")
    conn.execute(f"CREATE TABLE {name}(id)")
    api = SnapshotAuthority(conn, authority_id="b" * 32)
    try:
        with pytest.raises(PolicyStoreError):
            api.prepare()
        assert conn.execute("SELECT name FROM sqlite_master").fetchall() == [(name,)]
        assert not conn.in_transaction
    finally:
        conn.close()


@pytest.mark.parametrize(
    "mode,sync,allowed",
    [
        ("WAL", "FULL", True),
        ("WAL", "EXTRA", True),
        ("WAL", "NORMAL", False),
        ("DELETE", "FULL", False),
        ("DELETE", "EXTRA", True),
        ("OFF", "EXTRA", False),
        ("MEMORY", "EXTRA", False),
    ],
)
def test_durable_profile_is_explicit_not_changed(tmp_path, mode, sync, allowed):
    conn = sqlite3.connect(tmp_path / "mode.sqlite")
    conn.execute(f"PRAGMA journal_mode={mode}")
    conn.execute(f"PRAGMA synchronous={sync}")
    api = SnapshotAuthority(conn, authority_id="b" * 32)
    try:
        if allowed:
            api.prepare()
            api.provision(checkpoint(), operation_id="first")
        else:
            with pytest.raises(PolicyRefusal, match="unsupported_surface"):
                api.prepare()
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == mode.lower()
    finally:
        conn.close()


def test_pending_transaction_not_committed_or_rolled_back(authority):
    api, conn = authority
    api.provision(checkpoint(), operation_id="first")
    conn.execute("CREATE TABLE owner_pending(x)")
    conn.execute("INSERT INTO owner_pending VALUES(1)")
    for call in (
        lambda: api.current("a" * 32),
        lambda: api.prepare(),
        lambda: api.publish(checkpoint(), checkpoint(2), operation_id="two"),
        lambda: api.publication("a" * 32, "first"),
    ):
        with pytest.raises(PolicyRefusal, match="unsupported_surface"):
            call()
        assert conn.in_transaction
    conn.rollback()
    assert api.current("a" * 32) == checkpoint()


def test_independent_connections_cannot_overwrite_selected_generation(authority):
    api, conn = authority
    api.provision(checkpoint(), operation_id="first")
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    other_conn = sqlite3.connect(path)
    other_conn.execute("PRAGMA synchronous=FULL")
    other = SnapshotAuthority(other_conn, authority_id="b" * 32)
    try:
        old = other.current("a" * 32)
        api.publish(old, checkpoint(2), operation_id="winner")
        with pytest.raises(PolicyRefusal):
            other.publish(
                old,
                replace(checkpoint(2), envelope_sha256="f" * 64),
                operation_id="loser",
            )
        assert other.current("a" * 32) == checkpoint(2)
    finally:
        other_conn.close()


def test_authority_is_not_reconstructed_when_missing(authority):
    api, conn = authority
    with pytest.raises(PolicyRefusal, match="access_denied"):
        api.current("a" * 32)
    assert conn.execute("SELECT count(*) FROM snapshot_publications").fetchone()[0] == 0


def test_unprepared_authority_does_not_provision_on_read(tmp_path):
    conn = sqlite3.connect(tmp_path / "empty.sqlite")
    try:
        with pytest.raises(PolicyStoreError):
            SnapshotAuthority(conn, authority_id="b" * 32).current("a" * 32)
        assert not conn.execute("SELECT name FROM sqlite_master").fetchall()
    finally:
        conn.close()


def test_lost_commit_acknowledgment_keeps_recoverable_receipt(tmp_path):
    class Uncertain(sqlite3.Connection):
        armed = False

        def execute(self, sql, *args, **kwargs):
            result = super().execute(sql, *args, **kwargs)
            if sql == "COMMIT" and self.armed:
                self.armed = False
                raise sqlite3.OperationalError("injected acknowledgment loss")
            return result

    conn = sqlite3.connect(tmp_path / "uncertain.sqlite", factory=Uncertain)
    conn.execute("PRAGMA synchronous=EXTRA")
    api = SnapshotAuthority(conn, authority_id="b" * 32)
    try:
        api.prepare()
        conn.armed = True
        with pytest.raises(sqlite3.OperationalError):
            api.provision(checkpoint(), operation_id="uncertain")
        assert not conn.in_transaction
        assert api.current("a" * 32) == checkpoint()
        assert api.publication("a" * 32, "uncertain").checkpoint == checkpoint()
        assert (
            api.provision(checkpoint(), operation_id="uncertain").status == "unchanged"
        )
    finally:
        conn.close()


def test_capacity_refuses_without_pruning_or_advancing(authority, monkeypatch):
    from mnemosyne.core import snapshot_authority

    api, conn = authority
    api.provision(checkpoint(), operation_id="first")
    monkeypatch.setattr(snapshot_authority, "MAX_PUBLICATIONS", 1)
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        api.publish(checkpoint(), checkpoint(2), operation_id="second")
    assert api.current("a" * 32) == checkpoint()
    assert conn.execute("SELECT count(*) FROM snapshot_publications").fetchone()[0] == 1


def test_malformed_persisted_identity_is_content_free(authority):
    api, conn = authority
    conn.execute("UPDATE snapshot_authority_state SET authority_id=CAST(x'ff' AS TEXT)")
    conn.commit()
    with pytest.raises(PolicyRefusal, match="context_unavailable"):
        api.current("a" * 32)


@pytest.mark.parametrize("bad", ["", "a", "A" * 32, 1, None])
def test_store_identity_validation_is_consistent(authority, bad):
    api, _ = authority
    for call in (lambda: api.current(bad), lambda: api.publication(bad, "first")):
        with pytest.raises(ValueError):
            call()
