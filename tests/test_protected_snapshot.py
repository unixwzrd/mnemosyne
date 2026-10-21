"""Disposable owner snapshots; no production activation or key discovery."""

from dataclasses import replace
import hashlib
import sqlite3

import pytest

from mnemosyne.core.policy import PolicyRefusal
from mnemosyne.core.policy_lifecycle import PolicyLifecycle, PolicyRecordRef
from mnemosyne.core.policy_store import PolicyStore, RecordKind
from mnemosyne.core.protected_snapshot import (
    MAGIC, SnapshotIdentity, SealedSnapshot, seal_snapshot, open_snapshot,
)
from tests.test_policy_read import add, fixture as fixture
from tests.test_policy_evidence import evidence as evidence


def identity(**changes):
    values = dict(store_id="a" * 32, bank="bank:a", domain_id="domain:a", generation=1, lifecycle_epoch=0)
    values.update(changes)
    return SnapshotIdentity(**values)


def sealed(evidence):
    add(evidence[0], "w", content="PROTECTED-SNAPSHOT-CANARY")
    evidence[0].conn.execute("UPDATE working_memory SET rowid=10000 WHERE id='w'")
    evidence[0].conn.commit()
    if not hasattr(sqlite3.Connection, "serialize"):
        with pytest.raises(PolicyRefusal, match="unsupported_surface"):
            seal_snapshot(evidence[0].conn, identity(), key=b"x" * 44)
        return None
    from cryptography.fernet import Fernet
    key = Fernet.generate_key()
    return seal_snapshot(evidence[0].conn, identity(), key=key), key


def test_roundtrip_preserves_native_policy_and_never_changes_source(evidence):
    conn = evidence[0].conn
    result = sealed(evidence)
    if result is None:
        return
    artifact, key = result
    assert artifact.envelope.startswith(MAGIC)
    assert b"PROTECTED-SNAPSHOT-CANARY" not in artifact.envelope
    assert b"domain:a" not in artifact.envelope
    assert conn.execute("SELECT 1 FROM sqlite_master WHERE name='protected_snapshot_state'").fetchone() is None
    changes = conn.total_changes
    calls = []
    def current(store_id):
        calls.append(store_id)
        return artifact.checkpoint
    restored = open_snapshot(artifact.envelope, artifact.checkpoint, key=key, verify_current=current)
    try:
        assert restored.execute("SELECT content FROM working_memory WHERE id='w'").fetchone()[0] == "PROTECTED-SNAPSHOT-CANARY"
        assert restored.execute("SELECT rowid FROM working_memory WHERE id='w'").fetchone()[0] == 10000
        assert PolicyLifecycle(PolicyStore(restored)).epoch() == 0
        assert restored.execute("PRAGMA database_list").fetchall()[0][2] == ""
        assert restored.execute("PRAGMA temp_store").fetchone()[0] == 2
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            restored.execute("DELETE FROM working_memory")
        assert calls == ["a" * 32] * 2 and conn.total_changes == changes
    finally:
        restored.close()


def test_old_sqlite_cannot_read_envelope_and_does_not_modify_it(evidence, tmp_path):
    result = sealed(evidence)
    if result is None:
        return
    artifact, _ = result
    path = tmp_path / "protected.mnes"
    path.write_bytes(artifact.envelope)
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    conn = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("SELECT content FROM working_memory").fetchall()
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("CREATE TABLE IF NOT EXISTS working_memory(id TEXT,content TEXT)")
    finally:
        conn.close()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


@pytest.mark.parametrize("change", ["none", "old_generation", "changed_epoch", "changed_bank", "changed_domain", "changed_hash", "changed_store"])
def test_stale_or_missing_independent_authority_refuses(evidence, change):
    result = sealed(evidence)
    if result is None:
        return
    artifact, key = result
    old = artifact.checkpoint
    mutations = {"old_generation": {"generation": 2}, "changed_epoch": {"lifecycle_epoch": 1},
        "changed_bank": {"bank": "bank:b"}, "changed_domain": {"domain_id": "domain:b"}, "changed_store": {"store_id": "b" * 32}}
    current = None if change == "none" else replace(old, envelope_sha256="0" * 64) if change == "changed_hash" else replace(old, identity=replace(old.identity, **mutations[change]))
    with pytest.raises(PolicyRefusal, match="access_denied"):
        open_snapshot(artifact.envelope, old, key=key, verify_current=lambda store_id: current)


def test_authority_changes_during_open_refuse(evidence):
    result = sealed(evidence)
    if result is None:
        return
    artifact, key = result
    calls = []
    def verify(store_id):
        calls.append(True)
        return artifact.checkpoint if len(calls) == 1 else None
    with pytest.raises(PolicyRefusal, match="access_denied"):
        open_snapshot(artifact.envelope, artifact.checkpoint, key=key, verify_current=verify)
    assert len(calls) == 2


@pytest.mark.parametrize("mutation", ["key", "bytes", "prefix", "checkpoint"])
def test_wrong_key_tampering_and_substitution_refuse(evidence, mutation):
    result = sealed(evidence)
    if result is None:
        return
    artifact, key = result
    envelope, checkpoint = artifact.envelope, artifact.checkpoint
    if mutation == "key":
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
    elif mutation == "bytes":
        envelope = envelope[:-1] + bytes([envelope[-1] ^ 1])
        checkpoint = replace(checkpoint, envelope_sha256=hashlib.sha256(envelope).hexdigest())
    elif mutation == "prefix":
        envelope = b"bad" + envelope
        checkpoint = replace(checkpoint, envelope_sha256=hashlib.sha256(envelope).hexdigest())
    else:
        checkpoint = replace(checkpoint, identity=replace(checkpoint.identity, store_id="b" * 32))
    with pytest.raises(PolicyRefusal, match="access_denied"):
        open_snapshot(envelope, checkpoint, key=key, verify_current=lambda store_id: checkpoint)


def test_restore_old_snapshot_cannot_roll_back_independent_authority(evidence):
    result = sealed(evidence)
    if result is None:
        return
    old, key = result
    current = [old.checkpoint]
    conn = open_snapshot(old.envelope, old.checkpoint, key=key, verify_current=lambda store_id: current[0])
    try:
        conn.execute("PRAGMA query_only=OFF")
        lifecycle = PolicyLifecycle(PolicyStore(conn))
        lifecycle.quarantine(PolicyRecordRef(RecordKind.WORKING, "w"))
        updated = seal_snapshot(conn, identity(generation=2, lifecycle_epoch=1), key=key)
    finally:
        conn.close()
    # Crash before authority commit leaves the prior artifact authoritative.
    before = open_snapshot(old.envelope, old.checkpoint, key=key, verify_current=lambda store_id: current[0])
    before.close()
    with pytest.raises(PolicyRefusal):
        open_snapshot(updated.envelope, updated.checkpoint, key=key, verify_current=lambda store_id: current[0])
    current[0] = updated.checkpoint
    with pytest.raises(PolicyRefusal):
        open_snapshot(old.envelope, old.checkpoint, key=key, verify_current=lambda store_id: current[0])
    after = open_snapshot(updated.envelope, updated.checkpoint, key=key, verify_current=lambda store_id: current[0])
    try:
        assert PolicyLifecycle(PolicyStore(after)).epoch() == 1
        assert after.execute("SELECT count(*) FROM policy_quarantine").fetchone()[0] == 1
    finally:
        after.close()


@pytest.mark.parametrize("change", [{"store_id": "bad"}, {"generation": True}, {"generation": 0},
    {"lifecycle_epoch": -1}, {"generation": 2**63}, {"bank": ""}])
def test_invalid_identity_refuses(change):
    with pytest.raises(ValueError):
        identity(**change)


def test_missing_crypto_refuses_without_fallback(evidence, monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "cryptography.fernet", None)
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        seal_snapshot(evidence[0].conn, identity(), key=b"x" * 44)


def test_caller_transaction_is_not_committed_or_rolled_back(evidence):
    conn = evidence[0].conn
    conn.execute("INSERT INTO working_memory VALUES ('pending','pending')")
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        seal_snapshot(conn, identity(), key=b"x" * 44)
    assert conn.in_transaction
    assert conn.execute("SELECT content FROM working_memory WHERE id='pending'").fetchone()[0] == "pending"


def test_bounds_refuse_before_serializing(evidence, monkeypatch):
    import mnemosyne.core.protected_snapshot as module
    monkeypatch.setattr(module, "MAX_DATABASE_BYTES", 1)
    if not hasattr(sqlite3.Connection, "serialize"):
        with pytest.raises(PolicyRefusal, match="unsupported_surface"):
            seal_snapshot(evidence[0].conn, identity(), key=b"x" * 44)
        return
    from cryptography.fernet import Fernet
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        seal_snapshot(evidence[0].conn, identity(), key=Fernet.generate_key())


@pytest.mark.parametrize("change", ["content", "epoch", "domain", "version", "schema", "wal"])
def test_authenticated_but_inconsistent_snapshot_refuses(evidence, change):
    result = sealed(evidence)
    if result is None:
        return
    from cryptography.fernet import Fernet
    artifact, key = result
    cipher = Fernet(key)
    raw = cipher.decrypt(artifact.envelope[len(MAGIC):])
    if change in ("content", "wal"):
        raw = b"not sqlite" if change == "content" else raw[:18] + b"\x02\x02" + raw[20:]
    else:
        conn = sqlite3.connect(":memory:")
        try:
            conn.deserialize(raw)
            statements = {"epoch": "UPDATE protected_snapshot_state SET lifecycle_epoch=99",
                "domain": "UPDATE protected_snapshot_state SET domain_id='domain:b'",
                "version": "UPDATE protected_snapshot_state SET format_version=2",
                "schema": "ALTER TABLE protected_snapshot_state ADD COLUMN unknown TEXT"}
            conn.execute(statements[change])
            conn.commit()
            raw = conn.serialize()
        finally:
            conn.close()
    envelope = MAGIC + cipher.encrypt(raw)
    checkpoint = replace(artifact.checkpoint, envelope_sha256=hashlib.sha256(envelope).hexdigest())
    with pytest.raises(PolicyRefusal, match="access_denied"):
        open_snapshot(envelope, checkpoint, key=key, verify_current=lambda store_id: checkpoint)


@pytest.mark.parametrize("mode", ["exception", "coroutine", "object"])
def test_unavailable_or_deferred_authority_never_falls_back(evidence, mode):
    result = sealed(evidence)
    if result is None:
        return
    artifact, key = result
    ran, values = [], []
    async def deferred():
        ran.append(True)
        return artifact.checkpoint
    def verify(store_id):
        if mode == "exception":
            raise RuntimeError("synthetic authority failure")
        value = deferred() if mode == "coroutine" else object()
        values.append(value)
        return value
    with pytest.raises(PolicyRefusal, match="context_unavailable" if mode == "exception" else "access_denied"):
        open_snapshot(artifact.envelope, artifact.checkpoint, key=key, verify_current=verify)
    assert not ran
    if mode == "coroutine":
        assert values[0].cr_frame is None


def test_sealing_and_opening_use_only_memory_connections(evidence, monkeypatch):
    result = sealed(evidence)
    if result is None:
        return
    artifact, key = result
    connect, calls = sqlite3.connect, []
    def memory_only(database, *args, **kwargs):
        calls.append(database)
        assert database == ":memory:"
        return connect(database, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(sqlite3, "connect", memory_only)
        again = seal_snapshot(evidence[0].conn, identity(), key=key)
        conn = open_snapshot(again.envelope, again.checkpoint, key=key, verify_current=lambda store_id: again.checkpoint)
        conn.close()
    assert calls == [":memory:", ":memory:"]
    assert artifact.envelope != again.envelope


def test_sealed_receipt_cannot_mismatch_envelope(evidence):
    result = sealed(evidence)
    if result is None:
        return
    artifact, _ = result
    with pytest.raises(ValueError, match="inconsistent"):
        SealedSnapshot(artifact.envelope + b"x", artifact.checkpoint)
    assert "PROTECTED-SNAPSHOT-CANARY" not in repr(artifact)


@pytest.mark.parametrize("change", [{"generation": 1}, {"generation": 0}, {"bank": "bank:b"},
    {"store_id": "b" * 32}, {"domain_id": "domain:b"}])
def test_resealed_identity_cannot_reuse_or_change_namespace(evidence, change):
    result = sealed(evidence)
    if result is None:
        return
    artifact, key = result
    conn = open_snapshot(artifact.envelope, artifact.checkpoint, key=key, verify_current=lambda store_id: artifact.checkpoint)
    try:
        values = dict(generation=2)
        values.update(change)
        with pytest.raises((ValueError, PolicyRefusal)):
            seal_snapshot(conn, identity(**values), key=key)
    finally:
        conn.close()
