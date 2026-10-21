"""Synthetic owner metadata and independent-witness interruption controls."""

from dataclasses import replace
import hashlib
import json
import sqlite3

import pytest

from mnemosyne.core.host_configuration import (
    ConfigurationReceipt, ConfigurationRevision, HostConfigurationAuthority,
)
from mnemosyne.core.host_profile import LevelDisplayMetadata, ProfileDefinition
from mnemosyne.core.policy import PolicyDefinition, PolicyRefusal
from mnemosyne.core.policy_store import PolicyStoreError


def profile(version=1, *, policy_version=1, levels=("L0", "L1"), label="Sensitive", identity="example"):
    return ProfileDefinition(identity, version, PolicyDefinition("domain:example", policy_version, levels),
        tuple(LevelDisplayMetadata(level, label + level, "Admin " + level) for level in levels),
        (("clearance", "Access level", "Principal ceiling"),))


class UncertainCommit(sqlite3.Connection):
    fail_commit = False

    def execute(self, sql, *args):
        result = super().execute(sql, *args)
        if sql == "COMMIT" and self.fail_commit:
            self.fail_commit = False
            raise OSError("synthetic lost acknowledgment")
        return result


def connection(root, name, *, factory=sqlite3.Connection):
    folder = root / name
    folder.mkdir(mode=0o700, exist_ok=True)
    path = folder / "metadata.sqlite"
    conn = sqlite3.connect(path, timeout=0, factory=factory)
    path.chmod(0o600)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


@pytest.fixture
def authority(tmp_path):
    conn = connection(tmp_path, "authority", factory=UncertainCommit)
    witness = connection(tmp_path, "witness", factory=UncertainCommit)
    api = HostConfigurationAuthority(conn, authority_id="a" * 32,
        witness_connection=witness, witness_id="b" * 32)
    api.prepare()
    yield api, conn, witness
    conn.close()
    witness.close()


def publish(api, values=None, *, previous=None, operation="initial"):
    return api.publish((profile(),) if values is None else values, previous=previous, operation_id=operation)


def test_prepare_is_explicit_and_creates_no_active_access(authority):
    api, conn, witness = authority
    api.prepare()
    with pytest.raises(PolicyRefusal):
        api.current()
    assert conn.execute("SELECT count(*) FROM host_configuration_revisions").fetchone()[0] == 0
    assert witness.execute("SELECT count(*) FROM snapshot_publications").fetchone()[0] == 0
    assert not hasattr(api, "recall") and not hasattr(api, "get_memory")


def test_initial_publication_roundtrip_and_exact_retry(authority):
    api, conn, _ = authority
    receipt = publish(api)
    assert receipt.phase == "committed"
    current = api.current()
    assert current.revision == receipt.revision and current.profiles == (profile(),)
    assert publish(api) == receipt
    assert api.receipt("initial") == receipt
    assert api.receipt("absent") is None
    assert conn.execute("SELECT count(*) FROM host_configuration_revisions").fetchone()[0] == 1
    assert not conn.in_transaction


def test_prepared_update_preserves_previous_until_witness_then_fences(authority):
    api, _, _ = authority
    old = publish(api)
    pending = api.stage((profile(2, label="Changed"),), previous=old.revision, operation_id="next")
    assert pending.phase == "prepared" and api.current().revision == old.revision
    api.advance_witness(pending)
    with pytest.raises(PolicyRefusal, match="context_unavailable"):
        api.current()
    completed = api.finalize(pending)
    assert completed.phase == "committed" and api.current().revision == pending.revision


def test_unwitnessed_preparation_recovery_never_grants(authority):
    api, _, witness = authority
    old = publish(api)
    pending = api.stage((profile(2),), previous=old.revision, operation_id="next")
    assert api.recover("next") == pending
    assert api.current().revision == old.revision
    assert witness.execute("SELECT count(*) FROM snapshot_publications").fetchone()[0] == 1


def test_witnessed_preparation_recovers_on_fresh_connections(authority, tmp_path):
    api, conn, witness = authority
    old = publish(api)
    pending = api.stage((profile(2),), previous=old.revision, operation_id="next")
    api.advance_witness(pending)
    other = connection(tmp_path, "authority")
    other_witness = connection(tmp_path, "witness")
    fresh = HostConfigurationAuthority(other, authority_id="a" * 32,
        witness_connection=other_witness, witness_id="b" * 32)
    try:
        assert fresh.recover("next").phase == "committed"
        assert fresh.current().revision == pending.revision
        assert not conn.in_transaction and not witness.in_transaction
    finally:
        other.close()
        other_witness.close()


@pytest.mark.parametrize("phase", ["stage", "witness", "finalize"])
def test_lost_commit_ack_is_inspected_without_rollback(authority, phase):
    api, conn, witness = authority
    old = publish(api)
    if phase == "stage":
        conn.fail_commit = True
        with pytest.raises(OSError):
            api.stage((profile(2),), previous=old.revision, operation_id="next")
        pending = api.receipt("next")
        assert pending.phase == "prepared" and api.current().revision == old.revision
        assert api.recover("next") == pending
    else:
        pending = api.stage((profile(2),), previous=old.revision, operation_id="next")
        if phase == "witness":
            witness.fail_commit = True
            with pytest.raises(OSError):
                api.advance_witness(pending)
            with pytest.raises(PolicyRefusal):
                api.current()
        else:
            api.advance_witness(pending)
            conn.fail_commit = True
            with pytest.raises(OSError):
                api.finalize(pending)
        assert api.recover("next").phase == "committed"
        assert api.current().revision == pending.revision
    assert not conn.in_transaction and not witness.in_transaction


@pytest.mark.parametrize("change", ["operation", "generation", "digest", "authority"])
def test_forged_receipts_cannot_advance_or_finalize(authority, change):
    api, _, witness = authority
    pending = api.stage((profile(),), previous=None, operation_id="initial")
    revision, operation = pending.revision, pending.operation_id
    if change == "operation":
        operation = "other"
    elif change == "generation":
        revision = replace(revision, generation=2)
    elif change == "digest":
        revision = replace(revision, sha256="f" * 64)
    else:
        revision = replace(revision, authority_id="c" * 32)
    forged = ConfigurationReceipt(revision, operation, "prepared")
    for method in (api.advance_witness, api.finalize):
        with pytest.raises((PolicyRefusal, TypeError)):
            method(forged)
    assert witness.execute("SELECT count(*) FROM snapshot_publications").fetchone()[0] == 0


def test_stale_predecessor_conflicting_retry_and_pending_writer_refuse(authority):
    api, conn, _ = authority
    old = publish(api)
    with pytest.raises(PolicyRefusal):
        publish(api, (profile(2),))
    pending = api.stage((profile(2),), previous=old.revision, operation_id="next")
    with pytest.raises(PolicyRefusal):
        api.stage((profile(3),), previous=old.revision, operation_id="racing")
    api.advance_witness(pending)
    api.finalize(pending)
    with pytest.raises(PolicyRefusal):
        publish(api)
    assert conn.execute("SELECT count(*) FROM host_configuration_revisions").fetchone()[0] == 2


@pytest.mark.parametrize("side", ["authority", "witness"])
def test_caller_transactions_refuse_without_committing_them(authority, side):
    api, conn, witness = authority
    target = conn if side == "authority" else witness
    target.execute("BEGIN")
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        publish(api)
    assert target.in_transaction
    target.rollback()


def test_version_identity_and_order_cannot_be_redefined_or_rolled_back(authority):
    api, _, _ = authority
    old = publish(api)
    for values in ((profile(label="Forged"),), (profile(2, levels=("L1", "L0")),)):
        with pytest.raises(PolicyRefusal):
            publish(api, values, previous=old.revision, operation="bad")
    second = publish(api, (profile(2, policy_version=2, levels=("L1", "L0")),), previous=old.revision, operation="second")
    empty = publish(api, (), previous=second.revision, operation="remove")
    with pytest.raises(PolicyRefusal):
        publish(api, (profile(),), previous=empty.revision, operation="resurrect")
    assert api.current().profiles == ()


def test_empty_registry_and_immutable_ordered_profile_identity(authority):
    api, conn, _ = authority
    empty = publish(api, ())
    assert api.current().profiles == ()
    two = (profile(identity="z"), profile(identity="a"))
    publish(api, two, previous=empty.revision, operation="two")
    assert [p.profile_id for p in api.current().profiles] == ["a", "z"]
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM host_configuration_revisions")
    conn.rollback()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE host_policy_versions SET digest='other'")
    conn.rollback()


@pytest.mark.parametrize("table", ["extra", "sqliteOther"])
def test_unexpected_schema_refuses_before_read_or_write(authority, table):
    api, conn, _ = authority
    publish(api)
    conn.execute(f"CREATE TABLE {table}(value)")
    with pytest.raises(PolicyStoreError):
        api.current()
    assert not conn.in_transaction


def test_missing_or_swapped_file_permissions_and_identity_refuse(authority, tmp_path):
    api, conn, _ = authority
    publish(api)
    path = tmp_path / "authority/metadata.sqlite"
    path.chmod(0o644)
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        api.current()
    path.chmod(0o600)
    moved = tmp_path / "authority/old.sqlite"
    path.rename(moved)
    path.touch(mode=0o600)
    with pytest.raises(PolicyRefusal, match="context_unavailable"):
        api.current()
    assert not conn.in_transaction


def test_same_physical_file_and_wrong_identity_refuse(authority, tmp_path):
    api, conn, witness = authority
    other = connection(tmp_path, "authority")
    try:
        with pytest.raises(PolicyRefusal):
            HostConfigurationAuthority(conn, authority_id="a" * 32, witness_connection=other, witness_id="b" * 32)
        wrong = HostConfigurationAuthority(conn, authority_id="c" * 32, witness_connection=witness, witness_id="b" * 32)
        with pytest.raises(PolicyRefusal):
            wrong.current()
    finally:
        other.close()


def test_old_configuration_restore_refuses_current_witness(authority, tmp_path):
    api, conn, witness = authority
    old = publish(api)
    restored = connection(tmp_path, "restored")
    try:
        conn.backup(restored)
        publish(api, (profile(2),), previous=old.revision, operation="second")
        stale = HostConfigurationAuthority(restored, authority_id="a" * 32,
            witness_connection=witness, witness_id="b" * 32)
        with pytest.raises(PolicyRefusal, match="context_unavailable"):
            stale.current()
    finally:
        restored.close()


@pytest.mark.parametrize("what", ["profiles", "bytes", "revisions"])
def test_limits_refuse_without_new_configuration_or_witness(authority, monkeypatch, what):
    from mnemosyne.core import host_configuration as module

    api, conn, witness = authority
    if what == "profiles":
        monkeypatch.setattr(module, "MAX_PROFILES", 0)
        with pytest.raises(ValueError):
            publish(api)
    elif what == "bytes":
        monkeypatch.setattr(module, "MAX_CONFIGURATION_BYTES", 32)
        with pytest.raises(PolicyRefusal, match="resource_limit"):
            publish(api)
    else:
        monkeypatch.setattr(module, "MAX_CONFIGURATION_REVISIONS", 0)
        with pytest.raises(PolicyRefusal, match="resource_limit"):
            publish(api)
    assert conn.execute("SELECT count(*) FROM host_configuration_revisions").fetchone()[0] == 0
    assert witness.execute("SELECT count(*) FROM snapshot_publications").fetchone()[0] == 0


def test_noncanonical_or_invalid_payload_refuses(authority):
    from mnemosyne.core.host_configuration import _DDL

    api, conn, _ = authority
    publish(api)
    snapshot = api.current()
    parsed = json.loads(snapshot.canonical_bytes())
    noncanonical = json.dumps(parsed, indent=2).encode()
    conn.execute("DROP TRIGGER host_configuration_finalize_only")
    conn.execute("UPDATE host_configuration_revisions SET payload=?,digest=?", (noncanonical, hashlib.sha256(noncanonical).hexdigest()))
    conn.execute(_DDL["host_configuration_finalize_only"])
    conn.commit()
    with pytest.raises(PolicyRefusal, match="context_unavailable"):
        api.current()


def test_configuration_metadata_creates_no_admin_or_data_grants(authority):
    api, conn, _ = authority
    admin_label = profile(label="Administrator")
    publish(api, (admin_label,))
    assert api.current().profiles == (admin_label,)
    names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert names == {"host_configuration_state", "host_configuration_revisions", "host_profile_versions", "host_policy_versions"}
    assert not {"recall", "authorize", "read_memory", "grant_access"} & set(dir(api))


@pytest.mark.parametrize("value", [True, 0, -1, 2**63, "1"])
def test_revision_generation_is_bounded_exact_integer(value):
    with pytest.raises((ValueError, TypeError)):
        ConfigurationRevision("a" * 32, value, "b" * 64)


@pytest.mark.parametrize("mode,sync", [("WAL", "NORMAL"), ("DELETE", "FULL"), ("OFF", "EXTRA")])
def test_weakened_durability_is_not_silently_repaired(authority, mode, sync):
    api, conn, _ = authority
    conn.execute(f"PRAGMA journal_mode={mode}")
    conn.execute(f"PRAGMA synchronous={sync}")
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        publish(api)
    assert conn.execute("PRAGMA synchronous").fetchone()[0] == {"NORMAL": 1, "FULL": 2, "EXTRA": 3}[sync]


def test_locked_writer_failure_leaves_no_lifecycle_transaction(authority, tmp_path):
    api, conn, witness = authority
    other = connection(tmp_path, "authority")
    try:
        other.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.OperationalError):
            publish(api)
        assert not conn.in_transaction and not witness.in_transaction
        assert other.in_transaction
    finally:
        other.rollback()
        other.close()


def test_arbitrary_metadata_or_duplicate_profile_cannot_be_staged(authority):
    api, conn, _ = authority
    for values in (({"payload": "not an approved profile"},), (profile(), profile())):
        with pytest.raises((TypeError, ValueError)):
            publish(api, values)
    assert conn.execute("SELECT count(*) FROM host_configuration_revisions").fetchone()[0] == 0


def test_witness_identity_cannot_be_replaced_or_reset(authority):
    api, conn, witness = authority
    publish(api)
    wrong = HostConfigurationAuthority(conn, authority_id="a" * 32,
        witness_connection=witness, witness_id="c" * 32)
    with pytest.raises(PolicyRefusal):
        wrong.current()
    with pytest.raises(PolicyRefusal):
        wrong.prepare()
    assert api.current().revision.generation == 1
