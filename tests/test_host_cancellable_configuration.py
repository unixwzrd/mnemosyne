"""Opt-in storage cancellation and explicit legacy migration on disposable files."""

from dataclasses import replace
import hashlib
import sqlite3

import pytest

from mnemosyne.core.host_configuration import HostConfigurationAuthority, _checkpoint, _decode, _snapshot
from mnemosyne.core.policy import PolicyRefusal
from mnemosyne.core.policy_store import PolicyStoreError
from tests.test_host_registry import authority as authority, connection, profile, registry


@pytest.fixture
def cancellable(tmp_path):
    config, witness = connection(tmp_path, "format-two"), connection(tmp_path, "format-two-witness")
    owner = HostConfigurationAuthority(config, authority_id="a" * 32, witness_connection=witness,
        witness_id="b" * 32, storage_version=2)
    owner.prepare()
    owner.publish((profile(),), previous=None, operation_id="initial", registry=registry())
    yield owner, config, witness
    config.close()
    witness.close()


def prepare(owner, operation="proposal"):
    current = owner.current()
    candidate = replace(current.registry, grants=tuple(replace(g, classification_ceiling="L0") for g in current.registry.grants))
    return owner.stage(current.profiles, previous=current.revision, operation_id=operation, registry=candidate)


def cancel(owner, receipt, operation="cancellation"):
    previous = owner.current()
    candidate = owner.cancellation_candidate(receipt, previous=previous.revision)
    result = owner.stage_cancellation(receipt, previous=previous.revision, operation_id=operation)
    assert result.revision == candidate.revision
    owner.advance_witness(result)
    return owner.finalize(result)


def test_cancel_reaffirms_old_configuration_and_preserves_original_bytes(cancellable):
    owner, conn, _ = cancellable
    before = owner.current()
    pending = prepare(owner)
    original = conn.execute("SELECT * FROM host_configuration_revisions WHERE generation=2").fetchone()
    result = cancel(owner, pending)
    after = owner.current()
    assert result.phase == "committed" and after.revision == result.revision
    assert after.profiles == before.profiles and after.registry == before.registry
    assert after.abandoned.operation_id == pending.operation_id and after.abandoned.revision == pending.revision
    assert owner.receipt(pending.operation_id).phase == "cancelled"
    assert owner.receipt(result.operation_id) == result
    assert conn.execute("SELECT * FROM host_configuration_revisions WHERE generation=2").fetchone() == original
    for method in (owner.advance_witness, owner.finalize):
        with pytest.raises(PolicyRefusal):
            method(pending)
    with pytest.raises(PolicyRefusal):
        owner.recover(pending.operation_id)
    next_receipt = owner.publish(after.profiles, previous=after.revision, operation_id="next", registry=after.registry)
    assert next_receipt.revision.generation == 3
    assert owner.current().registry == before.registry and owner.current().abandoned is None
    with pytest.raises(PolicyRefusal):
        owner.stage(after.profiles, previous=next_receipt.revision, operation_id=pending.operation_id, registry=after.registry)


def test_successive_cancellations_copy_logical_not_abandoned_configuration(cancellable):
    owner, _, _ = cancellable
    initial = owner.current()
    for number in range(3):
        pending = prepare(owner, "proposal:" + str(number))
        cancel(owner, pending, "cancel:" + str(number))
        assert owner.current().registry == initial.registry
        assert owner.current().profiles == initial.profiles
        assert owner.receipt(pending.operation_id).phase == "cancelled"
    assert owner.current().revision.generation == initial.revision.generation + 3


def test_staged_versions_do_not_poison_cancelled_profile_or_policy(cancellable):
    owner, conn, _ = cancellable
    before = owner.current()
    proposed = replace(before.profiles[0], version=20, policy=replace(before.profiles[0].policy, version=20))
    pending = owner.stage((proposed,), previous=before.revision, operation_id="never-published", registry=before.registry)
    assert conn.execute("SELECT max(version) FROM host_committed_profile_versions").fetchone() == (1,)
    cancel(owner, pending)
    current = owner.current()
    replacement = replace(before.profiles[0], version=2, policy=replace(before.profiles[0].policy, version=2))
    owner.publish((replacement,), previous=current.revision, operation_id="proper-version-two", registry=before.registry)
    assert conn.execute("SELECT max(version) FROM host_committed_profile_versions").fetchone() == (2,)
    assert conn.execute("SELECT max(version) FROM host_committed_policy_versions").fetchone() == (2,)


@pytest.mark.parametrize("phase", ["advanced", "committed"])
def test_original_witness_admission_prevents_cancellation(cancellable, phase):
    owner, conn, _ = cancellable
    before = owner.current()
    pending = prepare(owner)
    owner.advance_witness(pending)
    if phase == "committed":
        owner.finalize(pending)
    with pytest.raises(PolicyRefusal):
        owner.stage_cancellation(pending, previous=before.revision, operation_id="too-late")
    assert conn.execute("SELECT count(*) FROM host_configuration_cancellations").fetchone() == (0,)
    assert owner.recover(pending.operation_id).phase == "committed"


def test_prepared_resolution_blocks_original_advancement(cancellable):
    owner, _, _ = cancellable
    before = owner.current()
    pending = prepare(owner)
    result = owner.stage_cancellation(pending, previous=before.revision, operation_id="cancel-wins")
    with pytest.raises(PolicyRefusal):
        owner.advance_witness(pending)
    assert owner.current() == before
    owner.advance_witness(result)
    with pytest.raises(PolicyRefusal):
        owner.current()
    assert owner.recover(result.operation_id).phase == "committed"
    assert owner.current().registry == before.registry


@pytest.mark.parametrize("which", ["owner", "witness"])
def test_independent_restore_fences_cancellation_state(cancellable, which):
    owner, conn, witness = cancellable
    pending = prepare(owner)
    target = conn if which == "owner" else witness
    image = sqlite3.connect(":memory:")
    try:
        target.backup(image)
        cancel(owner, pending)
        image.backup(target)
        with pytest.raises(PolicyRefusal):
            owner.current()
    finally:
        image.close()


def test_old_owner_schema_selection_refuses_opt_in_store(cancellable):
    owner, conn, witness = cancellable
    legacy = HostConfigurationAuthority(conn, authority_id="a" * 32, witness_connection=witness, witness_id="b" * 32)
    with pytest.raises(PolicyStoreError):
        legacy.current()
    with pytest.raises(PolicyStoreError):
        legacy.prepare()
    snapshot = owner.current()
    assert snapshot.storage_version == 2
    assert _decode(owner._authority_id, (snapshot.revision.generation, snapshot.revision.sha256.encode(),
        snapshot.canonical_bytes(), b"initial", b"committed"))[0] == snapshot


def test_quiescent_migration_retains_old_bytes_and_qualifies_new_owner(authority):
    old, conn, _ = authority
    old.publish((profile(),), previous=None, operation_id="legacy", registry=registry())
    before = old.current()
    payload = conn.execute("SELECT payload FROM host_configuration_revisions WHERE generation=1").fetchone()[0]
    upgraded = old.migrate_cancellable(operation_id="migration")
    after = upgraded.current()
    assert after.storage_version == 2 and after.revision.generation == before.revision.generation + 1
    assert after.profiles == before.profiles and after.registry == before.registry
    assert conn.execute("SELECT payload FROM host_configuration_revisions WHERE generation=1").fetchone()[0] == payload
    with pytest.raises(PolicyStoreError):
        old.current()
    assert upgraded.resume_cancellable_migration("migration").phase == "committed"
    pending = prepare(upgraded)
    cancel(upgraded, pending)
    assert upgraded.current().registry == before.registry


def test_migration_refuses_unwitnessed_legacy_head_without_schema_mutation(authority):
    old, conn, _ = authority
    old.publish((profile(),), previous=None, operation_id="legacy", registry=registry())
    pending = prepare(old)
    before = tuple(conn.iterdump())
    with pytest.raises(PolicyRefusal):
        old.migrate_cancellable(operation_id="migration")
    assert tuple(conn.iterdump()) == before
    assert old.receipt(pending.operation_id).phase == "prepared"


def test_migration_interruption_after_schema_preparation_fences_until_explicit_resume(authority, monkeypatch):
    import mnemosyne.core.cancellable_configuration as module
    old, conn, witness = authority
    old.publish((profile(),), previous=None, operation_id="legacy", registry=registry())
    before = old.current()
    original = module.resume_migration

    def fail(*args):
        raise OSError("SECRET-interruption")

    monkeypatch.setattr(module, "resume_migration", fail)
    with pytest.raises(OSError, match="SECRET-interruption"):
        old.migrate_cancellable(operation_id="migration")
    upgraded = HostConfigurationAuthority(conn, authority_id="a" * 32, witness_connection=witness,
        witness_id="b" * 32, storage_version=2)
    with pytest.raises(PolicyRefusal):
        upgraded.current()
    monkeypatch.setattr(module, "resume_migration", original)
    assert upgraded.resume_cancellable_migration("migration").phase == "committed"
    assert upgraded.current().registry == before.registry


def test_raw_owner_format_two_refuses_mixed_shared_policy_versions(cancellable):
    owner, _, _ = cancellable
    before = owner.current()
    alias = replace(before.profiles[0], profile_id="unused", policy=replace(before.profiles[0].policy, version=2))
    with pytest.raises(PolicyRefusal):
        owner.stage(before.profiles + (alias,), previous=before.revision, operation_id="poison", registry=before.registry)
    assert owner.current() == before


def test_legacy_snapshot_bytes_stay_identical(authority):
    owner, _, _ = authority
    owner.publish((profile(),), previous=None, operation_id="legacy", registry=registry())
    snapshot = owner.current()
    assert snapshot.storage_version == 1 and snapshot.abandoned is None
    assert b'"contract_version":2' in snapshot.canonical_bytes()
    assert b'"storage_version"' not in snapshot.canonical_bytes()
    assert hashlib.sha256(snapshot.canonical_bytes()).hexdigest() == snapshot.revision.sha256


@pytest.mark.parametrize("change", ["profiles", "registry"])
@pytest.mark.parametrize("successive", [False, True])
def test_corrupted_reaffirmation_cannot_publish_different_authority(cancellable, change, successive):
    from mnemosyne.core.cancellable_configuration import _EXTRA
    owner, conn, _ = cancellable
    if successive:
        cancel(owner, prepare(owner, "first"), "first-cancel")
    before = owner.current()
    original = prepare(owner)
    resolution = owner.stage_cancellation(original, previous=before.revision, operation_id="cancel")
    valid = owner._row()[0]
    profiles, value = valid.profiles, valid.registry
    if change == "profiles":
        profiles = (replace(profiles[0], version=2),)
    else:
        value = replace(value, grants=())
    corrupted = _snapshot(owner._authority_id, valid.revision.generation, profiles, value,
        storage_version=2, abandoned=valid.abandoned)
    conn.execute("DROP TRIGGER host_configuration_cancellations_finalize_only")
    conn.execute("UPDATE host_configuration_cancellations SET digest=?,payload=? WHERE generation=?",
        (corrupted.revision.sha256, corrupted.canonical_bytes(), resolution.revision.generation))
    conn.execute(_EXTRA["host_configuration_cancellations_finalize_only"])
    conn.commit()
    for method in (lambda: owner.current(), lambda: owner.receipt("cancel"),
                   lambda: owner.advance_witness(replace(resolution, revision=corrupted.revision))):
        with pytest.raises(PolicyRefusal):
            method()
    assert owner._witness.current(owner._authority_id) == _checkpoint(before.revision)


def test_missing_historical_resolution_cannot_forget_cancelled_receipt(cancellable):
    from mnemosyne.core.cancellable_configuration import _EXTRA
    owner, conn, _ = cancellable
    original = prepare(owner)
    cancel(owner, original)
    current = owner.current()
    owner.publish(current.profiles, previous=current.revision, operation_id="later", registry=current.registry)
    conn.execute("DROP TRIGGER host_configuration_cancellations_no_delete")
    conn.execute("DELETE FROM host_configuration_cancellations")
    conn.execute(_EXTRA["host_configuration_cancellations_no_delete"])
    conn.commit()
    with pytest.raises(PolicyRefusal):
        owner.receipt(original.operation_id)
    # The later independently witnessed configuration is still usable; missing
    # historical metadata cannot be interpreted as a different terminal result.
    assert owner.current().revision.generation == 3


@pytest.mark.parametrize("winner", ["original", "cancellation"])
def test_independent_connection_cannot_cross_owner_writer_reservation(cancellable, monkeypatch, winner):
    owner, conn, witness = cancellable
    before = owner.current()
    original = prepare(owner)
    owner_path = conn.execute("PRAGMA database_list").fetchone()[2]
    witness_path = witness.execute("PRAGMA database_list").fetchone()[2]
    other_conn, other_witness = sqlite3.connect(owner_path, timeout=0), sqlite3.connect(witness_path, timeout=0)
    other = HostConfigurationAuthority(other_conn, authority_id="a" * 32, witness_connection=other_witness,
        witness_id="b" * 32, storage_version=2)
    attempted = []
    try:
        if winner == "original":
            publish = owner._witness.publish

            def competing(*args, **kwargs):
                with pytest.raises(sqlite3.OperationalError, match="locked"):
                    other.stage_cancellation(original, previous=before.revision, operation_id="loser")
                attempted.append(True)
                return publish(*args, **kwargs)

            monkeypatch.setattr(owner._witness, "publish", competing)
            owner.advance_witness(original)
            owner.finalize(original)
            with pytest.raises(PolicyRefusal):
                other.stage_cancellation(original, previous=before.revision, operation_id="loser")
        else:
            def competing(statement):
                if statement.startswith("INSERT INTO main.host_configuration_cancellations"):
                    with pytest.raises(sqlite3.OperationalError, match="locked"):
                        other.advance_witness(original)
                    attempted.append(True)

            conn.set_trace_callback(competing)
            resolution = owner.stage_cancellation(original, previous=before.revision, operation_id="winner")
            conn.set_trace_callback(None)
            assert attempted == [True]
            with pytest.raises(PolicyRefusal):
                other.advance_witness(original)
            owner.advance_witness(resolution)
            owner.finalize(resolution)
        assert attempted == [True]
        assert owner.receipt(original.operation_id).phase == ("committed" if winner == "original" else "cancelled")
    finally:
        other_conn.close()
        other_witness.close()


@pytest.mark.parametrize("boundary", ["schema", "witness-before", "witness-after", "finalize-before", "finalize-after"])
def test_explicit_migration_interruption_and_reopen(authority, monkeypatch, boundary):
    import mnemosyne.core.cancellable_configuration as module
    old, conn, witness = authority
    old.publish((profile(),), previous=None, operation_id="legacy", registry=registry())
    before = old.current()
    target, method = ((module, "resume_migration") if boundary == "schema" else
        (old._witness.__class__, "publish") if boundary.startswith("witness") else (module, "finalize"))
    original = getattr(target, method)

    def fail(*args, **kwargs):
        if boundary.endswith("after"):
            original(*args, **kwargs)
        raise OSError("injected interruption")

    with monkeypatch.context() as patch:
        patch.setattr(target, method, fail)
        with pytest.raises(OSError):
            old.migrate_cancellable(operation_id="migration")
    reopened = HostConfigurationAuthority(conn, authority_id="a" * 32, witness_connection=witness,
        witness_id="b" * 32, storage_version=2)
    if boundary != "finalize-after":
        with pytest.raises(PolicyRefusal):
            reopened.current()
    assert reopened.resume_cancellable_migration("migration").phase == "committed"
    assert reopened.current().profiles == before.profiles and reopened.current().registry == before.registry
    assert reopened.resume_cancellable_migration("migration").phase == "committed"
    with pytest.raises(PolicyStoreError):
        old.current()


@pytest.mark.parametrize("which", ["owner", "witness"])
def test_migration_independent_restore_is_not_legacy_downgrade(authority, which):
    old, conn, witness = authority
    old.publish((profile(),), previous=None, operation_id="legacy", registry=registry())
    target = conn if which == "owner" else witness
    image = sqlite3.connect(":memory:")
    try:
        target.backup(image)
        new = old.migrate_cancellable(operation_id="migration")
        image.backup(target)
        with pytest.raises((PolicyStoreError, PolicyRefusal)):
            new.current()
        with pytest.raises((PolicyStoreError, PolicyRefusal)):
            old.current()
    finally:
        image.close()


def test_cancellation_at_capacity_is_terminal_without_extra_revision(cancellable, monkeypatch):
    import mnemosyne.core.host_configuration as configuration
    import mnemosyne.core.cancellable_configuration as module
    owner, _, _ = cancellable
    monkeypatch.setattr(configuration, "MAX_CONFIGURATION_REVISIONS", 2)
    monkeypatch.setattr(module, "MAX_CONFIGURATION_REVISIONS", 2)
    cancel(owner, prepare(owner))
    before = owner.current()
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        owner.stage(before.profiles, previous=before.revision, operation_id="overflow", registry=before.registry)
    assert owner.current() == before


@pytest.mark.parametrize("corruption", ["missing-publication", "missing-history", "extra-version", "conflicting-policy"])
def test_migration_validates_all_history_before_schema_mutation(authority, monkeypatch, corruption):
    old, conn, _ = authority
    old.publish((profile(),), previous=None, operation_id="legacy", registry=registry())
    first = old.current()
    old.publish((replace(profile(), version=2),), previous=first.revision, operation_id="second", registry=registry())
    if corruption == "missing-publication":
        publication = old._witness.publication
        monkeypatch.setattr(old._witness, "publication", lambda authority, operation:
            None if operation == "host-config:" + hashlib.sha256(b"legacy").hexdigest() else publication(authority, operation))
    elif corruption == "missing-history":
        from mnemosyne.core.host_configuration import _DDL
        conn.execute("DROP TRIGGER host_configuration_no_delete")
        conn.execute("DELETE FROM host_configuration_revisions WHERE generation=1")
        conn.execute(_DDL["host_configuration_no_delete"])
        conn.commit()
    elif corruption == "extra-version":
        conn.execute("INSERT INTO host_profile_versions VALUES('phantom',1,?)", ("0" * 64,))
        conn.commit()
    else:
        # Legacy accepts mixed versions under one live policy identity; migration
        # must not smuggle that unsupported namespace into format 2.
        current = old.current()
        alias = replace(profile(), profile_id="unused", policy=replace(profile().policy, version=2))
        old.publish(current.profiles + (alias,), previous=current.revision, operation_id="mixed", registry=current.registry)
    before = tuple(conn.iterdump())
    with pytest.raises(PolicyRefusal):
        old.migrate_cancellable(operation_id="migration")
    assert tuple(conn.iterdump()) == before


def test_migration_remembers_removed_committed_profile_versions(authority):
    old, conn, _ = authority
    spare = replace(profile(), profile_id="removed", version=7)
    old.publish((profile(), spare), previous=None, operation_id="legacy", registry=registry())
    before = old.current()
    old.publish((profile(),), previous=before.revision, operation_id="removed", registry=registry())
    new = old.migrate_cancellable(operation_id="migration")
    assert conn.execute("SELECT version FROM host_committed_profile_versions WHERE profile_id='removed'").fetchall() == [(7,)]
    current = new.current()
    with pytest.raises(PolicyRefusal):
        new.stage(current.profiles + (replace(spare, version=6),), previous=current.revision,
            operation_id="downgrade", registry=current.registry)


def test_version_registration_and_finalization_are_one_transaction(cancellable):
    owner, conn, _ = cancellable
    current = owner.current()
    revised = replace(profile(), version=2)
    pending = owner.stage((revised,), previous=current.revision, operation_id="version-two", registry=current.registry)
    owner.advance_witness(pending)
    denied = []

    def authorizer(action, table, column, database, trigger):
        if action == sqlite3.SQLITE_UPDATE and table == "host_configuration_revisions":
            denied.append(True)
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    conn.set_authorizer(authorizer)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            owner.finalize(pending)
    finally:
        # Disabling with None was added in Python 3.11; keep this fixture's
        # cleanup valid on the supported 3.10 interpreter as well.
        conn.set_authorizer(lambda *args: sqlite3.SQLITE_OK)
    assert denied == [True]
    assert conn.execute("SELECT max(version) FROM host_committed_profile_versions").fetchone() == (1,)
    assert owner.receipt(pending.operation_id).phase == "prepared"
    assert owner.recover(pending.operation_id).phase == "committed"
    assert conn.execute("SELECT max(version) FROM host_committed_profile_versions").fetchone() == (2,)


@pytest.mark.parametrize("field,value", [("profile_id", "\u00e9" * 65), ("policy_id", "p" * 129),
    ("profile_id", "\U0001f512" * 128), ("policy_id", "\U0001f512" * 256)])
def test_migration_retains_existing_character_based_identifier_contract(authority, field, value):
    owner, conn, _ = authority
    item = replace(profile(), profile_id=value) if field == "profile_id" else replace(profile(), policy=replace(profile().policy, policy_id=value))
    owner.publish((item,), previous=None, operation_id="legacy")
    new = owner.migrate_cancellable(operation_id="migration")
    assert new.current().profiles == (item,)
    table, column = ("host_committed_profile_versions", "profile_id") if field == "profile_id" else ("host_committed_policy_versions", "policy_id")
    assert conn.execute(f"SELECT {column} FROM {table}").fetchall() == [(value,)]
