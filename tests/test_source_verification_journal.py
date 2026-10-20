"""Synthetic S2b owner reports; no protected authorization or live data."""

import asyncio
import hashlib
import io
import json
import os
import socket
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from pathlib import Path
from threading import Barrier

import pytest

from mnemosyne.core.media import MediaStore
from mnemosyne.core.resolvers import CallableContentResolver
from mnemosyne.core.source_verification import SourceVerification, verify_source_revision
from mnemosyne.core.source_verification_journal import SourceVerificationJournal, VerificationJournalError


@pytest.fixture
def store(tmp_path):
    instance = MediaStore(db_path=tmp_path / "media.db")
    yield instance
    instance.conn.close()


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbid(*args, **kwargs):
        pytest.fail("journal used a socket or DNS")

    monkeypatch.setattr(socket.socket, "connect", forbid)
    monkeypatch.setattr(socket.socket, "connect_ex", forbid)
    monkeypatch.setattr(socket, "getaddrinfo", forbid)


def observation(store, data=b"original synthetic source", *, current=None, **kwargs):
    parent = store.upsert_asset(ref_kind="url", ref_value="archive://source/original", modality="document")
    registered = store.register_source_revision(
        parent.asset_id, revision_key="v1", content_hash=hashlib.sha256(data).hexdigest(),
        byte_size=len(data), **kwargs,
    )
    source = CallableContentResolver("fixture", frozenset({"archive"}),
                                     open_func=lambda _: io.BytesIO(data if current is None else current))
    return verify_source_revision(store, registered.revision_id, locator="archive://source/moved", resolver=source)


def record(journal, value, **kwargs):
    return journal.record(value, **{"event_key": "attempt-1", "producer": "s2a:8852984", **kwargs})


def test_absent_journal_reads_and_constructor_do_not_migrate_or_write(store):
    value = observation(store)
    before = list(store.conn.iterdump())
    changes = store.conn.total_changes
    journal = SourceVerificationJournal(store)
    assert journal.get(value.revision_id, event_key="unknown") is None
    assert journal.list(value.revision_id) == []
    assert list(store.conn.iterdump()) == before
    assert store.conn.total_changes == changes and not store.conn.in_transaction


def test_roundtrip_retry_reopen_and_no_source_status_mutation(store):
    value = observation(store)
    source_before = store.get_source_revision(value.revision_id)
    journal = SourceVerificationJournal(store)
    first = record(journal, value)
    assert (first.status, first.transaction_state) == ("created", "committed")
    before_changes = store.conn.total_changes
    again = record(journal, value)
    assert (again.status, again.event_id, again.transaction_state) == ("unchanged", first.event_id, "committed")
    assert store.conn.total_changes == before_changes
    stored = journal.get(value.revision_id, event_key="attempt-1")
    assert stored.observation == value and stored.recorded_at.endswith("Z")
    assert value.locator not in repr(stored) and value.revision_id not in repr(first)
    second = MediaStore(db_path=store.db_path)
    try:
        assert SourceVerificationJournal(second).get(value.revision_id, event_key="attempt-1") == stored
        assert store.get_source_revision(value.revision_id) == source_before
    finally:
        second.conn.close()


@pytest.mark.parametrize("change", ["producer", "time", "locator"])
def test_event_key_conflicts_preserve_original_and_caller_transaction(store, change):
    value = observation(store)
    journal = SourceVerificationJournal(store)
    record(journal, value)
    before = list(store.conn.iterdump())
    kwargs = {}
    if change == "producer":
        kwargs["producer"] = "different-artifact"
    elif change == "time":
        value = replace(value, checked_at="2026-10-19T00:00:00Z")
    else:
        value = replace(value, locator="archive://another/location")
    store.conn.execute("SAVEPOINT caller")
    with pytest.raises(VerificationJournalError, match="event_conflict"):
        record(journal, value, **kwargs)
    assert store.conn.in_transaction and list(store.conn.iterdump()) == before
    store.conn.execute("RELEASE caller")


def test_multiple_attempts_keep_relocation_and_changed_history(store):
    value = observation(store)
    journal = SourceVerificationJournal(store)
    first = record(journal, value)
    moved = replace(value, locator="archive://source/another-location")
    second = record(journal, moved, event_key="attempt-2")
    changed = replace(value, status="changed", reason="bytes_mismatch",
                      observed_sha256=hashlib.sha256(b"different bytes").hexdigest(), observed_byte_size=15)
    third = record(journal, changed, event_key="attempt-3")
    all_rows = journal.list(value.revision_id)
    assert {row.event_id for row in all_rows} == {first.event_id, second.event_id, third.event_id}
    assert journal.list(value.revision_id, limit=2) == all_rows[:2]
    assert journal.list(value.revision_id, limit=2, offset=2) == all_rows[2:]
    assert journal.list("another-revision") == []
    assert store.get_source_revision(value.revision_id)["digest_status"] == "asserted"


@pytest.mark.parametrize("status,reason", [
    ("missing", "source_missing"), ("inaccessible", "source_inaccessible"),
    ("unavailable", "source_unavailable"), ("unverified", "resolver_failure"),
    ("unverified", "invalid_stream"), ("unverified", "close_failed"),
    ("limit_exceeded", "stream_exceeds_budget"),
])
def test_failure_observations_are_history_not_fabricated_success(store, status, reason):
    value = observation(store)
    value = replace(value, status=status, reason=reason, observed_sha256=None, observed_byte_size=1)
    journal = SourceVerificationJournal(store)
    record(journal, value)
    assert journal.get(value.revision_id, event_key="attempt-1").observation == value


@pytest.mark.parametrize("reason", ["unsupported_scheme", "resolver_unconfigured", "expected_size_exceeds_budget"])
def test_unopened_observations_have_no_invented_count(store, reason):
    value = observation(store)
    status = {"unsupported_scheme": "unverified", "resolver_unconfigured": "unavailable",
              "expected_size_exceeds_budget": "limit_exceeded"}[reason]
    value = replace(value, status=status, reason=reason, observed_sha256=None, observed_byte_size=None)
    journal = SourceVerificationJournal(store)
    record(journal, value)
    assert journal.list(value.revision_id)[0].observation == value


def test_unsupported_original_representation_remains_unverified(store):
    value = observation(store, representation="http-response")
    assert value.reason == "unsupported_representation"
    journal = SourceVerificationJournal(store)
    record(journal, value)
    assert journal.list(value.revision_id)[0].observation == value


@pytest.mark.parametrize("changes", [
    {"status": "unknown"}, {"reason": "private arbitrary exception"},
    {"status": "changed", "reason": "bytes_mismatch"},
    {"observed_sha256": None}, {"observed_byte_size": None},
    {"observed_byte_size": True}, {"expected_byte_size": -1},
    {"expected_byte_size": 1.25}, {"observed_byte_size": 1073741826},
    {"checked_at": "2026-10-20T00:00:00"}, {"checked_at": "2026-02-30T00:00:00Z"},
    {"locator": "data://inline"}, {"locator": "archive://bad\n"},
    {"asset_id": None}, {"expected_sha256": "bad"}, {"revision_id": ""},
    {"producer": ""}, {"event_key": "\n"},
])
def test_invalid_reports_refuse_before_schema_creation(store, changes):
    changes = dict(changes)
    value = observation(store)
    kwargs = {key: changes.pop(key) for key in ("producer", "event_key") if key in changes}
    value = replace(value, **changes)
    before = list(store.conn.iterdump())
    with pytest.raises(ValueError):
        record(SourceVerificationJournal(store), value, **kwargs)
    assert list(store.conn.iterdump()) == before and not store.conn.in_transaction


def test_partial_outcomes_cannot_carry_complete_digest_and_unknown_revision_cannot_be_recorded(store):
    value = observation(store)
    journal = SourceVerificationJournal(store)
    with pytest.raises(ValueError, match="partial"):
        record(journal, replace(value, status="unverified", reason="close_failed"))
    with pytest.raises(ValueError):
        record(journal, asdict(value))
    unknown = replace(value, revision_id="unknown-revision")
    with pytest.raises(VerificationJournalError, match="revision_mismatch"):
        record(journal, unknown)
    assert not store.conn.in_transaction
    assert not any("verification_events" in row[0] for row in store.conn.execute("SELECT name FROM sqlite_master"))


def test_well_formed_owner_report_is_not_an_authentication_or_verifier_attestation(store):
    value = observation(store)
    reported = SourceVerification(**asdict(value))
    journal = SourceVerificationJournal(store)
    record(journal, reported, producer="owner-reported-identity-not-a-credential")
    assert journal.list(value.revision_id)[0].observation.status == "verified"
    assert store.get_source_revision(value.revision_id)["digest_status"] == "asserted"


@pytest.mark.parametrize("column,new", [("content_hash", "b" * 64), ("byte_size", 999),
                                       ("asset_id", "changed-parent"), ("digest_status", "verified")])
def test_registered_revision_snapshot_must_still_match(store, column, new):
    value = observation(store)
    store.conn.execute(f"UPDATE media_source_revisions SET {column} = ?", (new,))
    store.conn.commit()
    before = list(store.conn.iterdump())
    with pytest.raises(VerificationJournalError, match="revision_mismatch"):
        record(SourceVerificationJournal(store), value)
    assert list(store.conn.iterdump()) == before


def test_pending_caller_record_rollback_and_uncertain_commit_lookup(store):
    value = observation(store)
    journal = SourceVerificationJournal(store)
    store.conn.execute("BEGIN")
    receipt = record(journal, value)
    assert receipt.transaction_state == "pending"
    assert journal.get(value.revision_id, event_key="attempt-1") is not None
    store.conn.rollback()
    assert journal.get(value.revision_id, event_key="attempt-1") is None
    store.conn.execute("BEGIN")
    record(journal, value)
    store.conn.commit()  # Simulate caller losing the response after durable commit.
    retry = record(journal, value)
    assert retry.status == "unchanged" and retry.event_id == receipt.event_id
    assert len(journal.list(value.revision_id)) == 1


@pytest.mark.parametrize("autocommit", [True, False])
def test_explicit_autocommit_modes_preserve_ownership(tmp_path, autocommit):
    if not hasattr(sqlite3.Connection, "autocommit"):
        pytest.skip("explicit autocommit API requires Python 3.12")
    conn = sqlite3.connect(tmp_path / "explicit.db", autocommit=autocommit)
    conn.row_factory = sqlite3.Row
    store = MediaStore(conn=conn)
    try:
        value = observation(store)
        journal = SourceVerificationJournal(store)
        receipt = record(journal, value)
        assert receipt.transaction_state == ("committed" if autocommit else "pending")
        assert conn.in_transaction is (not autocommit)
        if not autocommit:
            conn.rollback()
    finally:
        conn.close()


def test_read_only_existing_journal_and_failed_write_do_not_leave_owned_lock(store):
    value = observation(store)
    record(SourceVerificationJournal(store), value)
    conn = sqlite3.connect(store.db_path.as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    readonly = MediaStore(conn=conn)
    try:
        journal = SourceVerificationJournal(readonly)
        assert journal.get(value.revision_id, event_key="attempt-1").observation == value
        assert not conn.in_transaction
        with pytest.raises(sqlite3.OperationalError):
            record(journal, value, event_key="attempt-2")
        assert not conn.in_transaction
    finally:
        conn.close()


def test_permission_failure_rolls_back_new_schema_and_preserves_caller_state(store):
    value = observation(store)
    journal = SourceVerificationJournal(store)
    store.conn.execute("CREATE TABLE caller_data (value TEXT)")
    store.conn.execute("SAVEPOINT caller")
    store.conn.execute("INSERT INTO caller_data VALUES ('pending')")

    def authorizer(action, table, *args):
        return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_INSERT and table == "media_source_verification_events" else sqlite3.SQLITE_OK

    store.conn.set_authorizer(authorizer)
    with pytest.raises(sqlite3.DatabaseError):
        record(journal, value)
    store.conn.set_authorizer(lambda *args: sqlite3.SQLITE_OK)
    assert store.conn.in_transaction
    assert store.conn.execute("SELECT * FROM caller_data").fetchone()[0] == "pending"
    assert journal.list(value.revision_id) == []
    store.conn.execute("RELEASE caller")
    assert record(journal, value).transaction_state == "committed"


def test_competing_identical_records_are_exactly_once(tmp_path, store):
    value = observation(store)
    barrier = Barrier(2)

    def worker():
        independent = MediaStore(db_path=store.db_path)
        try:
            journal = SourceVerificationJournal(independent)
            barrier.wait(timeout=10)
            return record(journal, value)
        finally:
            independent.conn.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = list(pool.map(lambda _: worker(), range(2)))
    assert sorted(result.status for result in receipts) == ["created", "unchanged"]
    assert len({result.event_id for result in receipts}) == 1
    assert len(SourceVerificationJournal(store).list(value.revision_id)) == 1


@pytest.mark.parametrize("broken", ["table", "index", "trigger"])
def test_unknown_or_partial_schema_refuses_without_repair(store, broken):
    value = observation(store)
    journal = SourceVerificationJournal(store)
    if broken == "table":
        store.conn.execute("CREATE TABLE media_source_verification_events (event_id TEXT)")
    else:
        record(journal, value)
        if broken == "index":
            store.conn.execute("DROP INDEX idx_source_verification_revision")
        else:
            store.conn.execute("CREATE TRIGGER unknown AFTER INSERT ON media_source_verification_events BEGIN SELECT 1; END")
    store.conn.commit()
    before = list(store.conn.iterdump())
    with pytest.raises(VerificationJournalError, match="incompatible_schema"):
        record(journal, value)
    with pytest.raises(VerificationJournalError, match="incompatible_schema"):
        journal.list(value.revision_id)
    assert list(store.conn.iterdump()) == before


def test_temp_shadow_tables_do_not_replace_main_revision_or_journal(store):
    value = observation(store)
    journal = SourceVerificationJournal(store)
    store.conn.execute("CREATE TEMP TABLE media_source_revisions (revision_id TEXT)")
    store.conn.execute("CREATE TEMP TABLE media_source_verification_events (event_id TEXT)")
    record(journal, value)
    assert journal.get(value.revision_id, event_key="attempt-1").observation == value
    assert store.conn.execute("SELECT count(*) FROM temp.media_source_verification_events").fetchone()[0] == 0


@pytest.mark.parametrize("kwargs", [{"limit": 0}, {"limit": 1001}, {"limit": True},
                                     {"offset": -1}, {"offset": 2**63}, {"offset": 1.5}])
def test_invalid_pagination_does_not_create_schema(store, kwargs):
    value = observation(store)
    with pytest.raises(ValueError):
        SourceVerificationJournal(store).list(value.revision_id, **kwargs)


def test_journal_never_fetches_or_stores_original_bytes(store, monkeypatch):
    original = b"THIS-SYNTHETIC-ORIGINAL-MUST-NOT-BE-ARCHIVED" * 400
    value = observation(store, original)
    from mnemosyne.core import source_verification, resolvers

    def forbid(*args, **kwargs):
        pytest.fail("journal attempted byte access")

    monkeypatch.setattr(source_verification, "verify_source_revision", forbid)
    monkeypatch.setattr(resolvers, "resolve_open", forbid)
    journal = SourceVerificationJournal(store)
    record(journal, value, event_key="bound ' ; DROP TABLE media_assets; --")
    assert len(journal.list(value.revision_id)) == 1
    assert original.decode() not in "\n".join(store.conn.iterdump())
    assert not any(row[2].upper() == "BLOB" for row in store.conn.execute("PRAGMA table_info(media_source_verification_events)"))


@pytest.mark.parametrize("phase", ["before_insert", "after_insert"])
@pytest.mark.parametrize("existing", [False, True])
def test_process_abort_keeps_schema_events_and_prior_data_atomic(store, tmp_path, phase, existing):
    value = observation(store)
    if existing:
        record(SourceVerificationJournal(store), value, event_key="prior")
    source = Path(__file__).resolve().parents[1]
    script = '''
import json, os, sqlite3, sys
from pathlib import Path
from mnemosyne.core.media import MediaStore
from mnemosyne.core.source_verification import SourceVerification
from mnemosyne.core.source_verification_journal import SourceVerificationJournal
path, values, phase = json.load(sys.stdin)
class AbortConnection(sqlite3.Connection):
    def execute(self, sql, *args):
        inserted = sql.startswith('INSERT INTO main.media_source_verification_events ')
        if inserted and phase == 'before_insert':
            os._exit(27)
        result = super().execute(sql, *args)
        if inserted and phase == 'after_insert':
            os._exit(27)
        return result
conn = sqlite3.connect(path, factory=AbortConnection)
conn.row_factory = sqlite3.Row
store = MediaStore(db_path=Path(path), conn=conn)
SourceVerificationJournal(store).record(SourceVerification(**values), event_key='child', producer='fixture')
'''
    before = list(store.conn.iterdump())
    env = {"PATH": os.defpath, "HOME": str(tmp_path), "PYTHONPATH": str(source),
           "MNEMOSYNE_DATA_DIR": str(tmp_path / "unused"), "MNEMOSYNE_LLM_ENABLED": "false",
           "MNEMOSYNE_NO_EMBEDDINGS": "1"}
    result = subprocess.run([sys.executable, "-c", script], cwd=tmp_path, env=env,
                            input=json.dumps([str(store.db_path), asdict(value), phase]), text=True,
                            capture_output=True, timeout=30)
    assert result.returncode == 27, result.stdout + result.stderr
    assert list(store.conn.iterdump()) == before
    assert record(SourceVerificationJournal(store), value).status == "created"


@pytest.mark.parametrize("column,value", [("status", "invented"), ("producer", ""), ("checked_at", "bad"),
                                          ("observed_sha256", None)])
def test_malformed_stored_records_refuse_instead_of_becoming_empty_success(store, column, value):
    verified = observation(store)
    journal = SourceVerificationJournal(store)
    record(journal, verified)
    store.conn.execute(f"UPDATE media_source_verification_events SET {column} = ?", (value,))
    store.conn.commit()
    before = list(store.conn.iterdump())
    with pytest.raises(VerificationJournalError, match="invalid_record"):
        journal.get(verified.revision_id, event_key="attempt-1")
    with pytest.raises(VerificationJournalError, match="invalid_record"):
        journal.list(verified.revision_id)
    assert list(store.conn.iterdump()) == before


@pytest.mark.parametrize("caller_owned", [False, True])
@pytest.mark.parametrize("failure", [sqlite3.OperationalError, KeyboardInterrupt, asyncio.CancelledError])
def test_failure_after_actual_insert_rolls_back_only_owned_work(store, caller_owned, failure):
    value = observation(store)
    record(SourceVerificationJournal(store), value, event_key="prior")
    before = list(store.conn.iterdump())

    class FailAfterInsert(sqlite3.Connection):
        def execute(self, sql, *args):
            result = super().execute(sql, *args)
            if sql.startswith('INSERT INTO main.media_source_verification_events '):
                raise failure("injected after-insert failure")
            return result

    conn = sqlite3.connect(store.db_path, factory=FailAfterInsert)
    conn.row_factory = sqlite3.Row
    wrapped = MediaStore(db_path=store.db_path, conn=conn)
    try:
        if caller_owned:
            conn.execute("SAVEPOINT caller")
        with pytest.raises(failure, match="injected"):
            record(SourceVerificationJournal(wrapped), value)
        assert conn.in_transaction == caller_owned
        assert list(conn.iterdump()) == before
        if caller_owned:
            conn.execute("RELEASE caller")
    finally:
        conn.close()
