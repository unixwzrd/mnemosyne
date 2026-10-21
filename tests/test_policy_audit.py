"""Synthetic audit metadata, fresh administrative scope and owned transactions."""

from dataclasses import replace
import sqlite3

import pytest

from mnemosyne.core.policy import PolicyRefusal, PolicySurface, RefusalReason
from mnemosyne.core.policy_audit import AuditReadGrant, PolicyAudit, PolicyAuditEvent
from mnemosyne.core.policy_lifecycle import PolicyRecordRef
from mnemosyne.core.policy_store import PolicyStoreError, RecordKind
from mnemosyne.runtime_context import bind_access_context
from tests.test_policy_read import context


@pytest.fixture
def journal(tmp_path):
    conn = sqlite3.connect(tmp_path / "audit.db")
    conn.execute("PRAGMA synchronous=EXTRA")
    ctx = context(operations={"audit:read"})
    state = {"epoch": 0, "calls": [], "context": ctx}
    def verify(candidate, *, bank, destination):
        assert candidate == state["context"]
        state["calls"].append(True)
        return AuditReadGrant(candidate.fingerprint(), "domain:a", bank, destination, "decision:audit", state["epoch"])
    api = PolicyAudit(conn, domain_id="domain:a", bank="bank:a", verify_read=verify)
    api.prepare()
    yield conn, ctx, state, api
    conn.close()


def event(ctx, **changes):
    values = dict(event_id="event:a", decision_id="decision:a", surface=PolicySurface.DIRECT,
        bank="bank:a", destination="channel:a", lifecycle_epoch=0, result="allow",
        requested=(PolicyRecordRef(RecordKind.WORKING,"w"),), returned=(PolicyRecordRef(RecordKind.WORKING,"w"),))
    values.update(changes)
    return PolicyAuditEvent.from_context(ctx, **values)


def read(fx, **options):
    with bind_access_context(fx[1]):
        return fx[3].read(destination="channel:a", **options)


def test_append_retry_reopen_and_bounded_read(journal):
    conn, ctx, state, api = journal
    item = event(ctx)
    first = api.append(item)
    assert first.status == "created" and first.transaction_state == "committed"
    assert api.append(item).status == "unchanged"
    api.append(event(ctx,event_id="event:b"))
    rows = read(journal,limit=1)
    assert len(rows) == 1 and rows[0].event == item and rows[0].recorded_at.endswith("Z")
    assert len(state["calls"]) == 3 and not conn.in_transaction
    assert read(journal,after_sequence=rows[0].sequence)[0].event.event_id == "event:b"
    assert "event:a" not in repr(rows[0]) and "person:a" not in repr(item)
    api.prepare()


@pytest.mark.parametrize("change", [{"principals":set()}, {"context_fingerprint":"bad"},
    {"surface":"direct"}, {"operation":"arbitrary shell"}, {"operation":"sync"},
    {"result":"unknown"}, {"result":"deny"}, {"reason":RefusalReason.ACCESS_DENIED},
    {"context_epoch":True}, {"lifecycle_epoch":-1}, {"requested":["w"]},
    {"requested":[PolicyRecordRef(RecordKind.WORKING,"w")]*2}])
def test_invalid_metadata_refuses(journal, change):
    with pytest.raises((TypeError,ValueError)):
        replace(event(journal[1]), **change)


def test_denied_metadata_never_contains_returned_records(journal):
    ctx = journal[1]
    item = event(ctx,result="deny",reason=RefusalReason.ACCESS_DENIED,returned=())
    journal[3].append(item)
    assert read(journal)[0].event == item
    with pytest.raises(ValueError):
        replace(item,returned=(PolicyRecordRef(RecordKind.WORKING,"w"),))


@pytest.mark.parametrize("change", [None, {"operations":{"read:bank"}}, {"banks":{"bank:b"}},
    {"destinations":{"channel:b"}}, {"assurance":"unknown"}])
def test_unauthorized_reads_never_select_payloads(journal, change):
    conn, ctx, state, api = journal
    api.append(event(ctx))
    selected = []
    def authorizer(action, table, column, *rest):
        if action == sqlite3.SQLITE_READ and table == "policy_audit_events":
            selected.append(column)
        return sqlite3.SQLITE_OK
    conn.set_authorizer(authorizer)
    try:
        with bind_access_context(None if change is None else context(**change)), pytest.raises(PolicyRefusal):
            api.read(destination="channel:a")
        assert not selected and not state["calls"]
    finally:
        conn.set_authorizer(None)


@pytest.mark.parametrize("kind", ["epoch", "context", "exception", "coroutine"])
def test_late_authority_change_refuses_before_return(journal, kind):
    conn, ctx, _, api = journal
    api.append(event(ctx))
    calls = []
    async def deferred():
        pytest.fail("must not run")
    def verify(candidate, *, bank, destination):
        calls.append(True)
        if len(calls) == 2:
            if kind == "context":
                from mnemosyne.runtime_context import _access_context
                _access_context.set(context(epoch=2,operations={"audit:read"}))
            elif kind == "exception":
                raise RuntimeError("synthetic unavailable")
            elif kind == "coroutine":
                return deferred()
        return AuditReadGrant(candidate.fingerprint(),"domain:a",bank,destination,"decision:audit",
            1 if kind == "epoch" and len(calls) == 2 else 0)
    api._verify = verify
    with bind_access_context(ctx), pytest.raises(PolicyRefusal):
        api.read(destination="channel:a")
    assert not conn.in_transaction


def test_capacity_failure_keeps_prior_records_and_retries(journal):
    conn, ctx, _, _ = journal
    fresh = sqlite3.connect(":memory:")
    try:
        api = PolicyAudit(fresh,domain_id="domain:a",bank="bank:a",verify_read=lambda *a,**k:None)
        api.prepare(max_events=1)
        item = event(ctx)
        api.append(item)
        with pytest.raises(PolicyRefusal,match="resource_limit"):
            api.append(event(ctx,event_id="event:b"))
        assert api.append(item).status == "unchanged" and not fresh.in_transaction
        assert fresh.execute("SELECT count(*) FROM policy_audit_events").fetchone()[0] == 1
    finally:
        fresh.close()


def test_event_conflict_and_wrong_bank_refuse_without_effect(journal):
    conn, ctx, _, api = journal
    api.append(event(ctx))
    for item in (event(ctx,decision_id="other"),event(ctx,bank="bank:b")):
        with pytest.raises(PolicyRefusal,match="access_denied"):
            api.append(item)
    assert conn.execute("SELECT count(*) FROM policy_audit_events").fetchone()[0] == 1
    assert not conn.in_transaction


def test_caller_transaction_stays_pending_and_read_refuses(journal):
    conn, ctx, _, api = journal
    conn.execute("BEGIN")
    assert api.append(event(ctx)).transaction_state == "pending"
    with bind_access_context(ctx),pytest.raises(PolicyRefusal,match="unsupported_surface"):
        api.read(destination="channel:a")
    assert conn.in_transaction
    conn.rollback()
    assert read(journal) == ()


@pytest.mark.parametrize("sql", ["DELETE FROM policy_audit_events", "UPDATE policy_audit_events SET digest='bad'"])
def test_append_only_triggers_refuse_mutation(journal, sql):
    conn, ctx, _, api = journal
    api.append(event(ctx))
    with pytest.raises(sqlite3.IntegrityError,match="immutable_audit"):
        conn.execute(sql)
    conn.rollback()
    assert len(read(journal)) == 1


@pytest.mark.parametrize("field,expression", [("payload","'broken'"), ("payload","CAST(x'80' AS TEXT)"),
    ("digest","CAST(x'80' AS TEXT)"), ("recorded_at","CAST(x'80' AS TEXT)"),
    ("recorded_at","'yesterday'"), ("event_id","'different'")])
def test_corrupt_metadata_refuses_with_fixed_error(journal,field,expression):
    conn, ctx, _, api = journal
    api.append(event(ctx))
    conn.execute("DROP TRIGGER policy_audit_no_update")
    conn.execute(f"UPDATE policy_audit_events SET {field}={expression}")
    # Restore the exact owner trigger so this tests decoding, not missing schema.
    from mnemosyne.core.policy_audit import _DDL
    conn.execute(_DDL["policy_audit_no_update"])
    conn.commit()
    with pytest.raises(PolicyRefusal,match="unsupported_surface"):
        read(journal)
    assert not conn.in_transaction


def test_refuses_incomplete_schema_and_nonempty_legacy_store(journal):
    conn, _, _, api = journal
    conn.execute("DROP TRIGGER policy_audit_no_delete")
    conn.commit()
    with pytest.raises(PolicyStoreError):
        api.prepare()
    legacy = sqlite3.connect(":memory:")
    try:
        legacy.execute("CREATE TABLE working_memory(content TEXT)")
        other = PolicyAudit(legacy,domain_id="domain:a",bank="bank:a",verify_read=lambda *a,**k:None)
        with pytest.raises(PolicyStoreError):
            other.prepare()
        assert legacy.execute("SELECT 1 FROM sqlite_master WHERE name='policy_audit_state'").fetchone() is None
    finally:
        legacy.close()


@pytest.mark.parametrize("failure", ["capacity", "pending", "deny", "schema"])
def test_audit_failure_or_denial_prevents_consumer(journal,failure):
    conn, ctx, _, api = journal
    calls = []
    item = event(ctx)
    if failure == "capacity":
        conn.execute("UPDATE policy_audit_state SET max_events=1")
        conn.commit()
        api.append(item)
        item = event(ctx,event_id="event:b")
    elif failure == "pending":
        conn.execute("BEGIN")
    elif failure == "deny":
        item = event(ctx,result="deny",reason=RefusalReason.ACCESS_DENIED,returned=())
    else:
        conn.execute("DROP TRIGGER policy_audit_no_delete")
        conn.commit()
    with pytest.raises((PolicyRefusal,PolicyStoreError)):
        api.admit(item,lambda value:calls.append(True))
    assert not calls and conn.in_transaction == (failure == "pending")
    conn.rollback()


def test_audit_admission_commits_before_consumer_without_retry(journal):
    conn, ctx, _, api = journal
    calls = []
    def consume(item):
        assert not conn.in_transaction
        assert conn.execute("SELECT count(*) FROM policy_audit_events").fetchone()[0] == 1
        calls.append(item.event_id)
    assert api.admit(event(ctx),consume).status == "created"
    assert calls == ["event:a"]
    error = RuntimeError("synthetic callback error")
    def fail(item):
        raise error
    with pytest.raises(RuntimeError) as caught:
        api.admit(event(ctx,event_id="event:b"),fail)
    assert caught.value is error and not conn.in_transaction
    assert conn.execute("SELECT count(*) FROM policy_audit_events").fetchone()[0] == 2


@pytest.mark.parametrize("phase", [2,3])
def test_read_epoch_changes_before_content_or_after_release_refuse(journal,phase):
    conn, ctx, _, api = journal
    api.append(event(ctx))
    calls = []
    def verify(candidate, *, bank, destination):
        calls.append(True)
        return AuditReadGrant(candidate.fingerprint(),"domain:a",bank,destination,"decision:audit",1 if len(calls)==phase else 0)
    api._verify = verify
    with bind_access_context(ctx),pytest.raises(PolicyRefusal):
        api.read(destination="channel:a")
    assert not conn.in_transaction


def test_payload_budget_and_capacity_parameters_refuse(journal):
    from mnemosyne.core import policy_audit as module
    conn, ctx, _, api = journal
    for value in (True,0,16385):
        with pytest.raises(ValueError):
            api.prepare(max_events=value)
    original = module.MAX_EVENT_BYTES
    try:
        module.MAX_EVENT_BYTES = 1
        with pytest.raises(PolicyRefusal,match="resource_limit"):
            api.append(event(ctx))
    finally:
        module.MAX_EVENT_BYTES = original
    assert conn.execute("SELECT count(*) FROM policy_audit_events").fetchone()[0] == 0


@pytest.mark.parametrize("statement", ["CREATE TABLE main.policy_audit_state", "CREATE TRIGGER main.policy_audit_no_delete",
    "INSERT INTO main.policy_audit_state", "INSERT INTO main.policy_audit_events"])
@pytest.mark.parametrize("after", [False,True])
def test_interrupted_setup_and_append_leave_no_owned_transaction(statement,after):
    class Interrupt(sqlite3.Connection):
        enabled = True
        def execute(self,sql,*args,**kwargs):
            hit = self.enabled and sql.startswith(statement)
            if hit:
                self.enabled = False
                if after:
                    super().execute(sql,*args,**kwargs)
                raise KeyboardInterrupt("synthetic interruption")
            return super().execute(sql,*args,**kwargs)
    conn = sqlite3.connect(":memory:",factory=Interrupt)
    api = PolicyAudit(conn,domain_id="domain:a",bank="bank:a",verify_read=lambda *a,**k:None)
    try:
        if statement.startswith("INSERT INTO main.policy_audit_events"):
            api.prepare()
            operation = lambda:api.append(event(context(operations={"audit:read"})))
        else:
            operation = api.prepare
        with pytest.raises(KeyboardInterrupt):
            operation()
        assert not conn.in_transaction
        if statement.startswith("INSERT INTO main.policy_audit_events"):
            assert conn.execute("SELECT count(*) FROM policy_audit_events").fetchone()[0] == 0
        else:
            assert conn.execute("SELECT count(*) FROM sqlite_master WHERE name LIKE 'policy_audit_%'").fetchone()[0] == 0
        api.prepare()
        assert api.append(event(context(operations={"audit:read"}))).status == "created"
    finally:
        conn.close()


def test_admission_does_not_run_consumer_after_uncertain_commit(tmp_path):
    class LostAck(sqlite3.Connection):
        enabled = False
        def execute(self,sql,*args,**kwargs):
            cursor = super().execute(sql,*args,**kwargs)
            if self.enabled and sql == "COMMIT":
                self.enabled = False
                raise KeyboardInterrupt("synthetic commit acknowledgment lost")
            return cursor
    conn = sqlite3.connect(tmp_path/"lost-ack.db",factory=LostAck)
    conn.execute("PRAGMA synchronous=EXTRA")
    try:
        api = PolicyAudit(conn,domain_id="domain:a",bank="bank:a",verify_read=lambda *a,**k:None)
        api.prepare()
        conn.enabled = True
        calls = []
        with pytest.raises(KeyboardInterrupt):
            api.admit(event(context(operations={"audit:read"})),lambda item:calls.append(True))
        assert not calls and not conn.in_transaction
        assert conn.execute("SELECT count(*) FROM policy_audit_events").fetchone()[0] == 1
    finally:
        conn.close()


@pytest.mark.parametrize("setting", ["memory", "sync_off", "sync_normal", "delete_full", "journal_off"])
def test_admission_refuses_nondurable_journal_without_effect(journal,setting):
    conn, ctx, _, api = journal
    if setting == "memory":
        conn = sqlite3.connect(":memory:")
        api = PolicyAudit(conn,domain_id="domain:a",bank="bank:a",verify_read=lambda *a,**k:None)
        api.prepare()
    else:
        conn.execute({"sync_off":"PRAGMA synchronous=OFF", "sync_normal":"PRAGMA synchronous=NORMAL", "delete_full":"PRAGMA synchronous=FULL",
            "journal_off":"PRAGMA journal_mode=OFF"}[setting])
    calls = []
    try:
        with pytest.raises(PolicyRefusal,match="unsupported_surface"):
            api.admit(event(ctx),lambda item:calls.append(True))
        assert not calls and conn.execute("SELECT count(*) FROM policy_audit_events").fetchone()[0] == 0
    finally:
        if setting == "memory":
            conn.close()


@pytest.mark.parametrize("name",["sqliteOther","sqliteXcache","SQLiteOther"])
def test_unrelated_sqlite_prefix_is_not_an_internal_table(name):
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute(f"CREATE TABLE {name}(value TEXT)")
        api = PolicyAudit(conn,domain_id="domain:a",bank="bank:a",verify_read=lambda *a,**k:None)
        with pytest.raises(PolicyStoreError):
            api.prepare()
        assert conn.execute("SELECT 1 FROM sqlite_master WHERE name='policy_audit_state'").fetchone() is None
        assert not conn.in_transaction
    finally:
        conn.close()
