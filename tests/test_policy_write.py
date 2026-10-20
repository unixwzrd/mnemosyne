"""Actual BEAM creation plus binding, with synthetic host decisions only."""

import asyncio
import hashlib
import os
import socket
import sqlite3
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mnemosyne.core import beam as beam_module
from mnemosyne.core.policy import PolicyRefusal, PolicySurface, RefusalReason
from mnemosyne.core.policy_read import BankReadGrant, PolicyReader
from mnemosyne.core.policy_store import PolicyStore, PolicyStoreError, RecordKind
from mnemosyne.core.policy_write import MAX_CONTENT_CHARACTERS, MemoryWriteGrant, MemoryWriteIntent, PolicyWriter
from mnemosyne.runtime_context import bind_access_context
from tests.test_policy_lexical import lexical as lexical, seed
from tests.test_policy_read import restriction


class WriteRegistry:
    def __init__(self, ctx, **policy):
        self.current = ctx.fingerprint()
        self.calls = []
        self.policy = restriction(classification_source="context", origin_context_id=ctx.context_id,
                                  origin_context_epoch=ctx.epoch, **policy)
        self.changes = {}

    def __call__(self, ctx, *, bank, destination, intent):
        self.calls.append(intent)
        if ctx.fingerprint() != self.current:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        values = dict(context_fingerprint=ctx.fingerprint(), intent_fingerprint=intent.fingerprint(), domain_id="domain:a",
                      bank=bank, destination=destination, decision_id="write:a", policy=self.policy)
        values.update(self.changes)
        return MemoryWriteGrant(**values)


@pytest.fixture
def creation(lexical):
    beam, store, ctx, *_ = lexical
    ctx = replace(ctx, channel_id="channel:source", operations={"read:bank", "recall:lexical", "create:working_memory", "create:episodic_memory"})
    registry = WriteRegistry(ctx)
    yield beam, store, ctx, registry, PolicyWriter(store, bank="bank:a", verify_context=registry)


def create(creation, text="orion gateway port", identity="new", kind=RecordKind.WORKING):
    beam, _, ctx, _, writer = creation
    with bind_access_context(ctx):
        return beam.create_authorized(text, writer=writer, record_kind=kind, record_id=identity, destination="channel:a")


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
def test_atomic_native_fts_binding_and_authorized_read(creation, kind):
    beam, store, ctx, registry, _ = creation
    content = "orion gateway port\n  exact formatting  "
    result = create(creation, content, kind=kind)
    assert result.record_id == "new" and result.transaction_state == "committed" and result.decision_id == "write:a"
    assert result.context_id == ctx.context_id and result.context_epoch == ctx.epoch
    native = beam.conn.execute(f"SELECT * FROM main.{kind.value} WHERE id='new'").fetchone()
    assert native["content"] == content and native["session_id"] == ctx.conversation_id and native["scope"] == "session"
    assert native["author_id"] == "person:a" and native["author_type"] is None and native["channel_id"] == "channel:source"
    assert datetime.fromisoformat(native["timestamp"]).utcoffset() == timezone.utc.utcoffset(None)
    assert store.get_binding(kind, "new").policy == registry.policy
    assert len(registry.calls) == 1 and registry.calls[0].content_sha256 == hashlib.sha256(content.encode()).hexdigest()
    assert not beam.conn.in_transaction and store.get_domain().mode == "prepared"
    reader = PolicyReader(store, bank="bank:a", verify_context=lambda actual, **kw: BankReadGrant(
        actual.fingerprint(), "domain:a", kw["bank"], kw["destination"], "read:a", {"person:a"}, {"tenant:a"}))
    with bind_access_context(ctx):
        hits = beam.recall_authorized_lexical("orion gateway", reader=reader, destination="channel:a").hits
    assert len(hits) == 1 and hits[0].content == content
    assert PolicyWriter.capabilities.surfaces == {PolicySurface.WRITE}
    assert content not in repr(result) and "person:a" not in repr(registry.policy)


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
def test_no_content_dedup_and_never_overwrite_existing_id(creation, kind):
    beam, *_ = creation
    create(creation, kind=kind)
    create(creation, identity="another", kind=kind)
    changes = beam.conn.total_changes
    for text in ("orion gateway port", "changed"):
        with pytest.raises(PolicyRefusal, match="access_denied"):
            create(creation, text, kind=kind)
    assert beam.conn.total_changes == changes
    assert beam.conn.execute(f"SELECT count(*) FROM main.{kind.value}").fetchone()[0] == 2


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
@pytest.mark.parametrize("bound", [False, True])
def test_existing_unbound_or_denied_target_never_disclosed(creation, kind, bound):
    beam, store, *_ = creation
    seed(creation, "new", text="private-canary", kind=kind, classification="sealed", bound=bound)
    def guard(cursor, row):
        assert "private-canary" not in row
        return sqlite3.Row(cursor, row)
    beam.conn.row_factory = guard
    with pytest.raises(PolicyRefusal, match="access_denied"):
        create(creation, kind=kind)
    binding = store.get_binding(kind, "new")
    assert (binding.policy.classification == "sealed") if bound else binding is None


@pytest.mark.parametrize("text", [None, "", " \n\t", "nul\0tail", "x" * (MAX_CONTENT_CHARACTERS + 1), "\ud800"])
def test_invalid_content_does_not_reach_verifier_or_storage(creation, text):
    changes = creation[0].conn.total_changes
    with pytest.raises(ValueError):
        create(creation, text)
    assert not creation[3].calls and creation[0].conn.total_changes == changes


@pytest.mark.parametrize("changes", [{"assurance": "unknown"}, {"projects": {"p"}}, {"banks": set()},
                                     {"destinations": set()}, {"conversation_id": None}, {"conversation_id": "other"},
                                     {"operations": {"read:bank"}}])
def test_missing_scope_never_reaches_verifier(creation, changes):
    beam, store, ctx, registry, writer = creation
    bad = replace(ctx, **changes)
    with pytest.raises(PolicyRefusal):
        create((beam, store, bad, registry, writer))
    assert not registry.calls


def test_missing_context_and_wrong_connection_refuse(creation, tmp_path):
    beam, _, _, _, writer = creation
    with pytest.raises(PolicyRefusal, match="missing_context"):
        beam.create_authorized("text", writer=writer, record_kind=RecordKind.WORKING, record_id="new", destination="channel:a")
    conn = sqlite3.connect(tmp_path / "other.db")
    try:
        other = PolicyWriter(PolicyStore(conn), bank="bank:a", verify_context=creation[3])
        with bind_access_context(creation[2]), pytest.raises(PolicyRefusal, match="access_denied"):
            beam.create_authorized("text", writer=other, record_kind=RecordKind.WORKING, record_id="new", destination="channel:a")
    finally:
        conn.close()


@pytest.mark.parametrize("changes", [{"context_fingerprint": "0" * 64}, {"intent_fingerprint": "0" * 64},
                                     {"bank": "other"}, {"destination": "other"}, {"domain_id": "other"}])
def test_request_bound_grant_mismatches_refuse(creation, changes):
    creation[3].changes = changes
    before = creation[0].conn.total_changes
    with pytest.raises(PolicyRefusal, match="access_denied"):
        create(creation)
    assert creation[0].conn.total_changes == before and not creation[0].conn.in_transaction


@pytest.mark.parametrize("changes", [{"classification_source": "manual"}, {"origin_context_id": "other"},
                                     {"origin_context_epoch": 2}, {"owner": "other"}, {"overlays": {"unsupported"}},
                                     {"classification": "sealed"}, {"compartments": {"missing"}},
                                     {"audiences": set()}, {"purposes": set()}, {"policy_version": 2}])
def test_host_policy_restrictions_must_fit_supported_context(creation, changes):
    creation[3].policy = replace(creation[3].policy, **changes)
    before = creation[0].conn.total_changes
    with pytest.raises(PolicyRefusal):
        create(creation)
    assert creation[0].conn.total_changes == before


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
def test_binding_failure_rolls_back_native_fts_and_preserves_caller(creation, kind):
    beam, store, *_ = creation
    seed(creation, "prior")
    beam.conn.execute("UPDATE working_memory SET importance=0.9 WHERE id='prior'")
    beam.conn.execute("""CREATE TEMP TRIGGER refuse_policy BEFORE INSERT ON main.policy_binding_terms
        BEGIN SELECT RAISE(ABORT,'injected'); END""")
    with pytest.raises(sqlite3.IntegrityError, match="injected"):
        create(creation, kind=kind)
    assert beam.conn.in_transaction
    assert beam.conn.execute(f"SELECT 1 FROM main.{kind.value} WHERE id='new'").fetchone() is None
    assert store.get_binding(kind, "new") is None
    fts = "fts_working" if kind is RecordKind.WORKING else "fts_episodes"
    assert beam.conn.execute(f"SELECT count(*) FROM main.{fts} WHERE {fts} MATCH 'orion'").fetchone()[0] == (1 if kind is RecordKind.WORKING else 0)
    beam.conn.rollback()
    assert beam.conn.execute("SELECT importance FROM working_memory WHERE id='prior'").fetchone()[0] == 0.5


def test_caller_success_is_pending_and_rollback_removes_everything(creation):
    beam, store, *_ = creation
    beam.conn.execute("BEGIN")
    result = create(creation)
    assert result.transaction_state == "pending" and beam.conn.in_transaction
    assert store.get_binding(RecordKind.WORKING, "new") is not None
    beam.conn.rollback()
    assert store.get_binding(RecordKind.WORKING, "new") is None
    assert beam.conn.execute("SELECT count(*) FROM working_memory").fetchone()[0] == 0
    assert beam.conn.execute("SELECT count(*) FROM fts_working").fetchone()[0] == 0


@pytest.mark.parametrize("fault", ["BEGIN", "COMMIT"])
def test_transaction_permission_failures_leave_no_owned_transaction(creation, fault):
    beam = creation[0]
    def authorize(action, first, second, database, source):
        return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_TRANSACTION and first == fault else sqlite3.SQLITE_OK
    beam.conn.set_authorizer(authorize)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            create(creation)
    finally:
        beam.conn.set_authorizer(lambda *args: sqlite3.SQLITE_OK)
    assert not beam.conn.in_transaction
    assert beam.conn.execute("SELECT count(*) FROM working_memory").fetchone()[0] == 0
    assert beam.conn.execute("SELECT count(*) FROM policy_bindings").fetchone()[0] == 0


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
def test_missing_or_changed_fts_trigger_refuses(creation, kind):
    beam = creation[0]
    trigger = "wm_ai" if kind is RecordKind.WORKING else "em_ai"
    beam.conn.execute(f"DROP TRIGGER {trigger}")
    beam.conn.commit()
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        create(creation, kind=kind)
    assert beam.conn.execute(f"SELECT count(*) FROM {kind.value}").fetchone()[0] == 0


def test_no_legacy_enrichment_provider_cache_or_other_table_mutation(creation, monkeypatch):
    beam = creation[0]
    attempts = []
    def forbidden(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("unsupported side effect")
    for name in ("remember", "remember_batch", "_invalidate_query_cache_after_remember_commit"):
        monkeypatch.setattr(beam_module.BeamMemory, name, forbidden)
    for name in ("embed_query", "embed", "_get_model", "_embed_api"):
        monkeypatch.setattr(beam_module._embeddings, name, forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    statements = []
    beam.conn.set_trace_callback(statements.append)
    create(creation)
    assert not attempts
    assert not any("UPDATE " in s.upper() or "DELETE " in s.upper() or "CREATE " in s.upper() for s in statements)
    assert beam.conn.execute("SELECT count(*) FROM memory_embeddings").fetchone()[0] == 0


def test_grant_replay_intent_mutation_and_epoch_change_refuse(creation):
    beam, store, ctx, registry, _ = creation
    seen = []
    def cached(actual, **kw):
        if not seen:
            seen.append(registry(actual, **kw))
        return seen[0]
    writer = PolicyWriter(store, bank="bank:a", verify_context=cached)
    current = (beam, store, ctx, registry, writer)
    create(current)
    for changed in ("different-content",):
        with pytest.raises(PolicyRefusal, match="access_denied"):
            create(current, changed, identity="other")
    registry.current = "0" * 64
    with pytest.raises(PolicyRefusal, match="access_denied"):
        create(creation, identity="another")


def test_verifier_failure_async_and_wrong_result_refuse(creation):
    beam, store, ctx, registry, _ = creation
    def failing(*args, **kwargs):
        raise RuntimeError("private verifier detail")
    async def async_result():
        return None
    for verifier, reason in ((failing, "context_unavailable"), (lambda *a, **k: async_result(), "unsupported_surface"),
                             (lambda *a, **k: {}, "access_denied")):
        writer = PolicyWriter(store, bank="bank:a", verify_context=verifier)
        with pytest.raises(PolicyRefusal, match=reason):
            create((beam, store, ctx, registry, writer))


def test_restricted_source_floor_is_host_authority_not_clearance(creation):
    # A clearance ceiling is not the source classification. The verifier, not
    # a guessed ceiling-to-label conversion, selects the input restriction.
    creation[3].policy = replace(creation[3].policy, classification="open")
    create(creation)
    assert creation[1].get_binding(RecordKind.WORKING, "new").policy.classification == "open"


def test_intent_is_immutable_bounded_and_fingerprint_sensitive():
    base = MemoryWriteIntent(RecordKind.WORKING, "id", "a" * 64, 1, "conversation")
    assert len(base.fingerprint()) == 64 and "conversation" not in repr(base)
    for changes in ({"record_kind": RecordKind.EPISODIC}, {"record_id": "other"}, {"content_sha256": "b" * 64},
                    {"content_characters": 2}, {"conversation_id": "other"}):
        assert replace(base, **changes).fingerprint() != base.fingerprint()
    for changes in ({"record_kind": RecordKind.CANONICAL}, {"content_sha256": "bad"}, {"content_characters": 0},
                    {"content_characters": True}, {"content_characters": MAX_CONTENT_CHARACTERS + 1}):
        with pytest.raises(ValueError):
            replace(base, **changes)


def test_async_context_binding_and_scope_do_not_cross(creation):
    beam, store, ctx, registry, writer = creation
    other = replace(ctx, context_id="ctx:b", conversation_id="other")
    async def exercise():
        async def allowed(identity):
            with bind_access_context(ctx):
                await asyncio.sleep(0)
                return beam.create_authorized("text", writer=writer, record_kind=RecordKind.WORKING,
                                               record_id=identity, destination="channel:a").record_id
        async def denied():
            with bind_access_context(other):
                await asyncio.sleep(0)
                with pytest.raises(PolicyRefusal, match="access_denied"):
                    beam.create_authorized("text", writer=writer, record_kind=RecordKind.WORKING,
                                           record_id="denied", destination="channel:a")
        assert await asyncio.gather(allowed("a"), denied(), allowed("b")) == ["a", None, "b"]
    asyncio.run(exercise())
    assert store.get_binding(RecordKind.WORKING, "denied") is None
    assert len(registry.calls) == 2


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
def test_process_abort_before_commit_recovers_prior_store(creation, kind):
    beam, store, *_ = creation
    seed(creation, "prior")
    code = '''
import os,sys
from pathlib import Path
from mnemosyne.core.beam import BeamMemory
from mnemosyne.core.policy_store import PolicyStore,RecordKind
from mnemosyne.core.policy_write import PolicyWriter
from mnemosyne.runtime_context import bind_access_context
from tests.test_policy_read import context
from tests.test_policy_write import WriteRegistry
beam=BeamMemory(session_id="conversation:a",db_path=Path(sys.argv[1]))
store=PolicyStore(beam.conn)
ctx=context(conversation_id=beam.session_id,operations={"create:"+sys.argv[2]})
registry=WriteRegistry(ctx)
writer=PolicyWriter(store,bank="bank:a",verify_context=registry)
original=store.bind
def crash(*args,**kwargs):
    original(*args,**kwargs)
    os._exit(23)
store.bind=crash
with bind_access_context(ctx):
    beam.create_authorized("interrupted text",writer=writer,record_kind=RecordKind(sys.argv[2]),record_id="crash",destination="channel:a")
'''
    repository = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, "-c", code, str(beam.db_path), kind.value], cwd=repository,
                            env={**os.environ, "PYTHONPATH": str(repository)}, capture_output=True, text=True, timeout=20)
    assert result.returncode == 23, result.stderr
    assert beam.conn.execute("SELECT content FROM working_memory WHERE id='prior'").fetchone()[0] == "orion gateway port"
    assert beam.conn.execute(f"SELECT 1 FROM {kind.value} WHERE id='crash'").fetchone() is None
    assert store.get_binding(kind, "crash") is None
    assert beam.conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
def test_native_or_binding_postconditions_refuse_unexpected_mutation(creation, kind):
    beam = creation[0]
    beam.conn.execute(f"""CREATE TEMP TRIGGER change_new AFTER INSERT ON main.policy_bindings BEGIN
        UPDATE {kind.value} SET scope='global' WHERE id=new.record_id; END""")
    beam.conn.commit()
    with pytest.raises(PolicyStoreError, match="incompatible"):
        create(creation, kind=kind)
    assert beam.conn.execute(f"SELECT count(*) FROM {kind.value}").fetchone()[0] == 0
    assert creation[1].get_binding(kind, "new") is None


def test_policy_schema_and_native_schema_refusal(creation):
    beam = creation[0]
    beam.conn.execute("DROP INDEX idx_policy_terms_reverse")
    with pytest.raises(PolicyStoreError, match="incompatible"):
        create(creation)
    assert beam.conn.execute("SELECT count(*) FROM working_memory").fetchone()[0] == 0


@pytest.mark.parametrize("kind", [RecordKind.CANONICAL, RecordKind.SOURCE_REVISION, "working_memory", None, {}])
def test_unsupported_kind_never_reaches_verifier(creation, kind):
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        create(creation, kind=kind)
    assert not creation[3].calls


@pytest.mark.parametrize("mode", [True, False])
def test_explicit_autocommit_modes_preserve_ownership(creation, mode):
    beam, store, *_ = creation
    if not hasattr(beam.conn, "autocommit"):
        pytest.skip("explicit sqlite3 autocommit parameter requires Python 3.12")
    beam.conn.autocommit = mode
    try:
        result = create(creation)
        assert result.transaction_state == ("committed" if mode else "pending")
        if mode:
            assert not beam.conn.in_transaction and store.get_binding(RecordKind.WORKING, "new")
        else:
            assert beam.conn.in_transaction
            beam.conn.rollback()
            assert store.get_binding(RecordKind.WORKING, "new") is None
    finally:
        beam.conn.autocommit = sqlite3.LEGACY_TRANSACTION_CONTROL


def test_temp_native_and_fts_shadows_do_not_redirect_write(creation):
    beam, *_ = creation
    for name in ("working_memory", "fts_working", "policy_bindings"):
        beam.conn.execute(f"CREATE TEMP TABLE {name}(id TEXT,content TEXT)")
    beam.conn.commit()
    create(creation)
    for name in ("working_memory", "fts_working", "policy_bindings"):
        assert beam.conn.execute(f"SELECT count(*) FROM temp.{name}").fetchone()[0] == 0
    assert beam.conn.execute("SELECT count(*) FROM main.working_memory").fetchone()[0] == 1


def test_one_shot_cancel_before_creation_preserves_owner_handler(creation):
    beam = creation[0]
    calls = []
    def cancel_once():
        calls.append(True)
        return int(len(calls) == 1)
    beam.conn.set_progress_handler(cancel_once, 1)
    try:
        with pytest.raises(sqlite3.OperationalError, match="interrupted"):
            create(creation)
        assert not beam.conn.in_transaction
        before = len(calls)
        assert beam.conn.execute("SELECT count(*) FROM working_memory").fetchone()[0] == 0
        assert len(calls) > before
    finally:
        beam.conn.set_progress_handler(None, 1)


def test_concurrent_independent_connections_create_one_bound_record(creation):
    beam, _, ctx, *_ = creation
    ready = threading.Barrier(2)
    def attempt():
        other = beam_module.BeamMemory(session_id=beam.session_id, db_path=beam.db_path)
        try:
            writer = PolicyWriter(PolicyStore(other.conn), bank="bank:a", verify_context=WriteRegistry(ctx))
            ready.wait(timeout=10)
            with bind_access_context(ctx):
                try:
                    return other.create_authorized("same input", writer=writer, record_kind=RecordKind.WORKING,
                                                    record_id="contended", destination="channel:a").transaction_state
                except PolicyRefusal as error:
                    return error.reason.value
        finally:
            other.conn.close()
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = [future.result(timeout=20) for future in [workers.submit(attempt), workers.submit(attempt)]]
    assert sorted(results) == ["access_denied", "committed"]
    assert beam.conn.execute("SELECT count(*) FROM working_memory WHERE id='contended'").fetchone()[0] == 1
    assert beam.conn.execute("SELECT count(*) FROM policy_bindings WHERE record_id='contended'").fetchone()[0] == 1


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
def test_orphan_binding_cannot_be_reused_for_new_content(creation, kind):
    beam, store, *_ = creation
    seed(creation, "new", kind=kind)
    beam.conn.execute(f"DELETE FROM main.{kind.value} WHERE id='new'")
    beam.conn.commit()
    changes = beam.conn.total_changes
    with pytest.raises(PolicyRefusal, match="access_denied"):
        create(creation, kind=kind)
    assert beam.conn.total_changes == changes and store.get_binding(kind, "new")
    assert beam.conn.execute(f"SELECT 1 FROM main.{kind.value} WHERE id='new'").fetchone() is None


def test_busy_writer_refuses_without_partial_creation_and_retry_is_fresh(creation):
    beam = creation[0]
    other = sqlite3.connect(str(beam.db_path))
    beam.conn.execute("PRAGMA busy_timeout=1")
    try:
        other.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            create(creation)
        assert not beam.conn.in_transaction
        assert beam.conn.execute("SELECT count(*) FROM working_memory").fetchone()[0] == 0
    finally:
        other.rollback()
        other.close()
    assert create(creation).transaction_state == "committed"
    assert len(creation[3].calls) == 2


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
@pytest.mark.parametrize("layout", ["unindexed", "contentless", "wrong-content", "wrong-rowid", "tokenizer"])
def test_changed_fts_configuration_refuses_without_native_or_policy_write(creation, kind, layout):
    beam, store, ctx, *_ = creation
    fts = "fts_working" if kind is RecordKind.WORKING else "fts_episodes"
    columns = "id UNINDEXED,content" if kind is RecordKind.WORKING else "content"
    if layout == "unindexed":
        columns += " UNINDEXED"
    if kind is RecordKind.EPISODIC:
        target = "" if layout == "contentless" else "missing_table" if layout == "wrong-content" else "episodic_memory"
        rowid = "other_id" if layout == "wrong-rowid" else "rowid"
        columns += f",content='{target}',content_rowid='{rowid}'"
    elif layout in ("contentless", "wrong-content"):
        columns += ",content=''" if layout == "contentless" else ",content='missing_table'"
    elif layout == "wrong-rowid":
        columns += ",content_rowid='other_id'"
    if layout == "tokenizer":
        columns += ",tokenize='porter'"
    beam.conn.execute(f"DROP TABLE main.{fts}")
    beam.conn.execute(f"CREATE VIRTUAL TABLE main.{fts} USING fts5({columns})")
    beam.conn.commit()
    changes = beam.conn.total_changes
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        create(creation, kind=kind)
    assert beam.conn.total_changes == changes and not beam.conn.in_transaction
    assert beam.conn.execute(f"SELECT count(*) FROM main.{kind.value}").fetchone()[0] == 0
    assert store.get_binding(kind, "new") is None
    reader = PolicyReader(store, bank="bank:a", verify_context=lambda actual, **kw: BankReadGrant(
        actual.fingerprint(), "domain:a", kw["bank"], kw["destination"], "read:a", {"person:a"}, {"tenant:a"}))
    with bind_access_context(ctx), pytest.raises(PolicyRefusal, match="unsupported_surface"):
        beam.recall_authorized_lexical("the and", reader=reader, destination="channel:a")


@pytest.mark.parametrize("target,rowid", [("epi\u017fodic_memory", "rowid"), ("ep\u0130sodic_memory", "rowid"),
                                          ("episodic_memory", "row\u0131d")])
def test_unicode_casefold_cannot_alias_native_fts_mapping(creation, target, rowid):
    beam = creation[0]
    beam.conn.execute("DROP TABLE main.fts_episodes")
    beam.conn.execute(f"CREATE VIRTUAL TABLE main.fts_episodes USING fts5(content,content='{target}',content_rowid='{rowid}')")
    beam.conn.commit()
    changes = beam.conn.total_changes
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        create(creation, kind=RecordKind.EPISODIC)
    assert beam.conn.total_changes == changes
    assert beam.conn.execute("SELECT count(*) FROM episodic_memory").fetchone()[0] == 0
