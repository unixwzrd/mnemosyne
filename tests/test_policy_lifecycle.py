"""Disposable v2 lineage/quarantine and explicit cross-path request epochs."""

from dataclasses import replace
import importlib.util
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from mnemosyne.core import beam as beam_module
from mnemosyne.core.policy import PolicyRefusal
from mnemosyne.core.policy_lifecycle import PolicyLifecycle, PolicyRecordRef, QuarantineReason
from mnemosyne.core.policy_read import PolicyReader
from mnemosyne.core.policy_store import PolicyStore, PolicyStoreError, RecordKind
from mnemosyne.core.policy_write import PolicyWriter
from mnemosyne.runtime_context import bind_access_context
from tests.test_policy_lexical import lexical as lexical, seed
from tests.test_policy_sources import fixture as fixture, source, context as source_context
from tests.test_policy_vector import vector as vector, add
from tests.test_policy_int8 import int8 as int8, add as add_int8
from tests.test_policy_write import creation as creation, create
from tests.test_source_expansion import Host


def ref(identity, kind=RecordKind.WORKING):
    return PolicyRecordRef(kind, identity)


@pytest.fixture
def lifecycle(vector):
    beam, store, ctx, registry, _ = vector
    ctx = replace(ctx, operations={"read:bank", "recall:lexical", "recall:vector", "recall:hybrid"})
    registry.register(ctx)
    catalog = PolicyLifecycle(store)
    catalog.prepare()

    def verify(context, **intent):
        return replace(registry(context, **intent), lifecycle_epoch=catalog.epoch())

    return beam, store, ctx, registry, PolicyReader(store, bank="bank:a", verify_context=verify), catalog


def child(fx, identity, parents, kind=RecordKind.WORKING):
    add(fx, identity, kind=kind, bound=False)
    return fx[5].bind_derivative(ref(identity, kind), parents)


def recall(fx, mode):
    beam, _, ctx, _, reader, _ = fx
    with bind_access_context(ctx):
        if mode == "direct":
            return [hit for identity in ("root", "child", "grandchild", "other") if (hit := reader.get(RecordKind.WORKING, identity, destination="channel:a"))]
        if mode == "candidates":
            return reader.candidate_ids(RecordKind.WORKING, destination="channel:a")
        if mode == "lexical":
            return beam.recall_authorized_lexical("orion gateway", reader=reader, destination="channel:a").hits
        options = dict(embedding_model=beam_module._embeddings._DEFAULT_MODEL, reader=reader, destination="channel:a")
        if mode == "vector":
            return beam.recall_authorized_vector((1.,0.,0.,0.), **options).hits
        return beam.recall_authorized_hybrid("orion gateway", (1.,0.,0.,0.), **options).hits


def test_explicit_upgrade_reopen_idempotence_preserves_native_and_legacy_marker(vector):
    beam, store, *_ = vector
    add(vector, "root")
    native = tuple(map(tuple, beam.conn.execute("SELECT id,content FROM working_memory")))
    catalog = PolicyLifecycle(store)
    assert store.get_domain().schema_version == 1
    assert catalog.prepare().status == "created"
    assert catalog.prepare().status == "unchanged"
    assert catalog.epoch() == 0 and store.get_domain().schema_version == 2
    assert store.get_domain().mode == "prepared"
    conn = sqlite3.connect(beam.db_path)
    try:
        assert PolicyLifecycle(PolicyStore(conn)).epoch() == 0
        assert tuple(conn.execute("SELECT id,content FROM working_memory")) == native
    finally:
        conn.close()


@pytest.mark.parametrize("mode", ["direct", "candidates", "lexical", "vector", "hybrid"])
@pytest.mark.parametrize("reason", list(QuarantineReason))
def test_transitive_quarantine_precedes_every_supported_candidate_consumer(lifecycle, mode, reason):
    beam, store, _, _, _, catalog = lifecycle
    add(lifecycle, "root")
    child(lifecycle, "child", [ref("root")])
    child(lifecycle, "grandchild", [ref("child")])
    add(lifecycle, "other", text="orion gateway other")
    before = {h.record_id for h in recall(lifecycle, mode)}
    assert before == {"root", "child", "grandchild", "other"}
    native = tuple(map(tuple, beam.conn.execute("SELECT id,content FROM working_memory ORDER BY id")))
    result = catalog.quarantine(ref("root"), reason)
    assert (result.status, result.epoch, result.transaction_state) == ("quarantined", 1, "committed")
    assert catalog.quarantine(ref("root"), reason).status == "unchanged" and catalog.epoch() == 1
    assert {h.record_id for h in recall(lifecycle, mode)} == {"other"}
    assert all(h.lifecycle_epoch == 1 for h in recall(lifecycle, mode))
    assert tuple(map(tuple, beam.conn.execute("SELECT id,content FROM working_memory ORDER BY id"))) == native
    with bind_access_context(lifecycle[2]):
        sql, params = lifecycle[4]._selection(RecordKind.WORKING, lifecycle[2], replace(lifecycle[3](lifecycle[2], bank="bank:a", destination="channel:a"), lifecycle_epoch=1))
    plan = beam.conn.execute("EXPLAIN QUERY PLAN " + sql + " SELECT * FROM eligible", params).fetchall()
    assert any("SEARCH q USING" in row[3] for row in plan)


def test_exact_lineage_retry_and_multi_parent_dag(lifecycle):
    beam, store, _, _, _, catalog = lifecycle
    add(lifecycle, "root")
    add(lifecycle, "other")
    first = child(lifecycle, "child", [ref("root"), ref("other")])
    assert first.status == "created"
    assert catalog.bind_derivative(ref("child"), [ref("other"), ref("root")]).status == "unchanged"
    assert beam.conn.execute("SELECT count(*) FROM policy_lineage_edges").fetchone()[0] == 2
    assert store.get_binding(RecordKind.WORKING, "child").policy.classification_source == "external"
    with pytest.raises(PolicyStoreError, match="incompatible"):
        catalog.bind_derivative(ref("child"), [ref("root")])
    catalog.quarantine(ref("other"))
    assert {h.record_id for h in recall(lifecycle, "lexical")} == {"root"}
    with pytest.raises(PolicyRefusal, match="access_denied"):
        child(lifecycle, "late", [ref("root"), ref("other")])
    assert store.get_binding(RecordKind.WORKING, "late") is None


@pytest.mark.parametrize("parents", [[], [ref("root"), ref("root")], [ref("child")], [ref("missing")], [ref(str(i)) for i in range(129)]])
def test_invalid_parent_manifest_never_publishes_binding(lifecycle, parents):
    _, store, _, _, _, _ = lifecycle
    add(lifecycle, "root")
    with pytest.raises((ValueError, PolicyRefusal)):
        child(lifecycle, "child", parents)
    assert store.get_binding(RecordKind.WORKING, "child") is None


def test_prebound_adoption_and_cycle_refuse(lifecycle):
    add(lifecycle, "root")
    child(lifecycle, "child", [ref("root")])
    with pytest.raises(PolicyRefusal, match="access_denied"):
        lifecycle[5].bind_derivative(ref("root"), [ref("child")])


@pytest.mark.parametrize("object_name", ["policy_lifecycle_state", "policy_lineage", "policy_lineage_edges", "policy_quarantine", "idx_policy_lineage_parent"])
def test_incomplete_v2_refuses_every_read_instead_of_downgrading(lifecycle, object_name):
    conn = lifecycle[0].conn
    conn.execute(f"DROP {'INDEX' if object_name.startswith('idx_') else 'TABLE'} main.{object_name}")
    conn.commit()
    with pytest.raises((PolicyStoreError, PolicyRefusal), match="incompatible|context_unavailable"):
        recall(lifecycle, "direct")
    with pytest.raises(PolicyStoreError, match="incompatible"):
        lifecycle[5].prepare()


def test_marker_downgrade_and_partial_v1_refuse(vector):
    conn = vector[0].conn
    conn.execute("CREATE TABLE policy_lineage(binding_id TEXT)")
    conn.commit()
    with pytest.raises(PolicyStoreError, match="incompatible"):
        vector[1].get_domain()
    conn.execute("DROP TABLE policy_lineage")
    conn.commit()
    catalog = PolicyLifecycle(vector[1])
    catalog.prepare()
    conn.execute("UPDATE policy_store_state SET schema_version=1")
    conn.commit()
    with pytest.raises(PolicyStoreError, match="incompatible"):
        catalog.epoch()


def test_upgrade_lineage_and_quarantine_keep_caller_transaction_owned(vector):
    beam, store, *_ = vector
    add(vector, "root")
    beam.conn.execute("UPDATE working_memory SET importance=.9 WHERE id='root'")
    catalog = PolicyLifecycle(store)
    assert catalog.prepare().transaction_state == "pending"
    assert catalog.quarantine(ref("root")).transaction_state == "pending"
    assert beam.conn.in_transaction
    beam.conn.rollback()
    assert store.get_domain().schema_version == 1
    assert not beam.conn.execute("SELECT 1 FROM sqlite_master WHERE name='policy_quarantine'").fetchone()
    catalog.prepare()
    seed(vector, "child", bound=False)
    beam.conn.execute("UPDATE working_memory SET importance=.9 WHERE id='root'")
    assert catalog.bind_derivative(ref("child"), [ref("root")]).transaction_state == "pending"
    beam.conn.rollback()
    assert store.get_binding(RecordKind.WORKING, "child") is None
    assert catalog.epoch() == 0


@pytest.mark.parametrize("stage", ["CREATE TABLE main.policy_lineage", "CREATE INDEX main.idx_policy_lineage_parent", "UPDATE main.policy_store_state", "COMMIT"])
def test_upgrade_interruption_preserves_v1_and_is_retryable(tmp_path, stage):
    class Failure(sqlite3.Connection):
        fail = False

        def execute(self, sql, parameters=()):
            if self.fail and sql.startswith(stage):
                raise KeyboardInterrupt("synthetic upgrade interruption")
            return super().execute(sql, parameters)

    conn = sqlite3.connect(tmp_path / "upgrade.db", factory=Failure)
    try:
        store = PolicyStore(conn)
        store.prepare("domain:a")
        catalog = PolicyLifecycle(store)
        conn.fail = True
        with pytest.raises(KeyboardInterrupt):
            catalog.prepare()
        assert not conn.in_transaction and store.get_domain().schema_version == 1
        conn.fail = False
        assert catalog.prepare().status == "created"
    finally:
        conn.close()


@pytest.mark.parametrize("mode", ["direct", "lexical", "vector", "hybrid"])
@pytest.mark.parametrize("epoch", [None, 1])
def test_missing_or_stale_host_epoch_refuses_before_content(lifecycle, mode, epoch):
    add(lifecycle, "root")
    beam, store, ctx, registry, _, catalog = lifecycle
    reader = PolicyReader(store, bank="bank:a", verify_context=lambda c, **kw: replace(registry(c, **kw), lifecycle_epoch=epoch))
    fx = (beam, store, ctx, registry, reader, catalog)
    with pytest.raises(PolicyRefusal, match="access_denied"):
        recall(fx, mode)


@pytest.mark.parametrize("mode", ["direct", "lexical", "vector", "hybrid"])
def test_epoch_change_at_output_refuses_and_clears_completed_payload_frames(lifecycle, mode):
    beam, store, ctx, registry, _, catalog = lifecycle
    add(lifecycle, "root", text="orion gateway LATE-REVOKED-CANARY")
    changes = []
    other = sqlite3.connect(beam.db_path)
    beam.conn.execute("PRAGMA journal_mode=WAL")

    def verify(context, **intent):
        # The trace below runs once native content has been selected. A fresh
        # independent authority reads current committed epoch, not our snapshot.
        epoch = other.execute("SELECT epoch FROM policy_lifecycle_state").fetchone()[0]
        return replace(registry(context, **intent), lifecycle_epoch=epoch)

    def revoke(sql):
        if not changes and "THEN n.content" in sql:
            changes.append(True)
            PolicyLifecycle(PolicyStore(other)).quarantine(ref("root"))

    if mode == "direct":
        needle = ",n.content"
        def revoke(sql):
            if not changes and needle in sql:
                changes.append(True)
                PolicyLifecycle(PolicyStore(other)).quarantine(ref("root"))

    beam.conn.set_trace_callback(revoke)
    reader = PolicyReader(store, bank="bank:a", verify_context=verify)
    try:
        with pytest.raises(PolicyRefusal, match="access_denied") as caught:
            recall((beam,store,ctx,registry,reader,catalog), mode)
        assert changes and not beam.conn.in_transaction
        tb = caught.value.__traceback__
        while tb:
            if tb.tb_frame.f_code.co_filename.endswith(("policy_read.py", "policy_lexical.py", "policy_vector.py", "policy_hybrid.py")):
                assert "LATE-REVOKED-CANARY" not in str(tb.tb_frame.f_locals)
            tb = tb.tb_next
    finally:
        beam.conn.set_trace_callback(None)
        other.close()


def test_stale_caller_wal_snapshot_rejects_fresh_authority_epoch(lifecycle):
    beam, store, ctx, registry, _, catalog = lifecycle
    add(lifecycle, "root")
    beam.conn.execute("PRAGMA journal_mode=WAL")
    other = sqlite3.connect(beam.db_path)
    try:
        beam.conn.execute("BEGIN")
        beam.conn.execute("SELECT content FROM working_memory").fetchall()
        PolicyLifecycle(PolicyStore(other)).quarantine(ref("root"))
        reader = PolicyReader(store, bank="bank:a", verify_context=lambda c, **kw: replace(registry(c, **kw),
            lifecycle_epoch=other.execute("SELECT epoch FROM policy_lifecycle_state").fetchone()[0]))
        with bind_access_context(ctx), pytest.raises(PolicyRefusal, match="access_denied"):
            reader.get(RecordKind.WORKING, "root", destination="channel:a")
        assert beam.conn.in_transaction
        beam.conn.rollback()
    finally:
        other.close()


def test_source_metadata_and_expansion_refuse_quarantined_revision(fixture, tmp_path):
    media, store, registry, _ = fixture
    identity = source(fixture)
    catalog = PolicyLifecycle(store)
    catalog.prepare()
    reader = PolicyReader(store, bank="bank:a", verify_context=lambda c, **kw: replace(registry(c, **kw), lifecycle_epoch=catalog.epoch()))
    with bind_access_context(source_context()):
        assert reader.get_source_revision(identity, destination="channel:a").lifecycle_epoch == 0
        catalog.quarantine(ref(identity, RecordKind.SOURCE_REVISION))
        assert reader.get_source_revision(identity, destination="channel:a") is None
    host = Host(tmp_path)
    try:
        lifecycle = PolicyLifecycle(host.store)
        lifecycle.prepare()
        original = host.metadata
        host.reader._verify = lambda c, **kw: replace(original(c, **kw), lifecycle_epoch=lifecycle.epoch())
        assert host.expand().content == host.data
        lifecycle.quarantine(ref(host.identity, RecordKind.SOURCE_REVISION))
        host.opens.clear()
        with pytest.raises(PolicyRefusal):
            host.expand()
        assert host.opens == []
    finally:
        host.media.conn.close()


@pytest.mark.parametrize("late_revoke", [False, True])
def test_v2_creation_requires_fresh_epoch_and_rolls_back_late_revocation(creation, late_revoke):
    beam, store, ctx, registry, _ = creation
    catalog = PolicyLifecycle(store)
    catalog.prepare()
    calls = []

    def verify(c, **kw):
        calls.append(True)
        return replace(registry(c, **kw), lifecycle_epoch=1 if late_revoke and len(calls) == 2 else catalog.epoch())

    writer = PolicyWriter(store, bank="bank:a", verify_context=verify)
    if late_revoke:
        with pytest.raises(PolicyRefusal, match="access_denied"):
            create((beam,store,ctx,registry,writer))
        assert store.get_binding(RecordKind.WORKING, "new") is None
        assert not beam.conn.execute("SELECT 1 FROM working_memory WHERE id='new'").fetchone()
    else:
        result = create((beam,store,ctx,registry,writer))
        assert result.lifecycle_epoch == 0
    assert len(calls) == 2 and not beam.conn.in_transaction


def test_older_explicit_policy_catalog_refuses_v2(lifecycle, tmp_path):
    repo = Path(__file__).resolve().parents[1]
    source = subprocess.run(["git", "show", "10d0819:mnemosyne/core/policy_store.py"], cwd=repo, capture_output=True, check=True, text=True).stdout
    path = tmp_path / "old_policy_store.py"
    path.write_text(source)
    name = "mnemosyne.core._p3b_old_policy_store"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
        with pytest.raises(module.PolicyStoreError, match="incompatible"):
            module.PolicyStore(lifecycle[0].conn).get_domain()
    finally:
        sys.modules.pop(name)


@pytest.mark.parametrize("operation", ["lineage", "quarantine"])
@pytest.mark.parametrize("stage", ["rows", "state", "commit"])
@pytest.mark.parametrize("caller_owned", [False, True])
def test_partial_lifecycle_mutation_rolls_back_only_its_own_work(lifecycle, operation, stage, caller_owned):
    beam, store, *_ = lifecycle
    add(lifecycle, "root")
    child(lifecycle, "previous", [ref("root")])
    add(lifecycle, "new", bound=False)
    error = KeyboardInterrupt("synthetic lifecycle cancellation")

    class Failure(sqlite3.Connection):
        fail = False

        def execute(self, sql, parameters=()):
            if self.fail and ((stage == "commit" and sql == "COMMIT") or (stage == "state" and
                ((operation == "quarantine" and sql.startswith("UPDATE main.policy_lifecycle_state")) or
                 (operation == "lineage" and sql.startswith("INSERT INTO main.policy_lineage VALUES"))))):
                raise error
            return super().execute(sql, parameters)

        def executemany(self, sql, parameters):
            if self.fail and stage == "rows" and sql.startswith("INSERT INTO main.policy_" + ("lineage_edges" if operation == "lineage" else "quarantine")):
                super().execute(sql, next(iter(parameters)))
                raise error
            return super().executemany(sql, parameters)

    conn = sqlite3.connect(beam.db_path, factory=Failure)
    try:
        catalog = PolicyLifecycle(PolicyStore(conn))
        if caller_owned:
            conn.execute("UPDATE working_memory SET importance=.9 WHERE id='root'")
        if caller_owned and stage == "commit":
            # A caller-owned mutation has no internal COMMIT to interrupt.
            conn.fail = True
            result = catalog.bind_derivative(ref("new"), [ref("root")]) if operation == "lineage" else catalog.quarantine(ref("root"))
            assert result.transaction_state == "pending" and conn.in_transaction
            conn.rollback()
        else:
            conn.fail = True
            with pytest.raises(KeyboardInterrupt) as caught:
                if operation == "lineage":
                    catalog.bind_derivative(ref("new"), [ref("root")])
                else:
                    catalog.quarantine(ref("root"))
            assert caught.value is error and conn.in_transaction == caller_owned
            if caller_owned:
                assert conn.execute("SELECT importance FROM working_memory WHERE id='root'").fetchone()[0] == .9
            conn.fail = False
            conn.rollback()
        assert catalog.epoch() == 0
        assert conn.execute("SELECT count(*) FROM policy_quarantine").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM policy_lineage").fetchone()[0] == 1
        assert store.get_binding(RecordKind.WORKING, "new") is None
    finally:
        conn.close()


def test_graph_budget_and_epoch_exhaustion_refuse_atomically(lifecycle, monkeypatch):
    import mnemosyne.core.policy_lifecycle as module
    add(lifecycle, "root")
    monkeypatch.setattr(module, "MAX_DERIVATIVES", 1)
    child(lifecycle, "first", [ref("root")])
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        child(lifecycle, "second", [ref("root")])
    assert lifecycle[1].get_binding(RecordKind.WORKING, "second") is None
    conn = lifecycle[0].conn
    conn.execute("UPDATE policy_lifecycle_state SET epoch=?", (2**63-1,))
    conn.commit()
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        lifecycle[5].quarantine(ref("root"))
    assert conn.execute("SELECT count(*) FROM policy_quarantine").fetchone()[0] == 0


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
def test_quarantined_vector_blob_and_text_never_enter_python_consumers(lifecycle, kind, monkeypatch):
    import struct
    add(lifecycle, "root", (.8,.6,0.,0.), kind=kind, text="QUARANTINE-CANARY-orion gateway")
    add(lifecycle, "allowed", kind=kind)
    lifecycle[5].quarantine(ref("root", kind))
    denied = struct.pack("4f", .8,.6,0.,0.)
    original = beam_module._vec_float32_blob_cosine

    def score(query, blob):
        assert blob != denied
        return original(query, blob)

    def guard(cursor, row):
        assert denied not in row and "QUARANTINE-CANARY-orion gateway" not in row
        return sqlite3.Row(cursor, row)

    lifecycle[0].conn.row_factory = guard
    monkeypatch.setattr(beam_module, "_vec_float32_blob_cosine", score)
    assert [h.record_id for h in recall(lifecycle, "vector")] == ["allowed"]


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
def test_native_int8_quarantine_excludes_parent_and_derivative_before_scoring(int8, kind, monkeypatch):
    beam, store, ctx, registry, _ = int8
    catalog = PolicyLifecycle(store)
    catalog.prepare()
    add_int8(int8, "root", (.8,.6,0.,0.), kind=kind)
    add_int8(int8, "child", (.6,.8,0.,0.), kind=kind, bound=False)
    catalog.bind_derivative(ref("child", kind), [ref("root", kind)])
    add_int8(int8, "allowed", kind=kind)
    catalog.quarantine(ref("root", kind))
    reader = PolicyReader(store, bank="bank:a", verify_context=lambda c, **kw: replace(registry(c, **kw), lifecycle_epoch=catalog.epoch()))
    original = beam_module._vec_int8_blob_cosine
    calls = []

    def score(query, blob):
        calls.append(blob)
        return original(query, blob)

    monkeypatch.setattr(beam_module, "_vec_int8_blob_cosine", score)
    hits = recall((beam,store,ctx,registry,reader,catalog), "hybrid")
    assert [h.record_id for h in hits] == ["allowed"] and len(calls) == 1


def test_v2_outputs_bind_the_final_fresh_decision(lifecycle):
    beam, store, ctx, registry, _, catalog = lifecycle
    add(lifecycle, "root")
    calls = []

    def verify(c, **kw):
        calls.append(True)
        return replace(registry(c, **kw), decision_id=f"lease:{len(calls)}", lifecycle_epoch=catalog.epoch())

    reader = PolicyReader(store, bank="bank:a", verify_context=verify)
    with bind_access_context(ctx):
        hit = reader.get(RecordKind.WORKING, "root", destination="channel:a")
        assert hit.decision_id == f"lease:{len(calls)}"
    for mode in ("candidates", "lexical", "vector", "hybrid"):
        hits = recall((beam,store,ctx,registry,reader,catalog), mode)
        assert all(hit.decision_id == f"lease:{len(calls)}" for hit in hits)


@pytest.mark.parametrize("mode", ["direct", "candidates", "lexical", "vector", "hybrid"])
def test_final_verifier_context_rebinding_refuses_before_return(lifecycle, mode):
    beam, store, ctx, registry, _, catalog = lifecycle
    add(lifecycle, "root")
    calls, entered, switch_at = [], [], None

    def verify(c, **kw):
        calls.append(True)
        grant = replace(registry(c, **kw), lifecycle_epoch=catalog.epoch())
        if len(calls) == switch_at:
            manager = bind_access_context(replace(ctx, context_id="ctx:changed-after-verification"))
            manager.__enter__()
            entered.append(manager)
        return grant

    reader = PolicyReader(store, bank="bank:a", verify_context=verify)
    def call():
        if mode == "direct":
            return reader.get(RecordKind.WORKING, "root", destination="channel:a")
        if mode == "candidates":
            return reader.candidate_ids(RecordKind.WORKING, destination="channel:a")
        if mode == "lexical":
            return beam.recall_authorized_lexical("orion gateway", reader=reader, destination="channel:a")
        options = dict(embedding_model=beam_module._embeddings._DEFAULT_MODEL, reader=reader, destination="channel:a")
        if mode == "vector":
            return beam.recall_authorized_vector((1.,0.,0.,0.), **options)
        return beam.recall_authorized_hybrid("orion gateway", (1.,0.,0.,0.), **options)

    with bind_access_context(ctx):
        assert call() is not None
    switch_at = len(calls)
    calls.clear()
    with bind_access_context(ctx):
        try:
            with pytest.raises(PolicyRefusal, match="access_denied"):
                call()
            assert entered
        finally:
            for manager in reversed(entered):
                manager.__exit__(None,None,None)


def test_source_final_verifier_context_rebinding_refuses(fixture):
    _, store, registry, _ = fixture
    identity = source(fixture)
    catalog = PolicyLifecycle(store)
    catalog.prepare()
    ctx = source_context()
    calls, entered, switch_at = [], [], None

    def verify(c, **kw):
        calls.append(True)
        grant = replace(registry(c, **kw), lifecycle_epoch=catalog.epoch())
        if len(calls) == switch_at:
            manager = bind_access_context(replace(ctx, context_id="source:changed"))
            manager.__enter__()
            entered.append(manager)
        return grant

    reader = PolicyReader(store, bank="bank:a", verify_context=verify)
    with bind_access_context(ctx):
        assert reader.get_source_revision(identity, destination="channel:a")
    switch_at = len(calls)
    calls.clear()
    with bind_access_context(ctx):
        try:
            with pytest.raises(PolicyRefusal, match="access_denied"):
                reader.get_source_revision(identity, destination="channel:a")
        finally:
            for manager in reversed(entered):
                manager.__exit__(None,None,None)
