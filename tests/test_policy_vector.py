"""Synthetic actual-vec0 qualification; no protected activation or providers."""

import asyncio
import hashlib
import math
import socket
import sqlite3
import statistics
import struct
import time
from dataclasses import replace

import pytest

from mnemosyne.core import beam as beam_module
from mnemosyne.core.policy import PolicyRefusal, PolicySurface
from mnemosyne.core.policy_projects import PolicyProjects
from mnemosyne.core.policy_read import PolicyReader
from mnemosyne.core.policy_store import PolicyStore, PolicyStoreError, RecordKind
from mnemosyne.core.policy_vector import CAPABILITIES
from mnemosyne.runtime_context import bind_access_context
from tests.test_policy_lexical import lexical as lexical, seed
from tests.test_policy_projects import ProjectRegistry, assign, project_context


@pytest.fixture
def vector(lexical, monkeypatch):
    beam, store, ctx, registry, reader = lexical
    pytest.importorskip("numpy")
    if not beam_module._SQLITE_VEC_AVAILABLE:
        pytest.skip("actual sqlite-vec required")
    monkeypatch.setattr(beam_module, "EMBEDDING_DIM", 4)
    for table in ("vec_working", "vec_episodes"):
        beam.conn.execute(f"DROP TABLE IF EXISTS {table}")
        beam.conn.execute(f"CREATE VIRTUAL TABLE {table} USING vec0(embedding float32[4])")
    beam.conn.commit()
    ctx = replace(ctx, operations={"read:bank", "recall:vector"})
    registry.register(ctx)
    yield beam, store, ctx, registry, reader


def add(vector, identity, values=(1.0, 0.0, 0.0, 0.0), *, kind=RecordKind.WORKING, embedded=True, **kwargs):
    seed(vector, identity, kind=kind, **kwargs)
    if embedded:
        beam = vector[0]
        rowid = beam.conn.execute(f"SELECT rowid FROM {kind.value} WHERE id=?", (identity,)).fetchone()[0]
        table = "vec_working" if kind is RecordKind.WORKING else "vec_episodes"
        beam.conn.execute(f"INSERT INTO {table}(rowid,embedding) VALUES(?,?)", (rowid, struct.pack(f"<{len(values)}f", *values)))
        beam.conn.commit()


def recall(vector, query=(1.0, 0.0, 0.0, 0.0), **kwargs):
    beam, _, ctx, _, reader = vector
    kwargs.setdefault("embedding_model", beam_module._embeddings._DEFAULT_MODEL)
    with bind_access_context(ctx):
        return beam.recall_authorized_vector(query, reader=reader, destination="channel:a", **kwargs)


def test_actual_both_tiers_exact_cosine_order_provenance_no_writes(vector):
    beam, store, ctx, registry, _ = vector
    add(vector, "legacy", (4.0, 3.0, 0.0, 0.0))
    add(vector, "exact", kind=RecordKind.EPISODIC)
    add(vector, "orthogonal", (0.0, 1.0, 0.0, 0.0))
    add(vector, "negative", (-1.0, 0.0, 0.0, 0.0))
    add(vector, "missing", embedded=False)
    changes = beam.conn.total_changes
    report = recall(vector)
    assert [h.record_id for h in report.hits] == ["exact", "legacy"]
    assert [h.score for h in report.hits] == pytest.approx([1.0, 0.8])
    assert all(h.context_id == ctx.context_id and h.decision_id == "decision:a" for h in report.hits)
    assert (report.eligible_records, report.scored_vectors, report.missing_vectors) == (5, 4, 1)
    assert report.embedding_dimension == 4 and len(registry.calls) == 1
    assert store.get_domain().mode == "prepared" and beam.conn.total_changes == changes
    assert not beam.conn.in_transaction and CAPABILITIES.surfaces == {PolicySurface.VECTOR}
    assert "orion" not in repr(report) and "orion" not in repr(report.hits[0])


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
@pytest.mark.parametrize("policy", [{"classification": "sealed"}, {"owner": "other"}, {"tenant_id": "other"},
                                   {"compartments": {"missing"}}, {"audiences": set()}, {"purposes": set()},
                                   {"overlays": {"unknown"}}])
def test_denied_vectors_and_text_never_reach_python(vector, monkeypatch, kind, policy):
    add(vector, "denied", (0.25, 0.75, 0.0, 0.0), text="denied-canary", kind=kind, **policy)
    add(vector, "allowed", kind=kind)
    denied_blob = struct.pack("<4f", 0.25, 0.75, 0.0, 0.0)
    scorer = beam_module._vec_float32_blob_cosine
    scored = []

    def guarded(query, blob):
        assert blob != denied_blob
        scored.append(blob)
        return scorer(query, blob)

    def row_guard(cursor, row):
        assert "denied-canary" not in row and denied_blob not in row
        return sqlite3.Row(cursor, row)

    vector[0].conn.row_factory = row_guard
    monkeypatch.setattr(beam_module, "_vec_float32_blob_cosine", guarded)
    report = recall(vector, top_k=1, scan_limit=1)
    assert [h.record_id for h in report.hits] == ["allowed"]
    assert len(scored) == report.scored_vectors == report.eligible_records == 1


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
def test_native_eligibility_and_distractor_flood_before_budget(vector, monkeypatch, kind):
    monkeypatch.setenv("MNEMOSYNE_CROSS_SESSION", "1")
    for i in range(32):
        add(vector, f"denied-{i}", (float("nan"), 0.0, 0.0, 0.0), kind=kind, classification="sealed")
    for identity, values in (("other", {"session_id": "other"}), ("expired", {"expired": True}),
                             ("superseded", {"superseded": True}), ("unbound", {"bound": False})):
        add(vector, identity, kind=kind, **values)
    add(vector, "global", session_id="other", scope="global", kind=kind)
    result = recall(vector, top_k=1, scan_limit=1)
    assert [h.record_id for h in result.hits] == ["global"]
    assert result.scored_vectors == result.eligible_records == 1


def test_project_union_empty_and_proposed(vector):
    beam, store, _, _, _ = vector
    catalog = PolicyProjects(store)
    catalog.prepare()
    for project in ("project:a", "project:b"):
        catalog.register(project, actor="admin")
    for identity, project, confirmed in (("a", "project:a", True), ("b", "project:b", True), ("proposed", "project:a", False)):
        add(vector, identity)
        assign(catalog, identity, project, confirmed=confirmed)
    ctx = project_context(conversation_id=beam.session_id, operations={"read:projects", "recall:vector"})
    registry = ProjectRegistry(ctx)
    reader = PolicyReader(store, bank="bank:a", verify_context=registry)
    with bind_access_context(ctx):
        for projects, expected in (({"project:a"}, ["a"]), ({"project:b"}, ["b"]), ({"project:a", "project:b"}, ["a", "b"]), (set(), [])):
            result = beam.recall_authorized_vector((1., 0., 0., 0.), reader=reader, destination="channel:a", projects=projects,
                                                    embedding_model=beam_module._embeddings._DEFAULT_MODEL)
            assert [h.record_id for h in result.hits] == expected
            assert result.eligible_records == len(expected)


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
def test_budget_overflow_refuses_without_partial_scoring(vector, monkeypatch, kind):
    add(vector, "a", kind=kind)
    add(vector, "z", kind=kind)
    calls = []
    monkeypatch.setattr(beam_module, "_vec_float32_blob_cosine", lambda *a: calls.append(a))
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        recall(vector, top_k=1, scan_limit=1)
    assert not calls


@pytest.mark.parametrize("query", [(), (0., 0., 0., 0.), (True, 0., 0., 0.), (math.nan, 0., 0., 0.),
                                  (math.inf, 0., 0., 0.), (10**1000, 0., 0., 0.), (1e-100, 0., 0., 0.),
                                  "query", iter([1., 0., 0., 0.]), ([1.], 0., 0., 0.)])
def test_invalid_query_vectors(vector, query):
    with pytest.raises(ValueError):
        recall(vector, query)


@pytest.mark.parametrize("kwargs", [{"top_k": 0}, {"top_k": True}, {"top_k": 101}, {"scan_limit": 1001},
                                   {"scan_limit": False}, {"top_k": 2, "scan_limit": 1}])
def test_invalid_bounds(vector, kwargs):
    with pytest.raises(ValueError):
        recall(vector, **kwargs)


def test_missing_context_model_conversation_permissions_and_connection(vector, tmp_path):
    beam, _, ctx, registry, reader = vector
    model = beam_module._embeddings._DEFAULT_MODEL
    with pytest.raises(PolicyRefusal, match="missing_context"):
        beam.recall_authorized_vector((1., 0., 0., 0.), embedding_model=model, reader=reader, destination="channel:a")
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        recall(vector, embedding_model="other-model")
    for bad in (replace(ctx, conversation_id=None), replace(ctx, conversation_id="other"), replace(ctx, operations={"read:bank"})):
        registry.register(bad)
        with bind_access_context(bad), pytest.raises(PolicyRefusal, match="access_denied"):
            beam.recall_authorized_vector((1., 0., 0., 0.), embedding_model=model, reader=reader, destination="channel:a")
    conn = sqlite3.connect(tmp_path / "other.db")
    try:
        other = PolicyReader(PolicyStore(conn), bank="bank:a", verify_context=registry)
        with bind_access_context(ctx), pytest.raises(PolicyRefusal, match="access_denied"):
            beam.recall_authorized_vector((1., 0., 0., 0.), embedding_model=model, reader=other, destination="channel:a")
    finally:
        conn.close()


@pytest.mark.parametrize("table", ["vec_working", "vec_episodes"])
@pytest.mark.parametrize("replacement", [None, "ordinary", "int8", "bit", "dimension"])
def test_unsupported_schema_refuses_even_empty(vector, table, replacement):
    conn = vector[0].conn
    conn.execute(f"DROP TABLE {table}")
    if replacement == "ordinary":
        conn.execute(f"CREATE TABLE {table}(rowid INTEGER,embedding BLOB)")
    elif replacement:
        ddl = "float32[8]" if replacement == "dimension" else f"{replacement}[8]"
        conn.execute(f"CREATE VIRTUAL TABLE {table} USING vec0(embedding {ddl})")
    conn.commit()
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        recall(vector)


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
@pytest.mark.parametrize("values", [(0., 0., 0., 0.), (math.nan, 0., 0., 0.), (math.inf, 0., 0., 0.)])
def test_corrupt_authorized_vector_refuses_without_mutation(vector, kind, values):
    add(vector, "bad", values, kind=kind)
    changes = vector[0].conn.total_changes
    with pytest.raises(PolicyStoreError, match="incompatible"):
        recall(vector)
    assert vector[0].conn.total_changes == changes


@pytest.mark.parametrize("text,reason", [("n\0" + "x" * 100000, "incompatible"), ("x" * 16385, "resource_limit")])
def test_selected_text_bounded_but_nonwinning_text_not_fetched(vector, text, reason):
    add(vector, "bad", text=text)
    with pytest.raises((PolicyRefusal, PolicyStoreError), match=reason):
        recall(vector)
    add(vector, "winner", kind=RecordKind.EPISODIC)
    # The tier tie breaker puts episodic first; unselected content is untouched.
    assert [h.record_id for h in recall(vector, top_k=1).hits] == ["winner"]


def test_no_global_knn_provider_fallback_or_dml(vector, monkeypatch):
    add(vector, "ok")
    attempts = []

    def forbidden(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("unsupported path")

    for name in ("_wm_vec_search", "_in_memory_vec_search"):
        monkeypatch.setattr(beam_module, name, forbidden)
    monkeypatch.setattr(beam_module.BeamMemory, "recall", forbidden)
    monkeypatch.setattr(beam_module._embeddings, "embed_query", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    statements = []
    vector[0].conn.set_trace_callback(statements.append)
    assert [h.record_id for h in recall(vector).hits] == ["ok"]
    assert not attempts
    assert not any(" MATCH " in s or s.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE", "CREATE", "ALTER")) for s in statements)
    query = next(s for s in statements if "CROSS JOIN main.vec_working" in s)
    plan = vector[0].conn.execute("EXPLAIN QUERY PLAN " + query).fetchall()
    assert any("SCAN ne" in r[3] for r in plan)
    # sqlite-vec 0.1.9's point-rowid plan; do not mistake a full scan for it.
    assert any("SCAN v VIRTUAL TABLE INDEX 3:2!___" == r[3] for r in plan)


def test_caller_transaction_and_snapshot_preserved(vector):
    beam, *_ = vector
    add(vector, "w")
    beam.conn.execute("UPDATE working_memory SET importance=0.9 WHERE id='w'")
    assert recall(vector).hits and beam.conn.in_transaction
    beam.conn.rollback()
    assert beam.conn.execute("SELECT importance FROM working_memory WHERE id='w'").fetchone()[0] == 0.5


def test_atomic_cross_tier_policy_and_content_snapshot(vector):
    beam, *_ = vector
    add(vector, "w")
    add(vector, "e", kind=RecordKind.EPISODIC)
    beam.conn.execute("PRAGMA journal_mode=WAL")
    other = sqlite3.connect(str(beam.db_path))
    changed = []

    def during_second_tier(statement):
        if statement.startswith("WITH eligible") and "main.episodic_memory" in statement and not changed:
            changed.append(True)
            other.execute("UPDATE policy_bindings SET classification='sealed' WHERE record_id='e'")
            other.execute("UPDATE episodic_memory SET content='new-denied-content' WHERE id='e'")
            other.commit()

    beam.conn.set_trace_callback(during_second_tier)
    try:
        first = recall(vector)
        assert changed and {h.record_id for h in first.hits} == {"w", "e"}
        assert all(h.content == "orion gateway port" for h in first.hits)
        assert [h.record_id for h in recall(vector).hits] == ["w"]
    finally:
        beam.conn.set_trace_callback(None)
        other.close()


def test_connection_failure_propagates_and_does_not_commit_caller(vector):
    beam, *_ = vector
    add(vector, "w")
    beam.conn.execute("UPDATE working_memory SET importance=0.9 WHERE id='w'")

    def refuse_vector_reads(action, table, column, database, trigger):
        return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_READ and table == "vec_working" else sqlite3.SQLITE_OK

    beam.conn.set_authorizer(refuse_vector_reads)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            recall(vector)
    finally:
        # Python 3.10 cannot disable this callback with None (added in 3.11).
        beam.conn.set_authorizer(lambda *args: sqlite3.SQLITE_OK)
    assert beam.conn.in_transaction
    beam.conn.rollback()
    assert beam.conn.execute("SELECT importance FROM working_memory WHERE id='w'").fetchone()[0] == 0.5


def test_async_binding_and_verifier_revocation(vector):
    beam, _, ctx, registry, reader = vector
    add(vector, "w")
    other = replace(ctx, context_id="ctx:b", conversation_id="other")
    registry.register(other)

    async def exercise():
        async def call(selected, allowed):
            with bind_access_context(selected):
                await asyncio.sleep(0)
                if allowed:
                    return [h.record_id for h in beam.recall_authorized_vector((1., 0., 0., 0.), embedding_model=beam_module._embeddings._DEFAULT_MODEL,
                                                                               reader=reader, destination="channel:a").hits]
                with pytest.raises(PolicyRefusal, match="access_denied"):
                    beam.recall_authorized_vector((1., 0., 0., 0.), embedding_model=beam_module._embeddings._DEFAULT_MODEL,
                                                   reader=reader, destination="channel:a")

        assert await asyncio.gather(call(ctx, True), call(other, False), call(ctx, True)) == [["w"], None, ["w"]]

    asyncio.run(exercise())
    registry.contexts.pop(ctx.context_id)
    with pytest.raises(PolicyRefusal, match="access_denied"):
        recall(vector)


def test_full_grant_variable_budget_and_return_cap(vector, monkeypatch):
    beam, store, ctx, registry, reader = vector
    add(vector, "w", text="long text " * 100)
    ctx = replace(ctx, audiences={"internal"} | {f"a{i}" for i in range(255)},
                  compartments={"work"} | {f"c{i}" for i in range(255)})
    registry.register(ctx, owners={"person:a"} | {f"o{i}" for i in range(255)}, tenants={"tenant:a"} | {f"t{i}" for i in range(131)})
    if hasattr(beam.conn, "setlimit"):
        beam.conn.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)
    monkeypatch.setattr(beam_module, "RECALL_CONTENT_CAP", 20)
    hit = recall((beam, store, ctx, registry, reader)).hits[0]
    assert len(hit.content) == 20 and hit.content_truncated
    assert len(beam.conn.execute("SELECT content FROM working_memory WHERE id='w'").fetchone()[0]) == 1000


def test_temp_vector_shadows_and_policy_schema_errors(vector):
    beam, *_ = vector
    add(vector, "w")
    beam.conn.execute("CREATE TEMP TABLE vec_working(rowid INTEGER,embedding BLOB)")
    beam.conn.execute("CREATE TEMP TABLE vec_episodes(rowid INTEGER,embedding BLOB)")
    assert [h.record_id for h in recall(vector).hits] == ["w"]
    beam.conn.execute("DROP INDEX idx_policy_terms_reverse")
    with pytest.raises(PolicyStoreError, match="incompatible"):
        recall(vector)


def test_one_shot_cancellation_propagates_and_preserves_owner_handler(vector):
    beam, *_ = vector
    add(vector, "w")
    calls = []

    def cancel_once():
        calls.append(True)
        return int(len(calls) == 1)

    beam.conn.set_progress_handler(cancel_once, 1)
    try:
        with pytest.raises(sqlite3.OperationalError, match="interrupted"):
            recall(vector)
        assert not beam.conn.in_transaction
        before = len(calls)
        assert beam.conn.execute("SELECT 1").fetchone()[0] == 1
        assert len(calls) > before
    finally:
        beam.conn.set_progress_handler(None, 1)


def test_1024_dimensions_and_exact_quality_under_denied_flood(vector, monkeypatch, capsys):
    beam, *_ = vector
    monkeypatch.setattr(beam_module, "EMBEDDING_DIM", 1024)
    for table in ("vec_working", "vec_episodes"):
        beam.conn.execute(f"DROP TABLE {table}")
        beam.conn.execute(f"CREATE VIRTUAL TABLE {table} USING vec0(embedding float32[1024])")
    beam.conn.commit()
    for i in range(128):
        values = (1.0, float(i % 32) / 32, *([0.] * 1022))
        add(vector, f"id-{i:03}", values, classification="team" if i % 4 == 0 else "sealed")
    query = (1.0, *([0.] * 1023))
    expected = sorted((f"id-{i:03}" for i in range(0, 128, 4)), key=lambda s: (int(s[3:]) % 32, s))
    times = []
    for _ in range(30):
        start = time.perf_counter_ns()
        result = recall(vector, query, top_k=32, scan_limit=32)
        times.append((time.perf_counter_ns() - start) / 1e6)
        assert [h.record_id for h in result.hits] == expected
        assert (result.eligible_records, result.scored_vectors, result.missing_vectors) == (32, 32, 0)
    with capsys.disabled():
        print({"workload": "actual-vec0-1024", "authorized": 32, "repeats": 30,
               "p50_ms": statistics.median(times), "p95_ms": sorted(times)[28],
               "id_oracle_sha256": hashlib.sha256("\n".join(expected).encode()).hexdigest()})
