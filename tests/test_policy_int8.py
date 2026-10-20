"""Real native int8 eligibility and scoring; no providers or live stores."""

from dataclasses import replace
import math
import socket
import sqlite3
import struct

import pytest

from mnemosyne.core import beam as beam_module
from mnemosyne.core.policy import PolicyRefusal
from mnemosyne.core.policy_store import PolicyStoreError, RecordKind
from mnemosyne.runtime_context import bind_access_context
from tests.test_policy_lexical import lexical as lexical, seed
from tests.test_policy_vector import recall


@pytest.fixture
def int8(lexical, monkeypatch):
    pytest.importorskip("numpy")
    beam, store, ctx, registry, reader = lexical
    if not beam_module._SQLITE_VEC_AVAILABLE:
        pytest.skip("actual sqlite-vec required")
    monkeypatch.setattr(beam_module, "EMBEDDING_DIM", 4)
    for table in ("vec_working", "vec_episodes"):
        beam.conn.execute(f"DROP TABLE IF EXISTS {table}")
        beam.conn.execute(f"CREATE VIRTUAL TABLE {table} USING vec0(embedding int8[4])")
    beam.conn.commit()
    ctx = replace(ctx, operations={"read:bank", "recall:vector", "recall:lexical", "recall:hybrid"})
    registry.register(ctx)
    return beam, store, ctx, registry, reader


def add(fx, identity, values=(1., 0., 0., 0.), *, kind=RecordKind.WORKING, raw=None, **policy):
    seed(fx, identity, kind=kind, **policy)
    beam = fx[0]
    table = "vec_working" if kind is RecordKind.WORKING else "vec_episodes"
    rowid = beam.conn.execute(f"SELECT rowid FROM {kind.value} WHERE id=?", (identity,)).fetchone()[0]
    if raw is None:
        beam_module._vec_table_insert(beam.conn, table, rowid, values)
    else:
        beam.conn.execute(f"INSERT INTO {table}(rowid, embedding) VALUES (?,vec_int8(?))", (rowid, raw))
        beam.conn.commit()


def test_native_normalized_rows_exact_quantized_score_and_read_only(int8):
    add(int8, "a", (4., 3., 0., 0.))
    add(int8, "b", kind=RecordKind.EPISODIC)
    add(int8, "negative", (-1., 0., 0., 0.))
    before = int8[0].conn.total_changes
    report = recall(int8)
    assert [h.record_id for h in report.hits] == ["b", "a"]
    for hit in report.hits:
        table = "vec_working" if hit.record_kind is RecordKind.WORKING else "vec_episodes"
        rowid = int8[0].conn.execute(f"SELECT rowid FROM {hit.record_kind.value} WHERE id=?", (hit.record_id,)).fetchone()[0]
        blob = int8[0].conn.execute(f"SELECT embedding FROM {table} WHERE rowid=?", (rowid,)).fetchone()[0]
        values = struct.unpack("4b", blob)
        expected = values[0] / math.sqrt(sum(v*v for v in values))
        assert hit.score == pytest.approx(expected)
    assert report.scored_vectors == report.eligible_records == 3
    assert int8[0].conn.total_changes == before and not int8[0].conn.in_transaction
    assert int8[1].get_domain().mode == "prepared"


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
@pytest.mark.parametrize("policy", [{"classification": "sealed"}, {"owner": "other"}, {"tenant_id": "other"},
                                   {"compartments": {"absent"}}, {"audiences": set()}, {"purposes": set()},
                                   {"overlays": {"unknown"}}])
def test_denied_blob_never_materialized_or_scored(int8, monkeypatch, kind, policy):
    canary = struct.pack("4b", 23, 29, 41, 53)
    add(int8, "denied", kind=kind, raw=canary, text="denied-int8-canary", **policy)
    add(int8, "allowed", kind=kind)
    native = beam_module._vec_int8_blob_cosine
    scored = []

    def score(query, row):
        assert row != canary
        scored.append(row)
        return native(query, row)

    def row_factory(cursor, row):
        assert canary not in row and "denied-int8-canary" not in row
        return sqlite3.Row(cursor, row)

    int8[0].conn.row_factory = row_factory
    monkeypatch.setattr(beam_module, "_vec_int8_blob_cosine", score)
    result = recall(int8, top_k=1, scan_limit=1)
    assert [h.record_id for h in result.hits] == ["allowed"] and len(scored) == 1


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
def test_denied_flood_and_native_eligibility_before_budget(int8, kind):
    for i in range(24):
        add(int8, f"denied-{i}", kind=kind, classification="sealed")
    for identity, kwargs in (("other", {"session_id": "other"}), ("expired", {"expired": True}),
                             ("superseded", {"superseded": True}), ("unbound", {"bound": False})):
        add(int8, identity, kind=kind, **kwargs)
    add(int8, "allowed", kind=kind)
    assert [h.record_id for h in recall(int8, top_k=1, scan_limit=1).hits] == ["allowed"]


@pytest.mark.parametrize("query", [(3.4e38, 0., 0., 0.), (1e-40, 0., 0., 0.), (19., 0., 0., 0.)])
def test_query_normalization_is_finite_before_quantization(int8, query):
    add(int8, "a")
    assert recall(int8, query).hits[0].score == pytest.approx(1.)


def test_zero_native_blob_is_corruption_not_missing(int8):
    add(int8, "bad", raw=b"\0"*4)
    with pytest.raises(PolicyStoreError, match="incompatible"):
        recall(int8)
    assert not int8[0].conn.in_transaction


def test_missing_vector_count_and_overflow(int8):
    seed(int8, "no-vector")
    add(int8, "yes-vector")
    result = recall(int8)
    assert (result.eligible_records, result.scored_vectors, result.missing_vectors) == (2, 1, 1)
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        recall(int8, top_k=1, scan_limit=1)


def test_mixed_supported_tiers_and_temp_shadows(int8):
    conn = int8[0].conn
    add(int8, "i8")
    seed(int8, "f32", kind=RecordKind.EPISODIC)
    conn.execute("DROP TABLE vec_episodes")
    conn.execute("CREATE VIRTUAL TABLE vec_episodes USING vec0(embedding float32[4])")
    rowid = conn.execute("SELECT rowid FROM episodic_memory WHERE id='f32'").fetchone()[0]
    conn.execute("INSERT INTO vec_episodes(rowid,embedding) VALUES (?,?)", (rowid, struct.pack("4f", 1., 0., 0., 0.)))
    conn.commit()
    conn.execute("CREATE TEMP TABLE vec_working(rowid,embedding)")
    assert {h.record_id for h in recall(int8).hits} == {"i8", "f32"}


def test_hybrid_native_int8_no_legacy_provider_or_dml(int8, monkeypatch):
    add(int8, "both")
    beam, _, ctx, _, reader = int8

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected fallback/provider")

    for name in ("embed", "embed_query"):
        monkeypatch.setattr(beam_module._embeddings, name, forbidden)
    monkeypatch.setattr(beam, "recall", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    statements = []
    beam.conn.set_trace_callback(statements.append)
    with bind_access_context(ctx):
        result = beam.recall_authorized_hybrid("orion gateway", (1., 0., 0., 0.),
            embedding_model=beam_module._embeddings._DEFAULT_MODEL, reader=reader, destination="channel:a")
    assert [(h.record_id, h.vector_rank, h.lexical_rank) for h in result.hits] == [("both", 1, 1)]
    assert not any("embedding MATCH" in s or s.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE", "CREATE")) for s in statements)
    point_read = next(s for s in statements if "CROSS JOIN main.vec_working" in s)
    plan = beam.conn.execute("EXPLAIN QUERY PLAN " + point_read).fetchall()
    assert any("SCAN v VIRTUAL TABLE INDEX 3:2!___" == row[3] for row in plan)


def test_caller_owned_transaction_retained(int8):
    add(int8, "a")
    conn = int8[0].conn
    conn.execute("UPDATE working_memory SET importance=.9 WHERE id='a'")
    assert recall(int8).hits and conn.in_transaction
    conn.rollback()
    assert conn.execute("SELECT importance FROM working_memory WHERE id='a'").fetchone()[0] == .5


@pytest.mark.parametrize("dimension", [384, 1024, 4096])
def test_high_dimension_actual_native_quantization_and_ranking(int8, monkeypatch, dimension):
    beam = int8[0]
    monkeypatch.setattr(beam_module, "EMBEDDING_DIM", dimension)
    for table in ("vec_working", "vec_episodes"):
        beam.conn.execute(f"DROP TABLE {table}")
        beam.conn.execute(f"CREATE VIRTUAL TABLE {table} USING vec0(embedding int8[{dimension}])")
    beam.conn.commit()
    query = tuple(1. if i % 2 else -1. for i in range(dimension))
    add(int8, "exact", query)
    add(int8, "opposite", tuple(-v for v in query))
    add(int8, "denied", query, classification="sealed")
    result = recall(int8, query, top_k=1, scan_limit=2)
    assert [h.record_id for h in result.hits] == ["exact"]
    assert result.hits[0].score == pytest.approx(1.)
    assert result.embedding_dimension == dimension
    assert (result.eligible_records, result.scored_vectors) == (2, 2)


@pytest.mark.parametrize("raw", [struct.pack("4b", 126, 126, 126, 126), struct.pack("4b", -128, 127, -128, 127)])
@pytest.mark.parametrize("query", [(1., 1., 1., 1.), (1., 0., 0., 0.), (-1., 1., -1., 1.)])
def test_saturated_legacy_rows_reuse_native_estimator(int8, raw, query):
    import numpy as np
    add(int8, "legacy", raw=raw)
    unit = np.asarray(query, dtype=np.float64)
    unit = (unit / np.linalg.norm(unit)).astype(np.float32)
    quantized = int8[0].conn.execute("SELECT vec_quantize_int8(?, 'unit')", (unit.tobytes(),)).fetchone()[0]
    expected = beam_module._vec_int8_blob_cosine(quantized, raw)
    result = recall(int8, query)
    assert [h.score for h in result.hits] == ([pytest.approx(expected)] if expected > 0 else [])


@pytest.mark.parametrize("invalid", [None, "not-a-blob", b"\1", b"\0"*4])
def test_invalid_query_quantizer_output_refuses_before_vectors(int8, invalid, monkeypatch):
    add(int8, "a")
    conn = int8[0].conn
    conn.create_function("vec_quantize_int8", 2, lambda *args: invalid)
    calls = []
    monkeypatch.setattr(beam_module, "_vec_int8_blob_cosine", lambda *args: calls.append(True))
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        recall(int8)
    assert not calls and not conn.in_transaction


def test_missing_quantizer_propagates_and_preserves_caller_work(int8):
    add(int8, "a")
    conn = int8[0].conn
    conn.execute("UPDATE working_memory SET importance=.9 WHERE id='a'")
    conn.create_function("vec_quantize_int8", 2, None)
    with pytest.raises(sqlite3.OperationalError):
        recall(int8)
    assert conn.in_transaction
    conn.rollback()
    assert conn.execute("SELECT importance FROM working_memory WHERE id='a'").fetchone()[0] == .5
