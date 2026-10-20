"""Actual FTS/vec0 authorized fusion, no providers or protected activation."""

from dataclasses import replace
import sqlite3

import pytest

from mnemosyne.core import beam as beam_module
from mnemosyne.core import policy_hybrid
from mnemosyne.core.policy import PolicyRefusal, PolicySurface, RefusalReason
from mnemosyne.core.policy_read import PolicyReader
from mnemosyne.core.policy_projects import PolicyProjects
from mnemosyne.core.policy_store import RecordKind
from mnemosyne.runtime_context import bind_access_context
from tests.test_policy_lexical import lexical as lexical
from tests.test_policy_vector import add, vector as vector
from tests.test_policy_projects import ProjectRegistry, assign


@pytest.fixture
def hybrid(vector):
    beam, store, ctx, registry, reader = vector
    ctx = replace(ctx, operations={"read:bank", "recall:hybrid", "recall:vector", "recall:lexical"})
    registry.register(ctx)
    return beam, store, ctx, registry, reader


def recall(fx, *, ctx=None, reader=None, **options):
    beam, _, context, _, native_reader = fx
    defaults = dict(embedding_model=beam_module._embeddings._DEFAULT_MODEL, reader=reader or native_reader,
                    destination="channel:a", top_k=3)
    defaults.update(options)
    with bind_access_context(ctx or context):
        return beam.recall_authorized_hybrid("orion gateway", (1.0, 0.0, 0.0, 0.0), **defaults)


def test_exact_rrf_union_ranks_and_provenance_no_writes_or_fallback(hybrid, monkeypatch):
    beam, store, ctx, registry, _ = hybrid
    add(hybrid, "a-both")
    add(hybrid, "b-vector", (0.8, 0.6, 0.0, 0.0), text="unrelated magma")
    add(hybrid, "c-lexical", (0.0, 1.0, 0.0, 0.0))

    def forbidden(*args, **kwargs):
        raise AssertionError("legacy recall/provider was invoked")

    monkeypatch.setattr(beam, "recall", forbidden)
    monkeypatch.setattr(beam_module._embeddings, "embed", forbidden)
    monkeypatch.setattr(beam_module._embeddings, "embed_query", forbidden)
    changes = beam.conn.total_changes
    result = recall(hybrid)
    assert [hit.record_id for hit in result.hits] == ["a-both", "b-vector", "c-lexical"]
    assert [hit.score for hit in result.hits] == pytest.approx([2 / 61, 1 / 62, 1 / 62])
    assert [(hit.lexical_rank, hit.vector_rank) for hit in result.hits] == [(1, 1), (None, 2), (2, None)]
    assert all(hit.context_id == ctx.context_id and hit.context_epoch == ctx.epoch for hit in result.hits)
    assert all(hit.decision_id == result.decision_id == "decision:a" for hit in result.hits)
    assert len(registry.calls) == 6
    assert beam.conn.total_changes == changes and not beam.conn.in_transaction
    assert store.get_domain().mode == "prepared"
    assert "orion" not in repr(result) and "a-both" not in repr(result.hits[0])
    assert policy_hybrid.CAPABILITIES.surfaces == {PolicySurface.HYBRID, PolicySurface.VECTOR, PolicySurface.LEXICAL}


def test_equal_ids_in_different_tiers_remain_distinct(hybrid):
    add(hybrid, "same", kind=RecordKind.WORKING)
    add(hybrid, "same", kind=RecordKind.EPISODIC)
    result = recall(hybrid)
    assert {(h.record_kind, h.record_id) for h in result.hits} == {
        (RecordKind.WORKING, "same"), (RecordKind.EPISODIC, "same")}
    assert len(result.hits) == 2


@pytest.mark.parametrize("kind", (RecordKind.WORKING, RecordKind.EPISODIC))
@pytest.mark.parametrize("restriction", ({"classification": "sealed"}, {"owner": "other"},
    {"tenant_id": "other"}, {"compartments": {"missing"}}, {"audiences": set()}, {"purposes": set()}, {"overlays": {"unknown"}}))
def test_denied_high_ranked_material_never_reaches_either_scorer_or_fuser(hybrid, monkeypatch, kind, restriction):
    canary = "DENIED-HYBRID-CANARY"
    denied = (0.125, 0.875, 0.0, 0.0)
    add(hybrid, "denied", denied, text="orion gateway " + canary, kind=kind, **restriction)
    add(hybrid, "allowed", kind=kind)
    import struct
    blob = struct.pack("<4f", *denied)
    old_lexical = beam_module._lexical_relevance_for_query
    old_vector = beam_module._vec_float32_blob_cosine

    def lexical_guard(query, text):
        assert canary not in text
        return old_lexical(query, text)

    def vector_guard(query, values):
        assert values != blob
        return old_vector(query, values)

    def row_guard(cursor, row):
        assert blob not in row
        assert all(canary not in value for value in row if isinstance(value, str))
        return sqlite3.Row(cursor, row)

    monkeypatch.setattr(beam_module, "_lexical_relevance_for_query", lexical_guard)
    monkeypatch.setattr(beam_module, "_vec_float32_blob_cosine", vector_guard)
    hybrid[0].conn.row_factory = row_guard
    result = recall(hybrid, top_k=1, scan_limit=1, candidate_limit=1)
    assert [hit.record_id for hit in result.hits] == ["allowed"]
    assert result.vector_eligible == result.vector_scored == result.lexical_examined == 1


def test_denied_flood_cannot_spend_budget_or_change_fusion(hybrid):
    add(hybrid, "allowed")
    before = recall(hybrid, top_k=1, scan_limit=1, candidate_limit=1)
    for number in range(24):
        add(hybrid, f"denied:{number}", (float("nan"), 0.0, 0.0, 0.0), classification="sealed")
    after = recall(hybrid, top_k=1, scan_limit=1, candidate_limit=1)
    assert [(h.record_id, h.score) for h in after.hits] == [(h.record_id, h.score) for h in before.hits]
    assert after.vector_eligible == before.vector_eligible == 1
    assert after.lexical_examined == before.lexical_examined == 1


@pytest.mark.parametrize("at", range(2, 7))
@pytest.mark.parametrize("scope_change", ({"owners": frozenset()}, {"owners": frozenset({"person:a", "other"})}))
def test_grant_changes_refuse_at_every_branch_fusion_and_release_checkpoint(hybrid, at, scope_change):
    beam, store, _, registry, _ = hybrid
    add(hybrid, "allowed")
    calls = 0

    def verify(ctx, **intent):
        nonlocal calls
        calls += 1
        grant = registry(ctx, **intent)
        return replace(grant, **scope_change) if calls >= at else grant

    reader = PolicyReader(store, bank="bank:a", verify_context=verify)
    with pytest.raises(PolicyRefusal) as caught:
        recall(hybrid, reader=reader)
    assert caught.value.reason == RefusalReason.ACCESS_DENIED
    assert calls == at
    assert not beam.conn.in_transaction


@pytest.mark.parametrize("operation", ("recall:hybrid", "recall:lexical", "recall:vector", "read:bank"))
def test_each_required_operation_is_explicit(hybrid, operation):
    _, _, ctx, registry, _ = hybrid
    ctx = replace(ctx, operations=ctx.operations - {operation})
    registry.register(ctx)
    with pytest.raises(PolicyRefusal):
        recall(hybrid, ctx=ctx)


def test_fresh_decision_ids_do_not_change_scope(hybrid):
    _, store, _, registry, _ = hybrid
    add(hybrid, "allowed")
    count = 0

    def verify(ctx, **intent):
        nonlocal count
        count += 1
        return replace(registry(ctx, **intent), decision_id=f"fresh:{count}")

    reader = PolicyReader(store, bank="bank:a", verify_context=verify)
    result = recall(hybrid, reader=reader)
    assert count == 6 and result.decision_id == "fresh:6"
    assert result.hits[0].decision_id == "fresh:6"


@pytest.mark.parametrize("operation", ("epoch", "participant"))
def test_host_context_change_during_verifier_is_refused_before_next_consumer(hybrid, operation):
    import mnemosyne.runtime_context as runtime
    _, store, ctx, registry, _ = hybrid
    add(hybrid, "allowed")
    calls = 0

    def verify(context, **intent):
        nonlocal calls
        calls += 1
        grant = registry(context, **intent)
        if calls == 2:
            changed = replace(ctx, epoch=ctx.epoch + 1) if operation == "epoch" else replace(ctx, principals={"unknown"})
            runtime._access_context.set(changed)
        return grant

    reader = PolicyReader(store, bank="bank:a", verify_context=verify)
    with pytest.raises(PolicyRefusal):
        recall(hybrid, reader=reader)
    assert calls == 2


def test_async_grant_from_later_checkpoint_is_closed_and_refused(hybrid):
    _, store, _, registry, _ = hybrid
    add(hybrid, "allowed")
    calls = 0
    created = []

    async def later():
        raise AssertionError("async verifier executed")

    def verify(ctx, **intent):
        nonlocal calls
        calls += 1
        if calls == 2:
            value = later()
            created.append(value)
            return value
        return registry(ctx, **intent)

    with pytest.raises(PolicyRefusal) as caught:
        recall(hybrid, reader=PolicyReader(store, bank="bank:a", verify_context=verify))
    assert caught.value.reason == RefusalReason.UNSUPPORTED_SURFACE
    assert created[0].cr_frame is None


def test_unsupported_model_never_falls_back_to_lexical_or_ordinary_recall(hybrid, monkeypatch):
    add(hybrid, "allowed")

    def forbidden(*args, **kwargs):
        raise AssertionError("fallback path called")

    monkeypatch.setattr(hybrid[0], "recall", forbidden)
    monkeypatch.setattr(policy_hybrid, "recall_authorized_lexical", forbidden)
    with pytest.raises(PolicyRefusal) as caught:
        recall(hybrid, embedding_model="other/model")
    assert caught.value.reason == RefusalReason.UNSUPPORTED_SURFACE


@pytest.mark.parametrize("options", ({"top_k": 0}, {"top_k": True}, {"top_k": 101},
                                     {"candidate_limit": 2}, {"scan_limit": 2}, {"candidate_limit": 1001}, {"scan_limit": 1001}))
def test_invalid_limits_refuse(hybrid, options):
    with pytest.raises(ValueError):
        recall(hybrid, **options)
    assert not hybrid[0].conn.in_transaction


def test_inconsistent_branch_content_is_not_merged(hybrid, monkeypatch):
    add(hybrid, "allowed")
    native = policy_hybrid.recall_authorized_lexical

    def changed(*args, **kwargs):
        report = native(*args, **kwargs)
        return replace(report, hits=tuple(replace(hit, content="changed content") for hit in report.hits))

    monkeypatch.setattr(policy_hybrid, "recall_authorized_lexical", changed)
    with pytest.raises(PolicyRefusal) as caught:
        recall(hybrid)
    assert caught.value.reason == RefusalReason.POLICY_MISMATCH


def test_caller_transaction_remains_owned_and_rollbackable(hybrid):
    beam, *_ = hybrid
    add(hybrid, "allowed")
    beam.conn.execute("CREATE TABLE unrelated(value)")
    beam.conn.execute("INSERT INTO unrelated VALUES(1)")
    changes = beam.conn.total_changes
    assert recall(hybrid).hits
    assert beam.conn.in_transaction and beam.conn.total_changes == changes
    beam.conn.rollback()
    assert beam.conn.execute("SELECT count(*) FROM unrelated").fetchone()[0] == 0


def test_missing_context_and_unregistered_expansion_do_not_authenticate(hybrid):
    beam, _, ctx, _, reader = hybrid
    with pytest.raises(PolicyRefusal) as caught:
        beam.recall_authorized_hybrid("orion", (1, 0, 0, 0), embedding_model=beam_module._embeddings._DEFAULT_MODEL,
                                     reader=reader, destination="channel:a")
    assert caught.value.reason == RefusalReason.MISSING_CONTEXT
    with pytest.raises(PolicyRefusal):
        recall(hybrid, ctx=replace(ctx, principals=ctx.principals | {"unmapped"}))


def test_project_selection_and_proposed_membership_cannot_broaden_fusion(hybrid):
    _, store, ctx, _, _ = hybrid
    catalog = PolicyProjects(store)
    catalog.prepare()
    catalog.register("project:a", actor="synthetic")
    catalog.register("project:b", actor="synthetic")
    for identity in ("a", "b", "proposed"):
        add(hybrid, identity)
    assign(catalog, "a", "project:a")
    assign(catalog, "b", "project:b")
    assign(catalog, "proposed", "project:a", confirmed=False)
    ctx = replace(ctx, projects={"project:a", "project:b"},
                  operations={"read:projects", "recall:hybrid", "recall:lexical", "recall:vector"})
    reader = PolicyReader(store, bank="bank:a", verify_context=ProjectRegistry(ctx))
    assert [h.record_id for h in recall(hybrid, ctx=ctx, reader=reader, projects={"project:a"}).hits] == ["a"]
    assert {h.record_id for h in recall(hybrid, ctx=ctx, reader=reader, projects={"project:a", "project:b"}).hits} == {"a", "b"}
    with pytest.raises(PolicyRefusal):
        recall(hybrid, ctx=ctx, reader=reader)


def test_both_branches_read_one_wal_snapshot(hybrid):
    beam, store, _, registry, _ = hybrid
    add(hybrid, "allowed", text="orion gateway before")
    beam.conn.execute("PRAGMA journal_mode=WAL")
    other = sqlite3.connect(beam.db_path)
    count = 0

    def verify(ctx, **intent):
        nonlocal count
        count += 1
        if count == 3:
            other.execute("UPDATE working_memory SET content='orion gateway after' WHERE id='allowed'")
            other.commit()
        return registry(ctx, **intent)

    try:
        reader = PolicyReader(store, bank="bank:a", verify_context=verify)
        result = recall(hybrid, reader=reader)
        assert result.hits[0].content == "orion gateway before"
        assert beam.conn.execute("SELECT content FROM working_memory WHERE id='allowed'").fetchone()[0] == "orion gateway after"
    finally:
        other.close()


@pytest.mark.parametrize("failure", (PolicyRefusal, KeyboardInterrupt))
def test_late_refusal_or_cancellation_does_not_retain_branch_payload_frames(hybrid, failure):
    _, store, _, registry, _ = hybrid
    add(hybrid, "allowed", text="orion gateway PRIVATE-BRANCH-MARKER")
    calls = 0
    error = PolicyRefusal(RefusalReason.ACCESS_DENIED) if failure is PolicyRefusal else KeyboardInterrupt("synthetic cancellation")

    def verify(ctx, **intent):
        nonlocal calls
        calls += 1
        if calls == 6:
            raise error
        return registry(ctx, **intent)

    try:
        recall(hybrid, reader=PolicyReader(store, bank="bank:a", verify_context=verify))
    except BaseException as caught:
        assert caught is error
        trace = caught.__traceback__
        while trace:
            module = trace.tb_frame.f_globals.get("__name__", "")
            if module in ("mnemosyne.core.policy_lexical", "mnemosyne.core.policy_vector", "mnemosyne.core.policy_hybrid"):
                assert all(name not in trace.tb_frame.f_locals for name in ("vector", "lexical", "combined", "hit", "hits"))
            trace = trace.tb_next
    else:
        raise AssertionError("late failure returned a report")
    assert calls == 6 and not hybrid[0].conn.in_transaction
