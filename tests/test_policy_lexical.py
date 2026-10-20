"""Real disposable BEAM/FTS qualification, not hybrid protection or live stores."""

import asyncio
import hashlib
import json
import socket
import sqlite3
import statistics
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from mnemosyne.core import beam as beam_module
from mnemosyne.core.beam import BeamMemory
from mnemosyne.core.policy import PolicyRefusal, PolicySurface
from mnemosyne.core.policy_lexical import CAPABILITIES, MAX_SCORING_CHARACTERS
from mnemosyne.core.policy_projects import PolicyProjects
from mnemosyne.core.policy_read import PolicyReader
from mnemosyne.core.policy_store import PolicyStore, PolicyStoreError, RecordKind
from mnemosyne.runtime_context import bind_access_context
from tests.test_policy_projects import ProjectRegistry, assign, project_context
from tests.test_policy_read import CANARY, Registry, context, restriction


@pytest.fixture
def lexical(tmp_path, monkeypatch):
    monkeypatch.setenv("MNEMOSYNE_NO_EMBEDDINGS", "1")
    monkeypatch.setenv("MNEMOSYNE_LLM_ENABLED", "false")
    monkeypatch.setenv("MNEMOSYNE_HOST_LLM_ENABLED", "false")
    monkeypatch.delenv("MNEMOSYNE_LEXICAL_GATE_MIN", raising=False)
    beam = BeamMemory(session_id="conversation:a", db_path=tmp_path / "lexical.db")
    store = PolicyStore(beam.conn)
    store.prepare("domain:a")
    from mnemosyne.core.policy import PolicyDefinition
    store.register_definition(PolicyDefinition("test", 1, ("open", "team", "sealed")))
    ctx = context(conversation_id=beam.session_id, operations={"read:bank", "recall:lexical"})
    registry = Registry()
    registry.register(ctx)
    reader = PolicyReader(store, bank="bank:a", verify_context=registry)
    yield beam, store, ctx, registry, reader
    beam.conn.close()


def seed(lexical, identity, text="orion gateway port", *, kind=RecordKind.WORKING,
         session_id="conversation:a", scope="session", expired=False, superseded=False, bound=True, **policy):
    beam, store, *_ = lexical
    beam.conn.execute(f"""INSERT INTO main.{kind.value}
        (id,content,session_id,scope,timestamp,source,valid_until,superseded_by)
        VALUES(?,?,?,?,?,?,?,?)""", (identity, text, session_id, scope, "2026-01-01T00:00:00Z", "synthetic",
                                   "2000-01-01T00:00:00Z" if expired else None, "later-id" if superseded else None))
    beam.conn.commit()
    if bound:
        store.bind(kind, identity, restriction(**policy))


def recall(lexical, query="orion gateway", **kwargs):
    beam, _, ctx, _, reader = lexical
    with bind_access_context(ctx):
        return beam.recall_authorized_lexical(query, reader=reader, destination="channel:a", **kwargs)


def test_real_fts_both_tiers_results_and_provenance_without_mutation(lexical):
    beam, store, ctx, registry, _ = lexical
    for kind, identity in ((RecordKind.WORKING, "w"), (RecordKind.EPISODIC, "e")):
        seed(lexical, identity, kind=kind)
    changes = beam.conn.total_changes
    report = recall(lexical)
    assert {hit.record_id for hit in report.hits} == {"w", "e"}
    assert all(hit.score == 1.0 and hit.content == "orion gateway port" for hit in report.hits)
    assert all(hit.context_id == ctx.context_id and hit.decision_id == "decision:a" for hit in report.hits)
    assert (report.examined_candidates, report.truncated, report.context_epoch) == (2, False, 1)
    assert len(registry.calls) == 1 and beam.conn.total_changes == changes
    assert not beam.conn.in_transaction and store.get_domain().mode == "prepared"
    assert CAPABILITIES.surfaces == {PolicySurface.LEXICAL}
    assert "orion" not in repr(report) and "orion" not in repr(report.hits[0])


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
@pytest.mark.parametrize("policy", [
    {"classification": "sealed"}, {"owner": "person:b"}, {"tenant_id": "tenant:b"},
    {"compartments": {"missing"}}, {"audiences": set()}, {"purposes": set()}, {"overlays": {"unknown"}},
])
def test_denied_content_never_reaches_python_or_scorer(lexical, monkeypatch, kind, policy):
    beam, *_ = lexical
    seed(lexical, "denied", text="orion gateway " + CANARY, kind=kind, **policy)
    seed(lexical, "allowed", kind=kind)
    scorer = beam_module._lexical_relevance_for_query
    scored = []

    def guarded(query, content):
        assert CANARY not in content
        scored.append(content)
        return scorer(query, content)

    def row_guard(cursor, row):
        assert all(CANARY not in value for value in row if isinstance(value, str))
        return sqlite3.Row(cursor, row)

    monkeypatch.setattr(beam_module, "_lexical_relevance_for_query", guarded)
    beam.conn.row_factory = row_guard
    assert [hit.record_id for hit in recall(lexical).hits] == ["allowed"]
    assert scored == ["orion gateway port"]


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
def test_denied_distractors_cannot_spend_pool_or_influence_scores(lexical, kind):
    seed(lexical, "z-allowed", kind=kind)
    before = recall(lexical, top_k=1, candidate_limit=1)
    for i in range(64):
        seed(lexical, f"a-denied-{i:03}", text="orion gateway " * (1 + i % 6), kind=kind, classification="sealed")
    after = recall(lexical, top_k=1, candidate_limit=1)
    assert [(h.record_id, h.score) for h in after.hits] == [(h.record_id, h.score) for h in before.hits]
    assert after.examined_candidates == before.examined_candidates == 1
    assert after.truncated is before.truncated is False


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
def test_native_scoping_precedes_pool_and_ignores_cross_session_env(lexical, monkeypatch, kind):
    monkeypatch.setenv("MNEMOSYNE_CROSS_SESSION", "1")
    for identity, kwargs in (("a-other", {"session_id": "other"}), ("b-expired", {"expired": True}),
                             ("c-superseded", {"superseded": True}), ("d-unbound", {"bound": False})):
        seed(lexical, identity, kind=kind, **kwargs)
    seed(lexical, "z-global", session_id="other", scope="global", kind=kind)
    report = recall(lexical, top_k=1, candidate_limit=1)
    assert [hit.record_id for hit in report.hits] == ["z-global"]
    assert report.examined_candidates == 1 and not report.truncated


def test_projects_union_proposed_exclusion_and_empty_selection(lexical):
    beam, store, _, _, _ = lexical
    catalog = PolicyProjects(store)
    catalog.prepare()
    for project in ("project:a", "project:b"):
        catalog.register(project, actor="admin")
    for identity, project, confirmed in (("a", "project:a", True), ("b", "project:b", True), ("proposed", "project:a", False)):
        seed(lexical, identity)
        assign(catalog, identity, project, confirmed=confirmed)
    ctx = project_context(conversation_id=beam.session_id, operations={"read:projects", "recall:lexical"})
    registry = ProjectRegistry(ctx)
    reader = PolicyReader(store, bank="bank:a", verify_context=registry)
    with bind_access_context(ctx):
        for selected, expected in (({"project:a"}, ["a"]), ({"project:b"}, ["b"]), ({"project:a", "project:b"}, ["a", "b"]), (set(), [])):
            report = beam.recall_authorized_lexical("orion gateway", reader=reader, destination="channel:a", projects=selected)
            assert [hit.record_id for hit in report.hits] == expected
            assert report.examined_candidates == len(expected)
    assert len(registry.calls) == 4


def test_context_conversation_operations_and_connection_are_mandatory(lexical, tmp_path):
    beam, store, ctx, registry, reader = lexical
    seed(lexical, "w")
    with pytest.raises(PolicyRefusal, match="missing_context"):
        beam.recall_authorized_lexical("orion", reader=reader, destination="channel:a")
    for bad in (replace(ctx, conversation_id=None), replace(ctx, conversation_id="other"), replace(ctx, operations={"read:bank"})):
        registry.register(bad)
        with bind_access_context(bad), pytest.raises(PolicyRefusal, match="access_denied"):
            beam.recall_authorized_lexical("orion", reader=reader, destination="channel:a")
    conn = sqlite3.connect(tmp_path / "other.db")
    try:
        other = PolicyReader(PolicyStore(conn), bank="bank:a", verify_context=registry)
        with bind_access_context(ctx), pytest.raises(PolicyRefusal, match="access_denied"):
            beam.recall_authorized_lexical("orion", reader=other, destination="channel:a")
    finally:
        conn.close()
    assert store.conn is beam.conn


def test_no_legacy_recall_fallback_ranker_provider_or_query_logging(lexical, monkeypatch):
    beam, *_ = lexical
    seed(lexical, "w")

    attempts = []

    def forbidden(*args, **kwargs):
        attempts.append("unsupported path")
        raise AssertionError("unsupported retrieval/provider path invoked")

    for name in ("_fts_search", "_fts_search_working", "_cjk_like_search", "_cyrillic_like_search", "_wm_vec_search"):
        monkeypatch.setattr(beam_module, name, forbidden)
    monkeypatch.setattr(BeamMemory, "recall", forbidden)
    from mnemosyne.core import embeddings, llm_backends, local_llm
    for name in ("get_embedding", "embed_query", "embed_text", "_get_model", "_embed_api"):
        if hasattr(embeddings, name):
            monkeypatch.setattr(embeddings, name, forbidden)
    for name in ("_download_model", "_load_llm_llamacpp", "_load_llm_ctransformers", "_call_remote_llm_with_model"):
        monkeypatch.setattr(local_llm, name, forbidden)
    monkeypatch.setattr(llm_backends, "call_host_llm", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    statements = []
    beam.conn.set_trace_callback(statements.append)
    assert [hit.record_id for hit in recall(lexical).hits] == ["w"]
    lowered = "\n".join(statements).lower()
    assert "match" in lowered and "native_eligible as materialized" in lowered
    forbidden_sql = [sql for sql in statements if any(word in sql.lower() for word in ("bm25", "insert ", "update ", "delete "))
                     or ("fts_" in sql.lower() and "order by rank" in sql.lower())]
    assert not forbidden_sql, forbidden_sql
    assert not attempts


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
def test_native_sql_content_is_evaluated_only_after_authorized_admission(lexical, kind):
    beam, store, *_ = lexical
    armed, evaluated, content_phase = [], [], [False]

    def guarded(value):
        if armed:
            assert content_phase[0], "content evaluated during metadata matching"
            assert CANARY not in value
            evaluated.append(value)
        return value

    beam.conn.create_function("guard_content", 1, guarded, deterministic=True)
    table = kind.value
    beam.conn.execute(f"DROP TABLE main.{table}")
    rowid = "rowid INTEGER PRIMARY KEY," if kind is RecordKind.EPISODIC else ""
    beam.conn.execute(f"""CREATE TABLE main.{table}({rowid}id TEXT UNIQUE NOT NULL,raw TEXT,
        content TEXT GENERATED ALWAYS AS (guard_content(raw)) VIRTUAL,session_id TEXT,scope TEXT,
        valid_until TEXT,superseded_by TEXT)""")
    for identity, content, level in (("allowed", "orion gateway", "team"), ("denied", "orion gateway " + CANARY, "sealed")):
        row = beam.conn.execute(f"INSERT INTO main.{table}(id,raw,session_id,scope) VALUES(?,?,?,?)",
                                (identity, content, "conversation:a", "session"))
        if kind is RecordKind.WORKING:
            beam.conn.execute("INSERT INTO main.fts_working(id,content) VALUES(?,?)", (identity, content))
        else:
            beam.conn.execute("INSERT INTO main.fts_episodes(rowid,content) VALUES(?,?)", (row.lastrowid, content))
        beam.conn.commit()
        store.bind(kind, identity, restriction(classification=level))

    def trace(sql):
        if sql.startswith("WITH eligible"):
            content_phase[0] = "CASE WHEN" in sql

    armed.append(True)
    beam.conn.set_trace_callback(trace)
    assert [hit.record_id for hit in recall(lexical).hits] == ["allowed"]
    assert evaluated and set(evaluated) == {"orion gateway"}


def test_hangul_exact_stage_retains_target_amid_authorized_prefix_flood(lexical):
    query = "\ubc14\ub098\ub098"
    for i in range(12):
        seed(lexical, f"a-prefix-{i:03}", text="\ubc14\ub098" + str(i))
    seed(lexical, "z-exact", text=query)
    report = recall(lexical, query, top_k=1, candidate_limit=3)
    assert [hit.record_id for hit in report.hits] == ["z-exact"]
    assert report.examined_candidates <= 3


def test_stage_overflow_false_is_not_a_completeness_certificate(lexical):
    query = "\ubc14\ub098\ub098"
    seed(lexical, "z-exact", text=query)
    seed(lexical, "a-expansion", text="\ubc14\ub098" + "00")
    report = recall(lexical, query, top_k=1, candidate_limit=1)
    assert [hit.record_id for hit in report.hits] == ["z-exact"]
    assert report.examined_candidates == 1 and report.truncated is False


def test_full_label_budget_and_content_chunks_fit_historical_variable_limit(lexical):
    beam, _, ctx, registry, _ = lexical
    for i in range(70):
        seed(lexical, f"row-{i:03}")
    ctx = replace(ctx, audiences={"internal"} | {f"a{i}" for i in range(255)},
                  compartments={"work"} | {f"c{i}" for i in range(255)})
    registry.register(ctx, owners={"person:a"} | {f"o{i}" for i in range(255)}, tenants={"tenant:a"} | {f"t{i}" for i in range(131)})
    if hasattr(beam.conn, "setlimit"):
        beam.conn.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)
    current = (beam, lexical[1], ctx, registry, lexical[4])
    report = recall(current, top_k=100, candidate_limit=100)
    assert len(report.hits) == report.examined_candidates == 70


def test_duplicate_fts_mapping_does_not_spend_pool_twice(lexical):
    beam, *_ = lexical
    seed(lexical, "a")
    seed(lexical, "b")
    for _ in range(5):
        beam.conn.execute("INSERT INTO fts_working(id,content) VALUES('a','orion gateway')")
    beam.conn.commit()
    report = recall(lexical, top_k=2, candidate_limit=2)
    assert [hit.record_id for hit in report.hits] == ["a", "b"]
    assert report.examined_candidates == 2 and not report.truncated


def test_missing_fts_and_catalog_errors_never_return_partial_success(lexical):
    beam, *_ = lexical
    seed(lexical, "w")
    beam.conn.execute("DROP TABLE fts_episodes")
    beam.conn.commit()
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        recall(lexical)
    assert not beam.conn.in_transaction


def test_missing_policy_schema_refuses_even_stopword_query(lexical):
    beam, *_ = lexical
    beam.conn.execute("DROP INDEX idx_policy_terms_reverse")
    with pytest.raises(PolicyStoreError, match="incompatible"):
        recall(lexical, "the and")


@pytest.mark.parametrize("fts,columns", [("fts_working", "id TEXT, content TEXT, fts_working TEXT, rank TEXT"),
                                         ("fts_episodes", "content TEXT, fts_episodes TEXT, rank TEXT")])
def test_empty_query_refuses_ordinary_table_instead_of_fts5(lexical, fts, columns):
    beam, *_ = lexical
    beam.conn.execute(f"DROP TABLE main.{fts}")
    beam.conn.execute(f"CREATE TABLE main.{fts}({columns})")
    beam.conn.commit()
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        recall(lexical, "the and")


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
def test_empty_query_refuses_missing_native_content_mapping(lexical, kind):
    beam, *_ = lexical
    beam.conn.execute(f"ALTER TABLE main.{kind.value} RENAME COLUMN content TO old_content")
    with pytest.raises(sqlite3.DatabaseError):
        recall(lexical, "the and")


@pytest.mark.parametrize("kwargs", [{"top_k": 0}, {"top_k": True}, {"top_k": 101}, {"candidate_limit": 1001},
                                     {"candidate_limit": True}, {"top_k": 3, "candidate_limit": 2}])
def test_query_and_pool_arguments_are_bounded(lexical, kwargs):
    with pytest.raises(ValueError):
        recall(lexical, **kwargs)


@pytest.mark.parametrize("query", [None, "", "   ", "x" * 4097, "bad\x85query"])
def test_invalid_query_refuses_without_echo(lexical, query):
    with pytest.raises(ValueError):
        recall(lexical, query)


def test_stopwords_empty_unsupported_fallback_and_safe_punctuation(lexical):
    assert recall(lexical, "the and").hits == ()
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        recall(lexical, "C++")
    seed(lexical, "w", text="rm -rf uses an orion gateway")
    assert [hit.record_id for hit in recall(lexical, "rm -rf").hits] == ["w"]
    assert recall(lexical, '" OR * : - ()').hits == ()


def test_return_content_cap_preserves_storage_and_late_scoring(lexical, monkeypatch):
    monkeypatch.setattr(beam_module, "RECALL_CONTENT_CAP", 20)
    text = "intro " * 30 + "orion gateway"
    seed(lexical, "w", text=text)
    hit = recall(lexical).hits[0]
    assert hit.score == 1 and hit.content == text[:20] and hit.content_truncated
    assert lexical[0].conn.execute("SELECT content FROM working_memory WHERE id='w'").fetchone()[0] == text


def test_oversized_authorized_memory_refuses_without_python_materialization(lexical):
    beam, *_ = lexical
    seed(lexical, "huge", text="orion gateway " + "x" * MAX_SCORING_CHARACTERS)

    def guarded(cursor, row):
        assert all(len(value) <= MAX_SCORING_CHARACTERS for value in row if isinstance(value, str))
        return sqlite3.Row(cursor, row)

    beam.conn.row_factory = guarded
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        recall(lexical)


@pytest.mark.parametrize("kind", [RecordKind.WORKING, RecordKind.EPISODIC])
@pytest.mark.parametrize("tail_size", [1, 100000])
def test_embedded_nul_cannot_bypass_native_scoring_bound(lexical, kind, tail_size):
    beam, *_ = lexical
    seed(lexical, "nul", text="orion gateway\x00" + "x" * tail_size, kind=kind)

    def guarded(cursor, row):
        assert all("\x00" not in value and len(value) <= MAX_SCORING_CHARACTERS for value in row if isinstance(value, str))
        return sqlite3.Row(cursor, row)

    beam.conn.row_factory = guarded
    with pytest.raises(PolicyStoreError, match="incompatible"):
        recall(lexical)


def test_pool_overflow_report_is_authorized_only_and_deterministic(lexical):
    for identity in ("a", "b", "c"):
        seed(lexical, identity)
    report = recall(lexical, top_k=1, candidate_limit=2)
    assert [hit.record_id for hit in report.hits] == ["a"]
    assert report.truncated and report.examined_candidates == 2


def test_literal_flag_collision_reuses_existing_guard(lexical):
    seed(lexical, "bare", text="git force install")
    seed(lexical, "literal", text="git --force install")
    assert [hit.record_id for hit in recall(lexical, "--force install").hits] == ["literal"]


def test_caller_transaction_and_snapshot_survive_qualified_read(lexical):
    beam, *_ = lexical
    seed(lexical, "w")
    beam.conn.execute("UPDATE working_memory SET importance=0.9 WHERE id='w'")
    assert recall(lexical).hits
    assert beam.conn.in_transaction
    beam.conn.rollback()
    assert beam.conn.execute("SELECT importance FROM working_memory WHERE id='w'").fetchone()[0] == 0.5


def test_atomic_policy_and_content_change_cannot_cross_snapshot(lexical):
    beam, *_ = lexical
    seed(lexical, "w")
    beam.conn.execute("PRAGMA journal_mode=WAL")
    other = sqlite3.connect(str(beam.db_path))
    changed = []

    def during_content(sql):
        if sql.startswith("WITH eligible") and "CASE WHEN" in sql and not changed:
            changed.append(True)
            other.execute("UPDATE policy_bindings SET classification='sealed' WHERE record_id='w'")
            other.execute("UPDATE working_memory SET content=? WHERE id='w'", ("orion gateway " + CANARY,))
            other.commit()

    beam.conn.set_trace_callback(during_content)
    try:
        first = recall(lexical)
        assert changed and first.hits[0].content == "orion gateway port"
        second = recall(lexical)
        assert second.hits == () and second.examined_candidates == 0
    finally:
        beam.conn.set_trace_callback(None)
        other.close()


def test_main_fts_tables_ignore_temp_shadows(lexical):
    beam, *_ = lexical
    seed(lexical, "w")
    beam.conn.execute("CREATE TEMP TABLE fts_working(id TEXT, content TEXT)")
    beam.conn.execute("INSERT INTO temp.fts_working VALUES('w',?)", (CANARY,))
    beam.conn.execute("CREATE TEMP TABLE fts_episodes(rowid INTEGER, content TEXT)")
    beam.conn.commit()
    assert [hit.content for hit in recall(lexical).hits] == ["orion gateway port"]


def test_expansion_term_budget_refuses_without_truncating_intent(lexical):
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        recall(lexical, " ".join(f"qword{i}" for i in range(130)))


def test_async_contexts_and_verifier_revocation_do_not_cross(lexical):
    beam, _, ctx, registry, reader = lexical
    seed(lexical, "w")
    other = replace(ctx, context_id="ctx:b", conversation_id="other")
    registry.register(other)

    async def exercise():
        async def allowed():
            with bind_access_context(ctx):
                await asyncio.sleep(0)
                return [hit.record_id for hit in beam.recall_authorized_lexical("orion", reader=reader, destination="channel:a").hits]

        async def denied():
            with bind_access_context(other):
                await asyncio.sleep(0)
                with pytest.raises(PolicyRefusal, match="access_denied"):
                    beam.recall_authorized_lexical("orion", reader=reader, destination="channel:a")

        results = await asyncio.gather(allowed(), denied(), allowed())
        assert results == [["w"], None, ["w"]]

    asyncio.run(exercise())
    registry.contexts.pop(ctx.context_id)
    with pytest.raises(PolicyRefusal, match="access_denied"):
        recall(lexical)


def test_lexical_quality_and_bounded_measurement(lexical, capsys):
    expected = []
    for i in range(128):
        identity = f"row-{i:03}"
        allowed = i % 4 == 0
        seed(lexical, identity, text="orion gateway port " + ("allowed" if allowed else CANARY),
             classification="team" if allowed else "sealed")
        if allowed:
            expected.append(identity)
    samples = []
    changes = lexical[0].conn.total_changes
    for _ in range(30):
        start = time.perf_counter_ns()
        report = recall(lexical, top_k=100, candidate_limit=100)
        samples.append((time.perf_counter_ns() - start) / 1e6)
        assert [hit.record_id for hit in report.hits] == expected
        assert not report.truncated and report.examined_candidates == 32
    assert lexical[0].conn.total_changes == changes
    root = Path(__file__).resolve().parents[1]
    hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ("mnemosyne/core/beam.py", "mnemosyne/core/policy_lexical.py")}
    measurement = dict(workload="actual BEAM/FTS 128 rows, 32 authorized, 30 repeats", false_allows=0,
                       expected_id_sha256=hashlib.sha256(json.dumps(expected).encode()).hexdigest(),
                       samples_ms=samples, p50_ms=statistics.median(samples), source_sha256=hashes,
                       python=sys.version, sqlite=sqlite3.sqlite_version,
                       database_bytes=lexical[0].conn.execute("PRAGMA page_count").fetchone()[0] * lexical[0].conn.execute("PRAGMA page_size").fetchone()[0],
                       boundary="lexical only; no hybrid ranking quality or approved overhead budget")
    with capsys.disabled():
        print("P2C_MEASUREMENT=" + json.dumps(measurement, sort_keys=True))
