"""Synthetic P2a qualification, not protected-mode or live adapter acceptance."""

import asyncio
import hashlib
import json
import sqlite3
import statistics
import sys
import time
from pathlib import Path

import pytest

from mnemosyne.core.policy import (
    AccessContext, MemoryPolicy, PolicyDefinition, PolicyRefusal, PolicySurface, RefusalReason,
)
from mnemosyne.core.policy_read import AuthorizedCandidate, BankReadGrant, PolicyReader
from mnemosyne.core.policy_store import PolicyStore, PolicyStoreError, RecordKind
from mnemosyne.runtime_context import bind_access_context


CANARY = "DENIED-SYNTHETIC-CONTENT-DO-NOT-RETURN"


def context(**changes):
    values = dict(context_id="ctx:a", epoch=1, policy_id="test", policy_version=1,
                  issuer="test-host", platform="fixture", principals={"person:a"},
                  classification_ceiling="team", purpose="engineering", assurance="authenticated",
                  banks={"bank:a"}, destinations={"channel:a"}, operations={"read:bank"},
                  compartments={"work"}, audiences={"internal"})
    values.update(changes)
    return AccessContext(**values)


def restriction(**changes):
    values = dict(policy_id="test", policy_version=1, classification="team", owner="person:a",
                  classification_source="manual", audiences={"internal"}, purposes={"engineering"},
                  compartments={"work"}, tenant_id="tenant:a")
    values.update(changes)
    return MemoryPolicy(**values)


class Registry:
    """Trusted fixture only: real hosts must authenticate/intersect all grants."""

    def __init__(self):
        self.contexts = {}
        self.calls = []

    def register(self, ctx, **changes):
        values = dict(context_fingerprint=ctx.fingerprint(), domain_id="domain:a", bank="bank:a",
                      destination="channel:a", decision_id="decision:a", owners={"person:a"}, tenants={"tenant:a"})
        values.update(changes)
        self.contexts[ctx.context_id] = (ctx.fingerprint(), BankReadGrant(**values))

    def __call__(self, ctx, *, bank, destination):
        self.calls.append((ctx.context_id, bank, destination))
        current = self.contexts.get(ctx.context_id)
        if current is None or current[0] != ctx.fingerprint():
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return current[1]


def add(store, identity, *, kind=RecordKind.WORKING, content="allowed synthetic", **policy):
    column = "body" if kind is RecordKind.CANONICAL else "content"
    store.conn.execute(f"INSERT INTO main.{kind.value}(id,{column}) VALUES (?,?)", (identity, content))
    store.conn.commit()
    return store.bind(kind, identity, restriction(**policy))


@pytest.fixture
def fixture(tmp_path):
    conn = sqlite3.connect(tmp_path / "read.db")
    conn.execute("CREATE TABLE working_memory(id TEXT PRIMARY KEY,content TEXT)")
    conn.execute("CREATE TABLE episodic_memory(id TEXT UNIQUE,content TEXT)")
    conn.execute("CREATE TABLE canonical_facts(id INTEGER PRIMARY KEY,body TEXT)")
    conn.commit()
    store = PolicyStore(conn)
    store.prepare("domain:a")
    store.register_definition(PolicyDefinition("test", 1, ("open", "team", "sealed")))
    registry = Registry()
    registry.register(context())
    yield store, registry, PolicyReader(store, bank="bank:a", verify_context=registry)
    conn.close()


def read(reader, identity="w", *, ctx=None, kind=RecordKind.WORKING):
    with bind_access_context(ctx or context()):
        return reader.get(kind, identity, destination="channel:a")


@pytest.mark.parametrize("kind,identity", [(RecordKind.WORKING, "w"), (RecordKind.EPISODIC, "e"), (RecordKind.CANONICAL, 1)])
def test_authorized_direct_read_provenance_and_candidate_content_boundary(fixture, kind, identity):
    store, registry, reader = fixture
    binding = add(store, identity, kind=kind)
    row = read(reader, identity, kind=kind)
    assert (row.record_id, row.record_kind, row.content) == (identity, kind, "allowed synthetic")
    assert (row.bank, row.binding_id, row.policy_id, row.policy_version, row.classification) == (
        "bank:a", binding.binding_id, "test", 1, "team")
    assert (row.context_id, row.context_epoch, row.decision_id) == ("ctx:a", 1, "decision:a")
    assert "synthetic" not in repr(row)
    with bind_access_context(context()):
        rows = reader.candidate_ids(kind, destination="channel:a")
    assert type(rows[0]) is AuthorizedCandidate and not hasattr(rows[0], "content")
    assert rows[0].record_id == identity and len(registry.calls) == 2
    assert not store.conn.in_transaction


@pytest.mark.parametrize("changes", [
    {"classification": "sealed"}, {"compartments": {"missing"}}, {"compartments": {"work", "missing"}},
    {"audiences": {"outsider"}}, {"audiences": set()}, {"purposes": {"marketing"}}, {"purposes": set()},
    {"owner": "person:b"}, {"tenant_id": "tenant:b"}, {"overlays": {"future:unknown"}},
])
def test_each_restriction_denies_without_returning_content(fixture, changes):
    store, _, reader = fixture
    add(store, "w", content=CANARY, **changes)
    assert read(reader) is None
    assert read(reader, "absent") is None
    with bind_access_context(context()):
        assert reader.candidate_ids(RecordKind.WORKING, destination="channel:a") == []


def test_missing_binding_unknown_term_and_unknown_classification_deny(fixture):
    store, _, reader = fixture
    store.conn.execute("INSERT INTO working_memory VALUES('unbound',?)", (CANARY,))
    store.conn.commit()
    binding = add(store, "unknown", content=CANARY)
    store.conn.execute("INSERT INTO policy_binding_terms VALUES(?, 'new-restriction', 'deny')", (binding.binding_id,))
    add(store, "bad-level", content=CANARY)
    store.conn.execute("UPDATE policy_bindings SET classification='unknown' WHERE record_id='bad-level'")
    store.conn.commit()
    for identity in ("unbound", "unknown", "bad-level"):
        assert read(reader, identity) is None


@pytest.mark.parametrize("changes,reason", [
    ({"projects": {"project:a"}}, RefusalReason.UNSUPPORTED_SURFACE),
    ({"assurance": "owner"}, RefusalReason.UNSUPPORTED_SURFACE),
    ({"operations": set()}, RefusalReason.ACCESS_DENIED),
    ({"operations": {"read"}}, RefusalReason.ACCESS_DENIED),
    ({"banks": set()}, RefusalReason.ACCESS_DENIED),
    ({"banks": {"*"}}, RefusalReason.ACCESS_DENIED),
    ({"destinations": set()}, RefusalReason.ACCESS_DENIED),
])
def test_unsupported_or_unselected_context_does_not_query_native(fixture, changes, reason):
    store, registry, reader = fixture
    add(store, "w")
    ctx = context(**changes)
    registry.register(ctx)
    statements = []
    store.conn.set_trace_callback(statements.append)
    with pytest.raises(PolicyRefusal) as error:
        read(reader, ctx=ctx)
    assert error.value.reason is reason and not statements and not registry.calls


def test_missing_context_never_promotes_request_token_or_empty_project_selection(fixture):
    _, _, reader = fixture
    with bind_access_context(None), pytest.raises(PolicyRefusal, match="missing_context"):
        reader.get(RecordKind.WORKING, "w", destination="channel:a")
    with pytest.raises(PolicyRefusal, match="access_denied"):
        read(reader, ctx=context(projects=set(), operations=set()))


@pytest.mark.parametrize("changes", [
    {"context_fingerprint": "0" * 64}, {"domain_id": "domain:b"}, {"bank": "bank:b"}, {"destination": "channel:b"},
])
def test_grant_must_match_exact_request_and_store(fixture, changes):
    store, registry, reader = fixture
    add(store, "w")
    registry.register(context(), **changes)
    with pytest.raises(PolicyRefusal, match="access_denied"):
        read(reader)


@pytest.mark.parametrize("owners,tenants,expected", [
    (set(), {"tenant:a"}, False), ({"person:a"}, set(), False),
    ({"person:a"}, {"tenant:a"}, True), ({"person:b"}, {"tenant:a"}, False),
])
def test_owner_and_tenant_intersection_not_union(fixture, owners, tenants, expected):
    store, registry, reader = fixture
    add(store, "w")
    registry.register(context(), owners=owners, tenants=tenants)
    assert (read(reader) is not None) == expected
    add(store, "no-tenant", tenant_id=None)
    assert (read(reader, "no-tenant") is not None) == ("person:a" in owners)


def test_unknown_policy_version_or_ceiling_refuses(fixture):
    _, registry, reader = fixture
    for ctx in (context(policy_version=2), context(classification_ceiling="unknown")):
        registry.register(ctx)
        with pytest.raises(PolicyRefusal, match="policy_mismatch"):
            read(reader, ctx=ctx)


def test_fresh_verification_rejects_revoked_and_old_copied_contexts(fixture):
    store, registry, reader = fixture
    add(store, "w")
    assert read(reader)
    registry.register(context(epoch=2))
    with pytest.raises(PolicyRefusal, match="access_denied"):
        read(reader)
    assert read(reader, ctx=context(epoch=2))
    registry.contexts.clear()
    with pytest.raises(PolicyRefusal, match="access_denied"):
        read(reader, ctx=context(epoch=2))
    assert len(registry.calls) == 4


def test_verifier_is_mandatory_typed_synchronous_and_failure_is_not_empty_success(fixture):
    store, _, _ = fixture
    with pytest.raises(TypeError):
        PolicyReader(store, bank="bank:a")
    with pytest.raises(TypeError):
        PolicyReader(None, bank="bank:a", verify_context=lambda c: None)
    with pytest.raises(TypeError):
        PolicyReader(store, bank="bank:a", verify_context=None)

    async def async_verify(*args, **kwargs):
        return None

    with pytest.raises(TypeError):
        PolicyReader(store, bank="bank:a", verify_context=async_verify)
    for output in (None, {}, True):
        reader = PolicyReader(store, bank="bank:a", verify_context=lambda *a, **k: output)
        with pytest.raises(PolicyRefusal, match="access_denied"):
            read(reader)
    reader = PolicyReader(store, bank="bank:a", verify_context=lambda *a, **k: async_verify())
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        read(reader)

    def failed(*args, **kwargs):
        raise RuntimeError(CANARY)

    reader = PolicyReader(store, bank="bank:a", verify_context=failed)
    with pytest.raises(PolicyRefusal) as error:
        read(reader)
    assert error.value.args == ("policy_refused:context_unavailable",)
    assert CANARY not in repr(error.value)


def test_cancellation_is_not_swallowed(fixture):
    store, _, _ = fixture

    def cancelled(*args, **kwargs):
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        read(PolicyReader(store, bank="bank:a", verify_context=cancelled))
    assert not store.conn.in_transaction


def test_no_content_materialized_for_denied_rows_or_candidate_listing(fixture):
    store, _, reader = fixture
    add(store, "denied", content=CANARY, classification="sealed")
    add(store, "allowed")
    materialized = []

    def tripwire(cursor, row):
        assert CANARY not in row
        if cursor.description and any(c[0] in ("body", "content") for c in cursor.description):
            materialized.append(tuple(row))
        return sqlite3.Row(cursor, row)

    store.conn.row_factory = tripwire
    assert read(reader, "denied") is None
    with bind_access_context(context()):
        assert len(reader.candidate_ids(RecordKind.WORKING, destination="channel:a")) == 1
    assert materialized == []
    assert read(reader, "allowed").content == "allowed synthetic"
    assert len(materialized) == 1 and store.conn.row_factory is tripwire


@pytest.mark.parametrize("autocommit", [None, True, False])
def test_sql_content_evaluation_happens_only_for_authorized_direct_read(fixture, autocommit):
    store, _, reader = fixture
    if autocommit is not None and not hasattr(store.conn, "autocommit"):
        pytest.skip("explicit sqlite3 autocommit mode requires Python 3.12+")
    evaluated = []
    armed = []

    def content_tripwire(value):
        if armed:
            evaluated.append(value)
            if value == CANARY:
                raise AssertionError("denied SQL content was evaluated")
        return value

    store.conn.create_function("guard_content", 1, content_tripwire, deterministic=True)
    store.conn.execute("DROP TABLE working_memory")
    store.conn.execute("CREATE TABLE working_memory(id TEXT PRIMARY KEY, raw TEXT, content TEXT GENERATED ALWAYS AS (guard_content(raw)) VIRTUAL)")
    store.conn.executemany("INSERT INTO working_memory(id,raw) VALUES (?,?)", [("allowed", "allowed synthetic"), ("denied", CANARY)])
    store.conn.commit()
    store.bind(RecordKind.WORKING, "allowed", restriction())
    store.bind(RecordKind.WORKING, "denied", restriction(classification="sealed"))
    if autocommit is not None:
        store.conn.autocommit = autocommit
    armed.append(True)
    assert read(reader, "denied") is None
    with bind_access_context(context()):
        assert [r.record_id for r in reader.candidate_ids(RecordKind.WORKING, destination="channel:a")] == ["allowed"]
    assert evaluated == []
    assert read(reader, "allowed").content == "allowed synthetic"
    assert evaluated == ["allowed synthetic"]


def test_materialized_metadata_and_indexed_plan_before_content(fixture):
    store, registry, reader = fixture
    add(store, "w")
    ctx = context()
    grant = registry(ctx, bank="bank:a", destination="channel:a")
    with store._transaction():
        sql, params = reader._selection(RecordKind.WORKING, ctx, grant, "w")
        plan = store.conn.execute("EXPLAIN QUERY PLAN " + sql + " SELECT * FROM eligible", params).fetchall()
    details = "\n".join(r[3] for r in plan)
    assert "MATERIALIZE eligible" in details
    assert any(name in details for name in (
        "idx_policy_binding_classification", "idx_policy_binding_owner", "sqlite_autoindex_policy_bindings",
    ))
    assert "main.working_memory" not in sql and "b.record_id=?" in sql


def test_denied_and_orphaned_candidates_do_not_consume_limit_or_offset(fixture):
    store, _, reader = fixture
    for i in range(12):
        add(store, f"a-denied-{i:02}", content=CANARY, classification="sealed")
    add(store, "b-orphan")
    store.conn.execute("DELETE FROM working_memory WHERE id='b-orphan'")
    store.conn.commit()
    for identity in ("c-one", "d-two", "e-three"):
        add(store, identity)
    with bind_access_context(context()):
        assert [r.record_id for r in reader.candidate_ids(RecordKind.WORKING, destination="channel:a", limit=1)] == ["c-one"]
        assert [r.record_id for r in reader.candidate_ids(RecordKind.WORKING, destination="channel:a", limit=1, offset=1)] == ["d-two"]


@pytest.mark.parametrize("kwargs", [{"limit": 0}, {"limit": 1001}, {"limit": True}, {"offset": -1}, {"offset": True}, {"offset": 2**63}])
def test_bounded_candidate_arguments(fixture, kwargs):
    _, _, reader = fixture
    with bind_access_context(context()), pytest.raises(ValueError):
        reader.candidate_ids(RecordKind.WORKING, destination="channel:a", **kwargs)


def test_bound_identifiers_allowlist_and_canonical_id_types(fixture):
    store, _, reader = fixture
    identity = "w'); DROP TABLE policy_bindings; --"
    add(store, identity)
    assert read(reader, identity).record_id == identity
    for invalid in ("working_memory", "working_memory;drop", None):
        with pytest.raises(ValueError):
            read(reader, kind=invalid)
    for invalid in ("1", True, 0):
        with pytest.raises(ValueError):
            read(reader, invalid, kind=RecordKind.CANONICAL)


def test_old_sqlite_and_parameter_budget_refuse_without_truncation(fixture, monkeypatch):
    store, registry, reader = fixture
    ctx = context(audiences={f"a{i}" for i in range(256)}, compartments={f"c{i}" for i in range(256)})
    registry.register(ctx, owners={f"o{i}" for i in range(256)}, tenants={f"t{i}" for i in range(256)})
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        read(reader, ctx=ctx)
    registry.register(context())
    monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 34, 0))
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        read(reader)
    assert not store.conn.in_transaction


@pytest.mark.parametrize("changes", [
    {"context_fingerprint": "x" * 64}, {"context_fingerprint": "0" * 63},
    {"domain_id": "bad\nvalue"}, {"bank": ""}, {"destination": " channel:a"},
    {"decision_id": "\x85"}, {"owners": "person:a"}, {"owners": {"o" * 257}},
    {"tenants": {str(i) for i in range(257)}},
])
def test_grant_validation_does_not_echo_values(changes):
    values = dict(context_fingerprint=context().fingerprint(), domain_id="domain:a", bank="bank:a",
                  destination="channel:a", decision_id="decision:a", owners={"person:a"})
    values.update(changes)
    with pytest.raises(ValueError):
        BankReadGrant(**values)


def test_exact_parameter_budget_boundary_and_immutable_grant(fixture):
    store, registry, reader = fixture
    add(store, "w")
    ctx = context(audiences={"internal"} | {f"a{i}" for i in range(255)},
                  compartments={"work"} | {f"c{i}" for i in range(255)})
    owners = {"person:a"} | {f"o{i}" for i in range(255)}
    tenants = {"tenant:a"} | {f"t{i}" for i in range(131)}
    assert sum(map(len, (ctx.audiences, ctx.compartments, owners, tenants))) == 900
    registry.register(ctx, owners=owners, tenants=tenants)
    owners.clear()
    assert read(reader, ctx=ctx)
    registry.register(ctx, owners={"person:a"} | {f"o{i}" for i in range(255)}, tenants=tenants | {"one-too-many"})
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        read(reader, ctx=ctx)


def test_empty_audiences_and_compartments_are_not_wildcards(fixture):
    store, registry, reader = fixture
    add(store, "w")
    for ctx in (context(audiences=set()), context(compartments=set())):
        registry.register(ctx)
        assert read(reader, ctx=ctx) is None
    add(store, "no-compartment", compartments=set())
    ctx = context(compartments=set())
    registry.register(ctx)
    assert read(reader, "no-compartment", ctx=ctx)


def test_unsupported_paths_not_declared(fixture):
    _, _, reader = fixture
    assert reader.capabilities.surfaces == {PolicySurface.DIRECT}
    for surface in PolicySurface:
        if surface is not PolicySurface.DIRECT:
            with pytest.raises(PolicyRefusal, match="unsupported_surface"):
                reader.capabilities.require(surface)


def test_unprepared_incompatible_catalog_and_sql_errors_do_not_fallback(fixture):
    store, _, reader = fixture
    add(store, "w")
    store.conn.execute("DROP INDEX idx_policy_terms_reverse")
    with pytest.raises(PolicyStoreError, match="incompatible"):
        read(reader)
    assert not store.conn.in_transaction
    absent = PolicyStore(sqlite3.connect(":memory:"))
    try:
        reader = PolicyReader(absent, bank="bank:a", verify_context=fixture[1])
        with pytest.raises(PolicyStoreError, match="unprepared"):
            read(reader)
    finally:
        absent.conn.close()


def test_no_native_mutations_or_caller_transaction_commit_and_safe_failure(fixture):
    store, _, reader = fixture
    add(store, "w")
    before = store.conn.total_changes
    schema = store.conn.execute("SELECT sql FROM sqlite_master ORDER BY name").fetchall()
    assert read(reader)
    assert store.conn.total_changes == before
    assert store.conn.execute("SELECT sql FROM sqlite_master ORDER BY name").fetchall() == schema
    store.conn.execute("INSERT INTO working_memory VALUES ('pending','caller data')")
    assert read(reader)
    assert store.conn.in_transaction

    def deny_content(action, table, column, *_):
        return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_READ and table == "working_memory" and column == "content" else sqlite3.SQLITE_OK

    store.conn.set_authorizer(deny_content)
    with pytest.raises(sqlite3.DatabaseError):
        read(reader)
    store.conn.set_authorizer(lambda *args: sqlite3.SQLITE_OK)
    assert store.conn.in_transaction
    assert store.conn.execute("SELECT content FROM working_memory WHERE id='pending'").fetchone()[0] == "caller data"
    store.conn.rollback()
    assert store.conn.execute("SELECT 1 FROM working_memory WHERE id='pending'").fetchone() is None


def test_temp_shadows_are_not_read(fixture):
    store, _, reader = fixture
    add(store, "w")
    store.conn.execute("CREATE TEMP TABLE working_memory(id TEXT,content TEXT)")
    store.conn.execute("INSERT INTO temp.working_memory VALUES('w',?)", (CANARY,))
    store.conn.execute("CREATE TEMP TABLE policy_bindings(binding_id TEXT)")
    store.conn.commit()
    assert read(reader).content == "allowed synthetic"


def test_snapshot_consistency_when_policy_changes_during_read(fixture):
    store, _, reader = fixture
    add(store, "w")
    store.conn.execute("PRAGMA journal_mode=WAL")
    filename = store.conn.execute("PRAGMA database_list").fetchone()[2]
    other = sqlite3.connect(filename)
    triggered = []

    def during_read(statement):
        if statement.startswith("WITH eligible") and not triggered:
            triggered.append(True)
            other.execute("UPDATE policy_bindings SET classification='sealed' WHERE record_id='w'")
            other.execute("UPDATE working_memory SET content=? WHERE id='w'", (CANARY,))
            other.commit()

    store.conn.set_trace_callback(during_read)
    try:
        assert read(reader).content == "allowed synthetic"
        assert triggered
        assert read(reader) is None
    finally:
        store.conn.set_trace_callback(None)
        other.close()


def test_async_a_b_a_contexts_and_copied_revocation(fixture):
    store, registry, reader = fixture
    add(store, "a", owner="person:a")
    add(store, "b", owner="person:b", audiences={"external"})
    a = context()
    b = context(context_id="ctx:b", principals={"person:b"}, audiences={"external"})
    registry.register(b, owners={"person:b"}, decision_id="decision:b")

    async def exercise():
        results = []
        a_bound = asyncio.Event()
        b_done = asyncio.Event()

        async def caller_a():
            with bind_access_context(a):
                results.append([r.record_id for r in reader.candidate_ids(RecordKind.WORKING, destination="channel:a")])
                a_bound.set()
                await b_done.wait()
                results.append([r.record_id for r in reader.candidate_ids(RecordKind.WORKING, destination="channel:a")])

        async def caller_b():
            await a_bound.wait()
            with bind_access_context(b):
                results.append([r.record_id for r in reader.candidate_ids(RecordKind.WORKING, destination="channel:a")])
            b_done.set()

        await asyncio.gather(caller_a(), caller_b())
        assert results == [["a"], ["b"], ["a"]]
        gate = asyncio.Event()

        async def copied():
            await gate.wait()
            with pytest.raises(PolicyRefusal, match="access_denied"):
                reader.get(RecordKind.WORKING, "a", destination="channel:a")

        with bind_access_context(a):
            child = asyncio.create_task(copied())
        registry.contexts.pop(a.context_id)
        gate.set()
        await child

    asyncio.run(exercise())


def test_bounded_quality_and_read_measurement(fixture, capsys):
    """Reproducible workload with raw samples; not an approved overhead budget."""
    store, _, reader = fixture
    expected = []
    for i in range(128):
        identity = f"row-{i:03}"
        allowed = i % 4 == 0
        add(store, identity, classification="team" if allowed else "sealed",
            content="allowed synthetic" if allowed else CANARY)
        if allowed:
            expected.append(identity)
    samples, direct_samples = [], []
    with bind_access_context(context()):
        for _ in range(100):
            start = time.perf_counter_ns()
            rows = reader.candidate_ids(RecordKind.WORKING, destination="channel:a", limit=1000)
            samples.append((time.perf_counter_ns() - start) / 1e6)
            assert [r.record_id for r in rows] == expected
            start = time.perf_counter_ns()
            assert reader.get(RecordKind.WORKING, expected[0], destination="channel:a").content == "allowed synthetic"
            direct_samples.append((time.perf_counter_ns() - start) / 1e6)
    source = Path(__file__).resolve().parents[1]
    source_hashes = {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in (
        "mnemosyne/core/policy.py", "mnemosyne/core/policy_read.py", "mnemosyne/core/policy_store.py",
    )}
    report = dict(workload="128 native rows; 32 authorized; 100 repeats", false_allows=0,
                  expected_id_sha256=hashlib.sha256(json.dumps(expected).encode()).hexdigest(),
                  candidate_ms=samples, direct_ms=direct_samples,
                  candidate_p50_ms=statistics.median(samples), direct_p50_ms=statistics.median(direct_samples),
                  sqlite=sqlite3.sqlite_version, python=sys.version, source_files_sha256=source_hashes,
                  provider_calls="not instrumented here; read path uses stdlib SQLite only",
                  database_bytes=store.conn.execute("PRAGMA page_size").fetchone()[0] * store.conn.execute("PRAGMA page_count").fetchone()[0],
                  injected_tokens=None, token_note="no prompt-packing workload",
                  boundary="synthetic bank-wide reader; not BEAM quality or an overhead budget")
    with capsys.disabled():
        print("P2A_MEASUREMENT=" + json.dumps(report, sort_keys=True))
