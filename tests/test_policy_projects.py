"""Synthetic project relevance; not active policy, transport or live memory tests."""

import asyncio
import hashlib
import json
import os
import sqlite3
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier

import pytest

from mnemosyne.core.policy import PolicyRefusal, RefusalReason
from mnemosyne.core.policy_projects import PolicyProjects
from mnemosyne.core.policy_read import BankReadGrant, PolicyReader, ProjectReadGrant
from mnemosyne.core.policy_store import PolicyStore, PolicyStoreError, RecordKind
from mnemosyne.runtime_context import bind_access_context
from tests.test_policy_read import CANARY, add, context, fixture as fixture, restriction


def project_context(**changes):
    values = dict(projects={"project:a", "project:b"}, operations={"read:projects"})
    values.update(changes)
    return context(**values)


class ProjectRegistry:
    """Test authority only; production authentication remains a host obligation."""

    def __init__(self, ctx):
        self.fingerprint = ctx.fingerprint()
        self.calls = []
        self.overrides = {}

    def __call__(self, ctx, *, bank, destination, projects):
        if ctx.fingerprint() != self.fingerprint or not projects <= ctx.projects:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        self.calls.append((ctx.fingerprint(), projects))
        values = dict(context_fingerprint=ctx.fingerprint(), domain_id="domain:a", bank=bank, destination=destination,
                      decision_id="decision:projects", owners={"person:a"}, tenants={"tenant:a"}, projects=projects)
        values.update(self.overrides)
        return ProjectReadGrant(**values)


@pytest.fixture
def projects(fixture):
    store, _, _ = fixture
    catalog = PolicyProjects(store)
    catalog.prepare()
    for project in ("project:a", "project:b", "project:empty"):
        catalog.register(project, actor="admin:fixture")
    ctx = project_context()
    registry = ProjectRegistry(ctx)
    reader = PolicyReader(store, bank="bank:a", verify_context=registry)
    return store, catalog, ctx, registry, reader


def assign(catalog, identity, project="project:a", *, confirmed=True, kind=RecordKind.WORKING):
    result = catalog.propose(kind, identity, project, origin="synthetic-import", actor="importer:fixture")
    if confirmed:
        catalog.confirm(kind, identity, project, actor="reviewer:fixture")
    return result


def selected(projects, selection=("project:a",), *, kind=RecordKind.WORKING, **kwargs):
    _, _, ctx, _, reader = projects
    with bind_access_context(ctx):
        return reader.candidate_ids(kind, destination="channel:a", projects=selection, **kwargs)


def test_no_implicit_preparation_and_existing_bank_reader_unchanged(fixture):
    store, _, reader = fixture
    catalog = PolicyProjects(store)
    before = store.conn.total_changes
    assert catalog.get_domain() is None
    assert catalog.get_membership(RecordKind.WORKING, "absent", "project:a") is None
    assert store.conn.total_changes == before
    add(store, "w")
    with bind_access_context(context()):
        assert reader.get(RecordKind.WORKING, "w", destination="channel:a")
    assert store.conn.execute("SELECT name FROM sqlite_master WHERE name LIKE 'policy_project%'").fetchall() == []
    with pytest.raises(PolicyStoreError, match="unprepared"):
        catalog.register("project:a", actor="admin:fixture")
    raw = PolicyStore(sqlite3.connect(":memory:"))
    try:
        with pytest.raises(PolicyStoreError, match="unprepared"):
            PolicyProjects(raw).prepare()
    finally:
        raw.conn.close()
    with pytest.raises(TypeError):
        PolicyProjects(None)


def test_optional_preparation_preserves_native_state_and_is_idempotent(fixture):
    store, _, _ = fixture
    add(store, "w")
    before = store.conn.execute("SELECT * FROM working_memory").fetchall()
    store.conn.execute("PRAGMA user_version=12345")
    catalog = PolicyProjects(store)
    first = catalog.prepare()
    changes = store.conn.total_changes
    assert catalog.prepare() == first
    assert catalog.get_domain().domain_id == "domain:a"
    assert store.conn.total_changes == changes
    assert store.conn.execute("PRAGMA user_version").fetchone()[0] == 12345
    assert store.conn.execute("SELECT * FROM working_memory").fetchall() == before
    assert store.get_domain().mode == "prepared" and not store.conn.in_transaction


@pytest.mark.parametrize("autocommit", [True, False])
def test_explicit_autocommit_modes_preserve_caller_ownership(projects, autocommit):
    store, catalog, _, _, _ = projects
    if not hasattr(store.conn, "autocommit"):
        pytest.skip("explicit sqlite3 autocommit mode requires Python 3.12+")
    add(store, "w")
    store.conn.autocommit = autocommit
    assign(catalog, "w")
    assert catalog.get_membership(RecordKind.WORKING, "w", "project:a").state == "confirmed"
    assert store.conn.in_transaction is (not autocommit)
    if not autocommit:
        store.conn.rollback()
        assert catalog.get_membership(RecordKind.WORKING, "w", "project:a") is None


@pytest.mark.parametrize("kind,identity", [(RecordKind.WORKING, "w"), (RecordKind.EPISODIC, "e"), (RecordKind.CANONICAL, 1)])
def test_provenance_proposal_confirmation_and_exact_retries(projects, kind, identity):
    store, catalog, _, _, _ = projects
    add(store, identity, kind=kind)
    assert assign(catalog, identity, confirmed=False, kind=kind) == "created"
    proposal = catalog.get_membership(kind, identity, "project:a")
    assert (proposal.origin, proposal.assigned_by, proposal.state) == ("synthetic-import", "importer:fixture", "proposed")
    assert proposal.assigned_at.endswith("Z") and proposal.confirmed_at is None
    assert selected(projects, kind=kind) == []
    assert catalog.confirm(kind, identity, "project:a", actor="reviewer:fixture") == "confirmed"
    confirmed = catalog.get_membership(kind, identity, "project:a")
    assert (confirmed.origin, confirmed.assigned_by, confirmed.assigned_at) == (proposal.origin, proposal.assigned_by, proposal.assigned_at)
    assert (confirmed.state, confirmed.confirmed_by) == ("confirmed", "reviewer:fixture")
    assert confirmed.confirmed_at.endswith("Z")
    changes = store.conn.total_changes
    assert catalog.propose(kind, identity, "project:a", origin="synthetic-import", actor="importer:fixture") == "unchanged"
    assert catalog.confirm(kind, identity, "project:a", actor="reviewer:fixture") == "unchanged"
    assert store.conn.total_changes == changes
    assert [r.record_id for r in selected(projects, kind=kind)] == [identity]
    assert "project:a" not in repr(confirmed)


def test_conflicts_and_unknown_targets_do_not_overwrite_provenance(projects):
    store, catalog, _, _, _ = projects
    add(store, "w")
    with pytest.raises(ValueError, match="proposal required"):
        catalog.confirm(RecordKind.WORKING, "w", "project:a", actor="reviewer:fixture")
    assign(catalog, "w")
    before = catalog.get_membership(RecordKind.WORKING, "w", "project:a")
    with pytest.raises(ValueError, match="registration provenance"):
        catalog.register("project:a", actor="other")
    with pytest.raises(ValueError, match="proposal provenance"):
        catalog.propose(RecordKind.WORKING, "w", "project:a", origin="different", actor="importer:fixture")
    with pytest.raises(ValueError, match="confirmation provenance"):
        catalog.confirm(RecordKind.WORKING, "w", "project:a", actor="other")
    with pytest.raises(PolicyRefusal, match="invalid_selection"):
        catalog.propose(RecordKind.WORKING, "w", "unknown", origin="manual", actor="admin")
    with pytest.raises(ValueError, match="binding is required"):
        catalog.propose(RecordKind.WORKING, "absent", "project:a", origin="manual", actor="admin")
    assert catalog.get_membership(RecordKind.WORKING, "absent", "project:a") is None
    assert catalog.get_membership(RecordKind.WORKING, "w", "project:a") == before


@pytest.mark.parametrize("value", ["", " leading", "trailing ", "bad\nvalue", "bad\x85value", "x" * 257])
def test_project_and_actor_labels_are_bounded_without_value_echo(projects, value):
    store, catalog, _, _, _ = projects
    add(store, "w")
    for operation in (
        lambda: catalog.register(value, actor="admin"),
        lambda: catalog.register("new", actor=value),
        lambda: catalog.propose(RecordKind.WORKING, "w", "project:a", origin=value, actor="admin"),
        lambda: catalog.propose(RecordKind.WORKING, "w", "project:a", origin="manual", actor=value),
    ):
        with pytest.raises(ValueError) as error:
            operation()
        if value:
            assert value not in str(error.value)
    assert catalog.get_membership(RecordKind.WORKING, "w", "project:a") is None


def test_per_binding_membership_budget_refuses_without_dropping_prior_rows(projects):
    store, catalog, _, _, _ = projects
    add(store, "w")
    for i in range(257):
        project = f"project:{i:03}"
        catalog.register(project, actor="admin")
        if i < 256:
            catalog.propose(RecordKind.WORKING, "w", project, origin="manual", actor="admin")
        else:
            with pytest.raises(ValueError, match="membership limit"):
                catalog.propose(RecordKind.WORKING, "w", project, origin="manual", actor="admin")
    assert store.conn.execute("SELECT COUNT(*) FROM policy_project_memberships").fetchone()[0] == 256
    assert not store.conn.in_transaction


def test_shared_union_deduplicates_and_interpretations_keep_separate_membership(projects):
    store, catalog, _, _, _ = projects
    for identity in ("shared", "interpretation-a", "interpretation-b", "unassigned", "proposed"):
        add(store, identity)
    assign(catalog, "shared", "project:a")
    assign(catalog, "shared", "project:b")
    assign(catalog, "interpretation-a", "project:a")
    assign(catalog, "interpretation-b", "project:b")
    assign(catalog, "proposed", confirmed=False)
    assert [r.record_id for r in selected(projects)] == ["interpretation-a", "shared"]
    assert [r.record_id for r in selected(projects, ["project:b"])] == ["interpretation-b", "shared"]
    union = selected(projects, ["project:a", "project:b", "project:a"])
    assert [r.record_id for r in union] == ["interpretation-a", "interpretation-b", "shared"]
    assert all(not hasattr(row, "projects") for row in union)


@pytest.mark.parametrize("policy", [
    {"classification": "sealed"}, {"owner": "person:b"}, {"tenant_id": "tenant:b"},
    {"audiences": {"external"}}, {"audiences": set()}, {"purposes": set()},
    {"compartments": {"work", "missing"}}, {"overlays": {"unknown"}},
])
def test_confirmed_membership_never_overrides_row_authorization(projects, policy):
    store, catalog, ctx, _, reader = projects
    add(store, "w", content=CANARY, **policy)
    assign(catalog, "w")
    assert selected(projects) == []
    with bind_access_context(ctx):
        assert reader.get(RecordKind.WORKING, "w", destination="channel:a", projects={"project:a"}) is None


@pytest.mark.parametrize("selection", [set(), [], ()])
def test_verified_empty_selection_is_empty_never_bank_fallback(projects, selection):
    store, catalog, _, registry, _ = projects
    add(store, "w")
    assign(catalog, "w")
    assert selected(projects, selection) == []
    assert registry.calls[-1][1] == frozenset()


@pytest.mark.parametrize("selection", ["project:a", {"project:unknown"}, {"project:empty"}, {"*"}, {" project:a"}, {"project:a\n"}])
def test_malformed_unknown_and_ungranted_selections_refuse(projects, selection):
    with pytest.raises(PolicyRefusal, match="invalid_selection"):
        selected(projects, selection)


def test_unknown_project_inside_host_grants_still_refuses(projects):
    store, _, _, _, _ = projects
    ctx = project_context(projects={"project:unknown"})
    reader = PolicyReader(store, bank="bank:a", verify_context=ProjectRegistry(ctx))
    with bind_access_context(ctx), pytest.raises(PolicyRefusal, match="invalid_selection"):
        reader.candidate_ids(RecordKind.WORKING, destination="channel:a", projects={"project:unknown"})


def test_known_project_without_members_is_supported_not_unknown(projects):
    store, _, _, _, _ = projects
    ctx = project_context(projects={"project:empty"})
    reader = PolicyReader(store, bank="bank:a", verify_context=ProjectRegistry(ctx))
    with bind_access_context(ctx):
        assert reader.candidate_ids(RecordKind.WORKING, destination="channel:a", projects={"project:empty"}) == []


def test_original_context_not_mutated_or_replaced_by_query_selection(projects):
    _, _, ctx, registry, _ = projects
    fingerprint = ctx.fingerprint()
    assert selected(projects, ["project:a"]) == []
    assert registry.calls == [(fingerprint, frozenset({"project:a"}))]
    assert ctx.projects == {"project:a", "project:b"} and ctx.fingerprint() == fingerprint


def test_mode_operation_grant_and_selection_must_match(projects):
    store, _, ctx, registry, reader = projects
    with bind_access_context(ctx), pytest.raises(PolicyRefusal, match="unsupported_surface"):
        reader.candidate_ids(RecordKind.WORKING, destination="channel:a")
    wrong_op = replace(ctx, operations={"read:bank"})
    with bind_access_context(wrong_op), pytest.raises(PolicyRefusal, match="access_denied"):
        reader.candidate_ids(RecordKind.WORKING, destination="channel:a", projects={"project:a"})
    registry.overrides["projects"] = {"project:b"}
    with pytest.raises(PolicyRefusal, match="access_denied"):
        selected(projects)

    def bank_only(*args, **kwargs):
        return BankReadGrant(ctx.fingerprint(), "domain:a", "bank:a", "channel:a", "decision", {"person:a"})

    with bind_access_context(ctx), pytest.raises(PolicyRefusal, match="access_denied"):
        PolicyReader(store, bank="bank:a", verify_context=bank_only).candidate_ids(RecordKind.WORKING, destination="channel:a", projects={"project:a"})
    bank_ctx = context()

    def project_only(*args, **kwargs):
        return ProjectReadGrant(bank_ctx.fingerprint(), "domain:a", "bank:a", "channel:a", "decision", {"person:a"})

    with bind_access_context(bank_ctx), pytest.raises(PolicyRefusal, match="access_denied"):
        PolicyReader(store, bank="bank:a", verify_context=project_only).candidate_ids(RecordKind.WORKING, destination="channel:a")


@pytest.mark.parametrize("selection", [set(), {"project:a"}])
def test_missing_catalog_never_becomes_empty_success_or_bank_fallback(fixture, selection):
    store, _, _ = fixture
    ctx = project_context()
    reader = PolicyReader(store, bank="bank:a", verify_context=ProjectRegistry(ctx))
    with bind_access_context(ctx), pytest.raises(PolicyStoreError, match="unprepared"):
        reader.candidate_ids(RecordKind.WORKING, destination="channel:a", projects=selection)


@pytest.mark.parametrize("sql", [
    "DROP INDEX idx_policy_project_selection", "DROP TABLE policy_projects",
    "UPDATE policy_project_state SET schema_version=99", "UPDATE policy_project_state SET domain_id='different'",
])
def test_incompatible_catalog_refuses_without_repair(projects, sql):
    store, catalog, _, _, _ = projects
    store.conn.execute(sql)
    store.conn.commit()
    before = store.conn.total_changes
    with pytest.raises(PolicyStoreError, match="incompatible"):
        selected(projects)
    with pytest.raises(PolicyStoreError, match="incompatible"):
        catalog.prepare()
    assert store.conn.total_changes == before and not store.conn.in_transaction


def test_selection_before_pagination_or_native_content_evaluation(projects):
    store, catalog, _, _, _ = projects
    for i in range(10):
        add(store, f"a-other-{i}", content=CANARY)
        assign(catalog, f"a-other-{i}", "project:b")
    for identity in ("b-orphan", "c-allowed", "d-allowed"):
        add(store, identity)
        assign(catalog, identity)
    store.conn.execute("DELETE FROM working_memory WHERE id='b-orphan'")
    store.conn.commit()
    store.conn.row_factory = lambda cursor, row: (_ for _ in ()).throw(AssertionError("denied content fetched")) if CANARY in row else row
    assert [r.record_id for r in selected(projects, limit=1)] == ["c-allowed"]
    assert [r.record_id for r in selected(projects, limit=1, offset=1)] == ["d-allowed"]


def test_project_predicate_is_materialized_indexed_and_content_free(projects):
    store, catalog, ctx, registry, reader = projects
    add(store, "w")
    assign(catalog, "w")
    grant = registry(ctx, bank="bank:a", destination="channel:a", projects=frozenset({"project:a"}))
    with store._transaction():
        sql, params = reader._selection(RecordKind.WORKING, ctx, grant, projects={"project:a"})
        plan = store.conn.execute("EXPLAIN QUERY PLAN " + sql + " SELECT * FROM eligible", params).fetchall()
    details = "\n".join(r[3] for r in plan)
    assert "MATERIALIZE eligible" in details
    assert "idx_policy_project_selection" in details or "sqlite_autoindex_policy_project_memberships" in details
    assert "EXISTS" in sql and "m.confirmed_by IS NOT NULL" in sql
    assert "main.working_memory" not in sql


def test_sql_side_content_tripwire_for_irrelevant_and_denied_rows(projects):
    store, catalog, ctx, _, reader = projects
    evaluated = []
    armed = []

    def guarded(value):
        if armed:
            evaluated.append(value)
            assert value != CANARY
        return value

    store.conn.create_function("guarded", 1, guarded, deterministic=True)
    store.conn.execute("DROP TABLE working_memory")
    store.conn.execute("CREATE TABLE working_memory(id TEXT PRIMARY KEY,raw TEXT,content TEXT GENERATED ALWAYS AS (guarded(raw)) VIRTUAL)")
    store.conn.executemany("INSERT INTO working_memory(id,raw) VALUES(?,?)", [("allowed", "synthetic"), ("irrelevant", CANARY), ("denied", CANARY)])
    store.conn.commit()
    for identity in ("allowed", "irrelevant", "denied"):
        store.bind(RecordKind.WORKING, identity, restriction(classification="sealed" if identity == "denied" else "team"))
        assign(catalog, identity, "project:b" if identity == "irrelevant" else "project:a")
    armed.append(True)
    assert [r.record_id for r in selected(projects)] == ["allowed"]
    with bind_access_context(ctx):
        for identity in ("irrelevant", "denied"):
            assert reader.get(RecordKind.WORKING, identity, destination="channel:a", projects={"project:a"}) is None
        assert evaluated == []
        assert reader.get(RecordKind.WORKING, "allowed", destination="channel:a", projects={"project:a"}).content == "synthetic"
    assert evaluated == ["synthetic"]


def test_admin_writes_preserve_caller_transaction_and_failure_rolls_back_only_operation(projects):
    store, catalog, _, _, _ = projects
    add(store, "w")
    store.conn.execute("INSERT INTO working_memory VALUES('pending','caller data')")
    catalog.propose(RecordKind.WORKING, "w", "project:a", origin="manual", actor="admin")
    assert store.conn.in_transaction

    def deny_confirmation(action, table, *_):
        return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_UPDATE and table == "policy_project_memberships" else sqlite3.SQLITE_OK

    store.conn.set_authorizer(deny_confirmation)
    with pytest.raises(sqlite3.DatabaseError):
        catalog.confirm(RecordKind.WORKING, "w", "project:a", actor="reviewer")
    store.conn.set_authorizer(lambda *args: sqlite3.SQLITE_OK)
    assert store.conn.in_transaction
    assert catalog.get_membership(RecordKind.WORKING, "w", "project:a").state == "proposed"
    assert store.conn.execute("SELECT 1 FROM working_memory WHERE id='pending'").fetchone()
    store.conn.rollback()
    assert catalog.get_membership(RecordKind.WORKING, "w", "project:a") is None


def test_prepare_failure_has_no_partial_tables(fixture):
    store, _, _ = fixture

    def deny_create(action, table, *_):
        return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_CREATE_TABLE and table == "policy_project_memberships" else sqlite3.SQLITE_OK

    store.conn.set_authorizer(deny_create)
    with pytest.raises(sqlite3.DatabaseError):
        PolicyProjects(store).prepare()
    store.conn.set_authorizer(lambda *args: sqlite3.SQLITE_OK)
    assert not store.conn.in_transaction
    assert store.conn.execute("SELECT name FROM sqlite_master WHERE name LIKE 'policy_project%'").fetchall() == []
    assert PolicyProjects(store).prepare().domain_id == "domain:a"


def test_deleted_parent_cannot_be_confirmed(projects):
    store, catalog, _, _, _ = projects
    add(store, "w")
    assign(catalog, "w", confirmed=False)
    store.conn.execute("DELETE FROM working_memory WHERE id='w'")
    store.conn.commit()
    with pytest.raises(ValueError, match="parent must exist"):
        catalog.confirm(RecordKind.WORKING, "w", "project:a", actor="reviewer")
    assert catalog.get_membership(RecordKind.WORKING, "w", "project:a").state == "proposed"


def test_concurrent_proposal_and_confirmation_are_idempotent(projects):
    store, _, _, _, _ = projects
    add(store, "w")
    filename = store.conn.execute("PRAGMA database_list").fetchone()[2]
    barrier = Barrier(2)

    def writer():
        conn = sqlite3.connect(filename, timeout=5)
        catalog = PolicyProjects(PolicyStore(conn))
        try:
            barrier.wait()
            proposal = catalog.propose(RecordKind.WORKING, "w", "project:a", origin="manual", actor="admin")
            confirmed = catalog.confirm(RecordKind.WORKING, "w", "project:a", actor="reviewer")
            assert not conn.in_transaction
            return proposal, confirmed
        finally:
            conn.close()

    with ThreadPoolExecutor(2) as pool:
        values = list(pool.map(lambda _: writer(), range(2)))
    assert sorted(v[0] for v in values) == ["created", "unchanged"]
    assert sorted(v[1] for v in values) == ["confirmed", "unchanged"]


def test_process_interruption_preserves_prior_proposal(projects):
    store, catalog, _, _, _ = projects
    add(store, "w")
    assign(catalog, "w", confirmed=False)
    filename = store.conn.execute("PRAGMA database_list").fetchone()[2]
    script = """
import os, sqlite3, sys
from mnemosyne.core.policy_store import PolicyStore, RecordKind
from mnemosyne.core.policy_projects import PolicyProjects
conn=sqlite3.connect(sys.argv[1])
conn.execute('BEGIN IMMEDIATE')
PolicyProjects(PolicyStore(conn)).confirm(RecordKind.WORKING,'w','project:a',actor='reviewer:fixture')
os._exit(73)
"""
    result = subprocess.run([sys.executable, "-c", script, filename], env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1])), capture_output=True, text=True)
    assert result.returncode == 73, result.stderr
    assert catalog.get_membership(RecordKind.WORKING, "w", "project:a").state == "proposed"
    assert selected(projects) == []


def test_interrupted_preparation_has_no_partial_generation(fixture):
    store, _, _ = fixture
    filename = store.conn.execute("PRAGMA database_list").fetchone()[2]
    script = """
import os, sqlite3, sys
from mnemosyne.core.policy_store import PolicyStore
from mnemosyne.core.policy_projects import PolicyProjects
conn=sqlite3.connect(sys.argv[1])
conn.execute('BEGIN IMMEDIATE')
PolicyProjects(PolicyStore(conn)).prepare()
os._exit(74)
"""
    result = subprocess.run([sys.executable, "-c", script, filename], env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1])), capture_output=True, text=True)
    assert result.returncode == 74, result.stderr
    catalog = PolicyProjects(store)
    assert catalog.get_domain() is None
    assert catalog.prepare().domain_id == "domain:a"


def test_pinned_p2a_bank_reader_ignores_optional_memberships_without_changing_them(projects, capsys):
    source = os.environ.get("MNEMOSYNE_PROJECT_LEGACY_SOURCE")
    if not source:
        pytest.skip("requires an explicitly pinned P2a source checkout")
    source = Path(source).resolve()
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    assert revision == "210d715aa2d614566817a8ade8ca9ee5d19cc66d"
    store, catalog, _, _, _ = projects
    add(store, "w")
    assign(catalog, "w", confirmed=False)
    before = store.conn.execute("SELECT * FROM policy_project_memberships").fetchall()
    filename = store.conn.execute("PRAGMA database_list").fetchone()[2]
    script = """
import hashlib, json, pathlib, sqlite3, sys
from mnemosyne.core import policy_read
from mnemosyne.core.policy import AccessContext
from mnemosyne.core.policy_read import PolicyReader, BankReadGrant
from mnemosyne.core.policy_store import PolicyStore, RecordKind
from mnemosyne.runtime_context import bind_access_context
root=pathlib.Path(sys.argv[1])
path=pathlib.Path(policy_read.__file__).resolve()
assert path.is_relative_to(root)
digest=hashlib.sha256(path.read_bytes()).hexdigest()
assert digest=='a3ab3e3446a0faf81058b08362dbf63fd316da715c0167405bf6c421e9909e9e'
ctx=AccessContext('ctx:old',1,'test',1,'fixture','fixture',{'person:a'},'team','engineering','authenticated',
 banks={'bank:a'},operations={'read:bank'},destinations={'channel:a'},audiences={'internal'},compartments={'work'})
def verify(c,*,bank,destination):
 assert c==ctx
 return BankReadGrant(c.fingerprint(),'domain:a',bank,destination,'decision:old',{'person:a'},{'tenant:a'})
conn=sqlite3.connect(sys.argv[2])
with bind_access_context(ctx):
 result=PolicyReader(PolicyStore(conn),bank='bank:a',verify_context=verify).get(RecordKind.WORKING,'w',destination='channel:a')
 assert result.content=='allowed synthetic'
assert not conn.in_transaction
conn.close()
print(json.dumps({'reader_sha256':digest,'source_revision':sys.argv[3],'result':'legacy bank read passes; not protected downgrade'}))
"""
    result = subprocess.run([sys.executable, "-S", "-c", script, str(source), filename, revision],
                            env=dict(os.environ, PYTHONPATH=str(source)), cwd=Path(filename).parent, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert store.conn.execute("SELECT * FROM policy_project_memberships").fetchall() == before
    with capsys.disabled():
        print("P2B_LEGACY=" + result.stdout.strip())


def test_temp_shadow_and_sql_identifiers_are_not_traversed(projects):
    store, catalog, _, _, _ = projects
    identity = "w');DROP TABLE policy_projects;--"
    project = "project:a');DROP TABLE working_memory;--"
    add(store, identity)
    catalog.register(project, actor="admin")
    assign(catalog, identity, project)
    for table in ("policy_projects", "policy_project_state", "policy_project_memberships"):
        store.conn.execute(f"CREATE TEMP TABLE {table}(shadow TEXT)")
    ctx = project_context(projects={project})
    reader = PolicyReader(store, bank="bank:a", verify_context=ProjectRegistry(ctx))
    with bind_access_context(ctx):
        assert [r.record_id for r in reader.candidate_ids(RecordKind.WORKING, destination="channel:a", projects={project})] == [identity]


def test_project_parameter_budget_is_not_truncated(projects):
    store, catalog, _, _, _ = projects
    add(store, "w")
    assign(catalog, "w")
    ctx = project_context(audiences={"internal"} | {f"a{i}" for i in range(255)}, compartments={"work"} | {f"c{i}" for i in range(255)})
    registry = ProjectRegistry(ctx)
    registry.overrides.update(owners={"person:a"} | {f"o{i}" for i in range(255)}, tenants={"tenant:a"} | {f"t{i}" for i in range(130)})
    assert sum(map(len, (ctx.audiences, ctx.compartments, registry.overrides["owners"], registry.overrides["tenants"]))) == 899
    reader = PolicyReader(store, bank="bank:a", verify_context=registry)
    with bind_access_context(ctx):
        assert reader.get(RecordKind.WORKING, "w", destination="channel:a", projects={"project:a"})
        with pytest.raises(PolicyRefusal, match="unsupported_surface"):
            reader.get(RecordKind.WORKING, "w", destination="channel:a", projects={"project:a", "project:b"})


def test_async_selections_do_not_cross_and_stale_context_refuses(projects):
    store, catalog, ctx, registry, reader = projects
    for identity, project in (("a", "project:a"), ("b", "project:b")):
        add(store, identity)
        assign(catalog, identity, project)

    async def query(project):
        with bind_access_context(ctx):
            await asyncio.sleep(0)
            return [r.record_id for r in reader.candidate_ids(RecordKind.WORKING, destination="channel:a", projects={project})]

    async def exercise():
        assert await asyncio.gather(query("project:a"), query("project:b"), query("project:a")) == [["a"], ["b"], ["a"]]

    asyncio.run(exercise())
    registry.fingerprint = replace(ctx, epoch=2).fingerprint()
    with pytest.raises(PolicyRefusal, match="access_denied"):
        selected(projects)


def test_project_workload_quality_and_measurement(projects, capsys):
    store, catalog, ctx, _, reader = projects
    expected = []
    for i in range(128):
        identity = f"row-{i:03}"
        allowed = i % 4 == 0
        relevant = i % 8 in (0, 1)
        add(store, identity, classification="team" if allowed else "sealed", content="synthetic allowed" if allowed and relevant else CANARY)
        assign(catalog, identity, "project:a" if relevant else "project:b")
        if allowed and relevant:
            expected.append(identity)
    samples, direct = [], []
    changes = store.conn.total_changes
    with bind_access_context(ctx):
        for _ in range(100):
            start = time.perf_counter_ns()
            rows = reader.candidate_ids(RecordKind.WORKING, destination="channel:a", projects={"project:a"}, limit=1000)
            samples.append((time.perf_counter_ns() - start) / 1e6)
            assert [r.record_id for r in rows] == expected
            start = time.perf_counter_ns()
            assert reader.get(RecordKind.WORKING, expected[0], destination="channel:a", projects={"project:a"}).content == "synthetic allowed"
            direct.append((time.perf_counter_ns() - start) / 1e6)
    assert store.conn.total_changes == changes
    root = Path(__file__).resolve().parents[1]
    hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ("mnemosyne/core/policy_projects.py", "mnemosyne/core/policy_read.py")}
    report = dict(workload="128 rows; 16 authorized and relevant; 100 repeats", false_allows=0,
                  expected_id_sha256=hashlib.sha256(json.dumps(expected).encode()).hexdigest(),
                  samples_ms=samples, direct_ms=direct, candidate_p50_ms=statistics.median(samples), direct_p50_ms=statistics.median(direct),
                  database_bytes=store.conn.execute("PRAGMA page_size").fetchone()[0] * store.conn.execute("PRAGMA page_count").fetchone()[0],
                  source_sha256=hashes, python=sys.version, sqlite=sqlite3.sqlite_version,
                  boundary="synthetic explicit project selector, no real transport or BEAM ranking quality")
    with capsys.disabled():
        print("P2B_MEASUREMENT=" + json.dumps(report, sort_keys=True))
