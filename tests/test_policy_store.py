"""Prepared catalog tests only; no protected retrieval or live stores."""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from mnemosyne.core.policy import MemoryPolicy, PolicyDefinition, PolicyRefusal
from mnemosyne.core.policy_store import PolicyStore, PolicyStoreError, RecordKind, StoreErrorCode


def native(conn):
    conn.execute("CREATE TABLE working_memory (id TEXT PRIMARY KEY, content TEXT)")
    conn.execute("CREATE TABLE episodic_memory (id TEXT UNIQUE NOT NULL, content TEXT)")
    conn.execute("CREATE TABLE canonical_facts (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("INSERT INTO working_memory VALUES ('w','synthetic working')")
    conn.execute("INSERT INTO episodic_memory VALUES ('e','synthetic episodic')")
    conn.execute("INSERT INTO canonical_facts VALUES (1,'synthetic canonical')")
    conn.commit()


@pytest.fixture
def store(tmp_path):
    conn = sqlite3.connect(tmp_path / "policy.db", check_same_thread=False)
    native(conn)
    yield PolicyStore(conn)
    conn.close()


def definition(**kwargs):
    values = dict(policy_id="synthetic-policy", version=1, levels=("open", "team", "sealed"))
    values.update(kwargs)
    return PolicyDefinition(**values)


def restriction(**kwargs):
    values = dict(policy_id="synthetic-policy", policy_version=1, classification="team", owner="person:synthetic",
                  classification_source="context", origin_context_id="ctx:synthetic", origin_context_epoch=1,
                  tenant_id="tenant:synthetic", compartments={"team:a"}, audiences={"internal"},
                  purposes={"engineering"}, overlays={"consent:external"})
    values.update(kwargs)
    return MemoryPolicy(**values)


def prepare(store):
    store.prepare("domain:synthetic")
    store.register_definition(definition())


def schema(conn):
    return [tuple(row) for row in conn.execute("SELECT name,sql FROM main.sqlite_master ORDER BY name")]


def rows(conn, table):
    return [tuple(row) for row in conn.execute(f"SELECT * FROM main.{table}")]


def test_constructor_and_absent_reads_do_not_initialize_or_backfill(store):
    before, changes = schema(store.conn), store.conn.total_changes
    assert store.get_domain() is None
    assert store.get_definition("unknown", 1) is None
    assert store.get_binding(RecordKind.WORKING, "w") is None
    assert store.conn.total_changes == changes
    assert schema(store.conn) == before
    assert not store.conn.in_transaction
    with pytest.raises(PolicyStoreError, match="unprepared"):
        store.bind(RecordKind.WORKING, "w", restriction())
    with pytest.raises(PolicyStoreError, match="unprepared"):
        store.register_definition(definition())
    assert schema(store.conn) == before
    assert not store.conn.in_transaction
    with pytest.raises(TypeError):
        PolicyStore(None)


def test_prepare_is_explicit_persistent_and_does_not_change_native_content_or_pragmas(store):
    before = {table: rows(store.conn, table) for table in ("working_memory", "episodic_memory", "canonical_facts")}
    store.conn.execute("PRAGMA user_version=536870915")
    foreign_keys = store.conn.execute("PRAGMA foreign_keys").fetchone()[0]
    first = store.prepare("domain:synthetic")
    assert (first.mode, first.schema_version, first.contract_version) == ("prepared", 1, 1)
    changes = store.conn.total_changes
    assert store.prepare("domain:synthetic") == first
    assert store.conn.total_changes == changes
    assert store.get_domain() == first
    assert store.conn.execute("PRAGMA user_version").fetchone()[0] == 536870915
    assert store.conn.execute("PRAGMA foreign_keys").fetchone()[0] == foreign_keys
    assert {table: rows(store.conn, table) for table in before} == before
    assert rows(store.conn, "policy_bindings") == []
    with pytest.raises(ValueError, match="different domain"):
        store.prepare("domain:other")
    assert store.get_domain() == first
    assert not store.conn.in_transaction


def test_definitions_are_immutable_versioned_and_not_an_implicit_latest(store):
    store.prepare("domain:synthetic")
    assert store.register_definition(definition()) == "created"
    assert store.register_definition(definition()) == "unchanged"
    assert store.get_definition("synthetic-policy", 1) == definition()
    assert store.get_definition("synthetic-policy", 2) is None
    with pytest.raises(ValueError, match="different vocabulary"):
        store.register_definition(definition(levels=("team", "open", "sealed")))
    assert store.register_definition(definition(version=2, levels=("public", "internal"))) == "created"
    assert store.get_definition("synthetic-policy", 1) == definition()
    with pytest.raises(TypeError):
        store.register_definition({"policy_id": "forged"})


@pytest.mark.parametrize("kind,identity", [(RecordKind.WORKING, "w"), (RecordKind.EPISODIC, "e"), (RecordKind.CANONICAL, 1)])
def test_binding_is_immutable_idempotent_and_preserves_native_record(store, kind, identity):
    prepare(store)
    before = rows(store.conn, kind.value)
    first = store.bind(kind, identity, restriction())
    second = store.bind(kind, identity, restriction())
    assert (first.status, second.status) == ("created", "unchanged")
    assert second.binding_id == first.binding_id
    record = store.get_binding(kind, identity)
    assert record.policy == restriction()
    assert record.record_kind is kind and record.record_id == identity
    assert record.registered_at.endswith("Z")
    assert rows(store.conn, kind.value) == before
    encoded = json.dumps(["v1", "domain:synthetic", kind.value, str(identity)], separators=(",", ":"))
    assert first.binding_id == "binding:sha256:" + hashlib.sha256(encoded.encode()).hexdigest()
    assert not store.conn.in_transaction


@pytest.mark.parametrize("changes", [
    {"classification": "sealed"}, {"owner": "person:other"}, {"tenant_id": None},
    {"classification_source": "manual"}, {"origin_context_epoch": 2}, {"compartments": {"team:b"}},
    {"audiences": set()}, {"purposes": set()}, {"overlays": {"hold:external"}},
])
def test_conflicting_binding_never_overwrites_fields_or_terms(store, changes):
    prepare(store)
    store.bind(RecordKind.WORKING, "w", restriction())
    before = store.get_binding(RecordKind.WORKING, "w")
    with pytest.raises(ValueError, match="different immutable"):
        store.bind(RecordKind.WORKING, "w", restriction(**changes))
    assert store.get_binding(RecordKind.WORKING, "w") == before


def test_definition_and_parent_must_exist_and_classification_must_match(store):
    store.prepare("domain:synthetic")
    with pytest.raises(ValueError, match="definition"):
        store.bind(RecordKind.WORKING, "w", restriction())
    store.register_definition(definition())
    with pytest.raises(PolicyRefusal, match="policy_mismatch"):
        store.bind(RecordKind.WORKING, "w", restriction(classification="unknown"))
    with pytest.raises(ValueError, match="parent"):
        store.bind(RecordKind.WORKING, "absent", restriction())
    store.conn.execute("DROP TABLE main.episodic_memory")
    store.conn.commit()
    with pytest.raises(ValueError, match="parent"):
        store.bind(RecordKind.EPISODIC, "e", restriction())
    assert rows(store.conn, "policy_bindings") == []
    assert rows(store.conn, "policy_binding_terms") == []


@pytest.mark.parametrize("kind,identity", [
    ("working_memory", "w"), ("working_memory; DROP TABLE working_memory", "w"),
    (RecordKind.CANONICAL, "1"), (RecordKind.CANONICAL, True), (RecordKind.CANONICAL, 0),
    (RecordKind.CANONICAL, 2**63), (RecordKind.WORKING, ""), (RecordKind.WORKING, "bad\u009bid"),
])
def test_invalid_targets_are_rejected_without_schema(store, kind, identity):
    before = schema(store.conn)
    with pytest.raises(ValueError):
        store.bind(kind, identity, restriction())
    with pytest.raises(ValueError):
        store.get_binding(kind, identity)
    assert schema(store.conn) == before


def test_terms_and_classification_are_normalized_and_reverse_indexed(store):
    prepare(store)
    result = store.bind(RecordKind.WORKING, "w", restriction())
    assert set(rows(store.conn, "policy_binding_terms")) == {
        (result.binding_id, "compartments", "team:a"), (result.binding_id, "audiences", "internal"),
        (result.binding_id, "purposes", "engineering"), (result.binding_id, "overlays", "consent:external"),
    }
    for table in ("policy_store_state", "policy_definitions", "policy_levels", "policy_bindings", "policy_binding_terms"):
        columns = {row[1]: row[2] for row in store.conn.execute(f"PRAGMA main.table_info('{table}')")}
        assert not {"content", "text", "metadata_json", "payload", "vector"} & set(columns)
        assert "BLOB" not in columns.values()
        assert store.conn.execute(f"PRAGMA main.foreign_key_list('{table}')").fetchall() == []
    reverse = store.conn.execute("EXPLAIN QUERY PLAN SELECT binding_id FROM main.policy_binding_terms WHERE dimension=? AND value=?",
                                 ("compartments", "team:a")).fetchall()
    assert any("idx_policy_terms_reverse" in row[3] for row in reverse)
    classification = store.conn.execute("EXPLAIN QUERY PLAN SELECT record_id FROM main.policy_bindings WHERE policy_id=? AND policy_version=? AND classification=?",
                                        ("synthetic-policy", 1, "team")).fetchall()
    assert any("idx_policy_binding_classification" in row[3] for row in classification)


def test_temporary_tables_cannot_shadow_real_policy_or_parent_rows(store):
    prepare(store)
    store.bind(RecordKind.WORKING, "w", restriction())
    before = store.get_binding(RecordKind.WORKING, "w")
    store.conn.execute("CREATE TEMP TABLE policy_bindings (binding_id TEXT)")
    store.conn.execute("CREATE TEMP TABLE policy_store_state (mode TEXT)")
    store.conn.execute("CREATE TEMP TABLE pragma_index_info (name TEXT, seqno INTEGER)")
    store.conn.execute("CREATE TEMP TABLE working_memory (id TEXT)")
    store.conn.execute("INSERT INTO temp.working_memory VALUES ('fake')")
    store.conn.commit()
    assert store.get_binding(RecordKind.WORKING, "w") == before
    assert store.get_domain().mode == "prepared"
    with pytest.raises(ValueError, match="parent"):
        store.bind(RecordKind.WORKING, "fake", restriction())


def test_historical_binding_survives_parent_delete_without_claiming_current_eligibility(store):
    prepare(store)
    store.bind(RecordKind.WORKING, "w", restriction())
    before = store.get_binding(RecordKind.WORKING, "w")
    store.conn.execute("DELETE FROM main.working_memory WHERE id='w'")
    store.conn.commit()
    assert store.get_binding(RecordKind.WORKING, "w") == before
    with pytest.raises(ValueError, match="parent"):
        store.bind(RecordKind.WORKING, "w", restriction())


@pytest.mark.parametrize("change", ["schema_version", "contract_version", "mode", "missing_table", "missing_index", "empty_marker", "wrong_domain"])
def test_incompatible_catalog_is_refused_without_repair_or_downgrade(store, change):
    prepare(store)
    if change in ("schema_version", "contract_version"):
        store.conn.execute(f"UPDATE main.policy_store_state SET {change}=2")
    elif change == "mode":
        store.conn.execute("PRAGMA ignore_check_constraints=ON")
        store.conn.execute("UPDATE main.policy_store_state SET mode='protected'")
    elif change == "missing_table":
        store.conn.execute("DROP TABLE main.policy_binding_terms")
    elif change == "missing_index":
        store.conn.execute("DROP INDEX main.idx_policy_terms_reverse")
    elif change == "empty_marker":
        store.conn.execute("DELETE FROM main.policy_store_state")
    else:
        store.conn.execute("UPDATE main.policy_store_state SET domain_id='' ")
    store.conn.commit()
    before = schema(store.conn)
    for operation in (store.get_domain, lambda: store.prepare("domain:synthetic"),
                      lambda: store.get_definition("synthetic-policy", 1),
                      lambda: store.bind(RecordKind.WORKING, "w", restriction())):
        with pytest.raises(PolicyStoreError, match="incompatible"):
            operation()
        assert schema(store.conn) == before
        assert not store.conn.in_transaction


@pytest.mark.parametrize("corruption", ["dimension", "control", "missing_definition", "classification", "binding_id", "level_rank"])
def test_malformed_metadata_is_refused_not_silently_dropped(store, corruption):
    prepare(store)
    result = store.bind(RecordKind.WORKING, "w", restriction())
    if corruption == "dimension":
        store.conn.execute("INSERT INTO main.policy_binding_terms VALUES (?, 'unsupported', 'canary')", (result.binding_id,))
    elif corruption == "control":
        store.conn.execute("UPDATE main.policy_binding_terms SET value=? WHERE dimension='audiences'", ("bad\u009bterm",))
    elif corruption == "missing_definition":
        store.conn.execute("DELETE FROM main.policy_definitions")
    elif corruption == "classification":
        store.conn.execute("UPDATE main.policy_bindings SET classification='unknown'")
    elif corruption == "binding_id":
        store.conn.execute("UPDATE main.policy_bindings SET binding_id='tampered'")
    else:
        store.conn.execute("UPDATE main.policy_levels SET rank=5 WHERE rank=2")
    store.conn.commit()
    with pytest.raises(PolicyStoreError, match="incompatible"):
        store.get_binding(RecordKind.WORKING, "w")
    assert not store.conn.in_transaction


def test_caller_transactions_and_same_named_savepoints_remain_owned(store):
    store.conn.execute("BEGIN")
    store.conn.execute("SAVEPOINT policy_catalog_operation")
    store.conn.execute("UPDATE main.working_memory SET content='outer' WHERE id='w'")
    prepare(store)
    store.bind(RecordKind.WORKING, "w", restriction())
    with pytest.raises(ValueError):
        store.bind(RecordKind.WORKING, "w", restriction(classification="sealed"))
    assert store.conn.in_transaction
    assert store.get_binding(RecordKind.WORKING, "w").policy == restriction()
    assert rows(store.conn, "working_memory") == [("w", "outer")]
    store.conn.execute("ROLLBACK TO SAVEPOINT policy_catalog_operation")
    store.conn.execute("RELEASE SAVEPOINT policy_catalog_operation")
    store.conn.rollback()
    assert store.get_domain() is None
    assert rows(store.conn, "working_memory") == [("w", "synthetic working")]


def test_failed_savepoint_creation_does_not_rewind_same_named_caller_savepoint(store):
    conn = store.conn
    conn.execute("BEGIN")
    conn.execute("SAVEPOINT policy_catalog_operation")
    conn.execute("UPDATE main.working_memory SET content='outer' WHERE id='w'")

    def deny_begin(action, first, second, database, source):
        if action == sqlite3.SQLITE_SAVEPOINT and first == "BEGIN":
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    conn.set_authorizer(deny_begin)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            store.get_domain()
    finally:
        # Disabling with None was added in Python 3.11.
        conn.set_authorizer(lambda *args: sqlite3.SQLITE_OK)
    assert conn.in_transaction
    assert rows(conn, "working_memory") == [("w", "outer")]
    conn.execute("ROLLBACK TO SAVEPOINT policy_catalog_operation")
    assert rows(conn, "working_memory") == [("w", "synthetic working")]
    conn.rollback()


def test_denied_read_savepoint_release_does_not_leave_an_owned_transaction(store):
    def deny_release(action, first, second, database, source):
        if action == sqlite3.SQLITE_SAVEPOINT and first == "RELEASE":
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    store.conn.set_authorizer(deny_release)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            store.get_domain()
    finally:
        store.conn.set_authorizer(lambda *args: sqlite3.SQLITE_OK)
    assert not store.conn.in_transaction
    assert store.get_domain() is None


def test_denied_caller_read_release_does_not_shadow_the_callers_savepoint(store):
    conn = store.conn
    conn.execute("BEGIN")
    conn.execute("SAVEPOINT policy_catalog_operation")
    conn.execute("UPDATE main.working_memory SET content='outer' WHERE id='w'")

    def deny_release(action, first, second, database, source):
        if action == sqlite3.SQLITE_SAVEPOINT and first == "RELEASE":
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    conn.set_authorizer(deny_release)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            store.get_domain()
    finally:
        conn.set_authorizer(lambda *args: sqlite3.SQLITE_OK)
    assert conn.in_transaction
    assert rows(conn, "working_memory") == [("w", "outer")]
    conn.execute("ROLLBACK TO SAVEPOINT policy_catalog_operation")
    assert rows(conn, "working_memory") == [("w", "synthetic working")]
    conn.execute("RELEASE SAVEPOINT policy_catalog_operation")
    conn.rollback()


@pytest.mark.parametrize("corruption", ["epoch_type", "nullability", "uniqueness"])
def test_same_named_columns_with_unsupported_types_or_constraints_refuse_before_writes(store, corruption):
    prepare(store)
    ddl = store.conn.execute("SELECT sql FROM main.sqlite_master WHERE name='policy_bindings'").fetchone()[0]
    indexes = [row[0] for row in store.conn.execute("SELECT sql FROM main.sqlite_master WHERE type='index' AND tbl_name='policy_bindings' AND sql IS NOT NULL")]
    # Fixed synthetic schema mutations, not a production DDL parser/migration.
    if corruption == "epoch_type":
        ddl = ddl.replace("origin_context_epoch INTEGER", "origin_context_epoch TEXT")
    elif corruption == "nullability":
        ddl = ddl.replace("owner TEXT NOT NULL", "owner TEXT")
    else:
        ddl = ddl.replace(", UNIQUE(record_kind,record_id)", "")
    store.conn.execute("DROP TABLE main.policy_bindings")
    store.conn.execute(ddl)
    for index in indexes:
        store.conn.execute(index)
    store.conn.commit()
    before = store.conn.total_changes
    for operation in (store.get_domain, lambda: store.bind(RecordKind.WORKING, "w", restriction()),
                      lambda: store.register_definition(definition(version=2))):
        with pytest.raises(PolicyStoreError, match="incompatible"):
            operation()
        assert store.conn.total_changes == before
        assert not store.conn.in_transaction


@pytest.mark.parametrize("stage", ["CREATE TABLE main.policy_levels", "CREATE INDEX", "INSERT INTO main.policy_store_state", "RELEASE SAVEPOINT", "COMMIT"])
def test_interrupted_preparation_is_atomic_and_retryable(tmp_path, stage):
    class Failure(sqlite3.Connection):
        fail = False

        def execute(self, sql, parameters=()):
            if self.fail and stage in sql:
                raise sqlite3.OperationalError("synthetic interruption")
            return super().execute(sql, parameters)

    conn = sqlite3.connect(tmp_path / "failure.db", factory=Failure)
    try:
        native(conn)
        instance = PolicyStore(conn)
        before = schema(conn)
        conn.fail = True
        with pytest.raises(sqlite3.OperationalError, match="interruption"):
            instance.prepare("domain:synthetic")
        assert not conn.in_transaction
        assert schema(conn) == before
        conn.fail = False
        assert instance.prepare("domain:synthetic").mode == "prepared"
    finally:
        conn.close()


@pytest.mark.parametrize("operation", ["definition", "binding"])
def test_mid_term_failure_preserves_prior_generation_and_caller_work(tmp_path, operation):
    class Failure(sqlite3.Connection):
        fail = False

        def executemany(self, sql, parameters):
            values = list(parameters)
            if self.fail:
                super().execute(sql, values[0])
                raise sqlite3.OperationalError("synthetic mid-batch interruption")
            return super().executemany(sql, values)

    conn = sqlite3.connect(tmp_path / "terms.db", factory=Failure)
    try:
        native(conn)
        instance = PolicyStore(conn)
        prepare(instance)
        instance.bind(RecordKind.WORKING, "w", restriction())
        before = {table: rows(conn, table) for table in ("policy_definitions", "policy_levels", "policy_bindings", "policy_binding_terms")}
        conn.execute("BEGIN")
        conn.execute("UPDATE main.working_memory SET content='outer' WHERE id='w'")
        conn.fail = True
        with pytest.raises(sqlite3.OperationalError, match="mid-batch"):
            if operation == "definition":
                instance.register_definition(definition(version=2))
            else:
                instance.bind(RecordKind.EPISODIC, "e", restriction())
        assert conn.in_transaction
        assert rows(conn, "working_memory") == [("w", "outer")]
        assert {table: rows(conn, table) for table in before} == before
        conn.fail = False
        conn.rollback()
        if operation == "definition":
            assert instance.register_definition(definition(version=2)) == "created"
        else:
            assert instance.bind(RecordKind.EPISODIC, "e", restriction()).status == "created"
    finally:
        conn.close()


@pytest.mark.parametrize("preexisting", [False, True])
def test_concurrent_independent_connections_prepare_and_bind_once(store, preexisting):
    if preexisting:
        prepare(store)
    path = store.conn.execute("PRAGMA database_list").fetchone()[2]
    connections = [sqlite3.connect(path, check_same_thread=False) for _ in range(4)]
    barrier = Barrier(4)

    def worker(conn):
        instance = PolicyStore(conn)
        barrier.wait(timeout=10)
        prepare(instance)
        return instance.bind(RecordKind.WORKING, "w", restriction())

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(worker, connections))
        assert len({r.binding_id for r in results}) == 1
        assert sorted(r.status for r in results) == ["created", "unchanged", "unchanged", "unchanged"]
    finally:
        for conn in connections:
            conn.close()


@pytest.mark.skipif(sys.version_info < (3, 12), reason="sqlite3 autocommit parameter requires Python 3.12+")
@pytest.mark.parametrize("autocommit", [True, False])
def test_explicit_sqlite_modes_persist_only_owned_transactions(tmp_path, autocommit):
    path = tmp_path / "modes.db"
    conn = sqlite3.connect(path, autocommit=autocommit)
    try:
        native(conn)
        instance = PolicyStore(conn)
        prepare(instance)
        instance.bind(RecordKind.WORKING, "w", restriction())
        assert conn.in_transaction is not autocommit
        if not autocommit:
            with sqlite3.connect(path) as observer:
                assert observer.execute("SELECT name FROM sqlite_master WHERE name='policy_store_state'").fetchone() is None
            conn.commit()
        with sqlite3.connect(path) as observer:
            assert PolicyStore(observer).get_binding(RecordKind.WORKING, "w").policy == restriction()
        with pytest.raises(ValueError):
            instance.bind(RecordKind.WORKING, "w", restriction(classification="sealed"))
        assert conn.in_transaction is not autocommit
    finally:
        conn.close()


@pytest.mark.parametrize("factory", [None, sqlite3.Row])
def test_reopen_and_reads_preserve_row_factory_and_do_not_write(store, factory):
    prepare(store)
    store.bind(RecordKind.WORKING, "w", restriction())
    path = store.conn.execute("PRAGMA database_list").fetchone()[2]
    conn = sqlite3.connect(path)
    conn.row_factory = factory
    try:
        instance = PolicyStore(conn)
        before = conn.total_changes
        assert instance.get_binding(RecordKind.WORKING, "w").policy == restriction()
        assert instance.get_definition("synthetic-policy", 1) == definition()
        assert instance.get_domain().mode == "prepared"
        assert conn.row_factory is factory
        assert conn.total_changes == before
        assert not conn.in_transaction
    finally:
        conn.close()


def test_no_storage_or_activation_paths_are_implicitly_enabled(store, monkeypatch):
    import socket
    from mnemosyne.core import embeddings, llm_backends

    def forbidden(*args, **kwargs):
        pytest.fail("policy metadata attempted source IO or inference")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(embeddings, "embed", forbidden)
    monkeypatch.setattr(llm_backends, "call_host_llm", forbidden)
    prepare(store)
    store.bind(RecordKind.WORKING, "w", restriction())
    assert store.get_binding(RecordKind.WORKING, "w").policy == restriction()
    assert not hasattr(store, "activate") and not hasattr(store, "deactivate")
    assert not hasattr(store, "recall")
    with pytest.raises(TypeError):
        store.prepare("domain:synthetic", mode="protected")


def test_interrupted_process_does_not_publish_preparation_or_partial_bindings(store, tmp_path):
    source = str(Path(__file__).resolve().parents[1])
    path = store.conn.execute("PRAGMA database_list").fetchone()[2]
    script = '''
import os,sqlite3,sys
from mnemosyne.core.policy import MemoryPolicy,PolicyDefinition
from mnemosyne.core.policy_store import PolicyStore,RecordKind
conn=sqlite3.connect(sys.argv[1]); conn.execute("BEGIN")
s=PolicyStore(conn); s.prepare("domain:synthetic")
s.register_definition(PolicyDefinition("synthetic-policy",1,("open","team")))
s.bind(RecordKind.WORKING,"w",MemoryPolicy("synthetic-policy",1,"team","person:synthetic","manual"))
os._exit(17)
'''
    env = {"PATH": os.defpath, "HOME": str(tmp_path), "PYTHONPATH": source,
           "HERMES_HOME": str(tmp_path / ".hermes"), "MNEMOSYNE_DATA_DIR": str(tmp_path / "data")}
    completed = subprocess.run([sys.executable, "-c", script, path], cwd=tmp_path, env=env,
                               text=True, capture_output=True, timeout=30)
    assert completed.returncode == 17, completed.stdout + completed.stderr
    assert store.get_domain() is None
    assert rows(store.conn, "working_memory") == [("w", "synthetic working")]
    prepare(store)
    assert store.bind(RecordKind.WORKING, "w", restriction()).status == "created"


def test_legacy_beam_stays_usable_before_and_after_preparation(tmp_path):
    from mnemosyne.core.beam import BeamMemory

    beam = BeamMemory(db_path=tmp_path / "legacy.db", session_id="synthetic")
    try:
        instance = PolicyStore(beam.conn)
        assert instance.get_domain() is None
        first = beam.remember("Synthetic legacy memory before optional policy preparation.", scope="global")
        prepare(instance)
        instance.bind(RecordKind.WORKING, first, restriction())
        second = beam.remember("Synthetic legacy memory after optional policy preparation.", scope="global")
        assert second is not None
        assert beam.conn.execute("SELECT content FROM working_memory WHERE id=?", (first,)).fetchone()[0].startswith("Synthetic legacy")
        assert instance.get_binding(RecordKind.WORKING, first).policy == restriction()
    finally:
        beam.conn.close()


@pytest.mark.parametrize("caller_transaction", [False, True])
def test_process_abort_mid_binding_preserves_prior_committed_catalog(store, tmp_path, caller_transaction):
    prepare(store)
    store.bind(RecordKind.WORKING, "w", restriction())
    before = {table: rows(store.conn, table) for table in ("policy_store_state", "policy_definitions", "policy_levels", "policy_bindings", "policy_binding_terms")}
    source = str(Path(__file__).resolve().parents[1])
    path = store.conn.execute("PRAGMA database_list").fetchone()[2]
    script = '''
import os,sqlite3,sys
from mnemosyne.core.policy import MemoryPolicy
from mnemosyne.core.policy_store import PolicyStore,RecordKind
class Abort(sqlite3.Connection):
    def executemany(self,sql,values):
        first=next(iter(values)); super().execute(sql,first); os._exit(17)
conn=sqlite3.connect(sys.argv[1],factory=Abort)
if sys.argv[2]=="True": conn.execute("BEGIN")
s=PolicyStore(conn)
s.bind(RecordKind.EPISODIC,"e",MemoryPolicy("synthetic-policy",1,"team","person:synthetic","manual",audiences={"internal"},purposes={"engineering"}))
'''
    env = {"PATH": os.defpath, "HOME": str(tmp_path), "PYTHONPATH": source,
           "HERMES_HOME": str(tmp_path / ".hermes"), "MNEMOSYNE_DATA_DIR": str(tmp_path / "data")}
    completed = subprocess.run([sys.executable, "-c", script, path, str(caller_transaction)], cwd=tmp_path, env=env,
                               text=True, capture_output=True, timeout=30)
    assert completed.returncode == 17, completed.stdout + completed.stderr
    assert {table: rows(store.conn, table) for table in before} == before
    assert store.get_binding(RecordKind.EPISODIC, "e") is None
    assert store.bind(RecordKind.EPISODIC, "e", restriction()).status == "created"


def test_pinned_legacy_reader_writer_ignores_preparation_without_destroying_metadata(tmp_path):
    from mnemosyne.core.beam import BeamMemory

    configured = os.environ.get("MNEMOSYNE_POLICY_LEGACY_SOURCE")
    if not configured:
        pytest.skip("set pinned legacy source/revision for old-client qualification")
    source = Path(configured).resolve()
    expected = os.environ.get("MNEMOSYNE_POLICY_LEGACY_REVISION", "")
    assert len(expected) == 40
    assert subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip() == expected
    subprocess.run(["git", "-C", str(source), "diff", "--quiet", "HEAD"], check=True)
    path = tmp_path / "old-client.db"
    beam = BeamMemory(db_path=path, session_id="synthetic")
    try:
        memory = beam.remember("Synthetic pinned old-client evidence.", scope="global")
        instance = PolicyStore(beam.conn)
        prepare(instance)
        instance.bind(RecordKind.WORKING, memory, restriction())
        before = instance.get_binding(RecordKind.WORKING, memory)
        script = '''
import sys,os
from pathlib import Path
import mnemosyne.core.beam as module
assert Path(module.__file__).resolve().is_relative_to(Path(os.environ["PYTHONPATH"]))
assert not (Path(os.environ["PYTHONPATH"])/"mnemosyne/core/policy_store.py").exists()
beam=module.BeamMemory(db_path=Path(sys.argv[1]),session_id="synthetic-old-client")
try:
    assert beam.conn.execute("SELECT content FROM main.working_memory WHERE id=?",(sys.argv[2],)).fetchone()[0]=="Synthetic pinned old-client evidence."
    assert beam.remember("Synthetic old-client write after preparation.",scope="global") is not None
finally:
    beam.conn.close()
'''
        env = {"PATH": os.defpath, "HOME": str(tmp_path), "PYTHONPATH": str(source),
               "HERMES_HOME": str(tmp_path / ".hermes"), "MNEMOSYNE_DATA_DIR": str(tmp_path / "unused"),
               "MNEMOSYNE_NO_EMBEDDINGS": "1", "MNEMOSYNE_LLM_ENABLED": "false", "MNEMOSYNE_HOST_LLM_ENABLED": "false"}
        completed = subprocess.run([sys.executable, "-c", script, str(path), memory], cwd=tmp_path, env=env,
                                   text=True, capture_output=True, timeout=30)
        assert completed.returncode == 0, completed.stdout + completed.stderr
        assert instance.get_binding(RecordKind.WORKING, memory) == before
        assert beam.conn.execute("SELECT 1 FROM main.working_memory WHERE content='Synthetic old-client write after preparation.'").fetchone() is not None
        assert instance.get_domain().mode == "prepared"  # Not protected downgrade safety.
    finally:
        beam.conn.close()


def test_store_errors_have_only_fixed_codes():
    for code in StoreErrorCode:
        assert PolicyStoreError(code).args == (f"policy_store:{code.value}",)
    with pytest.raises(ValueError):
        PolicyStoreError("private-canary")
