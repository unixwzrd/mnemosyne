"""Real int8[1024]/FTS protected owner recall; no hidden provider calls."""

from dataclasses import replace
import sqlite3

import pytest

from mnemosyne.core import beam as beam_module
from mnemosyne.core.policy import PolicyRefusal
from mnemosyne.core.policy_audit import PolicyAudit
from mnemosyne.core.policy_lifecycle import PolicyLifecycle
from mnemosyne.core.policy_read import PolicyReader
from mnemosyne.core.policy_store import RecordKind
from mnemosyne.core.protected_session import ProtectedSession
from mnemosyne.runtime_context import bind_access_context
from tests.test_policy_lexical import lexical as lexical
from tests.test_policy_int8 import int8 as int8, add
from tests.test_snapshot_authority import authority as authority
from tests.test_protected_repository import repository as repository
from tests.test_protected_snapshot import identity


@pytest.fixture
def native_session(int8, repository, tmp_path, monkeypatch):
    if not hasattr(sqlite3.Connection, "serialize"):
        pytest.skip("normal encrypted open requires SQLite serialization support")
    from cryptography.fernet import Fernet

    beam, store, ctx, registry, _ = int8
    monkeypatch.setattr(beam_module, "EMBEDDING_DIM", 1024)
    for table in ("vec_working", "vec_episodes"):
        beam.conn.execute(f"DROP TABLE {table}")
        beam.conn.execute(
            f"CREATE VIRTUAL TABLE {table} USING vec0(embedding int8[1024])"
        )
    beam.conn.commit()
    query = [1.0] + [0.0] * 1023
    add(int8, "allowed", query)
    add(int8, "episode", query, kind=RecordKind.EPISODIC)
    add(
        int8, "denied", query, text="orion gateway DENIED-NATIVE-SESSION", owner="other"
    )
    PolicyLifecycle(store).prepare()

    def verify(context, **intent):
        return replace(registry(context, **intent), lifecycle_epoch=0)

    source_reader = PolicyReader(store, bank="bank:a", verify_context=verify)
    repo = repository[0]
    repo._key = Fernet.generate_key()
    repo.publish(beam.conn, identity(), previous=None, operation_id="native:first")
    audit_conn = sqlite3.connect(tmp_path / "native-audit.sqlite")
    audit_conn.execute("PRAGMA synchronous=EXTRA")
    audit = PolicyAudit(
        audit_conn,
        domain_id="domain:a",
        bank="bank:a",
        verify_read=lambda *a, **k: None,
    )
    audit.prepare()
    with bind_access_context(ctx):
        session = ProtectedSession(
            repo, "a" * 32, destination="channel:a", verify_context=verify, audit=audit
        )
        try:
            yield session, beam, source_reader, query
        finally:
            session.close()
            audit_conn.close()


@pytest.mark.parametrize("mode", ["lexical", "vector", "hybrid"])
def test_native_snapshot_matches_authorized_predecessor_and_never_materializes_denied(
    native_session, monkeypatch, mode
):
    session, beam, reader, query = native_session

    def forbidden(*args, **kwargs):
        pytest.fail("unexpected provider or legacy fallback")

    for name in ("embed", "embed_query"):
        monkeypatch.setattr(beam_module._embeddings, name, forbidden)

    def guard(cursor, row):
        assert not any(
            "DENIED-NATIVE-SESSION" in value for value in row if isinstance(value, str)
        )
        return sqlite3.Row(cursor, row)

    session._conn.row_factory = guard
    statements = []
    session._conn.set_trace_callback(statements.append)
    model = beam_module._embeddings._DEFAULT_MODEL
    if mode == "lexical":
        expected = beam.recall_authorized_lexical(
            "orion gateway", reader=reader, destination="channel:a"
        )
        actual = session.lexical("orion gateway")
    elif mode == "vector":
        expected = beam.recall_authorized_vector(
            query, embedding_model=model, reader=reader, destination="channel:a"
        )
        actual = session.vector(query, embedding_model=model)
        assert actual.embedding_dimension == 1024
    else:
        expected = beam.recall_authorized_hybrid(
            "orion gateway",
            query,
            embedding_model=model,
            reader=reader,
            destination="channel:a",
        )
        actual = session.hybrid("orion gateway", query, embedding_model=model)
        assert actual.embedding_dimension == 1024
    assert [(hit.record_id, hit.content, hit.score) for hit in actual.hits] == [
        (hit.record_id, hit.content, hit.score) for hit in expected.hits
    ]
    assert {hit.record_id for hit in actual.hits} == {"allowed", "episode"}
    assert not any(
        s.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE", "CREATE"))
        for s in statements
    )


def test_missing_native_conversation_refuses_without_legacy_fallback(native_session):
    from mnemosyne.runtime_context import get_access_context

    session, *_ = native_session
    with bind_access_context(
        replace(get_access_context(required=True), conversation_id=None)
    ):
        with pytest.raises(PolicyRefusal):
            session.lexical("orion gateway")
