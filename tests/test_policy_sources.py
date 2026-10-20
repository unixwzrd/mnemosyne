"""Synthetic SP1 metadata boundary; no source expansion or protected activation."""

from dataclasses import replace
import sqlite3

import pytest

from mnemosyne.core.media import MediaStore
from mnemosyne.core.policy import AccessContext, MemoryPolicy, PolicyDefinition, PolicyRefusal, RefusalReason
from mnemosyne.core.policy_projects import PolicyProjects
from mnemosyne.core.policy_read import AuthorizedSourceRevision, BankReadGrant, PolicyReader
from mnemosyne.core.policy_store import PolicyStore, PolicyStoreError, RecordKind
from mnemosyne.runtime_context import bind_access_context


def context(**changes):
    values = dict(context_id="source:a", epoch=1, policy_id="synthetic", policy_version=1,
                  issuer="fixture-host", platform="fixture", principals={"person:a"},
                  classification_ceiling="internal", purpose="engineering", assurance="authenticated",
                  banks={"bank:a"}, destinations={"channel:a"},
                  operations={"read:bank", "read:source-revision"}, audiences={"team"}, compartments={"work"})
    values.update(changes)
    return AccessContext(**values)


def restriction(**changes):
    values = dict(policy_id="synthetic", policy_version=1, classification="internal", owner="person:a",
                  classification_source="manual", audiences={"team"}, purposes={"engineering"},
                  compartments={"work"}, tenant_id="tenant:a")
    values.update(changes)
    return MemoryPolicy(**values)


class Registry:
    def __init__(self):
        self.current = context()
        self.calls = []
        self.changes = {}

    def __call__(self, ctx, *, bank, destination):
        self.calls.append(ctx.fingerprint())
        if self.current != ctx:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        values = dict(context_fingerprint=ctx.fingerprint(), bank=bank, destination=destination,
                      domain_id="domain:a", decision_id=f"decision:{len(self.calls)}",
                      owners={"person:a"}, tenants={"tenant:a"})
        values.update(self.changes)
        return BankReadGrant(**values)


@pytest.fixture
def fixture(tmp_path):
    media = MediaStore(db_path=tmp_path / "sources.db")
    store = PolicyStore(media.conn)
    store.prepare("domain:a")
    store.register_definition(PolicyDefinition("synthetic", 1, ("unclassified", "internal", "restricted")))
    registry = Registry()
    reader = PolicyReader(store, bank="bank:a", verify_context=registry)
    yield media, store, registry, reader
    media.conn.close()


def source(fixture, key="first", *, bind=True, **policy):
    media, store, _, _ = fixture
    asset = media.upsert_asset(ref_kind="url", ref_value=f"https://example.invalid/{key}", modality="document")
    revision = media.register_source_revision(asset.asset_id, revision_key=key, content_hash="a" * 64,
                                             byte_size=42, archive_locator="archive:never-open-this")
    if bind:
        store.bind(RecordKind.SOURCE_REVISION, revision.revision_id, restriction(**policy))
    return revision.revision_id


def read(fixture, identity, *, ctx=None):
    with bind_access_context(ctx or context()):
        return fixture[3].get_source_revision(identity, destination="channel:a")


def test_read_exact_metadata_provenance_no_locator_no_writes(fixture, monkeypatch):
    identity = source(fixture)
    media, store, registry, _ = fixture
    import mnemosyne.core.source_verification as verifier

    def forbidden(*args, **kwargs):
        pytest.fail("metadata read attempted source verification")

    monkeypatch.setattr(verifier, "verify_source_revision", forbidden)
    before = store.conn.total_changes
    schema = store.conn.execute("SELECT name,sql FROM main.sqlite_master ORDER BY name").fetchall()
    first, second = read(fixture, identity), read(fixture, identity)
    assert type(first) is AuthorizedSourceRevision
    assert (first.record_id, first.record_kind, first.content_hash, first.byte_size) == (
        identity, RecordKind.SOURCE_REVISION, "a" * 64, 42)
    assert first.asset_id == media.get_source_revision(identity)["asset_id"]
    assert (first.bank, first.policy_id, first.policy_version, first.classification) == (
        "bank:a", "synthetic", 1, "internal")
    assert (first.context_id, first.context_epoch, first.digest_status) == ("source:a", 1, "asserted")
    assert first.binding_id == store.get_binding(RecordKind.SOURCE_REVISION, identity).binding_id
    assert first.decision_id != second.decision_id and len(registry.calls) == 2
    assert not hasattr(first, "archive_locator") and not hasattr(first, "content")
    assert identity not in repr(first) and first.asset_id not in repr(first)
    assert store.conn.total_changes == before and not store.conn.in_transaction
    assert store.conn.execute("SELECT name,sql FROM main.sqlite_master ORDER BY name").fetchall() == schema


@pytest.mark.parametrize("change", [
    {"classification": "restricted"}, {"owner": "person:b"}, {"tenant_id": "tenant:b"},
    {"audiences": set()}, {"audiences": {"other"}}, {"purposes": set()}, {"purposes": {"other"}},
    {"compartments": {"other"}}, {"overlays": {"unsupported"}},
])
def test_denied_sources_and_missing_ids_are_indistinguishable(fixture, change):
    identity = source(fixture, **change)
    assert read(fixture, identity) is None
    assert read(fixture, "missing") is None


def test_unbound_and_unknown_policy_do_not_acquire_default_public_access(fixture):
    identity = source(fixture, bind=False)
    assert read(fixture, identity) is None
    fixture[1].bind(RecordKind.SOURCE_REVISION, identity, restriction(classification="unclassified", audiences=set()))
    assert read(fixture, identity) is None
    other = source(fixture, "explicit-unclassified", classification="unclassified")
    assert read(fixture, other).classification == "unclassified"
    fixture[1].conn.execute("UPDATE main.policy_bindings SET classification='invalid' WHERE record_id=?", (other,))
    fixture[1].conn.commit()
    assert read(fixture, other) is None


def test_denied_metadata_never_decodes_into_python(fixture):
    identity = source(fixture, classification="restricted")
    conn = fixture[1].conn
    canary = "SYNTHETIC-DENIED-SOURCE-METADATA"
    conn.execute("UPDATE main.media_source_revisions SET representation=?,content_hash=? WHERE revision_id=?",
                 (canary, canary, identity))
    conn.commit()
    seen = []

    def decode(value):
        text = value.decode()
        seen.append(text)
        assert canary not in text
        return text

    conn.text_factory = decode
    assert read(fixture, identity) is None
    assert canary not in seen


@pytest.mark.parametrize("change", [
    {"operations": {"read:bank"}}, {"operations": {"read:source-revision"}},
    {"banks": set()}, {"destinations": set()}, {"assurance": "owner"}, {"projects": {"p:a"}},
])
def test_missing_scope_refuses_before_source_sql(fixture, change):
    identity = source(fixture)
    ctx = context(**change)
    fixture[2].current = ctx
    statements = []
    fixture[1].conn.set_trace_callback(statements.append)
    with pytest.raises(PolicyRefusal):
        read(fixture, identity, ctx=ctx)
    assert statements == []


def test_missing_context_refuses_before_sql(fixture):
    statements = []
    fixture[1].conn.set_trace_callback(statements.append)
    with pytest.raises(PolicyRefusal):
        fixture[3].get_source_revision("missing", destination="channel:a")
    assert statements == []


@pytest.mark.parametrize("change", [
    {"domain_id": "other"}, {"bank": "other"}, {"destination": "other"},
    {"context_fingerprint": "b" * 64}, {"owners": set()}, {"tenants": set()},
])
def test_mismatched_or_empty_grants_never_return_source_metadata(fixture, change):
    identity = source(fixture)
    fixture[2].changes = change
    try:
        assert read(fixture, identity) is None
    except PolicyRefusal as exc:
        assert exc.reason is RefusalReason.ACCESS_DENIED


def test_epoch_and_participant_changes_require_fresh_host_decisions(fixture):
    identity = source(fixture)
    first = read(fixture, identity)
    changed = context(epoch=2, principals={"person:a", "person:b"}, audiences=set())
    with pytest.raises(PolicyRefusal):
        read(fixture, identity, ctx=changed)
    fixture[2].current = changed
    assert read(fixture, identity, ctx=changed) is None
    fixture[2].current = context()
    assert read(fixture, identity).decision_id != first.decision_id


def test_new_source_revision_does_not_inherit_another_revisions_binding(fixture):
    identity = source(fixture)
    media = fixture[0]
    asset = media.get_source_revision(identity)["asset_id"]
    new = media.register_source_revision(asset, revision_key="corrected", content_hash="b" * 64,
                                         predecessor_revision_id=identity).revision_id
    assert read(fixture, new) is None
    assert read(fixture, identity)


def test_binding_retry_conflict_and_missing_parent_are_atomic(fixture):
    identity = source(fixture)
    store = fixture[1]
    assert store.bind(RecordKind.SOURCE_REVISION, identity, restriction()).status == "unchanged"
    before = store.get_binding(RecordKind.SOURCE_REVISION, identity)
    with pytest.raises(ValueError):
        store.bind(RecordKind.SOURCE_REVISION, identity, restriction(classification="unclassified"))
    with pytest.raises(ValueError):
        store.bind(RecordKind.SOURCE_REVISION, "missing", restriction())
    assert store.get_binding(RecordKind.SOURCE_REVISION, identity) == before
    assert not store.conn.in_transaction


def test_enclosing_transaction_is_preserved_and_binding_rolls_back(fixture):
    identity = source(fixture, bind=False)
    conn = fixture[1].conn
    conn.execute("BEGIN")
    fixture[1].bind(RecordKind.SOURCE_REVISION, identity, restriction())
    assert read(fixture, identity) and conn.in_transaction
    conn.rollback()
    assert read(fixture, identity) is None


def test_missing_optional_source_schema_does_not_create_it(fixture):
    conn = fixture[1].conn
    before = conn.total_changes
    assert read(fixture, "missing") is None
    with pytest.raises(ValueError):
        fixture[1].bind(RecordKind.SOURCE_REVISION, "missing", restriction())
    assert conn.execute("SELECT 1 FROM main.sqlite_master WHERE name='media_source_revisions'").fetchone() is None
    assert conn.total_changes == before


@pytest.mark.parametrize("column,value", [
    ("content_hash", "INVALID"), ("content_hash", "b" * 65), ("digest_status", "verified"),
    ("representation", "x" * 129), ("representation", ""), ("representation", "bad\0value"),
    ("representation", "\U0001f600" * 129), ("byte_size", -1), ("byte_size", 1.5),
])
def test_corrupt_authorized_metadata_fails_content_free(fixture, column, value):
    identity = source(fixture)
    conn = fixture[1].conn
    conn.execute(f"UPDATE main.media_source_revisions SET {column}=? WHERE revision_id=?", (value, identity))
    conn.commit()
    with pytest.raises(PolicyStoreError) as error:
        read(fixture, identity)
    assert str(error.value) == "policy_store:incompatible"
    assert not conn.in_transaction


def test_source_deleted_or_orphaned_is_not_returned(fixture):
    identity = source(fixture)
    conn = fixture[1].conn
    conn.execute("UPDATE main.media_source_revisions SET asset_id='missing' WHERE revision_id=?", (identity,))
    conn.commit()
    assert read(fixture, identity) is None
    conn.execute("DELETE FROM main.media_source_revisions WHERE revision_id=?", (identity,))
    conn.commit()
    assert read(fixture, identity) is None


def test_temp_shadow_cannot_replace_main_source(fixture):
    identity = source(fixture)
    conn = fixture[1].conn
    conn.execute("CREATE TEMP TABLE media_source_revisions AS SELECT * FROM main.media_source_revisions")
    conn.execute("UPDATE temp.media_source_revisions SET content_hash=?", ("b" * 64,))
    conn.commit()
    assert read(fixture, identity).content_hash == "a" * 64


@pytest.mark.parametrize("replacement", [
    "CREATE VIEW media_source_revisions AS SELECT 'x' AS revision_id",
    "CREATE TABLE media_source_revisions(revision_id TEXT PRIMARY KEY)",
])
def test_unknown_source_schema_is_not_read_or_migrated(fixture, replacement):
    identity = source(fixture)
    conn = fixture[1].conn
    conn.execute("DROP TABLE main.media_source_revisions")
    conn.execute(replacement)
    conn.commit()
    with pytest.raises(PolicyStoreError):
        read(fixture, identity)
    with pytest.raises(PolicyStoreError):
        fixture[1].bind(RecordKind.SOURCE_REVISION, identity, restriction())


def test_generic_read_enumeration_and_source_project_paths_refuse(fixture):
    identity = source(fixture)
    _, store, _, reader = fixture
    projects = PolicyProjects(store)
    projects.prepare()
    projects.register("p:a", actor="fixture")
    calls = [
        lambda: reader.get(RecordKind.SOURCE_REVISION, identity, destination="channel:a"),
        lambda: reader.candidate_ids(RecordKind.SOURCE_REVISION, destination="channel:a"),
        lambda: projects.get_membership(RecordKind.SOURCE_REVISION, identity, "p:a"),
        lambda: projects.propose(RecordKind.SOURCE_REVISION, identity, "p:a", origin="manual", actor="fixture"),
        lambda: projects.confirm(RecordKind.SOURCE_REVISION, identity, "p:a", actor="fixture"),
    ]
    for call in calls:
        with bind_access_context(context()), pytest.raises(PolicyRefusal) as error:
            call()
        assert error.value.reason is RefusalReason.UNSUPPORTED_SURFACE


def test_readonly_connection_and_null_size_supported(fixture, tmp_path):
    identity = source(fixture)
    media, store, registry, _ = fixture
    store.conn.execute("UPDATE main.media_source_revisions SET byte_size=NULL WHERE revision_id=?", (identity,))
    store.conn.commit()
    conn = sqlite3.connect(f"file:{media.db_path}?mode=ro", uri=True)
    try:
        reader = PolicyReader(PolicyStore(conn), bank="bank:a", verify_context=registry)
        with bind_access_context(context()):
            assert reader.get_source_revision(identity, destination="channel:a").byte_size is None
    finally:
        conn.close()


def test_grant_cannot_be_awaitable(fixture):
    identity = source(fixture)

    async def invalid():
        return None

    fixture[3]._verify = lambda *args, **kwargs: invalid()
    with pytest.raises(PolicyRefusal) as error:
        read(fixture, identity)
    assert error.value.reason is RefusalReason.UNSUPPORTED_SURFACE


def test_policy_version_mismatch_is_not_defaulted(fixture):
    identity = source(fixture)
    ctx = replace(context(), policy_version=2)
    fixture[2].current = ctx
    with pytest.raises(PolicyRefusal) as error:
        read(fixture, identity, ctx=ctx)
    assert error.value.reason is RefusalReason.POLICY_MISMATCH


def test_case_insensitive_native_key_does_not_substitute_another_revision(fixture):
    identity = source(fixture)
    conn = fixture[1].conn
    ddl = conn.execute("SELECT sql FROM main.sqlite_master WHERE name='media_source_revisions'").fetchone()[0]
    row = conn.execute("SELECT * FROM main.media_source_revisions WHERE revision_id=?", (identity,)).fetchone()
    conn.execute("DROP TABLE main.media_source_revisions")
    conn.execute(ddl.replace("revision_id TEXT PRIMARY KEY", "revision_id TEXT COLLATE NOCASE PRIMARY KEY"))
    values = list(row)
    values[0] = identity.upper()
    conn.execute("INSERT INTO main.media_source_revisions VALUES(?,?,?,?,?,?,?,?,?,?)", values)
    conn.commit()
    assert read(fixture, identity) is None
    with pytest.raises(ValueError, match="parent"):
        fixture[1].bind(RecordKind.SOURCE_REVISION, identity, restriction())


@pytest.mark.parametrize("value", [None, 1, True, "", "bad\0id", "x" * 257])
def test_invalid_revision_identity_refuses_without_sql(fixture, value):
    statements = []
    fixture[1].conn.set_trace_callback(statements.append)
    with pytest.raises(ValueError):
        read(fixture, value)
    assert statements == []


def test_sql_plan_materializes_eligibility_before_indexed_revision_lookup(fixture):
    identity = source(fixture)
    store, reader = fixture[1], fixture[3]
    with bind_access_context(context()):
        ctx, grant, _ = reader._decision("channel:a")
        sql, params = reader._selection(RecordKind.SOURCE_REVISION, ctx, grant, identity)
        plan = store.conn.execute("EXPLAIN QUERY PLAN " + sql + " SELECT r.content_hash FROM eligible AS e "
                                  "JOIN main.media_source_revisions AS r ON r.revision_id=e.record_id", params).fetchall()
    detail = "\n".join(row[3] for row in plan)
    assert "MATERIALIZE eligible" in detail
    assert any(name in detail for name in ("idx_policy_binding_classification", "idx_policy_binding_owner"))
    assert "sqlite_autoindex_media_source_revisions" in detail
