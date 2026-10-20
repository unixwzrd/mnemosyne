"""Bounded catalogue TEXT decoding refuses without sqlite3 payload errors."""

import hashlib
import sqlite3

import pytest

from mnemosyne.core.media import MediaStore
from mnemosyne.core.source_index_store import SourceIndexStore, SourceIndexStoreError
from mnemosyne.core.source_indexing import SourceSpan


@pytest.fixture
def fx(tmp_path):
    media = MediaStore(db_path=tmp_path / "decoding.db")
    conn = media.conn
    store = SourceIndexStore(conn)
    asset = store.register_source("source:a", "archive://synthetic/original").asset_id
    revision = media.register_source_revision(asset, revision_key="one", content_hash="a" * 64).revision_id
    text = "é\x00bounded excerpt" + "omitted " * 200
    plan = store.write("source:a", revision, text, extraction_sha256=hashlib.sha256(text.encode()).hexdigest(),
                       output_locator="archive://synthetic/extraction", spans=(SourceSpan(0, 17),))
    yield conn, store, plan, text
    conn.close()


@pytest.mark.parametrize("table,column", (
    ("media_source_index_excerpts", "text"),
    ("media_source_index_excerpts", "text_sha256"),
    ("media_source_index_plans", "source_revision_id"),
    ("media_source_index_plans", "extraction_sha256"),
    ("media_source_index_plans", "output_locator"),
    ("media_source_index_assets", "asset_id"),
    ("media_assets", "ref_value"),
))
@pytest.mark.parametrize("read", ("plan", "usage"))
def test_invalid_utf8_never_enters_sqlite_decoder_error(fx, table, column, read):
    conn, store, plan, _ = fx
    conn.execute(f"UPDATE {table} SET {column}=CAST(x'505249564154455fff' AS TEXT)")
    conn.commit()
    with pytest.raises(SourceIndexStoreError) as caught:
        store.get_plan(plan.fingerprint) if read == "plan" else store.usage("source:a")
    assert "PRIVATE" not in str(caught.value)
    assert caught.value.code in ("invalid-record", "unaccounted-legacy-state")
    assert not conn.in_transaction


def test_unicode_nul_and_sqlite_row_factory_remain_exact(fx):
    conn, store, plan, text = fx
    for factory in (None, sqlite3.Row):
        conn.row_factory = factory
        found = store.get_plan(plan.fingerprint)
        assert found.excerpts[0].text == text[:17]
        assert found.retained_utf8_bytes == len(text[:17].encode())
        assert store.usage("source:a").plan_count == 1


def test_decode_refusal_preserves_callers_unrelated_work(fx):
    conn, store, _, _ = fx
    conn.execute("UPDATE media_source_index_excerpts SET text=CAST(x'505249564154455fff' AS TEXT)")
    conn.commit()
    conn.execute("CREATE TABLE unrelated(value)")
    conn.execute("INSERT INTO unrelated VALUES(1)")
    with pytest.raises(SourceIndexStoreError, match="invalid-record"):
        store.usage("source:a")
    assert conn.in_transaction
    assert conn.execute("SELECT count(*) FROM unrelated").fetchone()[0] == 1
    conn.rollback()
    assert conn.execute("SELECT count(*) FROM unrelated").fetchone()[0] == 0
