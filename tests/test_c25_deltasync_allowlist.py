"""Regression tests for C25 — DeltaSync table + column allowlist.

Pre-C25: `DeltaSync.compute_delta(peer_id, table=...)` and
`DeltaSync.apply_delta(peer_id, delta, table=...)` interpolated the
`table` kwarg directly into f-string SQL:

    cursor.execute(f"SELECT * FROM {table} WHERE ...")
    cursor.execute(f"INSERT INTO {table} ({cols}) VALUES (...)")

Plus the apply_delta path used the keys of the peer-supplied `delta`
dict to build column lists:

    cols = [k for k in mem.keys() if k not in ("rowid",)]
    cursor.execute(f"INSERT INTO {table} ({', '.join(cols)}) ...")

Two real SQL injection vectors:
  1. Caller-supplied `table` kwarg (config-file injection, plugin
     misuse, etc.)
  2. Peer-controlled column names in incoming delta dicts (a
     remote peer can send a delta that smuggles arbitrary SQL into
     a column-name slot)

Post-C25:
  - `table` is validated against `ALLOWED_DELTA_TABLES` at the public
    method boundary; anything outside raises ValueError.
  - Column names in incoming deltas are filtered against the live
    schema's column allowlist (PRAGMA-derived, per-table, cached).
    Unknown columns are silently dropped and counted in a new
    `filtered_keys` stat so operators can spot a misconfigured peer.

Maintainer note (issue #64): streaming emit was wired live by commit
`b2a7fae`, raising the practical relevance of the allowlist.
"""

import sqlite3
import tempfile
from pathlib import Path

import pytest

from mnemosyne.core.memory import Mnemosyne
from mnemosyne.core.streaming import (
    ALLOWED_DELTA_TABLES,
    DeltaSync,
)


@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "test.db"


@pytest.fixture
def mnem(temp_db):
    """A Mnemosyne instance with a couple of working_memory rows so
    delta computation has something to return."""
    m = Mnemosyne(session_id="s1", db_path=temp_db)
    m.remember("Alice prefers Vim", source="pref", importance=0.7)
    m.remember("Bob owns the auth module", source="fact", importance=0.8)
    return m


@pytest.fixture
def sync_ckpt_dir(tmp_path):
    return tmp_path / "sync"


class TestC25TableAllowlist:

    def test_allowlist_constant_is_explicit(self):
        """The allowlist set must include both production tables AND
        be a frozenset (immutable). A test on the constant prevents
        accidental drift: someone adding `triples` or `facts` to the
        set without thinking about the schema-column allowlist
        implications would surface here."""
        assert isinstance(ALLOWED_DELTA_TABLES, frozenset)
        assert ALLOWED_DELTA_TABLES == frozenset({"working_memory", "episodic_memory"})

    def test_compute_delta_accepts_working_memory(self, mnem, sync_ckpt_dir):
        sync = DeltaSync(mnem, checkpoint_dir=sync_ckpt_dir)
        delta = sync.compute_delta("peer-A", table="working_memory")
        assert len(delta) >= 2, "expected the seeded rows in delta"

    def test_compute_delta_accepts_episodic_memory(self, mnem, sync_ckpt_dir):
        sync = DeltaSync(mnem, checkpoint_dir=sync_ckpt_dir)
        # No episodic rows seeded but the call should still succeed.
        delta = sync.compute_delta("peer-A", table="episodic_memory")
        assert delta == []

    def test_compute_delta_rejects_unknown_table(self, mnem, sync_ckpt_dir):
        sync = DeltaSync(mnem, checkpoint_dir=sync_ckpt_dir)
        with pytest.raises(ValueError, match="not in the allowlist"):
            sync.compute_delta("peer-A", table="some_other_table")

    def test_compute_delta_rejects_injection_attempt(self, mnem, sync_ckpt_dir):
        """The whole point of the allowlist. Pre-fix the payload
        below would have executed against the local DB."""
        sync = DeltaSync(mnem, checkpoint_dir=sync_ckpt_dir)
        payload = "working_memory; DROP TABLE episodic_memory; --"
        with pytest.raises(ValueError, match="not in the allowlist"):
            sync.compute_delta("peer-A", table=payload)

        # Sanity: episodic_memory still exists.
        conn = sqlite3.connect(str(mnem.db_path))
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='episodic_memory'"
        )
        assert cursor.fetchone() is not None, (
            "injection-attempt table arg somehow affected the schema"
        )
        conn.close()

    def test_compute_delta_rejects_non_string_table(self, mnem, sync_ckpt_dir):
        """Edge case — None / int / list as `table` must error
        clearly, not silently mis-route."""
        sync = DeltaSync(mnem, checkpoint_dir=sync_ckpt_dir)
        for bad in (None, 42, ["working_memory"], object()):
            with pytest.raises(ValueError):
                sync.compute_delta("peer-A", table=bad)

    def test_apply_delta_rejects_unknown_table(self, mnem, sync_ckpt_dir):
        sync = DeltaSync(mnem, checkpoint_dir=sync_ckpt_dir)
        with pytest.raises(ValueError, match="not in the allowlist"):
            sync.apply_delta("peer-A", [], table="something_else")

    def test_apply_delta_rejects_injection_attempt(self, mnem, sync_ckpt_dir):
        sync = DeltaSync(mnem, checkpoint_dir=sync_ckpt_dir)
        with pytest.raises(ValueError, match="not in the allowlist"):
            sync.apply_delta(
                "peer-A",
                [{"id": "x", "content": "y"}],
                table="working_memory; ATTACH DATABASE '/tmp/evil' AS evil; --",
            )

    def test_sync_to_inherits_validation(self, mnem, sync_ckpt_dir):
        sync = DeltaSync(mnem, checkpoint_dir=sync_ckpt_dir)
        with pytest.raises(ValueError, match="not in the allowlist"):
            sync.sync_to("peer-A", table="bogus")

    def test_sync_from_inherits_validation(self, mnem, sync_ckpt_dir):
        sync = DeltaSync(mnem, checkpoint_dir=sync_ckpt_dir)
        with pytest.raises(ValueError, match="not in the allowlist"):
            sync.sync_from("peer-A", [{"id": "x"}], table="bogus")


class TestC25ColumnAllowlist:

    def test_apply_delta_filters_unknown_column(self, mnem, sync_ckpt_dir):
        """[Attack vector] A peer sends a delta with a column name
        that doesn't exist in the schema. Pre-fix that key flowed
        straight into `INSERT INTO working_memory (col) VALUES (?)`
        and raised an OperationalError mid-batch (best case) or
        injected SQL (worst case). Post-fix it's filtered out and
        counted in `filtered_keys`; the rest of the row still applies."""
        sync = DeltaSync(mnem, checkpoint_dir=sync_ckpt_dir)
        delta = [{
            "id": "new-row-1",
            "content": "legit content",
            "source": "test",
            "timestamp": "2026-05-11T00:00:00",
            "session_id": "s1",
            "importance": 0.5,
            "totally_made_up_column": "garbage",
        }]
        stats = sync.apply_delta("peer-A", delta, table="working_memory")
        assert stats["inserted"] == 1, f"expected 1 insert, got {stats}"
        assert stats["filtered_keys"] >= 1, (
            f"unknown column wasn't filtered; got {stats}"
        )

        # Row exists; the bogus column is not in the DB schema.
        conn = sqlite3.connect(str(mnem.db_path))
        row = conn.execute(
            "SELECT id, content FROM working_memory WHERE id = ?",
            ("new-row-1",),
        ).fetchone()
        assert row is not None
        assert row[1] == "legit content"
        # Verify schema doesn't have the bogus column.
        cols = [r[1] for r in conn.execute("PRAGMA table_info(working_memory)").fetchall()]
        assert "totally_made_up_column" not in cols
        conn.close()

    def test_apply_delta_filters_injection_in_column_name(
        self, mnem, sync_ckpt_dir
    ):
        """[Attack vector] A peer sends `{"foo); DROP TABLE x; --": "v"}`
        as a key. Pre-fix the malicious string would have been
        interpolated into `INSERT INTO table (foo); DROP TABLE x; --) VALUES (?)`.
        Post-fix it's filtered as not-in-schema."""
        sync = DeltaSync(mnem, checkpoint_dir=sync_ckpt_dir)
        evil_col = "foo); DROP TABLE episodic_memory; --"
        delta = [{
            "id": "new-row-2",
            "content": "legit content",
            "source": "test",
            "timestamp": "2026-05-11T00:00:00",
            "session_id": "s1",
            "importance": 0.5,
            evil_col: "evil value",
        }]
        stats = sync.apply_delta("peer-A", delta, table="working_memory")
        assert stats["filtered_keys"] >= 1, (
            f"injection column wasn't filtered; got {stats}"
        )

        # Sanity: episodic_memory still exists.
        conn = sqlite3.connect(str(mnem.db_path))
        row = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='episodic_memory'"
        ).fetchone()
        assert row is not None, "injection in column name affected schema"
        conn.close()

    def test_apply_delta_filters_unknown_column_on_update(
        self, mnem, sync_ckpt_dir
    ):
        """Same filter applies on the UPDATE path (existing-row case)."""
        sync = DeltaSync(mnem, checkpoint_dir=sync_ckpt_dir)
        # First, insert via apply_delta so the id matches the existing
        # row on the next call.
        sync.apply_delta(
            "peer-A",
            [{
                "id": "upd-row-1",
                "content": "initial content",
                "source": "test",
                "timestamp": "2026-05-11T00:00:00",
                "session_id": "s1",
                "importance": 0.5,
            }],
            table="working_memory",
        )

        # Now send an update with both a real and a fake column.
        stats = sync.apply_delta(
            "peer-A",
            [{
                "id": "upd-row-1",
                "content": "updated content",
                "made_up_column": "should be filtered",
            }],
            table="working_memory",
        )
        assert stats["updated"] == 1
        assert stats["filtered_keys"] >= 1

        # The real update landed.
        conn = sqlite3.connect(str(mnem.db_path))
        row = conn.execute(
            "SELECT content FROM working_memory WHERE id = ?",
            ("upd-row-1",),
        ).fetchone()
        assert row[0] == "updated content"
        conn.close()

    def test_apply_delta_filters_reserved_columns(self, mnem, sync_ckpt_dir):
        """`rowid`, `timestamp`, `created_at` are reserved on UPDATE
        even though they're real columns in the schema. They're
        routing/metadata keys, not user-mutable fields. Pre-fix this
        was already true for UPDATE (the original code had the
        `if k not in ("id", "rowid", "timestamp", "created_at")`
        guard); C25 makes it explicit via the reserved set constant."""
        sync = DeltaSync(mnem, checkpoint_dir=sync_ckpt_dir)
        # Seed a row.
        sync.apply_delta(
            "peer-A",
            [{
                "id": "reserved-row",
                "content": "original",
                "source": "test",
                "timestamp": "2026-05-11T00:00:00",
                "session_id": "s1",
                "importance": 0.5,
            }],
            table="working_memory",
        )

        # Send an update that tries to mutate timestamp + created_at.
        # Pre-fix and post-fix: both are filtered out as reserved.
        stats = sync.apply_delta(
            "peer-A",
            [{
                "id": "reserved-row",
                "content": "new content",
                "timestamp": "2099-01-01T00:00:00",  # reserved
                "created_at": "2099-01-01T00:00:00",  # reserved
            }],
            table="working_memory",
        )
        assert stats["updated"] == 1

        conn = sqlite3.connect(str(mnem.db_path))
        row = conn.execute(
            "SELECT content, timestamp FROM working_memory WHERE id = ?",
            ("reserved-row",),
        ).fetchone()
        conn.close()
        assert row[0] == "new content"
        # timestamp NOT changed to 2099 (reserved on update path).
        assert "2099" not in row[1]


class TestC25EndToEndRoundtrip:
    """[/regression] Normal sync flow still works post-C25.
    Filtering edges and table allowlisting must not break legitimate
    use of the public API."""

    def test_compute_then_apply_preserves_content(self, mnem, sync_ckpt_dir, tmp_path):
        """Source instance: compute_delta. Destination instance:
        apply_delta. Content should round-trip."""
        sync_src = DeltaSync(mnem, checkpoint_dir=sync_ckpt_dir)
        delta = sync_src.compute_delta("peer-B", table="working_memory")
        assert len(delta) == 2

        # Fresh destination Mnemosyne.
        dest_db = tmp_path / "dest.db"
        dest_mnem = Mnemosyne(session_id="s1", db_path=dest_db)
        dest_sync = DeltaSync(dest_mnem, checkpoint_dir=tmp_path / "dest_sync")
        stats = dest_sync.apply_delta("peer-B", delta, table="working_memory")

        assert stats["inserted"] == 2
        assert stats["filtered_keys"] == 0, (
            f"legitimate delta got keys filtered: {stats}"
        )

        # Destination has the rows.
        conn = sqlite3.connect(str(dest_db))
        rows = conn.execute(
            "SELECT id, content FROM working_memory ORDER BY id"
        ).fetchall()
        conn.close()
        assert len(rows) == 2
        contents = [r[1] for r in rows]
        assert any("Alice" in c for c in contents)
        assert any("Bob" in c for c in contents)
