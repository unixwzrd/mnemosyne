"""Immutable publication and restore freshness using synthetic memory only."""

import hashlib
import os
import sqlite3

import pytest

from mnemosyne.core.policy import PolicyRefusal
from mnemosyne.core.protected_repository import ProtectedRepository
from mnemosyne.core.protected_snapshot import seal_snapshot
from tests.test_protected_snapshot import identity
from tests.test_policy_read import add, fixture as fixture
from tests.test_policy_evidence import evidence as evidence
from tests.test_snapshot_authority import authority as authority


@pytest.fixture
def repository(tmp_path, authority):
    root = tmp_path / "encrypted"
    root.mkdir(mode=0o700)
    api, _ = authority
    with ProtectedRepository(root, key=b"x" * 44, authority=api) as owner:
        yield owner, root, api


def publish(evidence, repository):
    source = evidence[0].conn
    add(evidence[0], "w", content="PRIVATE-REPOSITORY-CANARY")
    repo, _, _ = repository
    if not hasattr(sqlite3.Connection, "serialize"):
        with pytest.raises(PolicyRefusal, match="unsupported_surface"):
            repo.publish(source, identity(), previous=None, operation_id="first")
        return None
    from cryptography.fernet import Fernet

    repo._key = Fernet.generate_key()
    return repo.publish(source, identity(), previous=None, operation_id="first")


def test_encrypted_files_and_in_memory_open(evidence, repository):
    receipt = publish(evidence, repository)
    if receipt is None:
        return
    repo, root, _ = repository
    (path,) = root.iterdir()
    assert path.name == receipt.checkpoint.envelope_sha256 + ".mnes"
    assert (
        hashlib.sha256(path.read_bytes()).hexdigest()
        == receipt.checkpoint.envelope_sha256
    )
    assert b"PRIVATE-REPOSITORY-CANARY" not in path.read_bytes()
    assert path.stat().st_mode & 0o777 == 0o600
    conn, checkpoint = repo.open_current("a" * 32)
    try:
        assert checkpoint == receipt.checkpoint
        assert (
            conn.execute("SELECT content FROM working_memory WHERE id='w'").fetchone()[
                0
            ]
            == "PRIVATE-REPOSITORY-CANARY"
        )
        assert conn.execute("PRAGMA database_list").fetchone()[2] == ""
    finally:
        conn.close()


def test_old_artifact_retained_but_missing_new_never_falls_back(evidence, repository):
    first = publish(evidence, repository)
    if first is None:
        return
    repo, root, api = repository
    second = repo.publish(
        evidence[0].conn,
        identity(generation=2),
        previous=first.checkpoint,
        operation_id="second",
    )
    old = root / (first.checkpoint.envelope_sha256 + ".mnes")
    new = root / (second.checkpoint.envelope_sha256 + ".mnes")
    assert old.exists() and new.exists()
    new.unlink()
    with pytest.raises(PolicyRefusal, match="context_unavailable"):
        repo.open_current("a" * 32)
    assert api.current("a" * 32) == second.checkpoint


def test_racing_publication_leaves_encrypted_orphan_not_selected(evidence, repository):
    first = publish(evidence, repository)
    if first is None:
        return
    repo, root, api = repository
    second = repo.publish(
        evidence[0].conn,
        identity(generation=2),
        previous=first.checkpoint,
        operation_id="second",
    )
    with pytest.raises(PolicyRefusal, match="access_denied"):
        repo.publish(
            evidence[0].conn,
            identity(generation=2),
            previous=first.checkpoint,
            operation_id="loser",
        )
    assert api.current("a" * 32) == second.checkpoint
    assert len(list(root.glob("*.mnes"))) == 3
    assert not list(root.glob(".pending-*"))


@pytest.mark.parametrize("change", ["symlink", "bytes", "mode", "directory"])
def test_substituted_artifacts_refuse(evidence, repository, change, tmp_path):
    first = publish(evidence, repository)
    if first is None:
        return
    repo, root, api = repository
    path = root / (first.checkpoint.envelope_sha256 + ".mnes")
    if change == "symlink":
        other = tmp_path / "other"
        path.rename(other)
        path.symlink_to(other)
    elif change == "bytes":
        path.write_bytes(b"not an envelope")
    elif change == "mode":
        path.chmod(0o644)
    else:
        path.unlink()
        path.mkdir()
    with pytest.raises(PolicyRefusal):
        repo.open_current("a" * 32)
    assert api.current("a" * 32) == first.checkpoint


@pytest.mark.parametrize("change", ["replaced", "mode", "symlink"])
def test_root_changes_refuse_before_authority_use(repository, change, tmp_path):
    repo, root, _ = repository
    if change == "mode":
        root.chmod(0o755)
    else:
        moved = tmp_path / "moved"
        root.rename(moved)
        if change == "symlink":
            root.symlink_to(moved, target_is_directory=True)
        else:
            root.mkdir(mode=0o700)
    with pytest.raises(PolicyRefusal, match="access_denied"):
        repo.open_current("a" * 32)


def test_authority_change_during_open_refuses(evidence, repository, monkeypatch):
    first = publish(evidence, repository)
    if first is None:
        return
    repo, _, _ = repository
    read = repo._read

    def advance(checkpoint):
        payload = read(checkpoint)
        repo.publish(
            evidence[0].conn,
            identity(generation=2),
            previous=first.checkpoint,
            operation_id="second",
        )
        return payload

    monkeypatch.setattr(repo, "_read", advance)
    with pytest.raises(PolicyRefusal, match="access_denied"):
        repo.open_current("a" * 32)


@pytest.mark.parametrize("stage", ["file_sync", "directory_sync", "link", "authority"])
def test_failed_publication_never_advances_early(
    evidence, repository, monkeypatch, stage
):
    first = publish(evidence, repository)
    if first is None:
        return
    repo, root, api = repository
    real_fsync = os.fsync

    def fail_sync(fd):
        if (stage == "directory_sync") == (fd == repo._fd):
            raise OSError("injected sync failure")
        return real_fsync(fd)

    def fail(*args, **kwargs):
        raise OSError("injected publication failure")

    if stage in ("file_sync", "directory_sync"):
        monkeypatch.setattr(os, "fsync", fail_sync)
    elif stage == "link":
        monkeypatch.setattr(os, "link", fail)
    else:
        monkeypatch.setattr(api, "publish", fail)
    with pytest.raises((PolicyRefusal, OSError)):
        repo.publish(
            evidence[0].conn,
            identity(generation=2),
            previous=first.checkpoint,
            operation_id="second",
        )
    assert api.current("a" * 32) == first.checkpoint
    assert not list(root.glob(".pending-*"))


def test_uncertain_commit_is_inspected_not_rolled_back(
    evidence, repository, monkeypatch
):
    first = publish(evidence, repository)
    if first is None:
        return
    repo, root, api = repository
    real_publish = api.publish

    def uncertain(*args, **kwargs):
        real_publish(*args, **kwargs)
        raise OSError("acknowledgment lost after commit")

    monkeypatch.setattr(api, "publish", uncertain)
    with pytest.raises(OSError):
        repo.publish(
            evidence[0].conn,
            identity(generation=2),
            previous=first.checkpoint,
            operation_id="second",
        )
    recovered = api.publication("a" * 32, "second")
    assert recovered.checkpoint.identity.generation == 2
    assert api.current("a" * 32) == recovered.checkpoint
    assert (root / (recovered.checkpoint.envelope_sha256 + ".mnes")).exists()


def test_existing_identical_ciphertext_install_is_safe(evidence, repository):
    first = publish(evidence, repository)
    if first is None:
        return
    repo, root, _ = repository
    artifact = seal_snapshot(evidence[0].conn, identity(generation=2), key=repo._key)
    repo._install(artifact)
    repo._install(artifact)
    assert len(list(root.iterdir())) == 2


def test_closed_repository_refuses(repository):
    repo, _, _ = repository
    repo.close()
    repo.close()
    with pytest.raises(PolicyRefusal, match="context_unavailable"):
        repo.open_current("a" * 32)


def test_file_and_directory_sync_precede_authority_commit(
    evidence, repository, monkeypatch
):
    first = publish(evidence, repository)
    if first is None:
        return
    repo, _, api = repository
    events = []
    real_sync, real_link, real_publish = os.fsync, os.link, api.publish

    def sync(fd):
        events.append("directory_sync" if fd == repo._fd else "file_sync")
        return real_sync(fd)

    def link(*args, **kwargs):
        events.append("link")
        return real_link(*args, **kwargs)

    def commit(*args, **kwargs):
        events.append("authority_commit")
        assert api.current("a" * 32) == first.checkpoint
        return real_publish(*args, **kwargs)

    monkeypatch.setattr(os, "fsync", sync)
    monkeypatch.setattr(os, "link", link)
    monkeypatch.setattr(api, "publish", commit)
    repo.publish(
        evidence[0].conn,
        identity(generation=2),
        previous=first.checkpoint,
        operation_id="second",
    )
    assert events == ["file_sync", "link", "directory_sync", "authority_commit"]


def test_pending_alias_after_interruption_is_not_a_read_failure(evidence, repository):
    first = publish(evidence, repository)
    if first is None:
        return
    repo, root, _ = repository
    path = root / (first.checkpoint.envelope_sha256 + ".mnes")
    os.link(path, root / ".pending-interrupted-owner")
    conn, _ = repo.open_current("a" * 32)
    conn.close()
    assert path.stat().st_nlink == 2


@pytest.mark.parametrize("kind", ["mode", "symlink", "missing", "relative"])
def test_invalid_root_is_never_adopted(tmp_path, authority, kind):
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    path = root
    if kind == "mode":
        root.chmod(0o755)
    elif kind == "symlink":
        path = tmp_path / "alias"
        path.symlink_to(root, target_is_directory=True)
    elif kind == "missing":
        root.rmdir()
    else:
        path = "relative-root"
    with pytest.raises((PolicyRefusal, OSError)):
        ProtectedRepository(path, key=b"x" * 44, authority=authority[0])
    if kind == "mode":
        assert root.stat().st_mode & 0o777 == 0o755


def test_restrictive_umask_does_not_publish_an_unreadable_artifact(evidence, repository):
    first = publish(evidence, repository)
    if first is None:
        return
    repo, root, _ = repository
    old_mask = os.umask(0o277)
    try:
        second = repo.publish(evidence[0].conn, identity(generation=2), previous=first.checkpoint, operation_id="second")
    finally:
        os.umask(old_mask)
    assert (root / (second.checkpoint.envelope_sha256 + ".mnes")).stat().st_mode & 0o777 == 0o600
    conn, _ = repo.open_current("a" * 32)
    conn.close()


def test_cleanup_denial_preserves_sanitized_primary_error(evidence, repository, monkeypatch):
    first = publish(evidence, repository)
    if first is None:
        return
    repo, root, api = repository
    def fail(*args, **kwargs):
        raise PermissionError(13, "injected failure", "PRIVATE-PENDING-PATH")
    with monkeypatch.context() as patch:
        patch.setattr(os, "unlink", fail)
        with pytest.raises(PolicyRefusal, match="context_unavailable") as caught:
            repo.publish(evidence[0].conn, identity(generation=2), previous=first.checkpoint, operation_id="second")
        assert "PRIVATE-PENDING-PATH" not in str(caught.value)
    assert api.current("a" * 32) == first.checkpoint
    assert len(list(root.glob(".pending-*"))) == 1


def test_missing_root_constructor_is_content_free(tmp_path, authority):
    path = tmp_path / "PRIVATE-MISSING-ROOT"
    with pytest.raises(PolicyRefusal, match="context_unavailable") as caught:
        ProtectedRepository(path, key=b"x" * 44, authority=authority[0])
    assert "PRIVATE-MISSING-ROOT" not in str(caught.value)
