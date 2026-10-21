"""Owner-only immutable encrypted artifacts; authority is never rebuilt from files."""

import hashlib
import os
import stat
import uuid

from .policy import PolicyRefusal, RefusalReason
from .policy_read import _guard_policy_output
from .protected_snapshot import (
    MAX_ENVELOPE_BYTES,
    SnapshotIdentity,
    open_snapshot,
    seal_snapshot,
)
from .snapshot_authority import SnapshotAuthority


class ProtectedRepository:
    """Trusted host capability, not an agent tool or authentication boundary.

    The caller owns the private root, key and independent authority connection.
    No directories, authority or keys are discovered, provisioned or repaired.
    Files remain encrypted; plaintext snapshots exist only in owner memory.
    """

    def __init__(self, root, *, key, authority):
        if type(authority) is not SnapshotAuthority or type(key) is not bytes:
            raise TypeError("explicit owner key and independent authority required")
        if (
            os.name != "posix"
            or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_DIRECTORY")
            or not {os.open, os.stat, os.link, os.unlink}.issubset(os.supports_dir_fd)
        ):
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        path = os.fspath(root)
        if (
            type(path) is not str
            or not os.path.isabs(path)
            or os.path.realpath(path) != path
        ):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        self._fd = None
        self._root = path
        self._key = key
        self._authority = authority
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self._fd = fd
            info = os.fstat(fd)
            self._identity = (info.st_dev, info.st_ino)
            self._check_root()
        except PolicyRefusal:
            self.close()
            raise
        except OSError:
            self.close()
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None
        except BaseException:
            self.close()
            raise

    def close(self):
        fd, self._fd = self._fd, None
        if fd is not None:
            os.close(fd)

    def __enter__(self):
        self._check_root()
        return self

    def __exit__(self, *args):
        self.close()

    def _check_root(self):
        if self._fd is None:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        try:
            current = os.stat(self._root, follow_symlinks=False)
            info = os.fstat(self._fd)
            if (
                os.path.realpath(self._root) != self._root
                or (current.st_dev, current.st_ino) != self._identity
                or (info.st_dev, info.st_ino) != self._identity
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        except PolicyRefusal:
            raise
        except OSError:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None

    def _read(self, checkpoint):
        self._check_root()
        name = checkpoint.envelope_sha256 + ".mnes"
        try:
            fd = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._fd
            )
            with os.fdopen(fd, "rb") as handle:
                info = os.fstat(handle.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or not 0 < info.st_size <= MAX_ENVELOPE_BYTES
                ):
                    raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
                payload = handle.read(MAX_ENVELOPE_BYTES + 1)
            if (
                not 0 < len(payload) <= MAX_ENVELOPE_BYTES
                or hashlib.sha256(payload).hexdigest() != checkpoint.envelope_sha256
            ):
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            self._check_root()
            return payload
        except PolicyRefusal:
            raise
        except OSError:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None

    def _install(self, artifact):
        self._check_root()
        pending = ".pending-" + uuid.uuid4().hex
        final = artifact.checkpoint.envelope_sha256 + ".mnes"
        created = False
        try:
            fd = os.open(
                pending,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=self._fd,
            )
            created = True
            with os.fdopen(fd, "wb") as handle:
                # The host umask may remove owner write permission. Set only
                # this newly created private descriptor, never an existing file.
                os.fchmod(handle.fileno(), 0o600)
                if stat.S_IMODE(os.fstat(handle.fileno()).st_mode) != 0o600:
                    raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
                handle.write(artifact.envelope)
                handle.flush()
                os.fsync(handle.fileno())
            self._check_root()
            try:
                os.link(
                    pending,
                    final,
                    src_dir_fd=self._fd,
                    dst_dir_fd=self._fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                if self._read(artifact.checkpoint) != artifact.envelope:
                    raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            os.unlink(pending, dir_fd=self._fd)
            created = False
            os.fsync(self._fd)
            self._check_root()
        except PolicyRefusal:
            raise
        except OSError:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None
        finally:
            if created:
                # Only our unique pending file is disposable; a published orphan
                # may be needed to reconcile an uncertain authority commit.
                try:
                    os.unlink(pending, dir_fd=self._fd)
                except OSError:
                    # Preserve the primary refusal/cancellation. An encrypted
                    # pending orphan is recoverable; a raw cleanup path is not
                    # useful diagnostic output for an adapter.
                    pass

    def _current(self, store_id):
        self._check_root()
        result = self._authority.current(store_id)
        self._check_root()
        return result

    @_guard_policy_output
    def open_current(self, store_id):
        """Return an owner-only RAM connection and checkpoint, not a lifetime grant."""
        checkpoint = self._current(store_id)
        payload = self._read(checkpoint)
        conn = open_snapshot(
            payload, checkpoint, key=self._key, verify_current=self._current
        )
        return conn, checkpoint

    @_guard_policy_output
    def publish(self, conn, identity, *, previous, operation_id):
        """Durably install bytes, then compare-and-swap the independent authority.

        An exception may leave an unpublished encrypted artifact or an uncertain
        committed receipt. Inspect authority.publication before retrying. Never
        remove artifacts or select an older generation to hide that uncertainty.
        """
        if type(identity) is not SnapshotIdentity:
            raise TypeError("exact snapshot identity required")
        self._check_root()
        artifact = seal_snapshot(conn, identity, key=self._key)
        self._install(artifact)
        if previous is None:
            return self._authority.provision(
                artifact.checkpoint, operation_id=operation_id
            )
        return self._authority.publish(
            previous, artifact.checkpoint, operation_id=operation_id
        )
