"""Explicit bounded authorized bytes; no ordinary recall or protected activation."""

from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import asdict, dataclass, replace
from typing import Callable
from uuid import uuid4

from mnemosyne.core.policy import AdapterCapabilities, PolicyRefusal, PolicySurface, RefusalReason, _text
from mnemosyne.core.policy_read import AuthorizedSourceRevision, PolicyReader
from mnemosyne.core.resolvers import CallableContentResolver, ContentResolver, scheme_of
from mnemosyne.core.source_verification import verify_source_revision
from mnemosyne.runtime_context import get_access_context

__all__ = [
    "AuthorizedSourceBytes", "SourceExpander", "SourceExpansionError",
    "SourceExpansionGrant", "SourceExpansionIntent",
]

DEFAULT_EXPANSION_BYTES = 65536
MAX_EXPANSION_BYTES = 1048576


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("expected a SHA-256 hex digest")


def _budget(value):
    if type(value) is not int or not 0 <= value <= MAX_EXPANSION_BYTES:
        raise ValueError("max_bytes must be an integer in 0..1048576")


@dataclass(frozen=True, repr=False)
class SourceExpansionIntent:
    """One bounded request; constructing this is not an access decision."""

    request_id: str
    context_fingerprint: str
    destination: str
    source: AuthorizedSourceRevision
    max_bytes: int

    def __post_init__(self):
        _text(self.request_id, "request_id")
        _digest(self.context_fingerprint)
        _text(self.destination, "destination")
        if type(self.source) is not AuthorizedSourceRevision:
            raise TypeError("source must be authorized source metadata")
        _budget(self.max_bytes)

    def fingerprint(self):
        value = json.dumps([1, "expand-source", asdict(self)], sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True, repr=False)
class SourceExpansionGrant:
    """Trusted host's phase decision plus a confined resolver, not credentials."""

    intent_fingerprint: str
    phase: str
    decision_id: str
    locator: str
    resolver: ContentResolver

    def __post_init__(self):
        _digest(self.intent_fingerprint)
        if self.phase not in ("open", "read", "release"):
            raise ValueError("unsupported expansion phase")
        _text(self.decision_id, "decision_id")
        _text(self.locator, "locator", 4096)
        if scheme_of(self.locator) in (None, "data", "javascript"):
            raise ValueError("locator must reference external evidence")
        if not callable(getattr(self.resolver, "open", None)) or inspect.iscoroutinefunction(self.resolver.open):
            raise ValueError("resolver must support synchronous open")


@dataclass(frozen=True, repr=False)
class AuthorizedSourceBytes:
    """Verified transient bytes for one destination; not a reusable capability."""

    source: AuthorizedSourceRevision
    destination: str
    request_id: str
    release_decision_id: str
    content: bytes
    content_sha256: str


class SourceExpansionError(RuntimeError):
    """Content-free source outcome after authorization, never partial bytes."""

    def __init__(self, code):
        if code not in ("changed", "missing", "inaccessible", "unavailable", "unverified", "limit_exceeded"):
            raise ValueError("unsupported expansion outcome")
        self.code = code
        super().__init__("source_expansion:" + code)


class _RevisionSnapshot:
    def __init__(self, source):
        self.source = source

    def get_source_revision(self, revision_id):
        if revision_id != self.source.record_id:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return dict(revision_id=self.source.record_id, asset_id=self.source.asset_id,
                    content_hash=self.source.content_hash, byte_size=self.source.byte_size,
                    representation=self.source.representation, digest_status=self.source.digest_status)


class _CapturedStream:
    def __init__(self, stream, gate, buffer, maximum):
        self.stream, self.gate, self.buffer, self.maximum = stream, gate, buffer, maximum
        self.refusal = None

    def read(self, count):
        try:
            self.gate("read")
        except PolicyRefusal as error:
            self.refusal = error.reason
            raise
        chunk = self.stream.read(count)
        if type(chunk) is not bytes or len(chunk) > count:
            raise ValueError("invalid binary source stream")
        if len(self.buffer) + len(chunk) <= self.maximum:
            self.buffer.extend(chunk)
        return chunk

    def close(self):
        self.stream.close()


class SourceExpander:
    """Trusted-host-only seam; no default resolver, URI argument or schema writes."""

    capabilities = AdapterCapabilities("core-source-expansion", {PolicySurface.EXPAND})

    def __init__(self, reader: PolicyReader, *, authorize_source: Callable):
        if not isinstance(reader, PolicyReader):
            raise TypeError("reader must be an explicit PolicyReader")
        if not callable(authorize_source) or inspect.iscoroutinefunction(authorize_source):
            raise TypeError("authorize_source must be a synchronous trusted host callback")
        self._reader, self._authorize = reader, authorize_source

    def expand(self, revision_id: str, *, destination: str, max_bytes: int = DEFAULT_EXPANSION_BYTES):
        _budget(max_bytes)
        context = get_access_context(required=True)
        if "expand:source-revision" not in context.operations:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        conn = self._reader._store.conn
        if conn.in_transaction:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        source = self._reader.get_source_revision(revision_id, destination=destination)
        if source is None:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        if source.representation != "original-bytes":
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        if source.byte_size is not None and source.byte_size > max_bytes:
            raise SourceExpansionError("limit_exceeded")
        intent = SourceExpansionIntent("expansion:" + uuid4().hex, context.fingerprint(), destination, source, max_bytes)
        opened = None

        def current_context():
            current = get_access_context(required=True)
            if current.fingerprint() != intent.context_fingerprint or self._reader._bank != source.bank or self._reader._store.conn is not conn:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            if conn.in_transaction:
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            return current

        def checkpoint(phase):
            current = current_context()
            try:
                grant = self._authorize(current, intent=intent, phase=phase)
            except PolicyRefusal:
                raise
            except Exception:
                raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None
            if inspect.isawaitable(grant):
                if inspect.iscoroutine(grant):
                    grant.close()
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            if type(grant) is not SourceExpansionGrant or grant.intent_fingerprint != intent.fingerprint() or grant.phase != phase:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            current_context()
            fresh = self._reader.get_source_revision(revision_id, destination=destination)
            current_context()
            if fresh is None or replace(fresh, decision_id=source.decision_id) != source:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            if opened is not None and (grant.locator != opened.locator or grant.resolver is not opened.resolver):
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            try:
                supported = scheme_of(grant.locator) in grant.resolver.schemes
            except Exception:
                raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None
            if not supported:
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            return grant

        opened = checkpoint("open")
        buffer = bytearray()
        captured = None

        def open_once(locator):
            nonlocal captured
            if captured is not None or locator != opened.locator:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            stream = opened.resolver.open(locator)
            if stream is None:
                return None
            captured = _CapturedStream(stream, checkpoint, buffer, max_bytes)
            return captured

        resolver = CallableContentResolver("authorized-expansion", frozenset({scheme_of(opened.locator)}), open_func=open_once)
        try:
            observation = verify_source_revision(_RevisionSnapshot(source), revision_id,
                                                 locator=opened.locator, resolver=resolver, max_bytes=max_bytes)
            if captured is not None and captured.refusal is not None:
                raise PolicyRefusal(captured.refusal) from None
            if observation.status != "verified":
                raise SourceExpansionError(observation.status)
            content = bytes(buffer)
            digest = hashlib.sha256(content).hexdigest()
            if digest != source.content_hash or len(content) != observation.observed_byte_size:
                raise SourceExpansionError("unverified")
            released = checkpoint("release")
            return AuthorizedSourceBytes(source, destination, intent.request_id, released.decision_id, content, digest)
        finally:
            buffer.clear()
            content = None
