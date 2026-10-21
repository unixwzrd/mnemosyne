"""Explicit cooperative streaming under fresh evidence authority, never a loop."""

import asyncio
from dataclasses import dataclass
import inspect
import math

from .policy import PolicyRefusal, RefusalReason, _number, _text
from .policy_evidence import EvidenceLease, _consume, _require_consumer, _sha256
from .source_expansion import _clear_traceback_frames
from ..runtime_context import get_access_context


@dataclass(frozen=True)
class EvidenceStreamLimits:
    poll_seconds: float = 0.05
    timeout_seconds: float = 30.0
    max_chunks: int = 1024
    max_chunk_bytes: int = 8192
    max_total_bytes: int = 1048576

    def __post_init__(self):
        for name, minimum, maximum in (("poll_seconds", 0.005, 1.0), ("timeout_seconds", 0.005, 300.0)):
            value = getattr(self, name)
            if type(value) not in (int, float) or not minimum <= value <= maximum or not math.isfinite(value):
                raise ValueError("stream duration exceeds supported bounds")
        for name, maximum in (("max_chunks", 4096), ("max_chunk_bytes", 65536), ("max_total_bytes", 8388608)):
            if _number(getattr(self, name), name) > maximum:
                raise ValueError("stream output limit exceeds supported bounds")


@dataclass(frozen=True, repr=False)
class EvidenceStreamReceipt:
    scope_fingerprint: str
    destination: str
    lifecycle_epoch: int
    lease_count: int
    chunks_delivered: int
    bytes_delivered: int

    def __post_init__(self):
        _sha256(self.scope_fingerprint)
        _text(self.destination, "destination")
        _number(self.lifecycle_epoch, "lifecycle_epoch", minimum=0)
        _number(self.lease_count, "lease_count")
        _number(self.chunks_delivered, "chunks_delivered", minimum=0)
        _number(self.bytes_delivered, "bytes_delivered", minimum=0)


def _leases(values):
    if type(values) not in (tuple, list) or not 1 <= len(values) <= 32 or any(type(value) is not EvidenceLease for value in values):
        raise ValueError("stream requires 1..32 explicit evidence leases")
    values = tuple(values)
    if len({(value.record_kind, value.record_id) for value in values}) != len(values):
        raise ValueError("stream leases must be unique")
    if any((value.scope_fingerprint, value.bank, value.destination, value.projects, value.lifecycle_epoch) !=
           (values[0].scope_fingerprint, values[0].bank, values[0].destination, values[0].projects, values[0].lifecycle_epoch)
           for value in values):
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    return values


async def _next(stream, fingerprint):
    # Carry errors as data across our internal Task boundary: Python 3.10
    # otherwise replaces CancelledError before the gate can re-raise it.
    try:
        if get_access_context(required=True).fingerprint() != fingerprint:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        value = await stream.__anext__()
        if get_access_context(required=True).fingerprint() != fingerprint:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return True, value
    except BaseException as error:
        return False, error


async def _finish(stream, pending, errors):
    try:
        if pending is not None:
            if not pending.done():
                pending.cancel()
            try:
                success, value = await pending
                if not success and not isinstance(value, StopAsyncIteration):
                    errors.append(value)
            except BaseException as error:
                errors.append(error)
    finally:
        try:
            await stream.aclose()
        except BaseException as error:
            errors.append(error)


async def _close(stream, pending, errors):
    # The cleanup task is always drained, even after repeated caller cancellation.
    cleanup = asyncio.create_task(_finish(stream, pending, errors))
    cancellation = None
    while not cleanup.done():
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError as error:
            cancellation = cancellation or error
    result = cleanup.result()
    if cancellation is not None:
        raise cancellation
    return result


async def stream_evidence(evidence, leases, producer, consumer, *, limits=None):
    # A suspended coroutine's frame can be closed by frame.clear() on Python
    # 3.10. Clear only after the entire worker and cleanup tasks have unwound.
    errors = []
    try:
        return await _stream_evidence(evidence, leases, producer, consumer, limits=limits, errors=errors)
    finally:
        for error in errors:
            _clear_traceback_frames(error)


async def _stream_evidence(evidence, leases, producer, consumer, *, limits, errors):
    from .policy_evidence import PolicyEvidence
    if not isinstance(evidence, PolicyEvidence):
        raise TypeError("evidence must be a PolicyEvidence")
    leases = _leases(leases)
    limits = EvidenceStreamLimits() if limits is None else limits
    if type(limits) is not EvidenceStreamLimits:
        raise TypeError("limits must be EvidenceStreamLimits")
    _require_consumer(consumer)
    if not callable(producer):
        raise TypeError("producer must return a native async generator")
    fingerprint = get_access_context(required=True).fingerprint()

    def current():
        if get_access_context(required=True).fingerprint() != fingerprint:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        conn = evidence.reader._store.conn
        before = (conn.execute("PRAGMA main.data_version").fetchone()[0],
                  conn.execute("PRAGMA main.schema_version").fetchone()[0], conn.total_changes)
        values = tuple(evidence.resolve(lease) for lease in leases)
        after = (conn.execute("PRAGMA main.data_version").fetchone()[0],
                 conn.execute("PRAGMA main.schema_version").fetchone()[0], conn.total_changes)
        if before != after or conn is not evidence.reader._store.conn or conn.in_transaction:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return values

    loop = asyncio.get_running_loop()
    deadline = loop.time() + limits.timeout_seconds
    hits = current()
    if loop.time() >= deadline:
        raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
    stream = producer(hits)
    if not inspect.isasyncgen(stream):
        if inspect.iscoroutine(stream) or inspect.isgenerator(stream):
            stream.close()
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
    hits = None
    pending = None
    original_error = None
    chunks = total = 0
    try:
        while True:
            current()
            if loop.time() >= deadline:
                raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
            pending = asyncio.create_task(_next(stream, fingerprint))
            while not pending.done():
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
                await asyncio.wait((pending,), timeout=min(limits.poll_seconds, remaining))
                current()
            success, chunk = pending.result()
            if not success and isinstance(chunk, StopAsyncIteration):
                current()
                if loop.time() >= deadline:
                    raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
                return EvidenceStreamReceipt(leases[0].scope_fingerprint, leases[0].destination,
                    leases[0].lifecycle_epoch, len(leases), chunks, total)
            if not success:
                raise chunk
            pending = None
            if type(chunk) is not str:
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            try:
                size = len(chunk.encode("utf-8"))
            except UnicodeEncodeError:
                size = None
            if size is None:
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            if chunks >= limits.max_chunks or size > limits.max_chunk_bytes or total + size > limits.max_total_bytes:
                raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
            current()
            if loop.time() >= deadline:
                raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
            _consume(consumer, chunk)
            chunks, total = chunks + 1, total + size
            chunk = None
    except BaseException as error:
        original_error = error
        errors.append(error)
        raise
    finally:
        try:
            await _close(stream, pending, errors)
            if original_error is None and errors:
                raise errors[0]
        except BaseException as cleanup_error:
            errors.append(cleanup_error)
            if original_error is None:
                raise
