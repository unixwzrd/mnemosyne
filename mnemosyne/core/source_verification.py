"""Explicit, bounded byte observations; not authorization or evidence expansion."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from .resolvers import ContentResolver, scheme_of

if TYPE_CHECKING:
    from .media import MediaStore

__all__ = ["SourceVerification", "verify_source_revision"]

_READ_BYTES = 65536
_MAX_BUDGET = 1073741824


@dataclass(frozen=True)
class SourceVerification:
    """One byte observation; sensitive fields are excluded from repr, not access."""

    status: str
    reason: str
    checked_at: str
    revision_id: str = field(repr=False)
    locator: str = field(repr=False)
    asset_id: Optional[str] = field(default=None, repr=False)
    representation: Optional[str] = field(default=None, repr=False)
    expected_sha256: Optional[str] = field(default=None, repr=False)
    expected_byte_size: Optional[int] = field(default=None, repr=False)
    observed_sha256: Optional[str] = field(default=None, repr=False)
    observed_byte_size: Optional[int] = field(default=None, repr=False)


def verify_source_revision(
    store: "MediaStore", revision_id: str, *, locator: str,
    resolver: Optional[ContentResolver], max_bytes: int = 67108864,
) -> SourceVerification:
    """Hash an explicitly authorized source stream without returning/storing bytes.

    The trusted host owns access checks, resolver confinement and timeouts.
    A verified observation does not authorize or verify a subsequent reopen.
    """
    if type(max_bytes) is not int or not 0 <= max_bytes <= _MAX_BUDGET:
        raise ValueError("max_bytes must be an integer in 0..1073741824")
    if (
        not isinstance(locator, str) or not locator.strip() or len(locator) > 4096
        or any(ord(char) < 32 or ord(char) == 127 for char in locator)
        or scheme_of(locator) is None
    ):
        raise ValueError("locator must be a bounded external URI without control characters")
    if scheme_of(locator) in {"data", "javascript"}:
        raise ValueError("locator must reference external evidence")

    # Revision reads preserve caller snapshots and propagate database failures.
    revision = store.get_source_revision(revision_id)
    metadata = {
        "revision_id": revision_id,
        "locator": locator,
        "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    def result(status, reason, *, count=None, digest=None):
        return SourceVerification(
            status=status, reason=reason, observed_byte_size=count,
            observed_sha256=digest, **metadata,
        )

    if revision is None:
        return result("missing", "revision_missing")
    expected_hash = revision.get("content_hash")
    expected_size = revision.get("byte_size")
    asset_id = revision.get("asset_id")
    if (
        revision.get("revision_id") != revision_id
        or not isinstance(asset_id, str) or not asset_id
        or not isinstance(expected_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None
        or revision.get("digest_status") != "asserted"
        or (expected_size is not None and (
            type(expected_size) is not int or not 0 <= expected_size <= 2**63 - 1
        ))
    ):
        return result("unverified", "invalid_revision")
    metadata.update(
        asset_id=asset_id, representation=revision.get("representation"),
        expected_sha256=expected_hash, expected_byte_size=expected_size,
    )
    if revision.get("representation") != "original-bytes":
        return result("unverified", "unsupported_representation")
    if expected_size is not None and expected_size > max_bytes:
        return result("limit_exceeded", "expected_size_exceeds_budget")
    if resolver is None:
        return result("unavailable", "resolver_unconfigured")

    stream = None
    observation = None
    count = 0
    try:
        if scheme_of(locator) not in resolver.schemes:
            return result("unverified", "unsupported_scheme")
        stream = resolver.open(locator)
        if stream is None:
            return result("unavailable", "source_unavailable")
        digest = hashlib.sha256()
        while True:
            # One lookahead byte proves exact-fit EOF without unbounded reads.
            requested = min(_READ_BYTES, max_bytes - count + 1)
            chunk = stream.read(requested)
            if not isinstance(chunk, bytes) or len(chunk) > requested:
                observation = result("unverified", "invalid_stream", count=count)
                break
            if not chunk:
                observed_hash = digest.hexdigest()
                matches = observed_hash == expected_hash and (
                    expected_size is None or expected_size == count
                )
                observation = result(
                    "verified" if matches else "changed",
                    "bytes_match" if matches else "bytes_mismatch",
                    count=count, digest=observed_hash,
                )
                break
            count += len(chunk)
            if count > max_bytes:
                observation = result("limit_exceeded", "stream_exceeds_budget", count=count)
                break
            digest.update(chunk)
    except FileNotFoundError:
        observation = result("missing", "source_missing", count=count)
    except PermissionError:
        observation = result("inaccessible", "source_inaccessible", count=count)
    except (TimeoutError, ConnectionError):
        observation = result("unavailable", "source_unavailable", count=count)
    except Exception:
        observation = result("unverified", "resolver_failure", count=count)
    finally:
        if stream is not None:
            try:
                stream.close()
            except Exception:
                observation = result("unverified", "close_failed", count=count)
    return observation
