"""Explicit, side-effect-free excerpt admission; not durable retention enforcement."""

from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit


MAX_EXTRACTION_BYTES = 8 * 1024 * 1024
MAX_EXCERPT_BYTES = 4096
MAX_RETAINED_BYTES = 32768
MAX_EXCERPTS = 128
_PCHAR = r"(?:[A-Za-z0-9._~!$&'()*+,;=:@-]|%[0-9A-Fa-f]{2})"
_REG_NAME = r"(?:[A-Za-z0-9._~!$&'()*+,;=-]|%[0-9A-Fa-f]{2})"


class SourceIndexError(ValueError):
    """A fixed reason code, never the rejected source or locator."""


@dataclass(frozen=True)
class ExcerptLimits:
    """Candidate limits for one complete plan, not a lifetime source allowance."""

    per_excerpt_bytes: int = 1024
    retained_bytes: int = 8192
    excerpt_count: int = 32

    def __post_init__(self):
        for value, maximum in (
            (self.per_excerpt_bytes, MAX_EXCERPT_BYTES),
            (self.retained_bytes, MAX_RETAINED_BYTES),
            (self.excerpt_count, MAX_EXCERPTS),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise SourceIndexError("invalid-limits")


@dataclass(frozen=True)
class SourceSpan:
    """A half-open Unicode code-point range, validated against the extraction."""

    start: int
    end: int


@dataclass(frozen=True)
class SourceExcerpt:
    span: SourceSpan
    text: str = field(repr=False)
    utf8_bytes: int


@dataclass(frozen=True)
class SourceIndexPlan:
    """Bounded selected text; neither authorization nor a persistence receipt."""

    source_revision_id: str = field(repr=False)
    extraction_sha256: str = field(repr=False)
    output_locator: str = field(repr=False)
    source_utf8_bytes: int
    retained_utf8_bytes: int
    limits: ExcerptLimits
    coverage: str
    excerpts: tuple[SourceExcerpt, ...] = field(repr=False)
    fingerprint: str = field(repr=False)


def _external_locator(locator: str) -> None:
    if (
        type(locator) is not str or not locator or len(locator) > 4096
        or locator != locator.strip()
        or any(ord(char) <= 32 or ord(char) >= 127 for char in locator)
    ):
        raise SourceIndexError("invalid-locator")
    try:
        parsed = urlsplit(locator)
        if parsed.scheme not in {"file", "http", "https", "archive"} or "@" in parsed.netloc:
            raise SourceIndexError("invalid-locator")
        # urlsplit separates components; it intentionally is not a validator.
        # Admit an ASCII RFC 3986 subset without decoding/repairing references.
        if (
            re.fullmatch(rf"(?:{_PCHAR}|/)*", parsed.path) is None
            or re.fullmatch(rf"(?:{_PCHAR}|[/?])*", parsed.query) is None
            or re.fullmatch(rf"(?:{_PCHAR}|[/?])*", parsed.fragment) is None
        ):
            raise SourceIndexError("invalid-locator")
        if parsed.scheme == "file":
            if parsed.netloc not in {"", "localhost"} or not parsed.path.startswith("/"):
                raise SourceIndexError("invalid-locator")
        elif not parsed.hostname:
            raise SourceIndexError("invalid-locator")
        elif parsed.netloc.startswith("["):
            if re.fullmatch(r"\[[0-9A-Fa-f:.]+\](?::[0-9]*)?", parsed.netloc) is None:
                raise SourceIndexError("invalid-locator")
            ipaddress.IPv6Address(parsed.hostname)
        elif re.fullmatch(rf"{_REG_NAME}+(?::[0-9]*)?", parsed.netloc) is None:
            raise SourceIndexError("invalid-locator")
        # Force validation of malformed numeric/out-of-range ports, without I/O.
        parsed.port
    except ValueError:
        raise SourceIndexError("invalid-locator") from None


def _plan_fingerprint(revision, digest, locator, source_size, limits, spans):
    identity = [
        "source-index-plan:v1", revision, digest, locator, source_size,
        limits.per_excerpt_bytes, limits.retained_bytes, limits.excerpt_count,
        [[span.start, span.end] for span in spans],
    ]
    return hashlib.sha256(json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest()


def plan_source_index(
    source_revision_id: str,
    extracted_text: str,
    *,
    extraction_sha256: str,
    output_locator: str,
    spans: tuple[SourceSpan, ...],
    limits: ExcerptLimits = ExcerptLimits(),
    coverage: str = "excerpts",
) -> SourceIndexPlan:
    """Validate a whole selection without fetching, persisting or truncating text.

    Callers must already be authorized to read the extraction. A later writer
    must account for prior/alias/revision retention atomically; this function
    cannot make unbounded legacy ingestion safe.
    """
    if type(source_revision_id) is not str or re.fullmatch(r"revision:sha256:[0-9a-f]{64}", source_revision_id) is None:
        raise SourceIndexError("invalid-source-revision")
    if type(extraction_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", extraction_sha256) is None:
        raise SourceIndexError("invalid-extraction-digest")
    _external_locator(output_locator)
    if type(limits) is not ExcerptLimits:
        raise SourceIndexError("invalid-limits")
    limits.__post_init__()
    if type(coverage) is not str or coverage != "excerpts":
        raise SourceIndexError("unsupported-coverage")
    if type(spans) is not tuple or len(spans) > limits.excerpt_count:
        raise SourceIndexError("excerpt-count-exceeded")
    if type(extracted_text) is not str:
        raise SourceIndexError("invalid-extraction")
    if len(extracted_text) > MAX_EXTRACTION_BYTES:
        raise SourceIndexError("extraction-limit-exceeded")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in extracted_text):
        raise SourceIndexError("invalid-extraction")
    encoded = extracted_text.encode("utf-8")
    source_size = len(encoded)
    if source_size > MAX_EXTRACTION_BYTES:
        raise SourceIndexError("extraction-limit-exceeded")
    if hashlib.sha256(encoded).hexdigest() != extraction_sha256:
        raise SourceIndexError("extraction-digest-mismatch")
    del encoded

    selected = []
    retained = previous_end = 0
    for span in spans:
        if (
            type(span) is not SourceSpan or type(span.start) is not int or type(span.end) is not int
            or not 0 <= span.start < span.end <= len(extracted_text) or span.start < previous_end
        ):
            raise SourceIndexError("invalid-span")
        # Every UTF-8 code point takes at least one byte. Check before slicing.
        if span.end - span.start > limits.per_excerpt_bytes:
            raise SourceIndexError("excerpt-limit-exceeded")
        text = extracted_text[span.start:span.end]
        size = len(text.encode("utf-8"))
        if size > limits.per_excerpt_bytes:
            raise SourceIndexError("excerpt-limit-exceeded")
        retained += size
        if retained > limits.retained_bytes or retained * 4 > source_size:
            raise SourceIndexError("retention-limit-exceeded")
        selected.append(SourceExcerpt(span, text, size))
        previous_end = span.end

    fingerprint = _plan_fingerprint(source_revision_id, extraction_sha256, output_locator,
                                    source_size, limits, tuple(excerpt.span for excerpt in selected))
    return SourceIndexPlan(
        source_revision_id, extraction_sha256, output_locator, source_size, retained, limits,
        "excerpts" if selected else "reference-only", tuple(selected), fingerprint,
    )
