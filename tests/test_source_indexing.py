"""Synthetic S3a admission only: no live data, writers or authorization claims."""

from dataclasses import FrozenInstanceError, replace
import hashlib
import socket
import sqlite3

import pytest

from mnemosyne.core.source_indexing import (
    MAX_EXTRACTION_BYTES, ExcerptLimits, SourceIndexError, SourceSpan, plan_source_index,
)


REVISION = "revision:sha256:" + "a" * 64
TEXT = "Exact selected evidence.\n" + "omitted marker, not retained! " * 200


def plan(text=TEXT, spans=(SourceSpan(0, 24),), **kwargs):
    options = dict(extraction_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                   output_locator="archive://synthetic/extractions/one", spans=spans)
    options.update(kwargs)
    return plan_source_index(REVISION, text, **options)


def refused(code, call):
    with pytest.raises(SourceIndexError) as error:
        call()
    assert str(error.value) == code
    assert "omitted marker" not in repr(error.value)


def test_exact_selection_and_omitted_text():
    result = plan()
    assert result.source_revision_id == REVISION
    assert result.source_utf8_bytes == len(TEXT.encode())
    assert result.retained_utf8_bytes == 24
    assert result.excerpts[0].text == TEXT[:24]
    assert result.excerpts[0].span == SourceSpan(0, 24)
    assert result.coverage == "excerpts"
    assert "omitted marker" not in repr(result)
    assert TEXT[:24] not in repr(result.excerpts[0])
    assert "archive://" not in repr(result)
    assert not hasattr(result, "extracted_text")
    assert not hasattr(result, "authorized")


def test_non_ascii_offsets_and_whitespace_are_exact():
    text = "α\n🧭  Z\t" + "padding " * 30
    result = plan(text, (SourceSpan(0, 6),))
    assert result.excerpts[0].text == "α\n🧭  Z"
    assert result.excerpts[0].utf8_bytes == 10
    assert result.retained_utf8_bytes == 10


def test_fingerprint_repeatable_and_not_order_of_keywords():
    assert plan().fingerprint == plan().fingerprint
    assert len(plan().fingerprint) == 64
    assert plan().fingerprint != plan(output_locator="archive://synthetic/moved").fingerprint
    assert plan().fingerprint != plan(spans=(SourceSpan(1, 24),)).fingerprint
    assert plan().fingerprint != plan(limits=ExcerptLimits(retained_bytes=8000)).fingerprint
    assert plan().fingerprint != plan(TEXT + " ").fingerprint
    args = dict(extraction_sha256=hashlib.sha256(TEXT.encode()).hexdigest(),
                output_locator="archive://synthetic/extractions/one", spans=(SourceSpan(0, 24),))
    assert plan().fingerprint != plan_source_index("revision:sha256:" + "b" * 64, TEXT, **args).fingerprint


def test_result_and_input_limits_are_immutable():
    result = plan()
    with pytest.raises(FrozenInstanceError):
        result.excerpts = ()
    with pytest.raises(FrozenInstanceError):
        result.excerpts[0].text = "changed"
    with pytest.raises(FrozenInstanceError):
        result.limits.retained_bytes = 10000


@pytest.mark.parametrize("text", ["", "a", "ab", "abc"])
def test_tiny_sources_support_reference_only(text):
    result = plan(text, ())
    assert result.coverage == "reference-only"
    assert result.excerpts == ()
    assert result.retained_utf8_bytes == 0


@pytest.mark.parametrize("text", ["a", "short note", "x" * 1024])
def test_whole_document_is_rejected_even_when_it_fits_absolute_budget(text):
    refused("retention-limit-exceeded", lambda: plan(text, (SourceSpan(0, len(text)),)))


def test_fraction_exact_boundary_and_one_byte_over():
    assert plan("x" * 400, (SourceSpan(0, 100),)).retained_utf8_bytes == 100
    refused("retention-limit-exceeded", lambda: plan("x" * 400, (SourceSpan(0, 101),)))
    assert plan("🧭" * 400, (SourceSpan(0, 100),)).retained_utf8_bytes == 400


def test_multibyte_excerpt_cap_counts_bytes_not_characters():
    assert plan("🧭" * 2000, (SourceSpan(0, 256),)).retained_utf8_bytes == 1024
    refused("excerpt-limit-exceeded", lambda: plan("🧭" * 2000, (SourceSpan(0, 257),)))


def test_absolute_aggregate_and_individual_caps():
    text = "x" * 40000
    spans = tuple(SourceSpan(n * 1024, (n + 1) * 1024) for n in range(8))
    assert plan(text, spans).retained_utf8_bytes == 8192
    refused("retention-limit-exceeded", lambda: plan(text, spans + (SourceSpan(9000, 9001),)))
    refused("excerpt-limit-exceeded", lambda: plan(text, (SourceSpan(0, 1025),)))
    assert plan(text, (SourceSpan(0, 4096),), limits=ExcerptLimits(4096, 32768, 128)).retained_utf8_bytes == 4096


def test_no_truncation_or_partial_plan_on_late_invalid_span():
    refused("invalid-span", lambda: plan(spans=(SourceSpan(0, 10), SourceSpan(100, len(TEXT) + 1))))
    refused("excerpt-limit-exceeded", lambda: plan(spans=(SourceSpan(0, 10), SourceSpan(100, 1200))))


@pytest.mark.parametrize("spans", [
    [SourceSpan(0, 1)], iter((SourceSpan(0, 1),)), None,
    tuple(SourceSpan(i * 2, i * 2 + 1) for i in range(33)),
])
def test_span_container_and_count_are_bounded(spans):
    refused("excerpt-count-exceeded", lambda: plan(spans=spans))


@pytest.mark.parametrize("span", [
    SourceSpan(-1, 2), SourceSpan(0, 0), SourceSpan(2, 1), SourceSpan(0, 10000),
    SourceSpan(True, 2), SourceSpan(0, False), SourceSpan(0.0, 1), SourceSpan("0", 1), None,
])
def test_invalid_span(span):
    refused("invalid-span", lambda: plan(spans=(span,)))


@pytest.mark.parametrize("spans", [
    (SourceSpan(0, 10), SourceSpan(0, 10)),
    (SourceSpan(0, 10), SourceSpan(9, 20)),
    (SourceSpan(10, 20), SourceSpan(0, 10)),
])
def test_duplicate_overlapping_or_unsorted_spans_refuse(spans):
    refused("invalid-span", lambda: plan(spans=spans))


@pytest.mark.parametrize("field, value", [
    ("per_excerpt_bytes", 0), ("per_excerpt_bytes", 4097), ("per_excerpt_bytes", True),
    ("retained_bytes", 32769), ("retained_bytes", -1), ("retained_bytes", 1.5),
    ("excerpt_count", 129), ("excerpt_count", False), ("excerpt_count", "32"),
])
def test_invalid_limits(field, value):
    refused("invalid-limits", lambda: ExcerptLimits(**{field: value}))


def test_lower_limits_and_bypassed_constructor_are_rechecked():
    refused("excerpt-limit-exceeded", lambda: plan(limits=ExcerptLimits(per_excerpt_bytes=23)))
    refused("retention-limit-exceeded", lambda: plan(limits=ExcerptLimits(retained_bytes=23)))
    refused("invalid-limits", lambda: plan(limits=None))
    invalid = ExcerptLimits()
    object.__setattr__(invalid, "retained_bytes", 1000000)
    refused("invalid-limits", lambda: plan(limits=invalid))


@pytest.mark.parametrize("locator", [
    "", None, "relative/path", "data:text/plain,secret", "javascript:alert(1)",
    "blob://engine-owned-original", "ftp://host/source", "file:relative", "file://remote/source",
    "https:///missing-host", "https://user:secret@host/path", "https://host:bad/path",
    "https://host:65536/path", "http://[bad", " archive://host/one", "archive://host/one\n",
    "archive://host/" + "x" * 4096, "archive://host/\ud800",
    "https://bad host/path", "https://host/a b", "https://host/%", "https://host/%GG",
    "https://host/%0G", "https://host/%A", "https://host/\\payload", "https://host/path?value={raw}",
    "archive://bad host/one", "file:///tmp/a b", "https://host/[raw]", "https://host/?q=[raw]",
    "https://host/path#fragment#extra", "https://host/é", "https://é/path", "file:///tmp/é",
    "https://@host/path", "https://host:1:2/path", "https://[::1]extra/path",
    "https://[v1.name]/path", "https://[fe80::1%25en0]/path",
])
def test_invalid_external_reference(locator):
    refused("invalid-locator", lambda: plan(output_locator=locator))


@pytest.mark.parametrize("locator", [
    "file:///tmp/synthetic-extraction.txt", "file://localhost/tmp/synthetic.txt",
    "http://example.invalid/extract", "https://example.invalid:443/extract?revision=one",
    "archive://synthetic/extractions/one",
    "https://[::1]:443/path", "http://[::ffff:192.0.2.1]/path", "https://host:0/path",
    "https://host:/path", "https://host/%C3%A9?q=%2F%25#part-1", "file:///tmp/a%20b",
    "https://xn--9ca.example/path", "archive://synthetic/one?name=a/b?c#part/?end",
])
def test_valid_reference_is_retained_without_resolving(locator):
    assert plan(output_locator=locator).output_locator == locator


@pytest.mark.parametrize("digest", [None, "a" * 63, "g" * 64, "A" * 64])
def test_invalid_digest(digest):
    refused("invalid-extraction-digest", lambda: plan(extraction_sha256=digest))


def test_digest_is_over_exact_utf8_not_normalized_text():
    refused("extraction-digest-mismatch", lambda: plan(extraction_sha256="0" * 64))
    text = "e\u0301" * 100
    refused("extraction-digest-mismatch", lambda: plan(text, (), extraction_sha256=hashlib.sha256(("é" * 100).encode()).hexdigest()))


@pytest.mark.parametrize("revision", [None, "asset:one", "revision:sha256:" + "A" * 64, REVISION + "\n"])
def test_revision_shape_does_not_register_or_authorize(revision):
    refused("invalid-source-revision", lambda: plan_source_index(revision, TEXT,
        extraction_sha256=hashlib.sha256(TEXT.encode()).hexdigest(), output_locator="archive://synthetic/one", spans=()))


@pytest.mark.parametrize("coverage", ["full", "reference-only", None, False])
def test_unsupported_coverage_never_silently_falls_back(coverage):
    refused("unsupported-coverage", lambda: plan(coverage=coverage))


def test_transient_extraction_cap_and_utf8_validation():
    for text in ("x" * (MAX_EXTRACTION_BYTES + 1), "🧭" * (MAX_EXTRACTION_BYTES // 4 + 1)):
        refused("extraction-limit-exceeded", lambda: plan(text, ()))
    refused("invalid-extraction", lambda: plan_source_index(REVISION, "\ud800",
        extraction_sha256="0" * 64, output_locator="archive://synthetic/one", spans=()))
    refused("invalid-extraction", lambda: plan_source_index(REVISION, b"bytes",
        extraction_sha256="0" * 64, output_locator="archive://synthetic/one", spans=()))


def test_no_io_or_source_write_and_existing_files_unchanged(tmp_path, monkeypatch):
    original = tmp_path / "original.txt"
    original.write_text(TEXT)
    before = original.read_bytes()
    def forbidden(*args, **kwargs):
        pytest.fail("admission must not perform I/O")
    with monkeypatch.context() as patch:
        patch.setattr("builtins.open", forbidden)
        patch.setattr(sqlite3, "connect", forbidden)
        patch.setattr(socket.socket, "connect", forbidden)
        patch.setattr(socket, "getaddrinfo", forbidden)
        result = plan(output_locator=original.as_uri())
    assert original.read_bytes() == before
    assert tuple(tmp_path.iterdir()) == (original,)
    assert result.retained_utf8_bytes == 24


def test_plan_is_not_a_lifetime_budget_or_authorization_receipt():
    first = plan("x" * 400, (SourceSpan(0, 100),))
    second = plan("x" * 400, (SourceSpan(100, 200),))
    assert first.fingerprint != second.fingerprint
    assert not hasattr(first, "committed")
    assert not hasattr(first, "policy")
    # A durable writer must reject inappropriate cumulative retention separately.
    assert first.retained_utf8_bytes + second.retained_utf8_bytes == 200


def test_changing_result_does_not_forge_an_authorization_contract():
    forged = replace(plan(), retained_utf8_bytes=0)
    assert forged.fingerprint == plan().fingerprint
    assert not hasattr(forged, "verify_authorization")
