"""Exact synthetic token-budget checks; no tokenizer/model download."""

from dataclasses import replace
import json

import pytest

from mnemosyne.core.compact_recall import CompactCandidate, CompactRecall
from mnemosyne.core.policy import PolicyRefusal
from mnemosyne.core.policy_store import RecordKind
from mnemosyne.runtime_context import bind_access_context
from tests.test_policy_read import add, context, fixture as fixture
from tests.test_policy_evidence import evidence as evidence, issue


def byte_tokens(text):
    """Exact count for a synthetic byte tokenizer, not a real model estimate."""
    return len(text.encode("utf-8"))


def candidate(evidence, record_id, group=None, timestamp=None):
    return CompactCandidate(issue(evidence, record_id), group, timestamp)


def api(evidence, count=byte_tokens):
    return CompactRecall(
        evidence[3], tokenizer_id="synthetic:byte-v1", count_tokens=count
    )


def deliver(evidence, primary, candidates=(), **options):
    seen = []
    with bind_access_context(context()):
        receipt = api(evidence).deliver(primary, candidates, seen.append, **options)
    return receipt, seen[0], json.loads(seen[0])


def test_primary_order_exact_excerpts_provenance_and_token_budget(evidence):
    for value in ("a", "b"):
        add(evidence[0], value, content=(value + " technical evidence ") * 200)
    primary = [
        candidate(evidence, "b", "session:b"),
        candidate(evidence, "a", "session:a"),
    ]
    receipt, wire, decoded = deliver(evidence, primary, token_budget=2400)
    assert receipt.tokens == byte_tokens(wire) <= 2400
    assert decoded["tokenizer_id"] == "synthetic:byte-v1"
    assert [item["lease"]["record_id"] for item in decoded["primary"]] == ["b", "a"]
    for item in decoded["primary"]:
        original = (item["lease"]["record_id"] + " technical evidence ") * 200
        assert original.startswith(item["excerpt"])
        assert item["content_truncated"] == (len(item["excerpt"]) < len(original))
        assert item["original_characters"] == len(original)
        assert item["lease"]["value_fingerprint"]
    assert "technical evidence" not in repr(receipt)


def test_supplemental_reuses_existing_group_and_chronology_rules(evidence):
    for value in "abcde":
        add(evidence[0], value)
    primary = [candidate(evidence, "a", "same")]
    candidates = [
        candidate(evidence, "b", "same"),
        candidate(evidence, "c", "later", "2026-02-01T00:00:00Z"),
        candidate(evidence, "d", "early", "2026-01-01T00:00:00Z"),
        candidate(evidence, "e", None),
    ]
    receipt, _, decoded = deliver(evidence, primary, candidates, token_budget=6000)
    assert [item["lease"]["record_id"] for item in decoded["primary"]] == ["a"]
    assert [item["lease"]["record_id"] for item in decoded["evidence_pack"]] == [
        "d",
        "c",
    ]
    assert decoded["omitted_supplemental"] == 2 and receipt.omitted_items == 2


def test_budget_smaller_than_wire_metadata_refuses_not_fake_success(evidence):
    add(evidence[0], "w")
    with (
        bind_access_context(context()),
        pytest.raises(PolicyRefusal, match="resource_limit"),
    ):
        api(evidence).deliver(
            [candidate(evidence, "w")],
            [],
            lambda _: pytest.fail("unexpected output"),
            token_budget=1,
        )


def test_omissions_are_explicit_when_entry_metadata_does_not_fit(evidence):
    add(evidence[0], "w")
    receipt, _, decoded = deliver(
        evidence, [candidate(evidence, "w")], token_budget=200
    )
    assert decoded["primary"] == [] and decoded["omitted_primary"] == 1
    assert receipt.omitted_items == 1 and receipt.primary_items == 0


def test_tokenizer_change_or_revocation_before_consumer_refuses(evidence):
    add(evidence[0], "w")
    item = candidate(evidence, "w")
    seen = []

    def count(wire):
        evidence[1].contexts.clear()
        return byte_tokens(wire)

    with (
        bind_access_context(context()),
        pytest.raises(PolicyRefusal, match="access_denied"),
    ):
        api(evidence, count).deliver([item], [], seen.append)
    assert seen == []


def test_native_value_changed_during_counting_refuses(evidence):
    add(evidence[0], "w")
    item = candidate(evidence, "w")

    def count(wire):
        evidence[0].conn.execute(
            "UPDATE working_memory SET content='corrected' WHERE id='w'"
        )
        evidence[0].conn.commit()
        return byte_tokens(wire)

    with (
        bind_access_context(context()),
        pytest.raises(PolicyRefusal, match="access_denied"),
    ):
        api(evidence, count).deliver([item], [], lambda _: pytest.fail("stale output"))


def test_forged_or_revoked_candidate_never_reaches_tokenizer(evidence):
    add(evidence[0], "w")
    item = candidate(evidence, "w")
    forged = replace(item, lease=replace(item.lease, record_id="unknown"))
    with (
        bind_access_context(context()),
        pytest.raises(PolicyRefusal, match="access_denied"),
    ):
        api(evidence, lambda _: pytest.fail("unauthorized text counted")).deliver(
            [forged], [], lambda _: None
        )


@pytest.mark.parametrize("value", [True, -1, 1.5, "3", None])
def test_invalid_token_count_never_falls_back_to_estimate(evidence, value):
    add(evidence[0], "w")
    with (
        bind_access_context(context()),
        pytest.raises(PolicyRefusal, match="unsupported_surface"),
    ):
        api(evidence, lambda _: value).deliver(
            [candidate(evidence, "w")], [], lambda _: None
        )


def test_nonmonotone_token_lengths_still_obey_exact_final_count(evidence):
    add(evidence[0], "w", content="abcdefgh")

    def count(wire):
        primary = json.loads(wire)["primary"]
        size = len(primary[0]["excerpt"]) if primary else 0
        return {0: 10, 8: 900, 4: 1000, 3: 20, 2: 30, 1: 100}[size]

    seen = []
    with bind_access_context(context()):
        receipt = api(evidence, count).deliver(
            [candidate(evidence, "w")], [], seen.append, token_budget=100
        )
    assert json.loads(seen[0])["primary"][0]["excerpt"] == "ab"
    assert receipt.tokens == count(seen[0]) == 30


def test_nondeterministic_counter_refuses(evidence):
    add(evidence[0], "w")
    calls = []

    def count(wire):
        calls.append(True)
        return len(calls)

    with (
        bind_access_context(context()),
        pytest.raises(PolicyRefusal, match="context_unavailable"),
    ):
        api(evidence, count).deliver(
            [candidate(evidence, "w")], [], lambda _: pytest.fail("unstable count")
        )


@pytest.mark.parametrize("budget", [0, -1, True, 65537])
def test_invalid_budget_refuses(evidence, budget):
    add(evidence[0], "w")
    with bind_access_context(context()), pytest.raises(ValueError):
        api(evidence).deliver(
            [candidate(evidence, "w")], [], lambda _: None, token_budget=budget
        )


def test_duplicate_or_mixed_scope_never_reads(evidence):
    add(evidence[0], "w")
    item = candidate(evidence, "w")
    other = replace(
        item, lease=replace(item.lease, record_id="other", bank="different")
    )
    with bind_access_context(context()):
        with pytest.raises(ValueError):
            api(evidence).deliver([item], [item], lambda _: None)
        with pytest.raises(PolicyRefusal, match="access_denied"):
            api(evidence).deliver([item], [other], lambda _: None)


def test_long_native_memory_refuses_not_unbounded_injection(evidence):
    add(evidence[0], "w", content="x" * 16385)
    item = candidate(evidence, "w")
    with (
        bind_access_context(context()),
        pytest.raises(PolicyRefusal, match="resource_limit"),
    ):
        api(evidence).deliver([item], [], lambda _: None)


def test_unicode_excerpt_is_exact_and_expansion_uses_original_lease(evidence):
    text = "cafe\u0301 \u03b1\u03b2\u03b3 " * 40
    add(evidence[0], "w", content=text)
    item = candidate(evidence, "w")
    receipt, _, decoded = deliver(evidence, [item], token_budget=1200)
    assert text.startswith(decoded["primary"][0]["excerpt"])
    assert receipt.tokens <= 1200
    with bind_access_context(context()):
        assert evidence[3].resolve(item.lease).content == text


def test_deferred_counter_is_rejected_before_invocation(evidence):
    async def count(wire):
        pytest.fail("deferred token counter ran")

    with pytest.raises(TypeError):
        api(evidence, count)
