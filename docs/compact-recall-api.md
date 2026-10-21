# Compact Evidence Recall

`CompactRecall` delivers a token-budgeted JSON evidence pack using existing authorized evidence leases. It does not change normal recall, summarize facts, generate embeddings, fetch source documents or authorize access. Use it after indexed authorized retrieval and lease issuance, not as a filter over an unrestricted retrieval pool. On a protected repository, use the guarded `ProtectedSession`, not its private connection or underlying evidence object.

## API

```python
recall = CompactRecall(memory, tokenizer_id="host-pinned-tokenizer-revision",
                       count_tokens=host_exact_local_token_counter)
receipt = recall.deliver(primary, supplemental, host_synchronous_consumer,
                         token_budget=4096, max_supplemental=5,
                         max_excerpt_characters=4096)
```

`memory` is an explicit `PolicyEvidence` or `ProtectedSession`. The host supplies a synchronous deterministic exact token counter and its pinned identity. There is no heuristic fallback, remote tokenizer request, default tokenizer, model call or download. The trusted counter receives sensitive authorized text; do not point it at an unapproved service. Counts cover the exact canonical JSON string passed to the consumer, including metadata, ASCII escapes and omission fields. Surrounding prompt/messages, provider framing and response reserve remain the caller's budget responsibility.

Inputs are lists/tuples of `CompactCandidate(lease, group_id=None, timestamp=None)`, with 1–32 distinct record identities in total and one exact bank/destination/project/lifecycle/scope. Supply provenance groups/timestamps only from already authorized trusted host results, never arbitrary model claims. Primary ranking stays in input order. Existing `build_evidence_pack` rules select at most one supplemental candidate per explicit new group, excluding groups represented by primary, then order supplemental rows chronologically. Missing supplemental provenance is not invented: the item is omitted. Duplicate record identities or mixed scopes refuse.

Every supplied lease is freshly resolved, including candidates later omitted. Forbidden, revoked, stale or missing evidence refuses the complete request before token counting or delivery. Native memory-text evidence is supported; source-revision metadata and automatic external-source expansion are not. No source URI, revision or span is invented from a memory row. The exact lease can be resolved separately; original-document expansion remains the existing separately authorized resolver contract.

Native content over 16,384 characters refuses. This is an output-assembly ceiling after the existing resolver, not a claim of bounded internal SQLite page reads or a streaming native-text loader. Full originals remain external. No additional document store, persistent text cache or retention side channel is introduced.

## Output And Delivery

The consumer receives canonical JSON containing version, tokenizer identity, `primary`, `evidence_pack`, and explicit omitted-primary/supplemental counts. Each item retains exact lease/provenance metadata, a verbatim prefix, original character count and `content_truncated` flag. No ellipsis, rewritten sentence or generated claim is inserted. The sensitive `CompactRecallReceipt` records exact counted tokens, delivered/omitted counts, excerpt characters and scope fingerprint without copying text.

If a full excerpt does not fit, bounded geometric prefix lengths are tried and each complete candidate wire representation is counted exactly. Token length is not assumed monotonic in characters: this is not binary search, optimal packing or maximal budget utilization. Primary order is preserved, but rows may be clipped or omitted when metadata/text cannot fit. Unicode slices remain valid code-point prefixes, not necessarily grapheme boundaries. Omission is visible. If empty-pack metadata cannot fit, return `resource_limit`, not a successful empty substitute.

The final string is counted again to reject an observed unstable counter. All supplied leases are reauthorized after tokenizer/packing work, then the bound context is checked immediately before the synchronous `None`-returning consumer. A permission or participant change during counting blocks delivery; a prior lookup does not authorize new-context injection. The host still stops provider use on later changes through the cooperative streaming contract. Already emitted bytes cannot be retracted. No secure-erasure or malicious same-process sandbox claim is made.

## Example With Existing Leases

```python
primary = [CompactCandidate(primary_lease, "authorized-session-a")]
supplemental = [CompactCandidate(other_lease, "authorized-session-b",
                                 "2026-01-02T12:00:00Z")]
with bind_access_context(host_current_effective_context):
    receipt = CompactRecall(memory, tokenizer_id=host_tokenizer_id,
                            count_tokens=host_count_tokens).deliver(
        primary, supplemental, host_consume_json, token_budget=4096)
```

Leases come from authorized query/issuance, not model-supplied dictionaries. They are not access grants: reuse reloads and checks exact value/effective scope. Host callbacks are configured outside model tool arguments. No entry point is registered automatically; library qualification is separate from adapter acceptance and production activation.

Tests use an exact synthetic byte tokenizer and denied canaries, including nonmonotone counts, revocation/value changes during counting, omissions, Unicode fidelity and authorized expansion. Synthetic counters establish algorithm behavior, not deployed-model quality or token counts. Record guarded runtime cost and exact recall/omission behavior alongside savings; smaller output alone does not prove better quality.
