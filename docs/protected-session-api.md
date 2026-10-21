# Protected Owner Session API

`ProtectedSession` is the explicit trusted-host SDK facade over one independently current encrypted generation. It composes the qualified policy reader, metadata-only audit admission, evidence leases and cooperative stream gate. It does not modify ordinary bank opening or install itself in a CLI, MCP server or Hermes provider. Existing clients and stores retain legacy behavior; an old client given an encrypted artifact cannot read it as ordinary SQLite.

## Host Contract

The host constructs `ProtectedSession(repository, store_id, destination=..., verify_context=..., audit=..., projects=None)` inside `bind_access_context` using an authenticated, freshly resolved effective context. The host verifier must authenticate every applicable participant, intersect their permissions, pin current policy/grant epochs and bind the real bank/project/destination. An agent's independent broader grant must not enlarge the conversation ceiling. Chat titles, model arguments and serialized assertions are not identity authorities.

The repository key, independent authority and raw RAM connection remain trusted owner capabilities. The verifier is synchronous, must return the exact matching bank/project grant with the current snapshot lifecycle epoch, and must not call a model. A context or lease is not a bearer credential. Session construction checks the trusted grant using authority metadata before decrypting memory, then uses the ordinary reader checks on the opened snapshot. Every verifier invocation checks exact current generation before and after the host callback. A changed generation invalidates the session; do not silently refresh it or rebind an old operation to a new scope.

The audit object uses a separate owner-controlled metadata database with the same bank/domain. Admission must durably commit before candidate generation or output. Audit I/O is followed by fresh scope/epoch checks. Direct denied and absent IDs both return `None`; audit admission means the scoped operation was admitted, not that an inaccessible object exists or was retrieved. The initial admission does not contain guessed object metadata or query text. The host must protect audit access separately using whole-journal administrative grants.

## Supported Operations

| Method | Result / boundary |
| --- | --- |
| `get(kind, record_id)` | Exact authorized memory or `None`; native indexed policy predicates run before text materialization |
| `candidates(kind, limit=100, offset=0)` | Authorized IDs and provenance only, no memory text |
| `source_metadata(revision_id)` | Authorized asserted revision metadata; no source fetch, locator or project expansion |
| `lexical(query, top_k=20, candidate_limit=200)` | Existing authorized FTS behavior and limits, bound to the authenticated conversation |
| `vector(query_embedding, embedding_model=..., top_k=20, scan_limit=1000)` | Existing authorized vector eligibility/scoring; explicit caller-supplied vector and exact native identity/dimension checks |
| `hybrid(query, query_embedding, embedding_model=..., ...)` | Existing authorized lexical/vector RRF; no graph, global KNN or hidden embedding provider |
| `issue(kind, record_id)` | Payload-free evidence lease pinned to current scope/value/lifecycle |
| `resolve(lease)` | Fresh authorized reload; lease must match this bank/destination/project selection |
| `deliver(lease, consumer)` | One synchronous `None`-returning consumer after fresh reload and post-audit reauthorization |
| `await stream(leases, producer, consumer, limits=...)` | Existing bounded cooperative async-generator gate; fresh checks after audit and before each emitted chunk |
| `dispatch(operation, **arguments)` | Fixed synchronous allowlist of the above synchronous methods; never arbitrary attribute lookup or a legacy fallback |

Native retrieval uses the additive `AuthorizedRetrievalSession(connection, session_id)` owner record instead of instantiating a legacy `BeamMemory` or inventing an object via `__new__`. This record itself grants nothing; native functions still require a matching policy reader connection and authenticated conversation. No legacy initialization, schema creation, default-bank lookup, provider creation, embedding call or vector conversion is hidden in it. The vector extension is loaded explicitly only for requested native vector/hybrid operations, then extension loading is disabled. Missing optional capabilities refuse.

Close the session on success, failure and cancellation, using its context manager. The snapshot connection stays query-only. Audit writes do not write into the memory snapshot. A synchronous consumer can already have had effects when a later check or callback fails; never blindly retry delivery. Already emitted streaming text cannot be retracted. Producers must be cooperative; this API is not a sandbox against malicious same-process code or arbitrary additional privileged inputs to a model.

## Unsupported Surfaces

Writes, derivation, quarantine, maintenance, graph recall, persona injection, export/import/sync, administrative/debug SQL, source expansion, key administration and implicit bank initialization are not dispatch methods. They refuse, not fall back. Trusted owner provisioning/publication is separate from agent operations. The immutable snapshot boundary prevents plaintext reads by old SQLite clients; it does not make older adapter configurations compatible or grant permission to deploy them.

CLI/MCP/Hermes integration still needs a trusted host mapping and endpoint-level qualification. An unavailable authenticated participant set must deny, not use the agent's own broad credentials. This contribution does not enable protected mode in those legacy entry points or claim they can serve protected requests. Do not advertise broad P4 parity or a production-ready protected service from these SDK tests alone.

## Example

```python
with bind_access_context(host_effective_context):
    with ProtectedSession(repository, host_store_id,
                          destination=host_destination,
                          verify_context=host_current_grant,
                          audit=private_audit) as memory:
        lease = memory.issue(RecordKind.WORKING, "synthetic-id")
        memory.deliver(lease, host_synchronous_prompt_consumer)
```

The host supplies all names and callbacks through trusted configuration, not model arguments. This example has no default store, key lookup, model call or live migration. See [owner/authority publication and recovery](protected-owner-contract.md), [codec limits](protected-storage-design.md), [audit contract](policy-audit-contract.md) and [existing policy API](policy-api-guide.md).
