# Trusted Host Participant And Routing Contract

Run the complete disposable example with `python -B examples/protected_memory_demo.py` in an isolated environment with the optional `protected` dependency and supported SQLite serialization (normally Python 3.11+). It creates only synthetic RAM memory and uniquely owned temporary encrypted/authority/audit fixtures, exercises a broader agent plus narrower human, exact compact output, old-epoch refusal and a fresh request, and removes those fixtures on exit. It never opens a default bank, saves a key, calls a model, fetches a source or changes installed configuration. [Example source](../examples/protected_memory_demo.py) and its subprocess test are part of this candidate; the byte tokenizer is explicitly synthetic, not a deployed model estimate.

The reference `ProtectedHostAdapter` bridges an already authenticated transport request to the guarded owner SDK. It computes the effective all-participant intersection and selects store/destination from trusted host state, not tool arguments. It is an opt-in Python integration API, not a new authentication service, mandatory gateway or installed CLI/MCP/Hermes plugin. No production route or migration is enabled by importing it.

## Required Host Inputs

```python
adapter = ProtectedHostAdapter(
    adapter_id="my-application-memory",
    issuer="my-authenticated-host",
    load_snapshot=host_current_atomic_snapshot,
    resolve_store=host_owner_store_registry,
)
adapter.invoke(authenticated_request, "get",
               {"kind": "working_memory", "record_id": "example"},
               host_synchronous_consumer)
```

`authenticated_request` is an opaque host transport/session capability. It is not a model-generated title, claimed principal, context dictionary or bearer string this library independently verifies. `load_snapshot(request)` must authenticate it and return a fresh atomic `HostPolicySnapshot`, or refuse. It must guarantee the complete applicable participant roster and current authority epoch, including the agent if its participation is applicable. A replayed/stale claim cannot be made trustworthy merely by constructing the dataclass. There is deliberately no default loader, permissive participant fallback or environment-variable identity lookup.

The snapshot includes the authenticated `AccessContext`, exact `PolicyDefinition`, one `ParticipantGrant` per applicable principal, store ID, domain, bank, destination and current lifecycle epoch. The independently current host authority must advance the context epoch on roster, grant, purpose, policy or route changes, even if textual permissions later become equal again. Every principal grant must be current at the snapshot epoch and interpreted under its exact policy definition. Construct snapshots from one host-authority read/transaction rather than mixing independently cached grants. The memory's independent publication authority remains separate; both checks must pass.

`resolve_store(store_id)` is a trusted owner registry returning exactly `(ProtectedRepository, PolicyAudit)` for that host-resolved identity. It must not discover stores from tool paths or user-controlled names. Use private, appropriately thread-owned SQLite/repository handles; the API does not turn SQLite connections into cross-thread safe objects or start a global connection pool. Lookup failures refuse. Existing owner and restore-anchor contracts still apply.

## Effective Conversation Ceiling

`ParticipantGrant` contains explicit allowed banks/projects, owners/tenants, compartments/audiences, purposes, operations/destinations, classification ceiling and a bank-wide boolean. Empty permissions grant nothing; there are no wildcard semantics. `HostPolicySnapshot.effective()` verifies an exact nonduplicated roster, matching current epochs and valid policy vocabulary, then computes the lowest applicable classification ceiling and intersections of the applicable permission sets. Outer context claims can narrow but never broaden those intersections.

The actual bank/destination and purpose must be allowed by every participant. Project selections must be explicit subsets of every participant's project grant. An empty selection does not mean all projects: bank-wide access requires an explicit `bank_wide=True` from every participant plus the shared `read:bank` operation. Otherwise use a nonempty authorized selection and `read:projects`, or refuse. Different owners may produce an empty common owner set and therefore no eligible rows. Do not substitute the agent's broader independent owner/tenant privileges.

The binding reloads the authenticated host snapshot on every verifier call and rejects any change from its pinned initial snapshot. It returns fresh bank/project grants tied to the exact effective context and memory lifecycle epoch. Store publication changes independently invalidate the owner session. No role, schema, permission or epoch result is cached as authority. Context fingerprints are deterministic identities, not credentials.

## Dispatch And Output

`invoke` accepts only bounded argument dictionaries and read/evidence operations from the SDK's allowlist: get, candidates, source_metadata, lexical, vector, hybrid, issue and resolve. Record-kind strings are decoded to the existing enum. Scope selectors, keys, profiles, repositories and executable callbacks cannot be supplied through arguments. Unsupported operations receive a fixed metadata-only dispatch denial, not legacy fallback. A local frontend label is not evidence that a real CLI/MCP/Hermes endpoint has been connected or qualified.

The adapter binds the effective context for the complete session, opens only the host-selected current generation, performs audited indexed access, then rechecks the original grant after a separate output-audit boundary immediately before its trusted synchronous consumer. It restores any outer context and closes the decrypted snapshot on exit or failure. Consumers must return None; a callback may already have had effects when it fails, so there is no automatic retry. Already delivered bytes cannot be recalled.

Trusted applications may instead use `with adapter.session(request) as memory:` to drive the explicit SDK's evidence/stream/compact APIs. Do not expose that Python owner object, callbacks or raw handles as arbitrary model capabilities. The application still owns actual transport cancellation, authenticated ingress audit and the complete applicable roster. Missing participant information, unavailable authority and unsupported operations fail closed rather than borrowing the agent's credentials.

## Compatibility And Acceptance

Legacy configuration, stores and adapters remain unchanged. A deployed frontend without the authenticated-host contract cannot serve protected requests; it is not made protected by a capability declaration or a similarly named synthetic test. CLI/MCP/Hermes installations need their own exact-artifact, real authenticated dispatch and failure/cancellation qualification before activation. No endpoint parity, production migration, timing confidentiality, physical durability, shared-memory synchronization or deployment follows from reference adapter tests.

Qualification uses disposable atomic snapshots and a real encrypted owner repository. Tests distinguish A/B/A private reads from a shared A+B context, agent privileges broader than a human's, missing/duplicate/stale grants, disjoint scopes, project versus bank-wide access, policy/epoch changes during audit, fixed unsupported denials, source selector/callback overrides and outer-context restoration. Existing pinned real-Hermes loader tests remain separate; reference labels are not substituted for those results.
