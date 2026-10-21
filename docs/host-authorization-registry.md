# Host Authorization Registry

Downstream opt-in contract under development, not a deployed frontend or a regulatory certification. One generic mechanism uses configured vocabulary, scopes, purposes, recipients and routes across domains. It does not require separate healthcare, legal or financial rules engines. A configuration cannot establish an external fact such as current identity, consent or lawful disclosure by declaring it true in model-controlled input; the trusted host must supply any required current evidence. Unsupported predicates remain refused.

## Scope And Storage

`AuthorizationRegistry` contains explicit principal, store, destination, conversation and grant records. No original documents, memory text, embeddings, credentials, arbitrary expressions or executable callbacks are accepted. The trusted owner publishes the entire registry with profiles in the existing configuration prepare/witness/finalize protocol. Registry-bearing snapshots use envelope contract 2; existing profile-only contract 1 bytes remain unchanged. Older readers reject contract 2 rather than reopen it without grants. Registry activation is monotonic: a later publication cannot silently drop the registry and revert to profile-only operation.

One revision covers profiles and all registry records. Owner publication is not an authenticated administrative interface: raw owner connections, witness and mutation methods must remain outside model tools. The [scoped profile facade](host-profile-administration.md#profiles-with-an-existing-registry) can update permitted profiles while preserving the exact registry and validating its references. Configuration-only administrators cannot mutate or silently strip registry records. Principal, grant, audience and route administration remain separate unsupported capabilities, not implicit blanket administration.

## Records And Limits

All IDs are exact bounded nonblank strings, not display names or wildcard patterns. External identity mappings use issuer plus subject; aliases share a canonical `separation_id` for future independent-approval checks. Principals are explicitly human, agent or service and can be disabled. Disabling never deletes history or restores an earlier grant.

Each store pins a store identity, bank, domain, profile, owner-registry key and lifecycle epoch. Each grant is for exactly one principal/store pair and is intersected with every other audience member, never unioned across overlapping grants. Empty sets grant nothing; bank-wide access requires an explicit boolean. Destinations pin issuer/platform/route revision and the complete recipient set. Conversation records pin exact participants, store, destination, ceiling, purpose and operation/project selection. Destination recipients and conversation participants must match; the trusted transport must independently attest that complete audience before use.

Limits are 256 principals, 32 stores, 256 destinations, 256 conversations, 4,096 grants and 256 labels per set. IDs/labels are at most 128 Unicode characters, classification IDs 64. The existing 256 KiB canonical configuration payload and 1,024-revision bounds also apply; reaching any limit refuses rather than evicting revocation/history state. Lists cannot contain duplicates. Unknown fields, invalid Unicode, mixed types, dangling references and incompatible vocabulary refuse. All required record keys are explicit, including booleans and empty sets in serialized input.

## Acceptance Boundary

This increment must prove strict round trips, deterministic ordering, no privilege from empty/default records, wrong/missing scope refusal, exact issuer/subject mapping, bounded resources, atomic profile/registry publication, old-client refusal, no registry downgrade, concurrent/stale writers, interrupted publication and restore fencing with an independent surviving witness. Co-restoring all authorities still cannot prove freshness without a surviving anchor. No existing bank is migrated or reindexed.

Real request authentication, fresh transport/audience binding, provider/output hooks, tool-owner separation and exact frontend qualification remain required before protected activation. Registry records by themselves are neither credentials nor permission to invoke a legacy memory API.
