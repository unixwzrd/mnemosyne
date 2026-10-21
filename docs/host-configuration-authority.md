# Witnessed Host Configuration History

**Status:** Isolated H-A implementation candidate, not protected activation or a released public configuration API. This first increment persists bounded profile metadata only. It does not yet implement principal/grant/audience registries, authenticated request binding, administrative delegation/approval, self-elevation analysis, regulatory evaluators or frontend enforcement. Those remain separate work. No existing store or configuration is migrated.

## Owner Boundary

`HostConfigurationAuthority` is a trusted owner API, not an administrator role or model tool. Its objects, raw connections and publication methods must remain outside ordinary configuration administrators and agent tool capabilities. It grants no content access and has no recall/read-memory interface. A future administrative facade must separately authenticate and authorize its caller, scope metadata visibility and distinguish display edits from security-semantic changes. An administrator role cannot be inferred from a label in the registry.

Keys and content are not stored here. Profile IDs, terms and relationships can still be sensitive. This is not a sandbox against raw SQLite owners or code executing with their identity. Arbitrary same-owner shell/debug access can bypass application checks; no protection against such tools is claimed.

## Data And Bounds

The exact version-one document contains contract version, pinned authority identity, generation and an ordered profile array. Unknown document/profile fields and noncanonical encodings refuse on read. Profile metadata uses the [generic profile contract](host-profile-contract.md): explicit stable policy/level identities and independent user/admin labels, no government/health/legal names baked into retrieval code. There is no generic payload or executable callback slot.

The authority ID and separate witness ID are distinct pinned 32-character lowercase hexadecimal identities. Generations are positive exact integers, bounded by the implementation's 1,024-revision capacity. There are at most 32 profiles per document and 256 KiB canonical ASCII JSON bytes per revision. Profile/policy version registries preserve immutable semantic identities and refuse redefinition, lower-version reuse and conflicting/lower-version resurrection after removal. Explicit reuse of the same immutable identity is allowed only through a new current publication. Empty profile registries are supported and grant nothing. Capacity exhaustion refuses; no implicit pruning, epoch reset or history rewriting is supplied.

Only explicit owner-supplied file-backed SQLite connections are admitted. The configuration and witness files must have different device/inode identities, owner-only mode 0600, and immediate parent directories owned by the process with mode 0700. File identities are pinned and rechecked; same-file/hard-link, leaf symlink, replacement, changed permissions and unsupported POSIX identity operations refuse. Parent namespaces and both backup domains are a host responsibility; this is not a general symlink-race defense against a malicious owner. Caller transactions, custom row/text factories and weakened write durability refuse rather than being changed.

Authority writes require WAL with synchronous FULL/EXTRA or DELETE with EXTRA, matching the independently qualified publication journal's admitted profiles. The host must qualify real filesystem/OS durability. A committed application test is not a physical power-loss simulation.

## Interfaces And State Machine

```python
api = HostConfigurationAuthority(
    configuration_connection,
    authority_id=host_pinned_configuration_id,
    witness_connection=independent_witness_connection,
    witness_id=host_pinned_witness_id,
)
api.prepare()  # Explicit provisioning only; no active profile or access grant.
prepared = api.stage(profiles, previous=previous_revision, operation_id=operation_id)
api.advance_witness(prepared)
committed = api.finalize(prepared)
snapshot = api.current()
```

This is owner pseudocode: connections, private roots, admitted durability and host identities must already be explicit. No default file, key, environment-selected bank, implicit provisioning or actual CLI syntax is introduced. `profiles` is an exact tuple of `ProfileDefinition`; `previous` is the exact current `ConfigurationRevision`, or None for the first publication. The single-call `publish(...)` performs the same stages without automatic failure retry.

1. `prepare()` creates or validates exact metadata schemas and the separately pinned witness schema. It establishes no current publication and no person/agent grant. Provisioning spans two files, not one cross-file transaction; a failure can leave one empty prepared schema. Reads never prepare or repair it.
2. `stage()` validates a canonical bounded document and exact predecessor under a serialized configuration transaction. It durably records immutable prepared bytes and operation ID before witness advancement. A prepared successor does not itself make its profiles current. Version identity metadata is committed in this same transaction.
3. `advance_witness()` rechecks the exact latest recorded receipt and uses the existing `SnapshotAuthority` compare-and-advance journal through an explicit adapter mapping: store ID is the configuration authority ID, bank/domain are fixed `host-configuration` / `host-configuration-v1`, generation/lifecycle epoch are the configuration generation, and digest is the canonical metadata digest. The pinned witness identity is separate. This adaptation qualifies configuration-digest selection, not independent host authentication or a general restore service.
4. `finalize()` verifies that the exact prepared digest is witnessed before changing only its phase to committed. A mismatch fences access. `current()` returns only a committed matching generation after independent witness checks inside and after its metadata read, never a retained predecessor when the witness has advanced.

The prior committed generation remains readable while its witness is still current and a later proposal is only prepared. After witness advancement but before finalization, reads deny. Reordering permission semantics requires explicit new profile/policy versions; a presentation-only change still receives a fresh profile version and authority generation. Stable identical metadata may be reused without redefining its version.

`receipt(operation_id)` inspects sensitive owner metadata, not current authorization. An exact retry of the latest operation is idempotent; conflicting IDs, stale predecessors and replay of older historical operations refuse. The witness update uses a bounded hashed operation ID. There is no autonomous retry or notification loop.

## Recovery And Restore

`recover(operation_id)` inspects the stored receipt and current witness. If the exact latest prepared successor is witnessed, it can finalize that successor. If a newer proposal is unwitnessed and the exact predecessor remains witnessed, recovery returns the prepared receipt without advancing it. Missing/conflicting state or uncertainty refuses. The initial unwitnessed preparation has no current authority; inspect its receipt and explicitly admit it only through the owner workflow.

A lost COMMIT acknowledgment can mean a stage, witness or finalization already committed. Inspect receipts/current state before another action; never infer that an exception means no write occurred. Transaction cleanup does not roll back independently committed history or a witnessed revocation. Historical receipts do not select an old generation. Unsupported/corrupt/noncanonical state and a missing current artifact are not repaired from older grants or profile defaults.

Restoring old configuration while its witness remains current refuses. Restoring both databases together cannot be detected solely from their matching old contents. Distinct files/inodes/IDs do not prove independent recovery domains: an actual surviving trust anchor and operational restore procedure remain prerequisites for activation. No first-boot acceptance, hardware monotonic counter, full-machine rollback detection, cloud service or migration is supplied here. The operator's existing protected memory publication authority remains separate from configuration generation.

## Qualification Boundary

Tests use disposable metadata files and synthetic profile names only. Required controls include empty denied provisioning, canonical profile round-trip, exact retries/CAS, immutable version identities, concurrent/pending writers, lost acknowledgments at every stage, fresh-connection recovery, old-configuration/current-witness refusal, file/durability/schema failures, resource limits and absence of content/admin grants. Profile construction and serialization are not authentication or enforcement qualification.

This increment does not complete H-A's full principal/grant metadata model or H-B/H-C frontend authority and egress work. No new qualified compliance claim, live data access, protected activation, service restart, upstream submission or deployment follows from these unit tests.
