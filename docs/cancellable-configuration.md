# Audited Cancellation Of Unwitnessed Configuration

This opt-in core recovery API closes a narrow owner-state-machine gap: a durable configuration proposal that was never independently witnessed remains inert but blocks later writes. Cancellation preserves that proposal, independently approves and attributes a separate operation, and witnesses an exact reaffirmation of the prior usable configuration. It does not roll back a committed change, activate protected frontends, authenticate users or confer content access. Existing format-1 owners and serialized snapshots remain unchanged by default.

## Explicit Storage Selection

For a new disposable owner, supply `storage_version=2` to `HostConfigurationAuthority`, then explicitly provision it with `prepare()` and the usual initial `publish(...)`. Omission still selects format 1. Format 2 adds strict cancellation and committed-version tables and uses canonical snapshot envelope contract 3. Older clients, and format-1 instances, refuse its schema; do not use SQL to downgrade its marker or discard the extra tables.

The owner configuration database and independent witness retain the existing private-file, independent-identity, durability and ownership requirements. The administrative journal and its witness are separate again. These native owner connections and the authentication callbacks are not model tools or ordinary administration credentials.

## Trusted Cancellation Facade

Import `CancellationAdministration` and `CancellationAdministrationSnapshot` from `mnemosyne.core.host_cancellation_administration`. A trusted synchronous authenticator must return an exact current snapshot containing issuer, principal ID, canonical separation ID, authority ID, authorization revision/epoch, a bounded set of exact original operation IDs, a complete controlled-principal closure and explicit capabilities. The distinct capabilities are `recovery:view`, `recovery:cancel` and `recovery:approve`; grant, profile, registry, content and key rights imply none of them.

```python
recovery = CancellationAdministration(
    owner,
    authority_id=authority_id,
    issuer="recovery-login",
    authenticate=authenticate_recovery_operator,
    journal=journal,
)

view = recovery.view(proposer_request, original_operation_id)
plan = recovery.preview(proposer_request, original_operation_id)
approval = recovery.approve(independent_reviewer_request, plan)
receipt = recovery.apply(proposer_request, plan, approval=approval)
```

Requests above are host-authenticated opaque objects, not dictionaries or model-provided identities. Both actors must be enabled, registered and current under the same authorization revision/epoch. Their canonical control closures must resolve and be disjoint. Neither actor may control any grant holder, conversation participant or changed identity in either the prior or proposed registry. The initial recovery contract deliberately applies this conservative whole-proposal exclusion, not a speculative minimal-diff exemption. Hosts must supply complete control mappings; the library cannot discover hidden control relationships or prevent collusion.

Every write requires independent approval, including a same-semantics reaffirmation. Exact issuing objects, process/thread locality, bounded expiration and fresh claims are checked before each publication boundary and final return. `recovery.cancel(plan)` merely discards a local preview; it does not abandon a stored proposal. Plans are consumed before the mandatory journal write. A lost acknowledgment never authorizes replay.

## Preserved Proposal And Truthful Receipts

At generation N the original physical proposal remains `prepared`, byte-for-byte. The auxiliary cancellation row at that same generation has its own operation ID and canonical digest, binds the original operation/revision, and carries exactly the profiles and registry of logical committed generation N-1. The independent configuration witness publishes the reaffirmation, not the abandoned proposal. Subsequent ordinary publication uses generation N+1. Successive cancellations compare against the preceding logical resolution rather than the abandoned physical payload.

| Inspection | Before reaffirmation commits | After reaffirmation commits |
| --- | --- | --- |
| `owner.receipt(original_operation_id)` | Original `prepared` receipt | Derived `cancelled` receipt for the original revision |
| `owner.receipt(plan.operation_id)` | `None` or actual reaffirmation `prepared` receipt | Actual reaffirmation `committed` receipt |
| `owner.current()` | Prior configuration while the witness remains there; refuses an advanced-but-unfinalized boundary | Same prior semantics at the newly witnessed revision |

No physical row is rewritten to invent a cancelled phase. Resolution decoding verifies the preserved proposal, exact logical predecessor and unchanged configuration, including successive resolutions. Missing historical resolution metadata refuses original-receipt inspection rather than forgetting a cancellation. Original advancement/finalization refuses after a resolution is staged. An already witnessed original cannot be cancelled.

The version-2 owner holds a SQLite writer reservation across original witness admission and uses the same reservation for cancellation staging. A competing connection cannot admit both alternatives. This is arbitration, not an atomic transaction across files or a guarantee against the trusted OS owner.

## Audit And Uncertain Outcomes

The journal records a strict `CancellationAdministrationIntent` linking the original operation/revision, the reaffirmation revision and both actors. Its completion observation comes only from the actual cancellation operation receipt. Existing grant/profile/registry intent bytes remain unchanged. Older readers refuse unfamiliar intent forms. `journal.observe(original_operation_id, owner=owner)` explicitly refuses a derived `cancelled` receipt; it must not report the abandoned grant as committed. Read the linked cancellation intent and observe its own operation instead.

There is no multi-file atomic transaction. An exception can follow a durable intent, prepared resolution, witness publication or completed cancellation. Inspect exact receipts and the independent witness before choosing recovery. `owner.recover(cancel_operation_id)` finalizes only an already witnessed resolution; at the predecessor witness it returns the inert prepared receipt without publishing it. Any explicit owner decision to admit that prepared reaffirmation is a separately trusted recovery operation, not an automatic retry of a consumed facade plan. Recover a journal tail separately, then explicitly observe the cancellation operation. Never delete the proposal, reset an epoch, advance an obsolete original or silently fall back to unaudited administration.

Version 2 validates proposed profile/policy versions during staging but registers them atomically with finalization. A cancelled never-published version does not prevent a later legitimate version. Committed version identities remain monotonic even if a profile was subsequently removed. Reaffirmation can complete at the existing 1,024-generation capacity; it does not create spare capacity. A later successor at capacity refuses with `resource_limit` and requires a separately designed owner rollover, not history deletion.

## Explicit Legacy Migration

Only the trusted raw owner can request `upgraded = legacy_owner.migrate_cancellable(operation_id="reviewed-migration-id")`. This is an explicit owner-format migration, not a change to content stores, source indexes or private banks. It requires a quiescent format-1 owner with a committed head and matching witness, bounded contiguous independently witnessed committed history, consistent live policy namespaces and exact version-history coverage. An unresolved legacy proposal refuses before schema mutation; cancellation is not retroactively enabled for it.

Within the owner transaction, migration verifies history without retaining all decoded snapshots, reconstructs committed-only version tables, changes the strict schema and stages a same-semantics format-2 successor. It then witnesses and finalizes that successor. The independent witness cannot be part of the SQLite owner transaction. An interrupted format boundary refuses reads and ordinary writes rather than reopening in legacy mode. Reopen explicitly with `storage_version=2` and call `resume_cancellable_migration(exact_operation_id)` after inspecting its receipt; this resumes only the exact same-semantics transition, never a different proposal. A pre-schema transaction failure leaves format 1 untouched. Both old snapshot bytes and old version tables are preserved.

Restoring only the owner or only its witness fences incompatible state. Restoring every independent anchor together cannot establish freshness; supported recovery must retain an independently surviving anchor. Owner-format migration does not establish protected-store restore readiness, host authentication, provider/history isolation or a deployment approval.

## Qualification Boundary

Disposable tests exercise actual SQLite images, distinct connections, staged and witnessed races, interruption/reopen, corrupted/missing resolutions, conservative control exclusion, fresh claims, typed intent compatibility and candidate-hash parity across the existing facades. These are library guarantees under the stated trust boundary, not physical power-loss certification, full protected activation, regulatory compliance or a production migration. Hermes integration remains separate.
