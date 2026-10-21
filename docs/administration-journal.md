# Witnessed Administrative Attribution

This optional core journal records the authenticated actors and exact candidate behind explicitly journaled grant, registry and profile administration. It is not a memory store, transport authenticator, grant authority, activation switch or automatic recovery agent. Original documents, grants, replacement records, prompts, request credentials and complete claim/control sets are not copied into it. Existing non-journaled development APIs and ordinary memory behavior remain unchanged; a host claiming audited administration must explicitly require this journaled path and must not silently fall back to the unjournaled prerequisite. Raw owner writes are not automatically attributed.

## Storage And Trust

`AdministrationJournal(connection, witness_connection=..., authority_id=..., journal_id=..., witness_id=..., issuer=..., authenticate_read=...)` pins independent identities and explicit SQLite connections. The journal and its dedicated `SnapshotAuthority` witness must be distinct private owner-controlled files, also distinct from the configuration and configuration-witness files. Files require mode 0600 and private parent directories 0700; in-memory databases, aliasing, changed file identity, unexpected schema/temp objects, attached databases and unsupported transaction/durability settings refuse. WAL with FULL/EXTRA synchronous or DELETE with EXTRA is required for writes. No path discovery, daemon, cloud service or privileged helper is added.

`prepare(max_operations=1024)` is explicit owner provisioning. Capacity is immutable and at most 4,096 operations. Every intent reserves logical space for up to three events: intent, prepared-receipt observation and committed-receipt observation. Completion does not compete with later intents for those slots; no automatic eviction or history truncation occurs. This does not prevent disk-full, hardware or I/O failure. The witness is dedicated to this journal, with capacity and schema version bound into its initial root checkpoint.

The raw owner, both connections, append/observe/recover APIs and the authentication callback stay outside model tools and ordinary readers. They remain trusted native-code capabilities, not a sandbox against the OS/key owner. Configuration roles do not acquire journal access or grant/content rights automatically.

## Events And Meaning

An immutable `AdministrationIntent` contains the operation and plan digests, exact predecessor/candidate revisions, one target principal/store pair, and two `AdministrativeActor` attributions. Each attribution records issuer, principal, canonical actor, administrative authorization revision/epoch and a digest of the complete admitted claim. Those hashes bind the reviewed claims without storing their credentials or full scopes. They are not signatures, credentials or proof that a future host authenticator is correct.

`RegistryAdministrationIntent` instead names one exact supported collection/record target, and `ProfileAdministrationIntent` names one exact profile. All three share strict successor/actor/digest requirements and independent witness publication. Existing grant-intent bytes are unchanged; new readers strictly decode the three forms, refusing hybrids/unknown fields. Older readers refuse unsupported intent types rather than reinterpret them. The corresponding [registry facade](host-registry-administration.md) and explicit journaled [profile facade](host-profile-administration.md#independently-witnessed-profile-attribution) require independent approval and canonical control/beneficiary exclusions. This is not an automatic migration or a change to existing journal roots.

| Event kind | What it establishes | What it does not establish |
| --- | --- | --- |
| `intent` | The exact admitted proposal/approval metadata was durably witnessed before the facade attempted configuration staging | The grant was staged, committed, still authorized later or ever used |
| `prepared` | A matching prepared owner receipt was observed while the independently checked configuration was usable | Witness advancement or completed configuration publication |
| `committed` | A matching committed owner receipt was observed | That this grant is currently effective, or that the caller received success |

Every complete event includes its sequence, UTC time, journal/authority identity and exact candidate. Observations reference the witnessed intent digest. Payloads are canonical and bounded to 8 KiB; unknown fields, malformed identities, incompatible revisions and invalid references refuse. Rows are immutable except the journal's prepared-to-finalized publication flag. Contiguous sequence/count coverage detects missing interior events, and historical witness publications authenticate each returned event and its intent reference. No full hash-chain traversal is required.

## Grant Workflow

Pass the exact journal explicitly when constructing the trusted facade:

```python
admin = GrantAdministration(
    owner,
    authority_id=authority_id,
    issuer="administrative-login",
    authenticate=authenticate_administrator,
    journal=journal,
)
```

The existing view/preview/approve/apply methods remain the same. After fresh actor, control, approval, deadline and predecessor checks, apply consumes the local plan and commits/witnesses/finalizes the intent before calling configuration stage. It reauthenticates after journal I/O; an audit failure, ambiguous acknowledgment, revocation or expired plan prevents configuration staging. It then uses the existing configuration stage/witness/finalize protocol. After finalization, it records the actual committed receipt before the final authorization check and successful return.

There is deliberately no atomic transaction spanning all four files. Configuration may commit while its observation fails, or final authentication may refuse after both writes committed. A refusal is not proof that nothing changed. The intent remains available for explicit reconciliation; normal apply cannot replay its consumed plan. Logical event reservation does not eliminate these I/O uncertainty windows.

## Explicit Recovery And Reconciliation

Journal append prepares one local tail, publishes that exact event digest to the independent witness, then finalizes locally. Another append or read refuses while that tail is unresolved. `journal.recover()` can finish only that exact audit event: an exact predecessor permits explicit witness publication; an already matching witness permits local finalization. Any other checkpoint refuses. Recovery cannot stage, witness, finalize, retry or roll back configuration grants. Interrupted empty-root provisioning is retried only through explicit `prepare` with the same immutable identity and capacity.

`journal.observe(operation_id, owner=owner)` reads the real owner receipt, not a caller-supplied phase. It freshly validates the usable configuration before and after receipt lookup and matches the operation/candidate to the witnessed intent. No receipt returns `None` without asserting terminal failure. Existing observations cannot be downgraded or forgotten. A configuration witness advanced before local finalization fences observation until separately authorized configuration-owner recovery; journal recovery alone cannot finish it. Historical committed receipts remain observable after later configuration changes.

Restoring the journal alone or its witness alone fences inconsistent history. Co-restoring every independent trust anchor cannot prove freshness; the qualified host must preserve a surviving independent anchor for its supported restore domain. A private directory, file timestamp or deterministic marker is not a replacement. This journal does not retroactively give older unjournaled operations attribution or enforce every trusted owner's direct mutation path.

## Composed Recovery Qualification

The disposable `tests/test_host_administration_recovery.py` suite composes profile, grant and registry changes with fresh request binding and four-file recovery. It verifies that profile edits and subsequent grant restrictions remain intact across later route revisions; every old request handle fences, and the host must authenticate the matching fresh route. An unmapped newly joined participant refuses and cannot reuse the old handle. This is native policy/request admission evidence, not proof of a clean provider context, cancelled output or UI/history isolation.

Restoring only configuration or its independent witness fences configuration admission. Restoring only the administrative journal or its witness fences audit access and further journaled writes, without undoing a separately witnessed grant restriction. The test restores actual disposable SQLite backup images, including historical state; it does not edit state flags or point at live databases. Restoring all independent anchors together remains outside the surviving-anchor guarantee and is not called a passed freshness test.

For all three administrative intent types, journal-only recovery finalizes only the exact metadata tail and never stages a configuration proposal. When the configuration witness advanced but local finalization did not, journal recovery alone cannot repair it: separately authorized `owner.recover(operation_id)` must finalize that witnessed configuration, followed by explicit `journal.observe(operation_id, owner=owner)`. Neither operation replays a consumed administration plan. No automatic recovery loop, downgrade, reindex or service restart occurs.

### Unwitnessed Preparation And Opt-In Cancellation

In default owner format 1, after configuration staging succeeds but witness advancement does not happen, `owner.recover(operation_id)` deliberately returns the inert `prepared` receipt rather than authorizing it. The prior witnessed configuration remains readable. The durable prepared row also blocks a different successor; a fresh facade preview cannot overwrite it. The composed regression verifies this actual state instead of pretending receipt inspection resolves it.

Explicit opt-in [owner format 2 and audited cancellation](cancellable-configuration.md) add a separately authorized reaffirmation without modifying the preserved proposal. `CancellationAdministrationIntent` is a fourth strict intent form linking the abandoned operation/revision to the actual reaffirmation candidate. Observe the cancellation operation's real receipt; observing the original derived `cancelled` receipt refuses rather than inventing successful publication. All older intent bytes and journal roots remain unchanged. This does not add cancellation to an already pending legacy proposal or authorize a live migration. Never delete/overwrite prepared history, advance an obsolete proposal merely to unblock writes or reset an authority epoch.

## Separate Reader Authorization

`read(authenticated_request, destination=..., after_sequence=0, limit=100)` requires an exact current `AdministrationJournalRead` from the trusted synchronous read authenticator. It names the issuer/principal, whole configuration authority and journal, destination, administrative authorization revision/epoch and only `admin-journal:read`. Ordinary `grants:view`, profile capabilities, content clearances and content-decision `audit:read` do not supply this permission.

Authentication occurs before journal SQL and is rechecked after page materialization and immediately before returning. Changed claims, revoked access, wrong destination/authority/journal, foreign process/thread and reentry refuse with content-free errors. Pages are bounded to 1,000 events and contain only explicitly authorized administrative metadata. This is whole-journal authority, not an unimplemented per-store filter; authorized readers can see identifiers, counts and global activity. Constant-time confidentiality, real transport authentication and output routing are separate host qualifications.

## Qualification Boundary

Synthetic tests cover distinct reader rights, exact attribution, capacity, immutable/reference bounds, prepared-tail interruption, lost acknowledgments, journal-only/witness-only restore, historical digest mismatch, missing interior rows, configuration uncertainty, explicit reconciliation and no grant replay. These are local library guarantees under the trusted owner and surviving-anchor contract, not hardware power-loss certification, complete protected-host activation, regulatory compliance, production migration or Hermes integration.
