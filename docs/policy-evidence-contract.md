# P3c: Reauthorized Evidence Leases

Status: downstream implementation contract based on P3b `371a83c`. Additive explicit API only; no schema, default, adapter, live store or protected-activation change. This is a small part of P3, not completion of system-wide cache, stream, export or restore enforcement.

## Contract

`PolicyEvidence(reader).issue(kind, record_id, *, destination, projects=None)` performs a new authorized read and returns a frozen payload-free `EvidenceLease`. The lease records exact record/binding identity, a digest of the observed authorized value, and a fingerprint of the complete trusted context, bank/domain/destination, selected projects, owners/tenants and lifecycle epoch. Its metadata can itself be sensitive; it is not a public diagnostic or a credential. Constructing, copying or deserializing a lease grants nothing.

`resolve(lease)` reauthenticates the current host context and independently current epoch, pins that scope before every supported candidate/content consumer, reloads the native record and verifies its exact identity/digest. It never accepts a cached text/vector payload. A changed participant, purpose, grant, destination, project selection, policy epoch, binding, record or source revision refuses with a content-free code. Unrelated quarantine conservatively invalidates all leases at the prior store epoch. A missing/denied ID is not distinguishable through the refusal message.

Only prepared-v2 catalogs and existing explicit direct/native/source metadata reads are supported. Source leases contain no locator or original bytes and resolving them performs no source I/O. Projects use the existing confirmed-membership contract; project-selected source metadata remains unsupported. Caller-held transactions refuse so uncommitted records and retained caller snapshots cannot issue or resolve externally held evidence. No schema is implicitly prepared.

Both issue and resolution require fresh host authority; the host must not derive the current epoch from the reader's retained snapshot. Scope verification uses the existing reader contract, not a second identity service. A final cooperative check precedes return. Callers must resolve immediately before assembling a new tool/model/provider input and discard older payloads; this API cannot erase already returned bytes, prevent arbitrary in-process owner SQL, cancel blocked verifiers or make a later provider/stream callback linearizable. No callback runner, autonomous loop, implicit fallback, cache or provider invocation is added.

## Acceptance

Use synthetic stores and actual explicit readers. Cover positive working/episodic/canonical/source records, projects, immutable payload-free representation, exact retry, stale lifecycle/context/grants, quarantine of descendants, changed content or bindings, wrong bank/domain/destination, missing/deleted rows, forged leases, v1/unprepared catalogs, caller transactions, lost authority, awaitables/cancellation and final verifier rebinding. Instrument denied text before candidate consumers and retain original exception identity with cleared completed payload frames. Test repeated use with fresh decisions and zero recall writes. Include supported Python, installed-package controls and identical predecessor workloads; document unsupported paths instead of promoting global V5/V6 readiness.
