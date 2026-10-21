# Scoped Registry Administration

This opt-in core interface manages existing witnessed authorization metadata. It is not an identity provider, credential store, physical store mover, content reader, model tool or protected-mode activation switch. Normal legacy operation and the existing raw trusted-owner provisioning interface are unchanged. No source documents, private data, model calls or live services are needed for qualification.

## Trust And Scope

`RegistryAdministration(owner, authority_id=..., issuer=..., authenticate=..., journal=..., lifetime_seconds=60)` requires an exact `HostConfigurationAuthority`, a same-authority independently witnessed `AdministrationJournal` and a trusted synchronous host authenticator. There is no unjournaled fallback. The host returns an exact current `RegistryAdministrationSnapshot` from authenticated facts, never a model-selected username, chat label, scope or credential. `targets` contains at most 256 exact `(collection, record_id)` pairs; wildcards, Cartesian scopes, grant/profile capabilities and unknown collection names refuse.

The separate capabilities are `registry:view`, `registry:write` and `registry:approve`. None supplies content access, grant issuance, profile editing, journal reading, owner recovery, raw keys or administrative-role issuance. `controlled_principals` includes the canonical actor and every alias/agent/service identity it controls. Every ID must resolve in the current and candidate registry; the actor must be enabled with matching issuer and separation identity. Completeness of this control mapping is a trusted host responsibility, not discovered by this library. Disjoint complete control closures and different canonical actors are required for approval. This is not protection against collusion or arbitrary owner-level code.

| Collection | Supported existing-record changes | Refused binding changes |
|---|---|---|
| `principals` | Explicit enable/disable | ID, issuer, subject, separation identity and kind |
| `stores` | Strictly increase lifecycle epoch | ID, domain, bank, profile, owner registry key and capability |
| `destinations` | Strictly increase route revision | ID, issuer, platform, route identity, recipients and capability |
| `conversations` | Explicit ceiling, purpose, project/compartment/audience/operation bounds and enable/disable | ID, issuer, platform, transport conversation, store, destination and participants |

There are no presentation-only fields in these records. A conversation policy edit may broaden effective access, even though all grants remain unchanged; every write therefore needs independent approval. Existing store/identity/route binding changes are not ordinary configuration saves. Revision/epoch increases fence stale requests but do not prove a physical migration, new transport session or provider history purge. The actual host must separately qualify those boundaries; real frontends remain unavailable for protected activation until that is done.

Creation is deliberately unsupported: a proposed issuer mapping or new resource ID is not trusted provisioning/lifetime evidence. The raw owner bootstrap remains a separately trusted operation, not a fallback for denied administration. Explicit deletion of an unreferenced existing record is supported, with no cascade; referential validation refuses deleting referenced principals, stores or destinations. This facade cannot recreate deleted identities. Canonical merges/splits, new identity ownership, audience changes, multi-record bundles, store relocation, tombstones and authenticated provisioning require their own contracts and qualification. Do not erase historical owner or journal evidence to enable ID reuse.

## Workflow

1. `view(request, collection, record_id)` requires exact-target `registry:view` before owner access and fresh authorization before returning one typed record or its absence. It does not return the registry. Authorized views include the global revision; per-target activity confidentiality and constant-time behavior are not claimed.
2. `preview(request, collection, record_id, replacement)` requires view/write, an exact matching registered record type or `None` for deletion, and a non-no-op candidate. Profiles, grants and unrelated collections are preserved; the complete candidate passes existing reference, vocabulary and size checks. The immutable plan exposes old/new records, exact predecessor, affected principal IDs and an actor/candidate-bound digest. Treat this as sensitive metadata, not public logging material.
3. `approve(other_request, exact_plan)` requires current exact-target view/approve, distinct actors, the same independent authorization revision/epoch and disjoint canonical control closures. Neither actor may be a directly or indirectly affected principal. Affected sets include old/new principal aliases, store grant holders and conversation participants, destination recipients and referencing grants, and conversation participants. The check applies even to restriction or deletion.
4. `apply(request, exact_plan, approval=exact_approval)` freshly checks both claims, deadline, current predecessor and both registries' canonical controls. It consumes the plan before witnessing an attribution intent, then uses the existing stage/witness/finalize publication. Fresh checks surround journal and publication boundaries; delayed authentication or revocation refuses. A final receipt observation is separately journaled. Any intervening update, including A/B/A, invalidates a preview; a successful publication fences old request handles.
5. `cancel(exact_plan)` discards only the local pending preview. Plans and approvals are exact object-identity handles, process/thread-local, non-reentrant, expire after 1-300 seconds and are capped at 64 pending plans. They are not transferable bearer tokens or durable approvals.

The journal stores an explicit `RegistryAdministrationIntent` with `target_kind` and `target_id`, exact predecessor/candidate and bounded actor fingerprints. It never substitutes fake grant targets or stores replacements, credentials or memory content. Existing grant-intent serialization remains unchanged. New readers accept both strict forms; old H8 readers refuse unknown registry-intent rows rather than reinterpret them. The persisted journal is not rewritten or automatically migrated. Journal reads continue to require separate fresh whole-journal authorization; registry capabilities alone do not grant it.

## Example

The trusted host has already provisioned a disposable authority, journal and two authenticated administrator requests. This changes an existing third-party context, not either administrator's context or grants:

```python
from dataclasses import replace

view = admin.view(proposer_request, "conversations", "context:example")
replacement = replace(view.record, classification_ceiling="L0")
plan = admin.preview(proposer_request, "conversations", "context:example", replacement)
approval = admin.approve(reviewer_request, plan)
receipt = admin.apply(proposer_request, plan, approval=approval)
assert receipt.phase == "committed"
```

An actual frontend must acquire a fresh request binding and honor the clean-context/output/history requirements before continuing. A metadata receipt is not proof that any model context was sanitized or that any endpoint is activated.

## Failure And Recovery

After any uncertain write, inspect the owner receipt and independently witnessed attribution before deciding the next explicit operation. An error may follow a committed configuration or leave a prepared owner/audit tail. Never blindly resend the consumed plan. Use each owner's explicitly qualified recovery path; journal recovery never stages or repeats registry changes, and configuration recovery is not a facade capability. Current request access refuses inconsistent witnessed state. Co-restoring all independent anchors remains outside the surviving-anchor guarantee.

Qualification must exercise exact scope before reads; all four collections; immutable identity/store/route/audience bindings; canonical aliases and shared controllers in both snapshots; candidate reference failure; preserved grants; fresh claim changes and expiry around every write; no replay on lost acknowledgments; A/B/A and request fencing; typed journal coexistence; and no content-read or implicit permission API. This narrow core interface is not full H19/V/A/B acceptance, real host authentication, migration/restore qualification or deployment approval. Raw owner mutation, actual provisioning and broader profile attribution remain separately scoped work.
