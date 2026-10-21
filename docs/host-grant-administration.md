# Scoped Grant Administration

This opt-in core facade extends the existing witnessed authorization registry, not a real administrative transport, identity provider, protected activation switch or model tool. Existing profile-only and ordinary memory behavior is unchanged. The raw configuration owner and authenticator remain trusted. No original documents, model calls or live stores are required.

## Contract And Scope

`GrantAdministration(owner, authority_id=..., issuer=..., authenticate=..., lifetime_seconds=60)` accepts an exact `HostConfigurationAuthority` and a trusted synchronous callback. That callback receives an opaque authenticated host request and returns an exact current `GrantAdministrationSnapshot`; constructing a snapshot or passing a username is not authentication. Claims contain the issuer, canonical actor and independent separation identity, pinned configuration authority, independent authorization revision/positive epoch, explicit target pairs, complete actor-controlled identities and capabilities. A model cannot select these facts.

`targets` is a nonempty frozen set of at most 256 exact `(principal_id, store_id)` tuples. It is not a Cartesian product of independent principal/store scopes, wildcard, or grant union. The only capabilities are `grants:view`, `grants:write` and `grants:approve`. There are no implicit profile-edit, content-read, identity/route-edit, delegation, key, audit-read, recovery or activation capabilities. Configurable host role names may map to these capabilities; content clearance does not supply them automatically, nor does administrative authority imply content clearance.

`controlled_principals` is an explicit nonempty frozen set of at most 256 IDs, including the actor's own ID and all aliases, agents and service identities it controls. All IDs use the registry principal namespace. The actor must be registered, enabled and match the claim's issuer and canonical separation identity; every controlled ID must resolve. All controlled identities are compared by registered canonical actor, so an alias of a controlled identity is also excluded. Unknown mappings or host/registry contradictions refuse. The trusted host must supply the complete current control closure; registry metadata alone cannot discover ownership or distinguish colluding actors. Claims are bounded immutable host records, not serializable bearer credentials.

Issuing `grants:write` for an exact target pair authorizes proposing every supported grant field for that pair, including bank-wide access, subject to independent approval and the configured policy vocabulary. It is privileged issuance, not delegation bounded by the administrator's own content grants. No content permission is inferred for either administrator. The host must not issue this capability when it intends narrower field-level authority; such an issuance policy is not supplied by this facade.

## Workflow

1. `view(request, principal_id, store_id)` checks `grants:view` for the exact pair before owner metadata access and again before returning that grant or its absence. It never returns an entire registry. Authorized metadata views expose the global configuration revision, so per-target activity confidentiality and constant-time behavior are not promised.
2. `preview(request, principal_id, store_id, replacement)` requires `grants:view` and `grants:write`. The replacement is an exact `GrantRegistration` for that same pair, or `None` for deletion. An existing registry, registered target and registered store are mandatory; no provisioning or implicit default grant occurs. Unknown references, unsupported classifications, resource limits and no-op changes refuse. The process-local immutable plan contains the prior/replacement grants, exact predecessor and candidate/actor-bound digest. Every unrelated grant, identity, store, route, conversation and profile is preserved.
3. `approve(other_request, exact_plan)` requires current `grants:view` and `grants:approve` for the same pair. The approver must have a different principal and canonical actor, at the same independent administrative authorization revision/epoch. Neither proposer nor approver may be the beneficiary, a registered canonical alias, or control the beneficiary. The actors' canonical control closures must be disjoint: either controlling the other, or sharing any controlled actor, refuses. This conservative rule applies even to restriction/removal; separately trusted owner recovery remains available outside this facade. Every change requires approval, not just ceiling increases.
4. `apply(request, exact_plan, approval=exact_approval)` reauthenticates both actors, checks exact current predecessor and deadline, then uses existing stage/witness/finalize. Any changed target scope, controlled-identity set, capability, issuer, epoch or revision refuses. Copied/foreign/replayed handles refuse. The plan is consumed before the first write; ambiguous acknowledgment may follow a committed change. Inspect the owner receipt rather than automatically retrying. Existing witness/recovery and surviving-anchor limits remain unchanged.
5. `cancel(exact_plan)` discards only the local preview. Handles are bound to the issuing process/thread and expire after 1-300 seconds; at most 64 pending plans exist. Reentrant calls refuse. These are not transferable tokens or durable approval receipts.

Successful changes advance the global configuration generation and invalidate existing request handles. A stale preview cannot overwrite a concurrent restriction or revive a revoked grant after A/B/A publication. The facade cannot edit the identity mappings, route bindings, policy ordering, approval authority or any other metadata that could bypass its target check. Such changes require separate future scoped interfaces; the raw owner API must never be offered as a fallback.

## Example

The host has already provisioned a disposable witnessed registry and authenticated `proposer_request` and `reviewer_request`. It alone constructs `admin` with a qualified authenticator. This example modifies one existing grant, not either administrator's permissions:

```python
from dataclasses import replace

view = admin.view(proposer_request, "person:reader", store_id)
replacement = replace(view.grant, projects=frozenset({"project:notes"}))
plan = admin.preview(proposer_request, "person:reader", store_id, replacement)
approval = admin.approve(reviewer_request, plan)
receipt = admin.apply(proposer_request, plan, approval=approval)
assert receipt.phase == "committed"
```

Adding a grant uses an explicit `GrantRegistration` rather than merging independent grants; removing it passes `None`. The host must review the old/new scope before approval and use fresh request bindings afterward. Actual provider/history/output cancellation and authenticated CLI/MCP/Hermes endpoints are outside this core facade.

## Evidence And Remaining Gates

Use synthetic authorities to test exact-pair scope before reads; separation and controlled-identity refusal; grant create/replace/delete; reference validation; unchanged unrelated metadata; fresh authorization/expiry around publication; race/A/B/A/stale-plan refusal; receipt-based uncertainty; request fencing; content-free errors and legacy behavior. Authentication is local admission, not an atomic transaction with an external identity service; revocation after a gate cannot retract work already admitted.

Owner history durably records the candidate configuration and operation receipt, but does not supply a separately authorized administrative decision journal with durable proposer/approver attribution. That journal, actual host identity/control mappings, frontend activation and full lifecycle/migration/restore qualification remain separate required gates. Do not claim production grant-administration readiness from the facade tests alone or log raw request handles, claims, prompts, source paths or secret material.
