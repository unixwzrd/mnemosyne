# Hermes Projects And Agent Personas

This is the protected-host mapping contract and a regression fixture for the existing native APIs. It is not an installed Hermes feature, a configuration-file loader, proof of frontend authentication, or an activation recipe. Ordinary Hermes projects and personalities keep their existing behavior. The first protected route remains read-only, with one authenticated human and explicitly registered agent principals.

## Separate The Three Controls

| Hermes concept | Protected interpretation | What it does not authorize |
| --- | --- | --- |
| Project | Reviewed project scope plus one or more required compartments and a conversation ceiling | Access merely because a file, chat, folder, or repository belongs to the project |
| Persona / agent role | Explicit mapping from an approved agent configuration to a registered agent principal with its own grants | A prompt saying “I am cleared,” a selectable style name, or another role's privileges |
| Chat / conversation | Exact authenticated audience, route, selected scopes, purpose and maximum classification | Widening any human/agent grant or reusing a previously more privileged model context |

The source document has its own classification and restrictions. A project ceiling limits the conversation; it does not lower, replace or infer the classification of every document in that project. A future ingestion default is a separate reviewed policy, not implemented by this read-only integration. Unclassified does not automatically mean public or unrestricted.

## What Stock Hermes Actually Supplies

At the inspected Hermes baseline `a3f697334a894fe2d690572611100ebaa298d791`, `hermes_cli/projects_db.py` stores a generated `projects.id`, mutable slug/name, folders and archived state in a per-profile database. Use the exact project ID, not its display name, slug, working directory or a path match, as an input to the trusted mapping. IDs are scoped by backend instance and Hermes profile; they are not global security identities, immutable lifetime attestations or credentials. The current source does not add a protected classification, compartment, authorization epoch or grant.

`hermes_cli/personality.py` owns selectable named prompt overlays. User configuration can override built-ins, and `agent.personalities` overrides the top-level `personalities` block. Neutral selection can fall back to the manual system prompt. Consequently, neither a familiar name nor hashing an unselected raw configuration entry identifies the actual agent configuration. The protected mapping must cover the resolved definition and all admitted agent/system-prompt inputs. A stock personality is a style selector, not an authenticated principal.

## Trusted Mapping And Lifetimes

The operator must explicitly register the backend/profile realm, exact project identity and lifetime, approved agent/persona configuration revision, registered agent principal, project scopes, required compartments and conversation ceiling. This mapping belongs to the reviewed, witnessed host configuration, not an arbitrary field added by the model or an ordinary project tool. The actual authenticated frontend supplies current selections and complete recipients through a trusted channel; model tool arguments cannot supply them.

Use the existing `PrincipalRegistration`, `GrantRegistration`, `ConversationRegistration` and `DestinationRegistration` for identity, grants, context and output routing. `LocalRequestBinding` projects those current records to `HostPolicySnapshot`; `effective()` computes the complete-participant intersection. Do not add a second clearance evaluator or turn a UI project lookup into a grant issuer. The eventual Hermes-specific selection/lifetime attestation remains an unimplemented host boundary at this checkpoint.

Project rename and folder relocation do not change accepted source rights or grant access. Archive, deletion, restoration, same-name recreation, ID reuse, backend/profile changes, and persona-definition changes require current lifetime/revision validation. A previously retired ID cannot reactivate an old mapping. Even identical-looking A/B/A selections must advance the trusted session epoch. Missing or ambiguous lifetime evidence refuses protected admission; timestamps alone do not establish freshness. A neutral or unreviewed personality never silently selects a more privileged default.

Changing a security-relevant project or persona invalidates the old turn and its request/evidence handles. Start a fresh security/model context, independently admit new inputs and enforce prior transcript visibility. The fixture below proves request-handle fencing, not that stock Hermes currently clears provider state, revokes subscribers or protects transcript APIs.

Two persona labels controlled by the same person are not independent approvers. The mapping must retain canonical control relationships; the existing administrative actor separation rules still apply. Configuration authority does not imply content clearance.

## Worked Example

| Item | Classification ceiling | Required / permitted compartments | Consequence |
| --- | --- | --- | --- |
| Finance project conversation | Sensitive | Finance | Limits scope; grants nothing by itself |
| Human participant | Private | Finance | Cannot receive Sensitive material |
| Approved finance-agent principal | Sensitive | Finance | Cannot raise the human's ceiling |
| Effective shared context | Private | Finance | May recall authorized Private Finance evidence, not Sensitive evidence |
| Research document also linked in Finance | Private | Research | Still denied without Research authorization, despite project relevance |

A lower-clearance agent persona can narrow the context further. Giving the human a higher ceiling does not supply the agent's missing compartment, purpose or destination permission. A single source may belong to several projects while keeping the same policy and provenance; moving it between folders does not declassify it.

## Qualification And Remaining Work

`tests/test_host_project_persona_context.py` exercises the real witnessed registry, request binding, complete-audience intersection and encrypted native reader using disposable synthetic records. It covers both higher- and lower-clearance agents, project/chat ceilings, separate project membership and compartment controls, forged selection metadata, unknown selections, A/B/A changes, and one record relevant to two projects without broader read permission.

The fixture's authentication callback is deliberately synthetic. It does not bind actual Desktop project/personality events, authenticate a Dashboard user, observe native project deletion, or qualify provider/output/history enforcement. The next implementation must supply those trusted facts, revocable sessions, exact selection lifetimes and capability negotiation before enabling this mapping in Hermes. No live configuration, memory, persona, project, source document or service is changed by this checkpoint.
