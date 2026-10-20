# Source Integrity And Optional Policy-Aware Memory

This is the downstream contribution roadmap for the `unixwzrd/mnemosyne` fork. It describes work in progress, not an upstream release or a deployment recommendation. Existing Mnemosyne behavior remains the default. There is no switch that safely turns the whole system into protected mode yet.

## What We Are Building

Keep original documents and media in their existing authoritative repositories. Mnemosyne should retain compact memories, bounded evidence, search indexes and references to those originals, with revision/checksum lineage so a changed, moved or unavailable source is not mistaken for the evidence originally indexed. Ordinary recall should not fetch source documents. Authorized expansion is a separate, explicit operation.

Make per-memory policy optional and deployment-defined rather than requiring a government classification scheme, cloud service or central authorization server. Where policy is enabled, the trusted host supplies authenticated context and the retrieval engine enforces indexed access constraints before candidate limits or content disclosure. Policy cannot be trusted merely because a model supplied it. Derived facts, vectors, summaries, caches, exports and maintenance operations must retain applicable restrictions before protected operation is offered.

The immediate use cases are assistants with separate general/private contexts, several projects referencing the same evidence, and archive-backed research that must retain provenance without copying whole documents into memory. A common topic or project membership is not permission to disclose information.

## Implemented Checkpoints

These are locally qualified topic branches, not independently released packages. Source and policy branches have separate bases; installing one does not implicitly combine the other. SP1 explicitly combines source `d960a2e` and policy `eca181d` at merge checkpoint `36560f1`; it is not a merge into maintained or fork main. The contribution ledger records exact commits and artifacts. Topic pushes do not run the repository's main/PR CI workflow.

| Increment | Available behavior | Branch |
| --- | --- | --- |
| Q1 | Synthetic Hermes isolation fixtures and reproducible bounded legacy benchmark | [Q1 qualification](https://github.com/unixwzrd/mnemosyne/tree/contrib/q1-qualification-20261018) |
| S1a | Immutable asserted byte-revision metadata and external locators | [Source revisions](https://github.com/unixwzrd/mnemosyne/tree/contrib/s1-source-revisions-20261019) |
| S1b | Extraction revisions and correction lineage without rewriting legacy moments | [Extraction lineage](https://github.com/unixwzrd/mnemosyne/tree/contrib/s1b-extraction-lineage-20261019) |
| S2a | Explicit bounded source-byte verification, not an expansion grant | [Source verification](https://github.com/unixwzrd/mnemosyne/tree/contrib/s2a-source-verification-20261020) |
| S2b | Immutable owner-reported verification history and committed/pending receipts | [Verification journal](https://github.com/unixwzrd/mnemosyne/tree/contrib/s2b-verification-journal-20261020) |
| P1a/P1b | Optional policy/context contracts and explicitly prepared indexed metadata catalog | [Indexed policy](https://github.com/unixwzrd/mnemosyne/tree/contrib/p1b-indexed-policy-20261019) |
| P2a | Explicit trusted-context direct reads and authorized candidate IDs | [Authorized reads](https://github.com/unixwzrd/mnemosyne/tree/contrib/p2a-authorized-reads-20261020) |
| P2b | Confirmed project-membership selection; proposed memberships do not grant access | [Project selection](https://github.com/unixwzrd/mnemosyne/tree/contrib/p2b-project-selection-20261020) |
| P2c | Explicit native FTS lexical recall, authorized before limits/content, without global corpus ranking | [Lexical recall](https://github.com/unixwzrd/mnemosyne/tree/contrib/p2c-authorized-lexical-20261020) |

P2d adds [bounded authorized float32 vector recall](policy-vector-contract.md). Its locally qualified runtime checkpoint is `a6be9da15559c9466c5debb342b3099058802754`; P2d's final topic `a10dbf8` adds only qualification documentation after that runtime checkpoint. It does not invoke an embedding provider, migrate a vector store or replace ordinary hybrid recall.

At that runtime checkpoint, 580 selected regressions pass on Python 3.12 and all 64 new vector cases pass on each Python 3.10-3.14 without skips. Changed-file/fatal lint, generated-documentation checks and an offline exact-commit wheel smoke pass. The installed-target smoke excludes source checkouts and editable site hooks and uses existing NumPy/sqlite-vec dependencies; it is not minimal-install or live acceptance. Independent Cursor review found no actionable static issue; its runtime probes were blocked by its shell gate and are not counted as independent test results. A synthetic 1024-dimensional geometric workload returns the exact authorized neighbors without provider calls, but does not establish a real model's semantic quality or freshness. Full core/Hermes CI and protected activation remain unqualified.

P2e, on this dependent topic, adds [explicit atomic native creation](policy-write-contract.md) for working and episodic memories. A fresh host grant is bound to the exact request and input digest; native text, FTS and immutable policy are written together. It does not upsert or deduplicate existing rows, infer input classification from clearance, call a model, add embeddings, update/delete/reclassify existing memories or silently write from project-only context. Caller-owned transactions return a pending result until their owner commits. This is creation-only core functionality, not completion of protected writes across the system.

P2e's initial checkpoint `b94d5b7894e80f4390785da9df1adb3c056cc0d7` passed 647 selected regressions and the initial interpreter/artifact checks, but independent review then found that FTS5 can expose the expected columns while leaving content unindexed. The corrected shared lexical/create capability check now also requires the supported native FTS5 declaration, refusing unindexed content, contentless/wrong external mappings, custom tokenizers and unknown layouts. Both-tier regression coverage is included; final exact-commit qualification is recorded separately from the earlier checkpoint. No complete core/Hermes CI, power-loss, production-authentication or protected-mode acceptance is implied.

The final qualified runtime is `1115109be2fe5eb4317465131677db2ee82ca563`. Its shared schema check also uses ASCII matching so Unicode case folding cannot alias a different external-content table or rowid. Independent recheck passed 16 targeted tests and seven disposable probes, resolving both findings with no remaining actionable issue in scope. At this exact runtime, 660 selected regressions pass; all 80 new creation cases pass on Python 3.12-3.14, and Python 3.10/3.11 pass 78 with two explicit sqlite3 autocommit-API skips. The exact wheel passes minimal PyYAML-only installed-target creation, authorized lexical recall, pending rollback and both FTS correction regressions without source paths. Lint and generated-documentation checks pass. Earlier artifacts/results remain separate and superseded, not silently relabeled as the final candidate. Changes after this runtime checkpoint are qualification documentation only.

## Source And Policy Integration

SP1 adds [immutable source-revision policy associations and authorized metadata reads](source-policy-contract.md). Source metadata needs its own policy binding; citing a source from a memory or authorizing an earlier revision grants nothing to the current source. Both `read:bank` and `read:source-revision` are required, and an eligibility-first indexed query precedes native source metadata. The result omits original bytes, locators and unapproved ancestry. Protected project-selected source access and generic source enumeration refuse rather than silently fall back. This is the prerequisite metadata boundary, not completion of authorized exact-byte expansion.

The corrected SP1 runtime is `3cd219e8ef961ce7d20f48951b9020764122c772`; the initial `806896d` artifact is superseded. Independent review identified join-order/schema, oversized-field error, native text-contract and parent-schema defects, which have dedicated regression controls. Source/asset layouts now require native physical tables with binary keys, an eligibility-first CROSS JOIN enforces the documented SQLite loop order, native-valid representation text remains unchanged and corrupt-metadata errors are content-free. Qualification results and the final independent recheck are recorded in the downstream ledger, not inferred from the existence of these fixes.

At the corrected runtime, 1,148 selected source/policy/media/Hermes-provider regressions pass with two explicit uninstalled-Hermes-loader skips. All 62 new source-policy cases pass on each Python 3.10-3.14. The adapter suite passes 759 with one pinned-host-contract skip after matching its unchanged source to isolated `0.7.6` distribution metadata. Independent recheck closes all four findings with 16 probes plus selected regressions; Cursor's earlier final-review attempt stalled and receives no review credit. The first adapter run reproduced a stale test-environment metadata mismatch on unchanged source, and an installed-path test harness then required source-layout-aware invocation; neither was fixed by changing adapter code.

Exact-commit unreleased core wheel SHA-256: `543278f4e1ecaf0eb71a65a7932f4d17867bbbbe2c39a97dc10ca4cbed0574c7`. Unchanged-source adapter wheel SHA-256: `6642749cf0d646103d19ad7e0c740c8c1e7317e2f47620b557557dbb40433fac`. A `-I -S`, PyYAML-only installed-target smoke verifies 155 RECORD entries, actual imported module identities, positive/denied metadata, no read writes, caller rollback and legacy verifier/journal compatibility, detecting no provider/socket attempts. These development identities (`4.0.0b5`/`0.7.6`) are not new published versions or live installations. Changed/fatal lint and generated-documentation checks pass. The earlier artifact and initial failures remain separately retained and superseded. No full-system protected, semantic-quality, timing-confidentiality or overhead-budget acceptance is implied; the earlier write-tail question remains open.

The chosen absent-classification default is `unclassified` only where trusted inheritance does not supply a stricter classification. This is not public access: complete owner/audience/purpose and other restrictions still apply. SP1 supports explicitly bound unclassified records but does not yet implement ingestion normalization or migrate existing rows. Invalid explicit values are not defaulted. Legacy behavior remains unchanged.

## Remaining Delivery Stages

| Stage | Completion boundary |
| --- | --- |
| S2 remainder | Authorized exact-byte expansion on the integrated source/policy boundary and full resolver relocation/offline lifecycle; S2a/S2b verification and history alone do not authorize a later reopen |
| S3 | Reviewed excerpt/aggregate retention budgets and full-source search contract; no hidden full-document storage |
| S4 | Resumable indexing, usable prior generations, idempotency, coverage and embedding reuse |
| P2 remainder | Required vector formats, graph/canonical/hybrid entry points, remaining guarded write paths and explicit unsupported-path refusals |
| P3 | Derivative inheritance, revocation, cache invalidation, maintenance/export/sync restrictions and content-free audit |
| P4 | The same trusted contract through SDK, CLI, MCP, Hermes and resolvers; protected activation only after supported surfaces pass |
| R1 | Compact token-budgeted evidence recall and authorized expansion, measuring fidelity as well as token savings |

Performance changes are separate, profile-backed contributions, not speculative refactors bundled with schema or security work. Every runtime increment is compared with its preceding checkpoint using synthetic sources and disposable stores. Measures include correctness/authorized recall quality, latency, throughput, memory/index growth, embedding calls and injected tokens where the increment supports them. Small offline lexical timings do not establish semantic recall quality or an overall protected-mode overhead budget.

## Compatibility And Review

Legacy reads/writes are unchanged by default. Prepared metadata and explicit prototype APIs do not protect old entry points against bypass. The application/process owning the SQLite connection remains trusted; this is not a sandbox against arbitrary in-process SQL. Existing callers keep their transactions and snapshots, so request-start verification is not a promise of linearizable revocation.

Contributions remain on focused fork topic branches while upstream architecture and CLA questions are resolved. Maintainer acceptance, an upstream merge, a release and live deployment are separate gates. We do not claim upstream endorsement or production readiness. Existing source, models, original documents, private stores and embedding identities are not migrated by this contribution work.
