# Source Integrity And Optional Policy-Aware Memory

This is the downstream contribution roadmap for the `unixwzrd/mnemosyne` fork. It describes work in progress, not an upstream release or a deployment recommendation. Existing Mnemosyne behavior remains the default. There is no switch that safely turns the whole system into protected mode yet.

## What We Are Building

Keep original documents and media in their existing authoritative repositories. Mnemosyne should retain compact memories, bounded evidence, search indexes and references to those originals, with revision/checksum lineage so a changed, moved or unavailable source is not mistaken for the evidence originally indexed. Ordinary recall should not fetch source documents. Authorized expansion is a separate, explicit operation.

Make per-memory policy optional and deployment-defined rather than requiring a government classification scheme, cloud service or central authorization server. Where policy is enabled, the trusted host supplies authenticated context and the retrieval engine enforces indexed access constraints before candidate limits or content disclosure. Policy cannot be trusted merely because a model supplied it. Derived facts, vectors, summaries, caches, exports and maintenance operations must retain applicable restrictions before protected operation is offered.

The immediate use cases are assistants with separate general/private contexts, several projects referencing the same evidence, and archive-backed research that must retain provenance without copying whole documents into memory. A common topic or project membership is not permission to disclose information.

## Implemented Checkpoints

These are locally qualified topic branches, not independently released packages. Source and policy branches have separate bases; installing one does not implicitly combine the other. The contribution ledger records exact commits and artifacts. Topic pushes do not run the repository's main/PR CI workflow.

| Increment | Available behavior | Branch |
| --- | --- | --- |
| Q1 | Synthetic Hermes isolation fixtures and reproducible bounded legacy benchmark | [Q1 qualification](https://github.com/unixwzrd/mnemosyne/tree/contrib/q1-qualification-20261018) |
| S1a | Immutable asserted byte-revision metadata and external locators | [Source revisions](https://github.com/unixwzrd/mnemosyne/tree/contrib/s1-source-revisions-20261019) |
| S1b | Extraction revisions and correction lineage without rewriting legacy moments | [Extraction lineage](https://github.com/unixwzrd/mnemosyne/tree/contrib/s1b-extraction-lineage-20261019) |
| P1a/P1b | Optional policy/context contracts and explicitly prepared indexed metadata catalog | [Indexed policy](https://github.com/unixwzrd/mnemosyne/tree/contrib/p1b-indexed-policy-20261019) |
| P2a | Explicit trusted-context direct reads and authorized candidate IDs | [Authorized reads](https://github.com/unixwzrd/mnemosyne/tree/contrib/p2a-authorized-reads-20261020) |
| P2b | Confirmed project-membership selection; proposed memberships do not grant access | [Project selection](https://github.com/unixwzrd/mnemosyne/tree/contrib/p2b-project-selection-20261020) |
| P2c | Explicit native FTS lexical recall, authorized before limits/content, without global corpus ranking | [Lexical recall](https://github.com/unixwzrd/mnemosyne/tree/contrib/p2c-authorized-lexical-20261020) |

P2d, on this dependent branch, adds [bounded authorized float32 vector recall](policy-vector-contract.md). Its locally qualified runtime checkpoint is `a6be9da15559c9466c5debb342b3099058802754`; this overview's follow-up changes are documentation only. It does not invoke an embedding provider, migrate a vector store or replace ordinary hybrid recall.

At that runtime checkpoint, 580 selected regressions pass on Python 3.12 and all 64 new vector cases pass on each Python 3.10-3.14 without skips. Changed-file/fatal lint, generated-documentation checks and an offline exact-commit wheel smoke pass. The installed-target smoke excludes source checkouts and editable site hooks and uses existing NumPy/sqlite-vec dependencies; it is not minimal-install or live acceptance. Independent Cursor review found no actionable static issue; its runtime probes were blocked by its shell gate and are not counted as independent test results. A synthetic 1024-dimensional geometric workload returns the exact authorized neighbors without provider calls, but does not establish a real model's semantic quality or freshness. Full core/Hermes CI and protected activation remain unqualified.

## Remaining Delivery Stages

| Stage | Completion boundary |
| --- | --- |
| S2 | Expected-revision resolver verification, relocation, offline/changed-source states and reference-only media |
| S3 | Reviewed excerpt/aggregate retention budgets and full-source search contract; no hidden full-document storage |
| S4 | Resumable indexing, usable prior generations, idempotency, coverage and embedding reuse |
| P2 remainder | Required vector formats, graph/canonical/hybrid entry points, guarded writes and explicit unsupported-path refusals |
| P3 | Derivative inheritance, revocation, cache invalidation, maintenance/export/sync restrictions and content-free audit |
| P4 | The same trusted contract through SDK, CLI, MCP, Hermes and resolvers; protected activation only after supported surfaces pass |
| R1 | Compact token-budgeted evidence recall and authorized expansion, measuring fidelity as well as token savings |

Performance changes are separate, profile-backed contributions, not speculative refactors bundled with schema or security work. Every runtime increment is compared with its preceding checkpoint using synthetic sources and disposable stores. Measures include correctness/authorized recall quality, latency, throughput, memory/index growth, embedding calls and injected tokens where the increment supports them. Small offline lexical timings do not establish semantic recall quality or an overall protected-mode overhead budget.

## Compatibility And Review

Legacy reads/writes are unchanged by default. Prepared metadata and explicit prototype APIs do not protect old entry points against bypass. The application/process owning the SQLite connection remains trusted; this is not a sandbox against arbitrary in-process SQL. Existing callers keep their transactions and snapshots, so request-start verification is not a promise of linearizable revocation.

Contributions remain on focused fork topic branches while upstream architecture and CLA questions are resolved. Maintainer acceptance, an upstream merge, a release and live deployment are separate gates. We do not claim upstream endorsement or production readiness. Existing source, models, original documents, private stores and embedding identities are not migrated by this contribution work.
