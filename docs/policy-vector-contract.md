# P2d: Bounded Authorized Float32 Vector Recall

Status: provisional dependent increment on P2c `87d72a09c96e684a40a63cf108a7a7968abf0156`. This is one explicit vector surface, not hybrid parity, protected activation, model qualification or deployment. Legacy APIs, schema and provider defaults do not change.

## Interface And Trust

`BeamMemory.recall_authorized_vector(query_embedding, embedding_model=..., reader=..., destination=..., projects=None, top_k=20, scan_limit=1000)` requires the same explicit SQLite connection as `PolicyReader`, a freshly host-verified decision, matching conversation, `recall:vector` and the existing bank/project read operation. Grants and metadata follow P2a/P2b. Missing/incorrect context refuses; no implicit default principal or broadening of empty project selection is allowed.

The query is a host-supplied finite, nonzero list/tuple matching the configured embedding dimension, bounded to 4096 dimensions and float32 range; it is rounded to float32 and must remain nonzero. `embedding_model` must match the configured model. No query text or embedding provider is accepted or called. The trusted caller must establish that the supplied vector and existing store actually use the same model/revision/prefix contract: legacy `vec0` rows do not carry model or content-revision provenance, so matching configuration and dimension cannot prove historical identity or vector freshness. This increment neither certifies nor repairs mixed/stale embeddings; those stores must not be qualified for protected use on this evidence.

## Authorized Scan

Both native vector tiers must be actual `vec0(embedding float32[configured_dimension])` tables with the expected simple schema and an available extension. Missing, int8, binary, mixed-dimension or unknown schemas refuse even on an empty selection. No fallback to JSON embeddings, global KNN, soft availability defaults, graph or lexical recall is used. The initial format boundary is deliberate; it does not require converting a working database or claim support for the default quantized format.

Inside one caller-preserving SQLite snapshot, materialize indexed authorized metadata, then narrow by native same-session/global, expiry and supersession restrictions. The cross-session environment override is not honored. Bound eligible native identities to `scan_limit` per tier (1..1000); exceeding it refuses the entire request instead of returning a silently incomplete neighbor set. This budget includes eligible rows without vectors and does not bound total metadata or SQLite index work. Denied/ineligible rows cannot consume the budget.

An authorized outer loop joins exact native rowids to stored vectors. Only admitted blobs enter Python. Reuse BEAM's exact float32 blob cosine helper, which handles legacy non-unit norms and clamps nonpositive cosine to zero. Finite/nonzero native blobs are required; corrupt admitted vectors refuse rather than becoming fabricated zero scores. Rank all present authorized vectors within the bound, omit nonpositive scores and deterministically break ties by tier/native ID. No content is retrieved until the combined top-k is chosen. This is a bounded exact scan, not an approximate or globally ranked KNN followed by an access filter.

Return immutable scored hits with policy/decision provenance, output truncation flags, configured embedding identity/dimension, eligible/scored/missing-vector counts. Counts describe the authorized/native-eligible set only. Missing embeddings are explicit and do not count as a complete semantic corpus; scores do not certify factual correctness or model relevance. Text for selected hits uses P2c's NUL/type/16,384-character SQL guard and BEAM's output cap. Other authorized text remains unread. A corrupt selected record fails the request without returning partial hits.

## Boundaries And Qualification

No source hydration, embedding/model calls, query logging, recall counters, cache writes, schema preparation or reindexing is performed. Ordinary recall, quantized vectors, graph/canonical recall, guarded writes, adapters, revocation, derivative lineage and activation remain unqualified. Timing side channels and hostile database/extension replacement are not within this trusted-store boundary. Caller snapshots and inherited cancellation/cleanup limitations remain unchanged; the connection owner may need to recover a persistently cancelled connection.

Use real disposable native BEAM/vec0 stores, independent geometric result oracles, denied-vector/content tripwires, native/project eligibility, missing/corrupt vectors, exact overflow refusals, snapshots, cancellation and package/interpreter checks. A synthetic 1024-dimensional workload tests dimensional handling, not the operator's embedding service or semantic-model quality. No live data or provider is required. Exact candidate test evidence is recorded separately from this interface contract.

The query shape follows SQLite's [explicit CROSS JOIN loop-order control](https://www.sqlite.org/optoverview.html#manual_control_of_query_plans_using_cross_join) and sqlite-vec's [native vector formats](https://alexgarcia.xyz/sqlite-vec/api-reference.html). Qualify actual extension versions and query plans rather than assuming future planner/extension behavior.
