# PERF1: Reuse Deterministic Context Fingerprints

Enhancement development is paused for performance qualification. Base: P3c `21bd63f`. The preceding profile records 2,540 fingerprint calls and about 0.0479 s cumulative time in one bounded lifecycle workload. This is a narrow performance contribution, not policy activation or a schema/API redesign.

## Hypothesis And Invariants

Avoid repeating sorted-label JSON serialization and SHA-256 construction when the exact normalized context and contract version are unchanged. Retain one private entry per exact `AccessContext` instance; never use a global cache or cache an authorization grant. Reuse is permitted only for normalized builtin immutable field values and requires current field objects to be identical to the retained field objects. A replaced field, changed contract version or subclass must use the original algorithm. Identity comparison, not user-defined equality, guards reuse. Retained objects prevent object-ID reuse; no object-ID-only key is used.

Fingerprint bytes, dataclass fields/constructor/equality/hash, `asdict` output and every existing serialization domain must stay unchanged. A private implementation attribute is not part of dataclass serialization. Copy/replace/narrow/subclass behavior, fresh-context values, thread overlap, context changes during final callbacks and negative canaries require tests. Python owner code can still bypass frozen records; this is not a sandbox. Do not rely on a fingerprint to authenticate its supplier.

Every trusted verifier, current lifecycle epoch, indexed candidate predicate, final release check, transaction, rollback and stale-schema refusal remains unchanged. Measure verifier counts, exact output identities and native writes before latency. No schema-validity, permission or epoch cache is introduced.

## Experiment

Use the unchanged four-shape P3c direct/issue/resolve/denied fixture, explicit disposable stores and independently current epoch authority. Retain two unprofiled baseline runs, then alternating matched baseline/candidate pairs with raw samples and deterministic output/call-count oracles. Separately check cold/new context cost and bounded Python allocation per retained context; process RSS and Python allocations are distinct. Use cProfile to explain call-count changes, not as the speed measurement. Repeat the previous legacy workload, focused interpreter/security suites, artifact checks and code-analysis scope. Accept only repeatable improvement outside observed variance with equivalent behavior; otherwise remove the experiment and record it as rejected.
