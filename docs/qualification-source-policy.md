# Source/Policy Qualification Fixtures

These optional tests and the small benchmark establish bounded evidence for future source/policy changes. They add no production feature, schema, policy activation, live configuration, or model requirement. They do not qualify a complete Gateway deployment or recommend an upgrade.

## Real Host Dispatch

Use a clean Hermes source checkout with its required import dependencies available in the test interpreter. Install this repository's core and Hermes adapter in that interpreter according to CONTRIBUTING. Supply the exact reviewed host commit, not an automatically accepted moving branch:

```bash
export MNEMOSYNE_Q1_HERMES_SOURCE=/path/to/clean/hermes-checkout
export MNEMOSYNE_Q1_HERMES_REVISION=the-reviewed-40-character-host-commit
MNEMOSYNE_NO_EMBEDDINGS=1 python -m pytest integrations/hermes/tests/test_real_host_dispatch_qualification.py -q -s > host-qualification.log
```

The fixture verifies the host source pin and runs a fresh child interpreter with a synthetic HOME/HERMES_HOME, no inherited provider credentials, Python socket/backend tripwires, and disposable databases. It explicitly selects this checkout's core and adapter sources, checks the file actually loaded by Hermes, and records source-file digests and the candidate commit. These tripwires are not an OS sandbox and do not constrain native-library or subprocess networking. Real Hermes provider discovery and MemoryManager dispatch are used rather than fake host modules or a recording Beam. The only pause hook parks A immediately before its real provider call so B completes first; A then resumes and returns through its original manager. Source pins and Python/package versions belong in the retained execution record. A host that excludes an interpreter in its `requires-python` contract is explicitly skipped, not represented as qualified.

| Layout | Qualification boundary |
| --- | --- |
| Distinct homes, default stores | Assert fresh provider identities, A/B/A writes, target/non-target rows, canonical owner, and host-derived writer/home attribution |
| Same home, distinct initialized bank owners | The tested host resolves a default active profile, not two authenticated caller identities. Assert `canonical_owner_mismatch` and no canonical writes; this is a refusal characterization, not a passing routing/authorization acceptance |

The initial local run used Hermes `a3f697334a894fe2d690572611100ebaa298d791`, a downstream 0.22.0 source, with Mnemosyne baseline `d00119556435794238a725daa6423c852fc39921`. These identify tested source, not a latest-version claim. Other host pins require fresh qualification. Tests skip explicitly when no host source is configured; default CI success must not be reported as execution of these cases.

This fixture does not construct a Gateway/Dashboard session, dispatch through the AIAgent cache, test a private-bank wrapper, or establish participant-aware permissions. It complements existing supported-path tests and upstream #1015/#1188 rather than replacing their remaining real-Gateway acceptance. Do not parse session labels or fake host identity to turn the refused layout into a green success case.

## Small Offline Benchmark

Run this script in a fresh interpreter, with the repository on the import path:

```bash
PYTHONPATH=. python scripts/qualification_benchmark.py --samples 100 --corpus-size 128 > baseline.json
```

It uses temporary stores and scoped Python socket/backend tripwires, selects the repository source explicitly, and rejects unexpected imported file locations. Environment and socket patches are restored on exit. Four fixed operation shapes cover lexical match, lexical miss, reference lookup and unique writes. Each has a first-call measurement, five warmups and repeated steady samples. Every result is checked outside the timed section: expected match count/content, empty miss, expected reference hash, and the new row's content/source/scope/session. Stable output hashes alone are not correctness oracles. The first call is not a claim that operating-system disk caches were purged. Record at least two independent runs; compare dataset/output hashes and row accounting before interpreting timing differences.

Output includes raw samples, p50/p95/p99, operations/second, source commit/dirty state, loaded source-file digests, package/interpreter/platform identity, synthetic dataset hash, stable-output hashes, row counts, database bytes and the process memory high-water mark where supported. Embedding/model counters observe attempts at the listed backend boundaries and fail the run on any attempt, even if application code catches the initial exception; they are not literal assumed zeros. Negative tests exercise broken result oracles and socket/backend attempts. The process high-water mark is not per-operation memory allocation. The source commit plus dirty flag alone does not identify uncommitted edits; review candidates should use a clean committed checkpoint.

This is legacy lexical-mode evidence only. No embeddings, LLM calls, protected mode, GPU workload, source hydration or prompt packing is exercised. `injected_tokens` is null because no prompt is assembled. Relevance checks cover the fixed synthetic lexical cases, not general recall accuracy. Future policy/vector/packing benchmarks must be separate declared workloads, not claimed from this run.

Use cProfile only to explain a measured path; compare throughput/latency from unprofiled runs. Accept a refactor only when its gain exceeds repeated-run variance with unchanged declared output/accounting/quality invariants. Existing performance issues #900/#901/#1192 remain the coordination points; no engine optimization is included here.
