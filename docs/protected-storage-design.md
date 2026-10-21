# Opt-In Protected Storage And Restore Authority

Status: operator-authorized downstream design and disposable qualification, October 20, 2026. Base accepted P3e `c079623`. This is a prerequisite storage boundary for P4, not completed adapter parity, a public activation switch, a production migration or an upstream-approved format. Existing banks, paths, keys, services and ordinary clients remain unchanged. The operator approved including this design after the downgrade/restore decision was raised explicitly.

## Problem And Scope

A policy table in an ordinary SQLite file cannot require an unchanged old client to apply new policy. Restoring both rows and their local epoch also cannot prove current revocation authority. The existing prepared-v2 catalog deliberately preserves old native rows and legacy access; it must not be described as protected activation.

Separate the opt-in protected artifact from a legacy database. Store an authenticated encrypted snapshot that ordinary SQLite clients cannot open. Require an independently current, host-supplied checkpoint before decryption and again before returning the opened snapshot. Neither a decryption key, the snapshot's own metadata nor a historical verification receipt establishes current authority. Legacy stores retain their current representation; no automatic conversion or plaintext fallback is introduced.

This prototype addresses artifact opening and rollback detection only. It does not implement the durable publisher, authority backend, write-capable service, public activation, per-record adapter enforcement, automatic export/sync, key rotation or live migration. The returned read-only in-memory SQLite connection is a trusted owner's administrative handle, not an agent capability. Key/connection access must never be registered as a model tool or substituted for the existing policy reader/verifier.

## Format And API

The envelope is `MNEMOSYNE-PROTECTED-1` plus a NUL byte followed by an authenticated Fernet token. Inside is one consistent SQLite snapshot containing the existing native/policy tables and an exact `protected_snapshot_state` table with format version, random store identity, bank, domain, monotonically increasing generation and lifecycle epoch. Metadata and native contents are encrypted together. The clear envelope exposes its format, size and Fernet creation timestamp; it provides no timing/size confidentiality. Original source documents are not fetched or ingested by the codec.

Reuse the project's existing optional `cryptography>=41.0` dependency through a separate `protected` extra. No custom cipher, password KDF, environment lookup, default key, cloud dependency or mandatory service is added. The host explicitly provides a generated Fernet key through the keyword-only API. Losing that key makes the encrypted artifact unrecoverable; anyone holding it can decrypt and forge artifacts, so the independent current-checkpoint comparison remains required. Key provisioning and rotation require their own reviewed host contract.

| API | Boundary |
| --- | --- |
| `SnapshotIdentity(store_id, bank, domain_id, generation, lifecycle_epoch)` | Immutable sensitive identity metadata. `store_id` is 32 lowercase hex digits; generation starts at 1 and epoch at 0; counters fit signed SQLite integers |
| `SnapshotCheckpoint(identity, envelope_sha256)` | Exact content-addressed artifact identity selected by trusted current authority, not a signed bearer grant |
| `seal_snapshot(conn, identity, *, key)` | Produce an unpublished `SealedSnapshot(envelope, checkpoint)` from a prepared-v2 owner connection. Refuse caller transactions, mismatched domain/epoch, reused/decreasing generation and unsupported runtimes. Preserve the input connection, rows, rowids, catalog and transaction ownership |
| `open_snapshot(envelope, checkpoint, *, key, verify_current)` | Check format/length/hash and independent current checkpoint, authenticate/decrypt, open into RAM, validate the exact embedded identity and prepared-v2 state, recheck current checkpoint, return a read-only owner connection. Caller must close it |
| `verify_current(store_id)` | Host-owned synchronous current-authority callback returning an exact `SnapshotCheckpoint`. Missing, stale, mismatched or deferred authority refuses. Callback exceptions refuse as `context_unavailable`; no legacy fallback |

Serialization/deserialization support is required; stock Python 3.10 lacks these APIs and refuses before key use or opening. Legacy Python 3.10 functionality is unaffected. Python 3.11+ also must have SQLite compiled with serialization support and the optional cryptography dependency. Capability detection, not a version-string guess, determines availability.

The prototype admits at most 64 MiB of SQLite bytes and 90 MiB of envelope bytes. Whole-snapshot backup, serialization, authentication and decryption allocate multiple buffers; these are admission limits, not peak-RSS guarantees or a scalable million-memory storage engine. Larger stores refuse rather than silently spilling plaintext to disk. No plaintext file, WAL, journal or temporary file is intentionally created by this codec; native owners still control the source connection and operating-system swap/core dumps remain outside that promise. Opened connections use in-memory temporary storage and read-only SQL mode. They are not a hostile-code sandbox: a trusted owner can deliberately change SQLite pragmas or serialize plaintext.

The source is copied through SQLite's backup API into a private in-memory database; only that copy receives the format marker. SQLite documents that deserializing a WAL-mode header fails and explicitly permits setting header bytes 18/19 to rollback-mode value 1. The codec performs exactly that documented conversion after validating the SQLite header. It does not use VACUUM, which can change rowids and break native vector mappings. Both source rowids and the source WAL configuration remain unchanged.

## Independent Authority And Publication

The authority must authenticate the storage owner and resolve the exact store/bank/domain mapping outside model arguments. It must not derive its supposedly current generation or epoch from the snapshot being restored, a co-restored sidecar, a caller-supplied checkpoint, or a cached request-start decision. The codec deliberately supplies no permissive default authority implementation. A durable local authority may satisfy the contract when separately protected from the memory backup/restore domain; an existing remote authority may also satisfy it. Neither is mandatory infrastructure for unconfigured legacy users.

The authority selects an exact envelope digest, not merely a generation greater than some floor. This prevents substitution of different content at the same generation and makes interrupted publication explicit. A future host publisher must use immutable content-addressed artifact names and these ordered operations:

1. Read the independently current checkpoint and construct a proposed next generation under current policy/epoch authority.
2. Produce the envelope, write it into the approved protected root, fsync the file and containing directory, and verify its digest. Never replace or mutate the previous immutable artifact during staging.
3. Atomically compare-and-swap the current authority from the exact prior checkpoint to the exact new checkpoint. Reject stale writers and non-increasing generations; policy epochs must not decrease. Commit only after artifact durability is established.
4. A reader obtains the current checkpoint, loads only its exact artifact, and rechecks authority after opening and before each protected operation/output. Do not select arbitrary older files because the current artifact is missing.

A crash before authority commit leaves the previous artifact current; an unreferenced staged artifact is not implicitly published. A crash after authority commit must find the already durable new artifact or fail closed. Never roll authority back automatically to make an old artifact usable. Reconciliation of a genuinely older data backup is a new, separately authorized generation against current restrictions, not an overwrite of current authorization history. Publication/authority-backend tests must cover real failure injection before this protocol is declared implemented.

If both the memory artifact and its authority are rolled back together, this codec cannot detect that rollback. Restoration must establish freshness against a surviving trusted anchor or deny access. No software-only marker inside the same restored snapshot can prove that its own authorization history was not rolled back. Concurrent live revocation after the final check also requires the host's existing per-operation and streaming gates; opening is not a lifetime grant.

## Activation And Migration Gates

The encrypted representation makes old ordinary SQLite opens fail without making arbitrary in-process SQL safe. It does not make current adapters enforce policy. Before exposing activation, the managed owner must keep raw keys/connections private and route SDK/CLI/MCP/Hermes/plugins through the same authenticated participant intersection, policy reader/writer and evidence gates. Unsupported graph, maintenance, export, import, sync, diagnostics and mutation paths must refuse before content access or effects. A declaration alone is insufficient.

Existing plaintext sources, archives, backups and snapshots are not erased by sealing a copy. A future explicit migration must inventory those copies and their ownership, preserve a recovery path, present a dry-run plan, retain IDs/references/model identity, validate policy coverage and publish atomically. Required legacy rows lacking complete policy remain excluded until a trusted mapping is accepted. No migration or deletion is authorized by this design. Plaintext coexistence is a documented incomplete migration, not a protected-at-rest success.

Old-core and ordinary-SQLite qualification must actually attempt opening the encrypted file and prove no content is returned and the file remains unchanged. Test wrong keys, tampering, cross-store/bank/domain substitutions, missing/deferred/lost authority, old generations, revived epochs, authority changes during opening, source transaction ownership, rowids, optional-dependency refusal and no plaintext filesystem writes. Exercise retained policy reads and denied canaries after opening; encryption alone is not authorization. Keep exact runtime/artifact identities, failed evidence and predecessor costs separate from completed P4/V7/B8 acceptance.

## Authoritative Dependencies

- [Cryptography Fernet](https://cryptography.io/en/latest/fernet/): authenticated whole-message encryption, visible creation timestamp and in-memory size limitations. No cryptographic construction is implemented here.
- [Python sqlite3 serialization](https://docs.python.org/3.12/library/sqlite3.html#sqlite3.Connection.serialize): serialization support and in-memory deserialization, added in Python 3.11 and dependent on SQLite capabilities.
- [SQLite deserialize](https://sqlite.org/c3ref/deserialize.html): WAL-header restriction and explicitly documented rollback-header conversion.
- [SQLite VACUUM](https://sqlite.org/lang_vacuum.html): potential rowid changes; this is why it is not used to normalize the snapshot.
