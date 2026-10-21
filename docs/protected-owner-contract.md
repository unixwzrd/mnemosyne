# Protected Snapshot Owner Contract

This opt-in owner API adds immutable artifact publication and independent current-checkpoint authority to the qualified snapshot codec. It does not migrate existing banks, change legacy defaults, obtain keys, grant an agent access, or expose protected mode in the CLI, MCP or Hermes plugin. It must not be presented as complete adapter parity or production activation.

## Trust And Restore Boundary

The host supplies a private owner-only artifact directory, an explicit Fernet key and an independently current `SnapshotAuthority` connection. The authority has a separately pinned random identity and must live outside the memory snapshot's restore/backup domain. It records metadata only: store/bank/domain identity, generation, lifecycle epoch, exact encrypted-artifact digest and operation ID. These identifiers are sensitive even without memory text.

Restoring old encrypted artifacts cannot roll back the authority. If the selected current artifact is absent, damaged, inaccessible or restored to older bytes, opening refuses; no older artifact is selected. Co-restoring both the memory and its authority cannot be detected by a marker stored inside either backup. A surviving host trust anchor or independently current external authority is required; after loss of that anchor, deny access rather than re-create authority from files. The pinned authority ID prevents selecting a different authority, not replay of a complete older copy with the same ID.

This is a trusted-host capability, not a sandbox against a key holder, arbitrary Python code, a raw SQLite owner or filesystem administrator. Such code can read decrypted owner memory or forge its local databases. Keep keys, raw connections, repository objects and authority administration out of model tools and ordinary user request parameters. Authenticated context, all-participant permission intersection, policy enforcement and current-operation checks still apply inside each supported memory operation. An opened connection is not a lifetime authorization grant.

## Interfaces

`SnapshotAuthority(connection, authority_id=...)` accepts an explicit separate SQLite connection and a 32-character lowercase hexadecimal identity pinned by trusted configuration. `prepare()` is an explicit owner provisioning action, only on an empty logical database or its exact existing schema. Reads never call it. File-backed WAL with synchronous FULL/EXTRA or DELETE with synchronous EXTRA is required for authority writes; other journal/durability profiles and caller-owned pending transactions refuse without changing their settings or transaction ownership.

`current(store_id)` returns only the independently selected exact checkpoint. `provision(checkpoint, operation_id=...)` admits generation 1 only when the store is absent. `publish(previous, checkpoint, operation_id=...)` performs a serialized compare-and-swap: exact predecessor, same store/bank/domain, next generation and nondecreasing lifecycle epoch. Exact-artifact/idempotent metadata retry returns `unchanged`; a reused operation ID with different content or a racing predecessor refuses. The append-only owner API has a fixed 65,536-record ceiling; no implicit pruning or authority reset is offered. `publication(store_id, operation_id)` inspects a durable receipt after uncertainty; a historical receipt is not current authorization.

`ProtectedRepository(root, key=..., authority=...)` uses an existing canonical absolute POSIX directory owned by the process user with mode 0700. It pins directory device/inode identity and refuses symlinks, replacement, changed permissions and unsupported descriptor-relative operations. It does not create or chmod a root. The caller must protect its parent namespace and authority root; checks on a private directory are not a defense against a malicious same-user process racing namespace changes.

`publish(connection, identity, previous=..., operation_id=...)` seals a private in-memory copy without changing the source, writes the encrypted bytes to a unique mode-0600 pending file, flushes/fsyncs it, links it without overwriting to `<sha256>.mnes`, removes its own pending name, fsyncs the directory, and only then advances independent authority. An existing content-addressed file is reverified, never overwritten. Previous generations and unpublished encrypted artifacts remain untouched. Use one writer per store; compare-and-swap still rejects a competing stale predecessor.

`open_current(store_id)` returns `(connection, checkpoint)` to trusted owner code. The connection is an in-memory query-only SQLite snapshot, not an agent capability; the owner closes it. Artifact permissions/type/digest and current authority are checked before decrypting, then the codec verifies current authority again after metadata validation. Every subsequent policy operation and output boundary must check current generation/epoch again. Do not hand a raw connection to an adapter or treat successful opening as permission to bypass the policy reader.

## Interruption And Durability

File failure before authority publication leaves the previous generation current. A failure after immutable linking may leave a harmless unpublished encrypted artifact; do not delete it automatically. A lost authority COMMIT acknowledgment may mean the new generation is already current. Inspect `publication` and `current` before deciding what happened; do not blindly re-encrypt/resubmit or roll the authority back. Snapshot encryption is randomized, so repeating repository publication is not an exact-artifact retry. Reconcile the recorded operation ID and digest explicitly.

Logical ordering and injected interruption tests are not a physical power-loss simulation. SQLite durability and POSIX fsync still depend on the filesystem/VFS, OS and hardware honoring synchronization. No cross-filesystem atomic transaction or protection against co-restoring the trust anchor is claimed. Directory errors propagate as content-free refusal; the original owner exception from an uncertain authority commit remains visible to trusted host recovery. No cleanup daemon is introduced.

The codec retains its 64 MiB serialized-database and 90 MiB envelope admission limits, whole-snapshot allocation cost and Python/SQLite capability requirements. This is not a new scalable million-record storage engine. Unsupported Python/SQLite/crypto or filesystem capabilities refuse instead of falling back to plaintext.

## Isolated Usage

The following is trusted owner pseudocode, not a migration command. `source` is a prepared synthetic/native policy database, `authority_connection` is separately provisioned with an approved durability profile, and all paths and keys are supplied by the host rather than the model.

```python
authority = SnapshotAuthority(authority_connection, authority_id=host_pinned_id)
authority.prepare()  # Explicit first-time provisioning, never an open fallback.
with ProtectedRepository(private_artifact_root, key=host_key, authority=authority) as repo:
    receipt = repo.publish(source, generation_one_identity,
                           previous=None, operation_id="initial-import-1")
    connection, checkpoint = repo.open_current(receipt.checkpoint.identity.store_id)
    try:
        # Construct a freshly guarded policy reader; do not expose raw SQL.
        pass
    finally:
        connection.close()
```

Python's documented [descriptor-relative file operations and fsync](https://docs.python.org/3.12/library/os.html) and SQLite's [synchronous durability profiles](https://sqlite.org/pragma.html#pragma_synchronous) define the mechanisms used here. The host must qualify its real filesystem and supported adapter paths before deployment. This local contribution adds no keys, permissions, live writes, provider traffic, migrations or deployment authorization.
