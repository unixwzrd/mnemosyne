"""Opt-in owner format 2; preserved proposals and witnessed reaffirmations."""

import hashlib

from .host_configuration import (
    CancellationReference, ConfigurationReceipt, HostConfigurationAuthority,
    MAX_CONFIGURATION_REVISIONS, _DDL, _canonical, _checkpoint, _decode, _snapshot,
)
from .policy import PolicyRefusal, RefusalReason, _text


_EXTRA = {
    "host_configuration_cancellations": "CREATE TABLE host_configuration_cancellations (generation INTEGER PRIMARY KEY, original_operation_id TEXT NOT NULL UNIQUE, original_digest TEXT NOT NULL, operation_id TEXT NOT NULL UNIQUE, digest TEXT NOT NULL, payload BLOB NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('prepared','committed')))",
    "host_configuration_cancellations_no_delete": "CREATE TRIGGER host_configuration_cancellations_no_delete BEFORE DELETE ON host_configuration_cancellations BEGIN SELECT RAISE(ABORT,'immutable_cancellation'); END",
    "host_configuration_cancellations_finalize_only": "CREATE TRIGGER host_configuration_cancellations_finalize_only BEFORE UPDATE ON host_configuration_cancellations WHEN NOT (OLD.phase='prepared' AND NEW.phase='committed' AND NEW.generation=OLD.generation AND NEW.original_operation_id=OLD.original_operation_id AND NEW.original_digest=OLD.original_digest AND NEW.operation_id=OLD.operation_id AND NEW.digest=OLD.digest AND NEW.payload=OLD.payload) BEGIN SELECT RAISE(ABORT,'immutable_cancellation'); END",
}
for _table, _key in (("host_committed_profile_versions", "profile_id"), ("host_committed_policy_versions", "policy_id")):
    _EXTRA[_table] = f"CREATE TABLE {_table} ({_key} TEXT NOT NULL, version INTEGER NOT NULL, digest TEXT NOT NULL, PRIMARY KEY({_key},version))"
    for _action in ("UPDATE", "DELETE"):
        _name = _table + "_no_" + _action.lower()
        _EXTRA[_name] = f"CREATE TRIGGER {_name} BEFORE {_action} ON {_table} BEGIN SELECT RAISE(ABORT,'immutable_versions'); END"

_SELECT = """SELECT generation,
 CASE WHEN length(CAST(original_operation_id AS BLOB))<=1024 THEN CAST(original_operation_id AS BLOB) ELSE NULL END,
 CASE WHEN length(CAST(original_digest AS BLOB))=64 THEN CAST(original_digest AS BLOB) ELSE NULL END,
 CASE WHEN length(CAST(operation_id AS BLOB))<=1024 THEN CAST(operation_id AS BLOB) ELSE NULL END,
 CASE WHEN length(CAST(digest AS BLOB))=64 THEN CAST(digest AS BLOB) ELSE NULL END,
 CASE WHEN typeof(payload)='blob' AND length(payload)<=262144 THEN payload ELSE NULL END,
 CASE WHEN phase IN ('prepared','committed') THEN CAST(phase AS BLOB) ELSE NULL END
 FROM main.host_configuration_cancellations"""


def definitions():
    return {**_DDL, **_EXTRA}


def _enabled(owner):
    if type(owner) is not HostConfigurationAuthority or owner._storage_version != 2:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)


def _publication(owner, receipt):
    operation = "host-config:" + hashlib.sha256(receipt.operation_id.encode("utf-8")).hexdigest()
    value = owner._witness.publication(owner._authority_id, operation)
    if value is None or value.checkpoint != _checkpoint(receipt.revision):
        raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)


def _resolution_record(owner, *, generation=None, operation_id=None):
    sql, parameters = _SELECT, ()
    if generation is not None:
        sql += " WHERE generation=?"
        parameters = (generation,)
    elif operation_id is not None:
        sql += " WHERE operation_id=?"
        parameters = (operation_id,)
    value = owner._store.conn.execute(sql + " ORDER BY generation DESC LIMIT 1", parameters).fetchone()
    if value is None:
        return None
    number, original, old_digest, operation, digest, payload, phase = value
    if any(type(item) is not bytes for item in (original, old_digest, operation, digest, payload, phase)):
        raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
    snapshot, receipt = _decode(owner._authority_id, (number, digest, payload, operation, phase))
    old = owner._raw_row(generation=number)
    if (old is None or old[1].phase != "prepared" or snapshot.storage_version != 2
            or snapshot.abandoned != CancellationReference(old[1].operation_id, old[0].revision)
            or original != old[1].operation_id.encode("utf-8") or old_digest != old[0].revision.sha256.encode("ascii")
            or receipt.operation_id == old[1].operation_id or snapshot.revision.sha256 == old[0].revision.sha256):
        raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
    if receipt.phase == "committed":
        _publication(owner, receipt)
    return snapshot, receipt


def _resolution(owner, *, generation=None, operation_id=None):
    result = _resolution_record(owner, generation=generation, operation_id=operation_id)
    current = result
    # Walk iteratively: a bounded chain of cancellations must not exhaust the
    # Python stack, and every reaffirmation must preserve its logical predecessor.
    while current is not None:
        snapshot = current[0]
        number = snapshot.revision.generation
        if not 2 <= number <= MAX_CONFIGURATION_REVISIONS:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        prior = owner._raw_row(generation=number - 1)
        resolved = _resolution_record(owner, generation=number - 1)
        previous = resolved if resolved is not None else prior
        if (previous is None or previous[1].phase != "committed" or previous[0].storage_version != 2
                or snapshot.profiles != previous[0].profiles or snapshot.registry != previous[0].registry):
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        _publication(owner, previous[1])
        current = resolved
    return result


def row(owner, *, operation_id=None, generation=None):
    raw = owner._raw_row(operation_id=operation_id, generation=generation)
    if raw is None:
        return _resolution(owner, operation_id=operation_id) if operation_id is not None else None
    resolution = _resolution(owner, generation=raw[0].revision.generation)
    if resolution is None:
        head = owner._raw_row()
        if (raw[0].abandoned is not None or (raw[1].phase == "prepared" and head is not None
                and raw[0].revision.generation < head[0].revision.generation)):
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        return raw
    if operation_id is not None:
        phase = "cancelled" if resolution[1].phase == "committed" else "prepared"
        return raw[0], ConfigurationReceipt(raw[0].revision, raw[1].operation_id, phase)
    return resolution


def _consistent(profiles):
    policies = {}
    for profile in profiles:
        prior = policies.setdefault(profile.policy.policy_id, profile.policy)
        if prior != profile.policy:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)


def _versions(profiles):
    for profile in profiles:
        yield "host_committed_profile_versions", "profile_id", profile.profile_id, profile.version, profile.canonical_bytes()
        yield "host_committed_policy_versions", "policy_id", profile.policy.policy_id, profile.policy.version, _canonical({
            "policy_id": profile.policy.policy_id, "version": profile.policy.version, "levels": list(profile.policy.levels)})


def register_versions(owner, profiles, *, record):
    _consistent(profiles)
    conn = owner._store.conn
    for table, column, identity, version, payload in _versions(profiles):
        digest = hashlib.sha256(payload).hexdigest()
        prior = conn.execute(f"SELECT version,CASE WHEN length(CAST(digest AS BLOB))=64 THEN CAST(digest AS BLOB) ELSE NULL END FROM main.{table} WHERE {column}=? ORDER BY version DESC LIMIT 1", (identity,)).fetchone()
        if prior is not None and (type(prior[0]) is not int or prior[0] < 1 or type(prior[1]) is not bytes
                or len(prior[1]) != 64 or any(c not in b"0123456789abcdef" for c in prior[1])):
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        if prior is not None and (version < prior[0] or (version == prior[0] and digest.encode("ascii") != prior[1])):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        if record and (prior is None or version > prior[0]):
            conn.execute(f"INSERT INTO main.{table} VALUES(?,?,?)", (identity, version, digest))


def finalize(owner, receipt):
    _enabled(owner)
    owner._ready(write=True)
    with owner._store._transaction(write=True):
        owner._schema()
        snapshot, stored = owner._stored(receipt)
        owner._require_witness(snapshot.revision)
        if stored.phase == "prepared":
            register_versions(owner, snapshot.profiles, record=True)
            table = "host_configuration_cancellations" if snapshot.abandoned is not None else "host_configuration_revisions"
            owner._store.conn.execute(f"UPDATE main.{table} SET phase='committed' WHERE generation=?", (snapshot.revision.generation,))
    owner._require_witness(snapshot.revision)
    return ConfigurationReceipt(snapshot.revision, receipt.operation_id, "committed")


def advance_witness(owner, receipt):
    _enabled(owner)
    owner._ready(write=True)
    # Hold the owner writer reservation across the independent publication.
    # Original advancement and cancellation cannot both pass their owner check.
    with owner._store._transaction(write=True):
        owner._schema()
        snapshot, _ = owner._stored(receipt)
        old = owner._row(generation=snapshot.revision.generation - 1)
        target = _checkpoint(snapshot.revision)
        operation = "host-config:" + hashlib.sha256(receipt.operation_id.encode("utf-8")).hexdigest()
        if snapshot.revision.generation == 1:
            owner._witness.provision(target, operation_id=operation)
        else:
            if old is None or old[1].phase != "committed":
                raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
            owner._witness.publish(_checkpoint(old[0].revision), target, operation_id=operation)
    return receipt


def _candidate(owner, receipt, previous):
    if type(receipt) is not ConfigurationReceipt or receipt.phase != "prepared":
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    original = owner._raw_row()
    if original is None or original[1] != receipt or original[0].storage_version != 2:
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    if _resolution(owner, generation=receipt.revision.generation) is not None:
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    old = owner._row(generation=receipt.revision.generation - 1)
    if old is None or old[1].phase != "committed" or old[0].revision != previous or old[0].storage_version != 2:
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    owner._require_witness(previous)
    return _snapshot(owner._authority_id, receipt.revision.generation, old[0].profiles, old[0].registry,
        storage_version=2, abandoned=CancellationReference(receipt.operation_id, receipt.revision))


def cancellation_candidate(owner, receipt, *, previous):
    _enabled(owner)
    owner._ready()
    with owner._store._transaction():
        owner._schema()
        return _candidate(owner, receipt, previous)


def stage_cancellation(owner, receipt, *, previous, operation_id):
    _enabled(owner)
    owner._ready(write=True)
    _text(operation_id, "operation_id")
    conn = owner._store.conn
    with owner._store._transaction(write=True):
        owner._schema()
        candidate = _candidate(owner, receipt, previous)
        if row(owner, operation_id=operation_id) is not None or operation_id == receipt.operation_id:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        conn.execute("INSERT INTO main.host_configuration_cancellations VALUES(?,?,?,?,?,?,'prepared')",
            (receipt.revision.generation, receipt.operation_id, receipt.revision.sha256,
             operation_id, candidate.revision.sha256, candidate.canonical_bytes()))
    return ConfigurationReceipt(candidate.revision, operation_id, "prepared")


def _legacy_history(owner):
    head = owner._raw_row()
    if head is None or head[1].phase != "committed":
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
    if head[0].revision.generation > MAX_CONFIGURATION_REVISIONS - 1:
        raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
    owner._require_witness(head[0].revision)
    expected = {"host_profile_versions": set(), "host_policy_versions": set()}
    for number in range(1, head[0].revision.generation + 1):
        value = owner._raw_row(generation=number)
        if value is None or value[1].phase != "committed" or value[0].storage_version != 1:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        _publication(owner, value[1])
        _consistent(value[0].profiles)
        for table, _, identity, version, payload in _versions(value[0].profiles):
            expected[table.replace("host_committed_", "host_")].add((identity.encode("utf-8"), version, hashlib.sha256(payload).hexdigest().encode("ascii")))
    for table, column, byte_limit in (("host_profile_versions", "profile_id", 512), ("host_policy_versions", "policy_id", 1024)):
        rows = owner._store.conn.execute(f"SELECT CASE WHEN length(CAST({column} AS BLOB))<=? THEN CAST({column} AS BLOB) ELSE NULL END,version,CASE WHEN length(CAST(digest AS BLOB))=64 THEN CAST(digest AS BLOB) ELSE NULL END FROM main.{table} LIMIT ?", (byte_limit, MAX_CONFIGURATION_REVISIONS * 32 + 1)).fetchall()
        if len(rows) > MAX_CONFIGURATION_REVISIONS * 32 or set(rows) != expected[table]:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
    return head[0]


def migrate(owner, *, operation_id):
    if type(owner) is not HostConfigurationAuthority or owner._storage_version != 1:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
    owner._ready(write=True)
    _text(operation_id, "operation_id")
    conn = owner._store.conn
    with owner._store._transaction(write=True):
        owner._schema()
        current = _legacy_history(owner)
        if owner._raw_row(operation_id=operation_id) is not None:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        for ddl in _EXTRA.values():
            prefix = "CREATE TRIGGER " if ddl.startswith("CREATE TRIGGER ") else "CREATE TABLE "
            conn.execute(ddl.replace(prefix, prefix + "main.", 1))
        conn.execute("UPDATE main.host_configuration_state SET schema_version=2 WHERE singleton=1")
        upgraded = HostConfigurationAuthority(conn, authority_id=owner._authority_id,
            witness_connection=owner._witness_connection, witness_id=owner._witness._authority_id, storage_version=2)
        upgraded._schema()
        for number in range(1, current.revision.generation + 1):
            old = owner._raw_row(generation=number)
            register_versions(upgraded, old[0].profiles, record=True)
        successor = _snapshot(owner._authority_id, current.revision.generation + 1,
            current.profiles, current.registry, storage_version=2)
        owner._require_witness(current.revision)
        conn.execute("INSERT INTO main.host_configuration_revisions VALUES(?,?,?,?,?)",
            (successor.revision.generation, successor.revision.sha256, successor.canonical_bytes(), operation_id, "prepared"))
    resume_migration(upgraded, operation_id)
    return upgraded


def resume_migration(owner, operation_id):
    _enabled(owner)
    owner._ready(write=True)
    _text(operation_id, "operation_id")
    with owner._store._transaction():
        owner._schema()
        current = owner._raw_row(operation_id=operation_id)
        old = None if current is None else owner._raw_row(generation=current[0].revision.generation - 1)
        if (current is None or old is None or current[0].storage_version != 2 or current[0].abandoned is not None
                or old[0].storage_version != 1 or old[1].phase != "committed"
                or current[0].profiles != old[0].profiles or current[0].registry != old[0].registry):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        if current[1].phase == "committed":
            _publication(owner, current[1])
            return current[1]
        if current != owner._row():
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    actual = owner._witness.current(owner._authority_id)
    if actual == _checkpoint(old[0].revision):
        owner.advance_witness(current[1])
    elif actual != _checkpoint(current[0].revision):
        raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
    return owner.finalize(current[1])
