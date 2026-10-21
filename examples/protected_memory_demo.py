"""Complete disposable protected-memory example; never opens a default bank."""

from base64 import urlsafe_b64encode
from contextlib import ExitStack, closing
from dataclasses import replace
import json
from pathlib import Path
import secrets
import sqlite3
import tempfile

from mnemosyne.core.compact_recall import CompactCandidate, CompactRecall
from mnemosyne.core.policy import (
    AccessContext,
    MemoryPolicy,
    PolicyDefinition,
    PolicyRefusal,
    RefusalReason,
)
from mnemosyne.core.policy_audit import PolicyAudit
from mnemosyne.core.policy_host import (
    HostPolicySnapshot,
    ParticipantGrant,
    ProtectedHostAdapter,
)
from mnemosyne.core.policy_lifecycle import PolicyLifecycle
from mnemosyne.core.policy_store import PolicyStore, RecordKind
from mnemosyne.core.protected_repository import ProtectedRepository
from mnemosyne.core.protected_snapshot import SnapshotIdentity
from mnemosyne.core.snapshot_authority import SnapshotAuthority


def run_demo():
    with (
        tempfile.TemporaryDirectory(prefix="mnemosyne-protected-demo-") as temporary,
        ExitStack() as stack,
    ):
        root = Path(temporary).resolve()
        source = stack.enter_context(closing(sqlite3.connect(":memory:")))
        source.execute("CREATE TABLE working_memory(id TEXT PRIMARY KEY,content TEXT)")
        source.execute("CREATE TABLE episodic_memory(id TEXT UNIQUE,content TEXT)")
        source.execute("CREATE TABLE canonical_facts(id INTEGER PRIMARY KEY,body TEXT)")
        source.executemany(
            "INSERT INTO working_memory VALUES(?,?)",
            [
                ("allowed-note", "A compact note pointing to archive://demo/source-1."),
                (
                    "restricted-note",
                    "Synthetic restricted note; never emitted to the shared consumer.",
                ),
            ],
        )
        source.commit()
        definition = PolicyDefinition("demo", 1, ("unclassified", "team", "sealed"))
        store = PolicyStore(source)
        store.prepare("domain:demo")
        store.register_definition(definition)
        policy = MemoryPolicy(
            "demo",
            1,
            "unclassified",
            "person:a",
            "manual",
            compartments={"work"},
            audiences={"internal"},
            purposes={"research"},
        )
        store.bind(RecordKind.WORKING, "allowed-note", policy)
        store.bind(
            RecordKind.WORKING,
            "restricted-note",
            replace(policy, classification="sealed", owner="person:b"),
        )
        PolicyLifecycle(store).prepare()
        authority_conn = stack.enter_context(
            closing(sqlite3.connect(root / "authority.sqlite"))
        )
        authority_conn.execute("PRAGMA synchronous=EXTRA")
        authority = SnapshotAuthority(authority_conn, authority_id="b" * 32)
        authority.prepare()
        artifact_root = root / "encrypted"
        artifact_root.mkdir(mode=0o700)
        # This is standard random Fernet-key encoding, not a password or KDF.
        # The key exists only in this owner process and is never printed/saved.
        key = urlsafe_b64encode(secrets.token_bytes(32))
        repository = stack.enter_context(
            ProtectedRepository(artifact_root, key=key, authority=authority)
        )
        repository.publish(
            source,
            SnapshotIdentity("a" * 32, "bank:demo", "domain:demo", 1, 0),
            previous=None,
            operation_id="demo:first",
        )
        audit_conn = stack.enter_context(
            closing(sqlite3.connect(root / "audit.sqlite"))
        )
        audit_conn.execute("PRAGMA synchronous=EXTRA")
        audit = PolicyAudit(
            audit_conn,
            domain_id="domain:demo",
            bank="bank:demo",
            verify_read=lambda *a, **k: None,
        )
        audit.prepare()
        context = AccessContext(
            "context:demo",
            1,
            "demo",
            1,
            "host:demo",
            "synthetic",
            {"person:a", "agent:a"},
            "sealed",
            "research",
            "authenticated",
            banks={"bank:demo"},
            compartments={"work"},
            audiences={"internal"},
            operations={"read:bank"},
            destinations={"conversation:demo"},
        )
        common = dict(
            authority_epoch=1,
            banks=context.banks,
            compartments=context.compartments,
            audiences=context.audiences,
            purposes={"research"},
            operations=context.operations,
            destinations=context.destinations,
            bank_wide=True,
        )
        human = ParticipantGrant(
            "person:a", classification_ceiling="team", owners={"person:a"}, **common
        )
        agent = ParticipantGrant(
            "agent:a",
            classification_ceiling="sealed",
            owners={"person:a", "person:b"},
            **common,
        )
        state = {
            "snapshot": HostPolicySnapshot(
                context,
                definition,
                (human, agent),
                "a" * 32,
                "domain:demo",
                "bank:demo",
                "conversation:demo",
                0,
            )
        }
        request = object()  # A stand-in for a real authenticated host capability.
        adapter = ProtectedHostAdapter(
            adapter_id="demo",
            issuer="host:demo",
            load_snapshot=lambda actual: (
                state["snapshot"] if actual is request else None
            ),
            resolve_store=lambda identity: (
                (repository, audit) if identity == "a" * 32 else None
            ),
        )
        with adapter.session(request) as memory:
            allowed = memory.get(RecordKind.WORKING, "allowed-note")
            assert allowed is not None
            assert memory.get(RecordKind.WORKING, "restricted-note") is None
            assert memory.get(RecordKind.WORKING, "absent-note") is None
            lease = memory.issue(RecordKind.WORKING, "allowed-note")
            captured = []
            receipt = CompactRecall(
                memory,
                tokenizer_id="synthetic:utf8-byte-v1",
                count_tokens=lambda text: len(text.encode("utf-8")),
            ).deliver(
                [CompactCandidate(lease, "authorized-demo-group")],
                [],
                captured.append,
                token_budget=2000,
            )
            assert json.loads(captured[0])["primary"][0]["excerpt"] == allowed.content
            state["snapshot"] = replace(
                state["snapshot"],
                context=replace(context, epoch=2),
                grants=(
                    replace(human, authority_epoch=2),
                    replace(agent, authority_epoch=2),
                ),
            )
            try:
                memory.resolve(lease)
            except PolicyRefusal as error:
                assert error.reason is RefusalReason.ACCESS_DENIED
            else:
                raise AssertionError("old host epoch reused")
        fresh = []
        adapter.invoke(
            request,
            "get",
            {"kind": "working_memory", "record_id": "allowed-note"},
            fresh.append,
        )
        assert fresh[0].content == allowed.content
        return {
            "synthetic_only": True,
            "effective_ceiling": "team",
            "broader_agent_did_not_expand_access": True,
            "denied_matches_absent": True,
            "exact_wire_byte_tokens": receipt.tokens,
            "token_budget": 2000,
            "old_host_epoch_refused": True,
            "fresh_request_succeeded": True,
            "default_banks_opened": 0,
            "model_or_source_fetch_calls": 0,
        }


if __name__ == "__main__":
    print(json.dumps(run_demo(), indent=2))
