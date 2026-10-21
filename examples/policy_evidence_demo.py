"""Disposable policy API walkthrough; never opens the default memory bank."""

import json
from pathlib import Path
import sqlite3
import tempfile

from mnemosyne.core.policy import AccessContext, MemoryPolicy, PolicyDefinition, PolicyRefusal, RefusalReason
from mnemosyne.core.policy_evidence import PolicyEvidence
from mnemosyne.core.policy_lifecycle import PolicyLifecycle, PolicyRecordRef
from mnemosyne.core.policy_read import BankReadGrant, PolicyReader
from mnemosyne.core.policy_store import PolicyStore, RecordKind
from mnemosyne.runtime_context import bind_access_context


def main():
    with tempfile.TemporaryDirectory(prefix="mnemosyne-policy-example-") as directory:
        path = Path(directory) / "synthetic.db"
        conn, authority = sqlite3.connect(path), sqlite3.connect(path)
        try:
            # Minimal synthetic native table, not a production schema migration.
            conn.execute("CREATE TABLE working_memory(id TEXT PRIMARY KEY,content TEXT)")
            conn.executemany("INSERT INTO working_memory VALUES(?,?)", [
                ("source-note", "Synthetic source observation"),
                ("derived-note", "Synthetic derived conclusion"),
            ])
            conn.commit()
            store = PolicyStore(conn)
            store.prepare("domain:example")
            store.register_definition(PolicyDefinition("example", 1, ("unclassified", "restricted")))
            store.bind(RecordKind.WORKING, "source-note", MemoryPolicy("example", 1, "unclassified",
                "person:example", "manual", audiences={"team:example"}, purposes={"engineering"}))
            lifecycle = PolicyLifecycle(store)
            lifecycle.prepare()
            parent = PolicyRecordRef(RecordKind.WORKING, "source-note")
            child = PolicyRecordRef(RecordKind.WORKING, "derived-note")
            lifecycle.bind_derivative(child, [parent])
            current = PolicyLifecycle(PolicyStore(authority))
            context = AccessContext(context_id="context:example", epoch=1, policy_id="example", policy_version=1,
                issuer="synthetic-host", platform="example", principals={"person:example"},
                classification_ceiling="unclassified", purpose="engineering", assurance="authenticated",
                banks={"bank:example"}, audiences={"team:example"}, operations={"read:bank"},
                destinations={"destination:example"})
            calls = []

            def verify_fixture(candidate, *, bank, destination):
                # Example-only registry. A real host authenticates participants,
                # intersects permissions and checks current grants independently.
                if (candidate != context or bank != "bank:example" or destination != "destination:example"):
                    raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
                calls.append(True)
                return BankReadGrant(candidate.fingerprint(), "domain:example", bank, destination,
                    f"decision:{len(calls)}", {"person:example"}, lifecycle_epoch=current.epoch())

            api = PolicyEvidence(PolicyReader(store, bank="bank:example", verify_context=verify_fixture))
            with bind_access_context(context):
                lease = api.issue(RecordKind.WORKING, "derived-note", destination="destination:example")
                resolved = api.resolve(lease)
                delivered = []
                delivery = api.deliver(lease, lambda hit: delivered.append(hit.record_id))
                assert delivered == ["derived-note"] and delivery.lease == lease
            assert resolved.content == "Synthetic derived conclusion"
            receipt = lifecycle.quarantine(parent)
            with bind_access_context(context):
                try:
                    api.resolve(lease)
                except PolicyRefusal as error:
                    refusal = error.reason.value
                else:
                    raise AssertionError("revoked evidence remained reusable")
            assert conn.execute("SELECT count(*) FROM working_memory").fetchone()[0] == 2
            result = {"resolved": True, "lease_contains_payload": hasattr(lease, "content"),
                "quarantine_epoch": receipt.epoch, "old_lease": refusal,
                "native_rows_preserved": 2, "protected_mode_activated": False}
            print(json.dumps(result, indent=2))
            return result
        finally:
            authority.close()
            conn.close()


if __name__ == "__main__":
    main()
