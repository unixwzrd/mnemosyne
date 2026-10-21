"""Model-free stream revocation example using only a disposable SQLite store."""

import asyncio
import json
from pathlib import Path
import sqlite3
import tempfile

from mnemosyne.core.policy import AccessContext, MemoryPolicy, PolicyDefinition, PolicyRefusal
from mnemosyne.core.policy_evidence import PolicyEvidence
from mnemosyne.core.policy_lifecycle import PolicyLifecycle, PolicyRecordRef
from mnemosyne.core.policy_read import BankReadGrant, PolicyReader
from mnemosyne.core.policy_store import PolicyStore, RecordKind
from mnemosyne.runtime_context import bind_access_context


async def main():
    with tempfile.TemporaryDirectory(prefix="mnemosyne-stream-example-") as directory:
        path = Path(directory) / "synthetic.db"
        conn, authority = sqlite3.connect(path), sqlite3.connect(path)
        try:
            conn.execute("CREATE TABLE working_memory(id TEXT PRIMARY KEY,content TEXT)")
            conn.execute("INSERT INTO working_memory VALUES('note','Synthetic authorized input')")
            conn.commit()
            store = PolicyStore(conn)
            store.prepare("domain:example")
            store.register_definition(PolicyDefinition("example",1,("unclassified",)))
            store.bind(RecordKind.WORKING,"note",MemoryPolicy("example",1,"unclassified","person:example","manual",
                audiences={"team:example"},purposes={"engineering"}))
            lifecycle = PolicyLifecycle(store)
            lifecycle.prepare()
            current = PolicyLifecycle(PolicyStore(authority))
            context = AccessContext("context:example",1,"example",1,"synthetic-host","example",{"person:example"},
                "unclassified","engineering","authenticated",banks={"bank:example"},operations={"read:bank"},
                destinations={"destination:example"},audiences={"team:example"})
            def verify_fixture(candidate,*,bank,destination):
                # Example only: real hosts must authenticate all participants
                # and check current authority independently of these claims.
                assert candidate == context and bank == "bank:example" and destination == "destination:example"
                return BankReadGrant(candidate.fingerprint(),"domain:example",bank,destination,"decision:example",
                    {"person:example"},lifecycle_epoch=current.epoch())
            evidence = PolicyEvidence(PolicyReader(store,bank="bank:example",verify_context=verify_fixture))
            sent, closed = [], []
            async def producer(hits):
                assert hits[0].content == "Synthetic authorized input"
                try:
                    yield "first authorized chunk"
                    yield "must not be forwarded after revocation"
                finally:
                    closed.append(True)
            def consume(chunk):
                sent.append(chunk)
                lifecycle.quarantine(PolicyRecordRef(RecordKind.WORKING,"note"))
            with bind_access_context(context):
                lease = evidence.issue(RecordKind.WORKING,"note",destination="destination:example")
                try:
                    await evidence.stream([lease],producer,consume)
                except PolicyRefusal as error:
                    refused = error.reason.value
                else:
                    raise AssertionError("revoked stream completed")
            result = {"chunks_delivered":len(sent),"producer_closed":closed==[True],"next_chunk":refused,
                "native_rows_preserved":conn.execute("SELECT count(*) FROM working_memory").fetchone()[0],
                "protected_mode_activated":False}
            assert sent == ["first authorized chunk"] and result["producer_closed"]
            print(json.dumps(result,indent=2))
            return result
        finally:
            authority.close()
            conn.close()


if __name__ == "__main__":
    asyncio.run(main())
