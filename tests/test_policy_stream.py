"""Native cooperative streams with disposable authority and no model calls."""

import asyncio
from dataclasses import FrozenInstanceError, asdict, replace
import inspect
from pathlib import Path
import runpy
import sqlite3

import pytest

from mnemosyne.core.policy import PolicyRefusal
from mnemosyne.core.policy_evidence import PolicyEvidence
from mnemosyne.core.policy_lifecycle import PolicyRecordRef
from mnemosyne.core.policy_read import PolicyReader
from mnemosyne.core.policy_store import RecordKind
from mnemosyne.core.policy_stream import EvidenceStreamLimits, EvidenceStreamReceipt
from mnemosyne.runtime_context import bind_access_context
from tests.test_policy_read import add, context, fixture as fixture
from tests.test_policy_evidence import evidence as evidence, issue
from tests.test_policy_delivery import source_fixture as source_fixture, projects as projects
from tests import test_policy_sources as source_tests
from tests.test_policy_projects import assign
from mnemosyne.core.policy_lifecycle import PolicyLifecycle


def run(api, lease, producer, consumer, **options):
    with bind_access_context(context()):
        return asyncio.run(api.stream([lease], producer, consumer, **options))


def test_normal_chunks_receipt_and_all_cleanup(evidence):
    store, registry, _, api, _ = evidence
    add(store, "w", content="STREAM-INPUT-CANARY")
    lease = issue(evidence)
    sent, closed, streams = [], [], []
    async def producer(hits):
        assert len(hits) == 1 and hits[0].content == "STREAM-INPUT-CANARY"
        try:
            for chunk in ("Hello ", "\u754c", ""):
                await asyncio.sleep(0)
                yield chunk
        finally:
            closed.append(True)
    def factory(hits):
        stream = producer(hits)
        streams.append(stream)
        return stream
    changes, calls = store.conn.total_changes, len(registry.calls)
    receipt = run(api, lease, factory, sent.append)
    assert sent == ["Hello ", "\u754c", ""] and closed == [True]
    assert type(receipt) is EvidenceStreamReceipt and receipt.chunks_delivered == 3 and receipt.bytes_delivered == 9
    assert receipt.lease_count == 1 and receipt.destination == lease.destination
    assert "STREAM-INPUT-CANARY" not in str(asdict(receipt)) and "Hello " not in repr(receipt)
    assert streams[0].ag_frame is None and len(registry.calls) > calls
    assert store.conn.total_changes == changes and not store.conn.in_transaction
    with pytest.raises(FrozenInstanceError):
        receipt.chunks_delivered = 0


def test_empty_stream_completes_without_consumer(evidence):
    add(evidence[0], "w")
    async def producer(hits):
        if False:
            yield ""
    receipt = run(evidence[3], issue(evidence), producer, lambda chunk: pytest.fail("no chunks"))
    assert receipt.chunks_delivered == receipt.bytes_delivered == 0


@pytest.mark.parametrize("mutation", ["quarantine", "content", "owner", "missing_context", "changed_context"])
def test_stale_authority_prevents_producer_creation(evidence, mutation):
    store, registry, lifecycle, api, _ = evidence
    add(store, "w")
    lease = issue(evidence)
    ctx = context()
    if mutation == "quarantine":
        lifecycle.quarantine(PolicyRecordRef(RecordKind.WORKING, "w"))
    elif mutation == "content":
        store.conn.execute("UPDATE working_memory SET content='changed' WHERE id='w'")
        store.conn.commit()
    elif mutation == "owner":
        registry.register(ctx, owners={"person:b"})
    elif mutation == "changed_context":
        ctx = context(epoch=2)
        registry.register(ctx)
    with bind_access_context(None if mutation == "missing_context" else ctx), pytest.raises(PolicyRefusal):
        asyncio.run(api.stream([lease], lambda hits: pytest.fail("producer created"), lambda chunk: pytest.fail("consumed")))


@pytest.mark.parametrize("mutation", ["quarantine", "owner", "content"])
def test_revocation_while_waiting_cancels_and_closes_pending_producer(evidence, mutation):
    store, registry, lifecycle, api, _ = evidence
    add(store, "w")
    lease = issue(evidence)
    closed, cancelled = [], []
    async def scenario():
        entered = asyncio.Event()
        async def producer(hits):
            try:
                entered.set()
                await asyncio.Event().wait()
                yield "MUST-NOT-BE-EMITTED"
            except asyncio.CancelledError:
                cancelled.append(True)
                raise
            finally:
                closed.append(True)
        task = asyncio.create_task(api.stream([lease], producer, lambda chunk: pytest.fail("consumed"),
            limits=EvidenceStreamLimits(poll_seconds=0.005)))
        await entered.wait()
        if mutation == "quarantine":
            lifecycle.quarantine(PolicyRecordRef(RecordKind.WORKING, "w"))
        elif mutation == "owner":
            registry.register(context(), owners={"person:b"})
        else:
            store.conn.execute("UPDATE working_memory SET content='changed' WHERE id='w'")
            store.conn.commit()
        with pytest.raises(PolicyRefusal):
            await asyncio.wait_for(task, 5)
        assert asyncio.all_tasks() == {asyncio.current_task()}
    with bind_access_context(context()):
        asyncio.run(scenario())
    assert closed == cancelled == [True] and not store.conn.in_transaction


def test_revocation_after_one_chunk_prevents_next_output(evidence):
    store, _, lifecycle, api, _ = evidence
    add(store, "w")
    lease = issue(evidence)
    sent, closed = [], []
    async def producer(hits):
        try:
            yield "first"
            yield "DENIED-NEXT-CHUNK"
        finally:
            closed.append(True)
    def consume(chunk):
        sent.append(chunk)
        lifecycle.quarantine(PolicyRecordRef(RecordKind.WORKING, "w"))
    with pytest.raises(PolicyRefusal):
        run(api, lease, producer, consume)
    assert sent == ["first"] and closed == [True]


def test_producer_task_context_switch_never_leaks_chunk(evidence):
    add(evidence[0], "w")
    async def producer(hits):
        with bind_access_context(context(context_id="ctx:other")):
            yield "CROSS-CONTEXT-CANARY"
    with pytest.raises(PolicyRefusal):
        run(evidence[3], issue(evidence), producer, lambda chunk: pytest.fail("consumed"))


@pytest.mark.parametrize("chunk", [b"bytes", 0, None, "OUTPUT-CANARY\ud800"])
def test_invalid_chunks_refuse_content_free_without_forwarding(evidence, chunk):
    add(evidence[0], "w")
    async def producer(hits):
        yield chunk
    with pytest.raises(PolicyRefusal, match="unsupported_surface") as caught:
        run(evidence[3], issue(evidence), producer, lambda value: pytest.fail("consumed"))
    assert caught.value.__context__ is None


@pytest.mark.parametrize("limits,chunks,expected", [
    (EvidenceStreamLimits(max_chunks=1), ("first", "second"), ["first"]),
    (EvidenceStreamLimits(max_chunk_bytes=2), ("\u754c",), []),
    (EvidenceStreamLimits(max_total_bytes=4), ("aaa", "bb"), ["aaa"]),
])
def test_output_budgets_are_checked_before_forwarding(evidence, limits, chunks, expected):
    add(evidence[0], "w")
    sent, closed = [], []
    async def producer(hits):
        try:
            for chunk in chunks:
                yield chunk
        finally:
            closed.append(True)
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        run(evidence[3], issue(evidence), producer, sent.append, limits=limits)
    assert sent == expected and closed == [True]


def test_total_timeout_closes_waiting_producer(evidence):
    add(evidence[0], "w")
    closed = []
    async def producer(hits):
        try:
            await asyncio.Event().wait()
            yield "late"
        finally:
            closed.append(True)
    with pytest.raises(PolicyRefusal, match="resource_limit"):
        run(evidence[3], issue(evidence), producer, lambda chunk: pytest.fail("consumed"),
            limits=EvidenceStreamLimits(poll_seconds=0.005, timeout_seconds=0.05))
    assert closed == [True]


@pytest.mark.parametrize("where", ["producer", "consumer"])
@pytest.mark.parametrize("error", [RuntimeError("synthetic error"), asyncio.CancelledError("synthetic cancellation")])
def test_errors_cancel_once_and_clear_completed_payload_frames(evidence, where, error):
    add(evidence[0], "w", content="STREAM-FRAME-CANARY")
    lease = issue(evidence)
    closed, calls = [], []
    async def producer(hits):
        private = hits[0].content
        try:
            if where == "producer":
                assert private == "STREAM-FRAME-CANARY"
                raise error
            yield private
        finally:
            closed.append(True)
    def consumer(chunk):
        calls.append(True)
        assert chunk == "STREAM-FRAME-CANARY"
        raise error
    with pytest.raises(type(error)) as caught:
        run(evidence[3], lease, producer, consumer)
    assert caught.value is error and closed == [True]
    assert len(calls) == (1 if where == "consumer" else 0)
    tb = error.__traceback__
    while tb is not None:
        if tb.tb_frame.f_code.co_name in {"stream_evidence", "_next", "producer", "consumer", "_consume"}:
            assert not tb.tb_frame.f_locals
        tb = tb.tb_next


def test_repeated_cancellation_drains_cleanup_without_retries(evidence):
    add(evidence[0], "w")
    lease = issue(evidence)
    closed, calls = [], []
    async def scenario():
        entered, cleaning, finish = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def producer(hits):
            try:
                entered.set()
                await asyncio.Event().wait()
                yield "late"
            finally:
                cleaning.set()
                await finish.wait()
                closed.append(True)
        task = asyncio.create_task(evidence[3].stream([lease], producer, calls.append))
        await entered.wait()
        task.cancel("first")
        await cleaning.wait()
        task.cancel("second")
        await asyncio.sleep(0)
        finish.set()
        with pytest.raises(asyncio.CancelledError) as caught:
            await task
        assert caught.value.args == ("first",)
        assert asyncio.all_tasks() == {asyncio.current_task()}
    with bind_access_context(context()):
        asyncio.run(scenario())
    assert closed == [True] and not calls


@pytest.mark.parametrize("values", [[], (), None, "lease", [None]])
def test_invalid_lease_collections_refuse_before_factory(evidence, values):
    with pytest.raises(ValueError):
        asyncio.run(evidence[3].stream(values, lambda hits: pytest.fail("factory"), lambda chunk: None))


@pytest.mark.parametrize("change", [{"poll_seconds":True}, {"poll_seconds":0}, {"poll_seconds":2},
    {"timeout_seconds":float("inf")}, {"timeout_seconds":float("nan")}, {"timeout_seconds":10**1000},
    {"max_chunks":True}, {"max_chunks":0}, {"max_chunks":4097}, {"max_chunk_bytes":65537}, {"max_total_bytes":8388609}])
def test_invalid_limits_refuse(change):
    with pytest.raises(ValueError):
        EvidenceStreamLimits(**change)


def test_duplicate_and_mixed_scope_leases_refuse_before_producer(evidence):
    add(evidence[0], "w")
    lease = issue(evidence)
    for values, error in (([lease,lease],ValueError),
        ([lease,replace(lease,record_id="other",destination="channel:other")],PolicyRefusal)):
        with pytest.raises(error):
            asyncio.run(evidence[3].stream(values,lambda hits: pytest.fail("factory"),lambda chunk: None))


@pytest.mark.parametrize("kind", ["coroutine", "generator", "list"])
def test_unsupported_producer_result_refuses_without_running(evidence, kind):
    add(evidence[0], "w")
    results, ran = [], []
    async def coroutine():
        ran.append(True)
    def generator():
        ran.append(True)
        yield "value"
    def producer(hits):
        value = {"coroutine":coroutine,"generator":generator,"list":list}[kind]()
        results.append(value)
        return value
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        run(evidence[3],issue(evidence),producer,lambda chunk:pytest.fail("consumed"))
    assert not ran
    if kind == "coroutine":
        assert inspect.getcoroutinestate(results[0]) == inspect.CORO_CLOSED


def test_native_content_change_mid_batch_refuses_before_factory(evidence):
    store, _, _, _, original = evidence
    add(store,"w")
    add(store,"second")
    first, second = issue(evidence), issue(evidence,"second")
    calls = []
    def verify(ctx,**intent):
        calls.append(True)
        if len(calls) == 6:
            store.conn.execute("UPDATE working_memory SET content='changed' WHERE id='w'")
            store.conn.commit()
        return original(ctx,**intent)
    api = PolicyEvidence(PolicyReader(store,bank="bank:a",verify_context=verify))
    with bind_access_context(context()),pytest.raises(PolicyRefusal):
        asyncio.run(api.stream([first,second],lambda hits:pytest.fail("factory"),lambda chunk:None))


def test_external_native_change_mid_batch_refuses_before_factory(evidence):
    store, _, _, _, original = evidence
    add(store,"w")
    add(store,"second")
    first, second = issue(evidence), issue(evidence,"second")
    authority = sqlite3.connect(store.conn.execute("PRAGMA database_list").fetchone()[2])
    calls = []
    def verify(ctx,**intent):
        calls.append(True)
        if len(calls) == 6:
            authority.execute("UPDATE working_memory SET content='changed' WHERE id='w'")
            authority.commit()
        return original(ctx,**intent)
    api = PolicyEvidence(PolicyReader(store,bank="bank:a",verify_context=verify))
    try:
        with bind_access_context(context()),pytest.raises(PolicyRefusal):
            asyncio.run(api.stream([first,second],lambda hits:pytest.fail("factory"),lambda chunk:None))
    finally:
        authority.close()


def test_revocation_just_before_ready_chunk_prevents_consumer(evidence):
    add(evidence[0], "w")
    lease = issue(evidence)
    async def producer(hits):
        evidence[2].quarantine(PolicyRecordRef(RecordKind.WORKING,"w"))
        yield "READY-DENIED-CANARY"
    with pytest.raises(PolicyRefusal):
        run(evidence[3],lease,producer,lambda chunk:pytest.fail("consumed"))


def test_missing_authority_while_waiting_stops_stream(evidence):
    add(evidence[0],"w")
    lease = issue(evidence)
    closed = []
    async def scenario():
        entered = asyncio.Event()
        async def producer(hits):
            try:
                entered.set()
                await asyncio.Event().wait()
                yield "late"
            finally:
                closed.append(True)
        task = asyncio.create_task(evidence[3].stream([lease],producer,lambda chunk:pytest.fail("consumed"),
            limits=EvidenceStreamLimits(poll_seconds=0.005)))
        await entered.wait()
        evidence[1].contexts.clear()
        with pytest.raises(PolicyRefusal):
            await asyncio.wait_for(task,5)
        assert asyncio.all_tasks() == {asyncio.current_task()}
    with bind_access_context(context()):
        asyncio.run(scenario())
    assert closed == [True]


def test_real_loopback_wait_is_cancelled_and_socket_closes(evidence):
    add(evidence[0], "w")
    lease = issue(evidence)
    sent = []
    async def scenario():
        waiting, disconnected = asyncio.Event(), asyncio.Event()
        handlers = []
        async def handle(reader, writer):
            handlers.append(asyncio.current_task())
            try:
                writer.write(b"first\n")
                await writer.drain()
                assert await reader.read() == b""
                disconnected.set()
            finally:
                writer.close()
                await writer.wait_closed()
        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async def producer(hits):
            reader, writer = await asyncio.open_connection("127.0.0.1",port)
            try:
                first = await reader.readline()
                yield first.decode("utf-8")
                waiting.set()
                second = await reader.readline()
                yield second.decode("utf-8")
            finally:
                writer.close()
                await writer.wait_closed()
        task = asyncio.create_task(evidence[3].stream([lease],producer,sent.append,
            limits=EvidenceStreamLimits(poll_seconds=0.005)))
        try:
            await asyncio.wait_for(waiting.wait(),5)
            evidence[2].quarantine(PolicyRecordRef(RecordKind.WORKING,"w"))
            with pytest.raises(PolicyRefusal):
                await asyncio.wait_for(task,5)
            await asyncio.wait_for(disconnected.wait(),5)
            await asyncio.gather(*handlers)
            assert asyncio.all_tasks() == {asyncio.current_task()}
        finally:
            if not task.done():
                task.cancel()
                try:
                    await task
                except BaseException:
                    pass
            server.close()
            await server.wait_closed()
    with bind_access_context(context()):
        asyncio.run(scenario())
    assert sent == ["first\n"]


def test_parallel_public_private_public_tasks_do_not_share_context(evidence):
    store, registry, _, api, _ = evidence
    add(store,"w")
    lease = issue(evidence)
    private = context(context_id="private",principals={"person:b"})
    registry.register(private,owners={"person:b"})
    sent = []
    async def producer(hits):
        await asyncio.sleep(0)
        yield "allowed"
    async def request(ctx, expected):
        with bind_access_context(ctx):
            if expected:
                await api.stream([lease],producer,lambda chunk:sent.append((ctx.context_id,chunk)))
            else:
                with pytest.raises(PolicyRefusal):
                    await api.stream([lease],lambda hits:pytest.fail("private factory"),sent.append)
    async def scenario():
        await asyncio.gather(request(context(),True),request(private,False),request(context(),True))
    asyncio.run(scenario())
    assert sent == [(context().context_id,"allowed")] * 2


def test_source_scope_never_fetches_original_bytes(source_fixture, monkeypatch):
    media, store, registry, _ = source_fixture
    identity = source_tests.source(source_fixture)
    PolicyLifecycle(store).prepare()
    authority = sqlite3.connect(media.conn.execute("PRAGMA database_list").fetchone()[2])
    try:
        current = PolicyLifecycle(type(store)(authority))
        def verify(ctx, **intent):
            return replace(registry(ctx,**intent),lifecycle_epoch=current.epoch())
        api = PolicyEvidence(PolicyReader(store,bank="bank:a",verify_context=verify))
        import mnemosyne.core.source_verification as verification
        monkeypatch.setattr(verification,"verify_source_revision",lambda *a,**kw:pytest.fail("source fetched"))
        async def producer(hits):
            assert hits[0].record_id == identity
            assert not hasattr(hits[0],"content") and not hasattr(hits[0],"archive_locator")
            yield "assertion only"
        sent = []
        with bind_access_context(source_tests.context()):
            lease = api.issue(RecordKind.SOURCE_REVISION,identity,destination="channel:a")
            receipt = asyncio.run(api.stream([lease],producer,sent.append))
        assert sent == ["assertion only"] and receipt.lease_count == 1
    finally:
        authority.close()


def test_project_scope_preserves_exact_selection(projects):
    store,catalog,ctx,registry,_ = projects
    add(store,"w")
    assign(catalog,"w")
    PolicyLifecycle(store).prepare()
    authority = sqlite3.connect(store.conn.execute("PRAGMA database_list").fetchone()[2])
    try:
        current = PolicyLifecycle(type(store)(authority))
        def verify(context,**intent):
            return replace(registry(context,**intent),lifecycle_epoch=current.epoch())
        api = PolicyEvidence(PolicyReader(store,bank="bank:a",verify_context=verify))
        async def producer(hits):
            assert hits[0].record_id == "w"
            yield "selected"
        sent = []
        with bind_access_context(ctx):
            lease = api.issue(RecordKind.WORKING,"w",destination="channel:a",projects={"project:a"})
            asyncio.run(api.stream([lease],producer,sent.append))
            with pytest.raises(PolicyRefusal):
                asyncio.run(api.stream([replace(lease,projects=frozenset({"project:b"}))],
                    lambda hits:pytest.fail("wrong project"),sent.append))
        assert sent == ["selected"]
    finally:
        authority.close()


@pytest.mark.parametrize("change", [{"destination":""},{"lifecycle_epoch":-1},{"lease_count":0},
    {"chunks_delivered":True},{"bytes_delivered":-1},{"scope_fingerprint":"bad"}])
def test_invalid_receipts_refuse(change):
    with pytest.raises((TypeError,ValueError)):
        EvidenceStreamReceipt(**(dict(scope_fingerprint="a"*64,destination="channel:a",lifecycle_epoch=0,
            lease_count=1,chunks_delivered=0,bytes_delivered=0) | change))


def test_complete_documented_stream_example(capsys):
    demo = runpy.run_path(str(Path(__file__).resolve().parents[1]/"examples/policy_stream_demo.py"))
    result = asyncio.run(demo["main"]())
    assert result == {"chunks_delivered":1,"producer_closed":True,"next_chunk":"access_denied",
        "native_rows_preserved":1,"protected_mode_activated":False}
    assert '"producer_closed": true' in capsys.readouterr().out
