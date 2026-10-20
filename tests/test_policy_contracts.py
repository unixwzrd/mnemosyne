"""P1a contracts with synthetic claims; no protected retrieval is claimed."""

import asyncio
import contextvars
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from mnemosyne.core.policy import (
    AccessContext, AdapterCapabilities, MemoryPolicy, PolicyDefinition,
    PolicyRefusal, PolicySurface, RefusalReason,
)
from mnemosyne.runtime_context import (
    bind_access_context, get_access_context, get_request_token_name,
    request_token_name, set_request_token_name,
)


def context(**overrides):
    values = dict(context_id="ctx:synthetic", epoch=1, policy_id="policy:synthetic", policy_version=1,
                  issuer="adapter:synthetic", platform="synthetic", principals={"person:alpha"},
                  classification_ceiling="team", purpose="engineering", assurance="authenticated",
                  banks={"synthetic"}, projects={"one", "two"}, compartments={"team:a"},
                  audiences={"team"}, operations={"read", "write"}, destinations={"local"},
                  channel_id="channel:a", conversation_id="conversation:a")
    values.update(overrides)
    return AccessContext(**values)


def binding(**overrides):
    values = dict(policy_id="policy:synthetic", policy_version=1, classification="team",
                  owner="person:alpha", classification_source="manual")
    values.update(overrides)
    return MemoryPolicy(**values)


def test_records_are_frozen_and_inputs_do_not_alias():
    projects, principals, levels = ["one", "two"], {"person:alpha"}, ["open", "team"]
    ctx = context(projects=projects, principals=principals)
    policy = PolicyDefinition("policy:synthetic", 1, levels)
    record = binding(compartments=projects)
    projects.clear()
    principals.clear()
    levels.clear()
    assert ctx.projects == {"one", "two"}
    assert ctx.principals == {"person:alpha"}
    assert policy.levels == ("open", "team")
    assert record.compartments == {"one", "two"}
    for value, attr in ((ctx, "purpose"), (policy, "policy_id"), (record, "owner")):
        with pytest.raises(FrozenInstanceError):
            setattr(value, attr, "modified")


def test_custom_vocabulary_does_not_impose_taxonomy_or_defaults():
    definition = PolicyDefinition("policy:synthetic", 1, ("open", "team", "sealed"))
    definition.validate_context(context())
    definition.validate_binding(binding())
    assert definition.levels == ("open", "team", "sealed")


@pytest.mark.parametrize("arguments", [
    {"levels": []}, {"levels": {"open", "team"}}, {"levels": ["open", "open"]},
    {"levels": ["x"] * 65}, {"levels": ["x" * 65]}, {"levels": ["bad\nlevel"]},
    {"levels": ["bad\u009blevel"]},
    {"version": True}, {"version": 0}, {"version": 2**63}, {"policy_id": " "},
])
def test_invalid_policy_definition(arguments):
    values = dict(policy_id="policy:synthetic", version=1, levels=("open", "team"))
    values.update(arguments)
    with pytest.raises(ValueError):
        PolicyDefinition(**values)


@pytest.mark.parametrize("arguments", [
    {"principals": []}, {"principals": "person:alpha"}, {"principals": {"person:alpha": True}},
    {"projects": ["one"] * 257}, {"projects": [None]}, {"projects": ["bad\0project"]},
    {"issuer": ""}, {"issuer": "x" * 257}, {"epoch": True}, {"epoch": -1},
    {"policy_version": 0}, {"classification_ceiling": "x" * 65},
    {"channel_id": "bad\nchannel"}, {"conversation_id": ""}, {"assurance": ""},
    {"context_id": "bad\u0085context"}, {"context_id": "bad\u009bcontext"},
])
def test_invalid_context_is_rejected(arguments):
    with pytest.raises(ValueError):
        context(**arguments)


@pytest.mark.parametrize("arguments", [
    {"policy_id": "another"}, {"policy_version": 2}, {"classification_ceiling": "unknown"},
])
def test_context_vocabulary_mismatch_is_content_free(arguments):
    with pytest.raises(PolicyRefusal) as error:
        PolicyDefinition("policy:synthetic", 1, ("open", "team")).validate_context(context(**arguments))
    assert str(error.value) == "policy_refused:policy_mismatch"


def test_narrowing_only_selects_subsets_and_preserves_trust_fields():
    original = context()
    smaller = original.narrow(projects=["one"], operations=["read"], destinations=[])
    assert smaller.projects == {"one"}
    assert smaller.operations == {"read"}
    assert smaller.destinations == frozenset()
    assert smaller.principals == original.principals
    assert smaller.compartments == original.compartments
    assert (smaller.epoch, smaller.policy_version, smaller.purpose, smaller.issuer) == (
        original.epoch, original.policy_version, original.purpose, original.issuer,
    )
    assert original.projects == {"one", "two"}
    assert original.narrow().fingerprint() == original.fingerprint()
    assert original.narrow(projects=[]).projects == frozenset()
    with pytest.raises(TypeError):
        original.narrow(principals=["person:privileged"])


@pytest.mark.parametrize("selection", [
    {"projects": {"denied-project-canary"}}, {"banks": {"another-bank"}},
    {"operations": {"export"}}, {"destinations": {"remote-provider"}},
    {"projects": "one"}, {"projects": ["one", "bad\nproject"]},
])
def test_unknown_or_malformed_selection_refuses_without_echo(selection):
    with pytest.raises(PolicyRefusal) as error:
        context().narrow(**selection)
    assert str(error.value) == "policy_refused:invalid_selection"
    assert error.value.__cause__ is None


def test_wildcard_label_has_no_special_semantics():
    with pytest.raises(PolicyRefusal):
        context(projects={"*"}).narrow(projects={"one"})


@pytest.mark.parametrize("change", [
    {"context_id": "another"}, {"epoch": 2}, {"policy_id": "another"}, {"policy_version": 2},
    {"issuer": "another"}, {"platform": "another"}, {"principals": {"person:beta"}},
    {"classification_ceiling": "open"}, {"purpose": "review"}, {"assurance": "owner"},
    {"banks": set()}, {"projects": set()}, {"compartments": set()}, {"audiences": set()},
    {"operations": set()}, {"destinations": set()}, {"channel_id": None}, {"conversation_id": None},
])
def test_fingerprint_binds_every_context_field(change):
    assert context(**change).fingerprint() != context().fingerprint()


def test_fingerprint_is_order_independent_and_record_repr_omits_claims():
    assert context(projects=["two", "one"]).fingerprint() == context(projects=["one", "two"]).fingerprint()
    assert len(context().fingerprint()) == 64
    for record in (context(), binding(), PolicyDefinition("secret-policy-canary", 1, ("open",)),
                   AdapterCapabilities("secret-adapter-canary")):
        for canary in ("person:alpha", "secret-policy-canary", "secret-adapter-canary", "team:a"):
            assert canary not in repr(record)


@pytest.mark.parametrize("arguments", [
    {"classification_source": "unknown"}, {"classification_source": "context"},
    {"origin_context_id": "ctx"}, {"origin_context_epoch": 1},
    {"origin_context_id": "ctx", "origin_context_epoch": True}, {"tenant_id": ""},
    {"owner": ""}, {"overlays": "a-label"},
])
def test_invalid_binding_metadata_refuses(arguments):
    with pytest.raises(ValueError):
        binding(**arguments)


def test_context_derived_binding_keeps_explicit_origin_and_opaque_overlays():
    record = binding(classification_source="context", origin_context_id="ctx:synthetic",
                     origin_context_epoch=0, overlays={"consent:external"})
    PolicyDefinition("policy:synthetic", 1, ("team",)).validate_binding(record)
    assert record.overlays == {"consent:external"}
    for changed in (replace(record, classification="unknown"), replace(record, policy_version=2)):
        with pytest.raises(PolicyRefusal):
            PolicyDefinition("policy:synthetic", 1, ("team",)).validate_binding(changed)


def test_capabilities_default_to_none_and_check_each_surface():
    empty = AdapterCapabilities("synthetic")
    selected = AdapterCapabilities("synthetic", surfaces=[PolicySurface.LEXICAL, PolicySurface.WRITE])
    for surface in PolicySurface:
        with pytest.raises(PolicyRefusal, match="unsupported_surface"):
            empty.require(surface)
        if surface in selected.surfaces:
            selected.require(surface)
        else:
            with pytest.raises(PolicyRefusal, match="unsupported_surface"):
                selected.require(surface)
    with pytest.raises(PolicyRefusal):
        selected.require("lexical")


@pytest.mark.parametrize("arguments", [
    {"surfaces": ["lexical"]}, {"surfaces": "lexical"}, {"contract_version": True},
    {"contract_version": 2}, {"surfaces": [PolicySurface.WRITE] * 257},
])
def test_invalid_capability_declarations(arguments):
    with pytest.raises(ValueError):
        AdapterCapabilities("synthetic", **arguments)


def test_runtime_default_is_legacy_and_token_identity_does_not_create_grants():
    token = request_token_name.set("synthetic-token")
    try:
        assert get_request_token_name() == "synthetic-token"
        assert get_access_context() is None
        with pytest.raises(PolicyRefusal, match="missing_context"):
            get_access_context(required=True)
        with pytest.raises(ValueError):
            get_access_context(required="yes")
    finally:
        request_token_name.reset(token)


def test_legacy_context_import_does_not_load_policy_or_optional_dependencies(tmp_path):
    source = str(Path(__file__).resolve().parents[1])
    script = '''
import sys
from mnemosyne.runtime_context import get_access_context, get_request_token_name, set_request_token_name
assert "mnemosyne.core" not in sys.modules
assert "mnemosyne.core.policy" not in sys.modules
assert get_access_context() is None
set_request_token_name("synthetic-token")
assert get_request_token_name() == "synthetic-token"
assert "mnemosyne.core" not in sys.modules
'''
    env = {"PATH": os.defpath, "HOME": str(tmp_path), "PYTHONPATH": source,
           "HERMES_HOME": str(tmp_path / ".hermes"), "MNEMOSYNE_DATA_DIR": str(tmp_path / "data")}
    completed = subprocess.run([sys.executable, "-S", "-c", script], cwd=tmp_path, env=env,
                               text=True, capture_output=True, timeout=30)
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_tool_dictionary_cannot_bind_and_scoped_bindings_restore_on_errors():
    forged = {"principals": ["person:owner"], "projects": ["all"], "trusted": True}
    with pytest.raises(TypeError):
        with bind_access_context(forged):
            pytest.fail("dictionary was accepted")
    outer, inner = context(), context(context_id="ctx:inner")
    with bind_access_context(outer):
        assert get_access_context(required=True) is outer
        with pytest.raises(RuntimeError):
            with bind_access_context(inner):
                assert get_access_context(required=True) is inner
                raise RuntimeError("synthetic handler failure")
        assert get_access_context(required=True) is outer
        with bind_access_context(None):
            assert get_access_context() is None
        assert get_access_context() is outer
    assert get_access_context() is None


def test_async_a_b_a_overlap_and_task_snapshot_lifetime():
    async def run():
        a, b = context(context_id="ctx:a"), context(context_id="ctx:b")
        paused, resume = asyncio.Event(), asyncio.Event()

        async def first():
            with bind_access_context(a):
                assert get_access_context() is a
                paused.set()
                await resume.wait()
                assert get_access_context() is a
                return get_access_context().fingerprint()

        async def second():
            await paused.wait()
            assert get_access_context() is None
            with bind_access_context(b):
                await asyncio.sleep(0)
                assert get_access_context() is b
            resume.set()

        first_result, _ = await asyncio.gather(first(), second())
        assert first_result == a.fingerprint()
        assert get_access_context() is None
        delayed = asyncio.Event()

        async def child():
            await delayed.wait()
            return get_access_context()

        with bind_access_context(a):
            task = asyncio.create_task(child())
        assert get_access_context() is None
        delayed.set()
        assert await task is a  # Parent reset is not child revocation.

    asyncio.run(run())


def test_thread_context_is_explicit_and_token_attribution_stays_separate():
    token = request_token_name.set("synthetic-token")
    try:
        with bind_access_context(context()):
            copied, empty = contextvars.copy_context(), contextvars.Context()
            with ThreadPoolExecutor(max_workers=1) as pool:
                assert pool.submit(empty.run, get_access_context).result(timeout=10) is None
                assert pool.submit(copied.run, get_access_context).result(timeout=10) is get_access_context()
            assert get_request_token_name() == "synthetic-token"
            set_request_token_name("another-token")
            assert get_access_context().principals == {"person:alpha"}
    finally:
        request_token_name.reset(token)


def test_cancelled_async_handler_restores_its_outer_context():
    async def run():
        started = asyncio.Event()
        outer, inner = context(), context(context_id="ctx:cancelled")

        async def handler():
            try:
                with bind_access_context(inner):
                    started.set()
                    await asyncio.Future()
            finally:
                assert get_access_context() is outer

        with bind_access_context(outer):
            task = asyncio.create_task(handler())
            await started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert get_access_context() is outer
        assert get_access_context() is None

    asyncio.run(run())


def test_legacy_beam_reads_writes_and_schema_do_not_enable_policy(tmp_path):
    from mnemosyne.core.beam import BeamMemory

    beam = BeamMemory(db_path=tmp_path / "legacy.db", session_id="synthetic")
    try:
        before = [tuple(row) for row in beam.conn.execute("SELECT name, sql FROM sqlite_master ORDER BY name")]
        assert get_access_context() is None
        memory = beam.remember("Synthetic legacy memory without policy metadata.", scope="global")
        assert memory is not None
        assert beam.conn.execute("SELECT content FROM working_memory WHERE id=?", (memory,)).fetchone()[0].startswith("Synthetic legacy")
        with bind_access_context(context()):
            PolicyDefinition("policy:synthetic", 1, ("open", "team")).validate_context(get_access_context(required=True))
            # Bound metadata alone does not protect or alter the legacy API.
            second = beam.remember("Synthetic owner-mode legacy write with a bound context.", scope="global")
            assert second is not None
        assert [tuple(row) for row in beam.conn.execute("SELECT name, sql FROM sqlite_master ORDER BY name")] == before
        assert all("policy" not in row[0] for row in before)
    finally:
        beam.conn.close()


def test_policy_contracts_do_not_open_storage_or_call_providers(monkeypatch):
    import socket
    from mnemosyne.core import embeddings, llm_backends

    def forbidden(*args, **kwargs):
        pytest.fail("policy contract attempted storage, IO or inference")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(embeddings, "embed", forbidden)
    monkeypatch.setattr(llm_backends, "call_host_llm", forbidden)
    with bind_access_context(context()):
        current = get_access_context(required=True).narrow(projects=["one"])
        PolicyDefinition("policy:synthetic", 1, ("open", "team")).validate_context(current)
        assert current.fingerprint()


def test_refusals_accept_only_fixed_reason_codes():
    with pytest.raises(ValueError):
        PolicyRefusal("private-object-canary")
    for reason in RefusalReason:
        error = PolicyRefusal(reason)
        assert error.args == (f"policy_refused:{reason.value}",)
