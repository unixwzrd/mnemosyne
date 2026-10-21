"""Restricted tools use the actual witnessed binding and encrypted read adapter."""

import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from mnemosyne.core.policy import PolicyRefusal
from mnemosyne.core.policy_host import ProtectedHostAdapter
from tests.test_host_binding_adapter import (
    authority as authority,
)
from tests.test_host_binding_adapter import (
    evidence as evidence,
)
from tests.test_host_binding_adapter import (
    fixture as fixture,
)
from tests.test_host_binding_adapter import (
    registered as registered,
)
from tests.test_host_binding_adapter import (
    registry_authority as registry_authority,
)
from tests.test_host_binding_adapter import (
    repository as repository,
)
from tests.test_host_binding_adapter import (
    session as session,
)
from tests.test_policy_lexical import lexical as lexical
from tests.test_policy_lexical import seed

from mnemosyne_hermes.restricted_tools import RestrictedMemoryTools


@pytest.fixture
def tools(registered):
    binding, adapter, request, *_ = registered
    handle = binding.admit(request)
    try:
        yield RestrictedMemoryTools(binding=binding, adapter=adapter, handle=handle)
    finally:
        binding.close(handle)


def test_allowed_memory_and_identical_denied_missing_shapes(tools):
    allowed = json.loads(tools.invoke("protected_memory_get", {"kind": "working_memory", "record_id": "w"}))
    assert allowed == {"found": True, "memory": {"kind": "working_memory", "record_id": "w",
                                               "content": "PRIVATE-REPOSITORY-CANARY"}}
    denied = tools.invoke("protected_memory_get", {"kind": "working_memory", "record_id": "denied"})
    missing = tools.invoke("protected_memory_get", {"kind": "working_memory", "record_id": "missing"})
    assert denied == missing == '{"found":false,"memory":null}'


@pytest.mark.parametrize("name", ["terminal", "read_file", "execute_code", "delegate_task", "memory",
    "remember", "export", "tool_call", "session_search", "protected_memory_get_tool", "",
    "protected_memory_source", "protected_memory_write"])
def test_no_legacy_or_executable_tool_fallback(tools, name):
    with pytest.raises(PolicyRefusal):
        tools.invoke(name, {})


@pytest.mark.parametrize("extra", ["bank", "projects", "store_id", "context", "principal", "destination",
    "key", "profile", "consumer", "repository", "owner", "path", "handle"])
def test_scope_and_owner_capabilities_are_never_model_arguments(tools, extra):
    with pytest.raises(PolicyRefusal):
        tools.invoke("protected_memory_get", {"kind": "working_memory", "record_id": "w", extra: "forged"})


@pytest.mark.parametrize("arguments", [None, [], {1: "x"}, {}, {"kind": "working_memory"},
    {"kind": "media_source_revisions", "record_id": "x"}, {"kind": "wrong", "record_id": "x"},
    {"kind": "working_memory", "record_id": True}, {"kind": "working_memory", "record_id": ""},
    {"kind": "working_memory", "record_id": "x" * 257}, {"kind": "working_memory", "record_id": 2**64}])
def test_invalid_get_inputs_refuse(tools, arguments):
    with pytest.raises(PolicyRefusal):
        tools.invoke("protected_memory_get", arguments)


@pytest.mark.parametrize("arguments", [{}, {"query": "x"}, {"query": "x", "top_k": True},
    {"query": "", "top_k": 1}, {"query": "x", "top_k": 0}, {"query": "x", "top_k": 11},
    {"query": "x" * 2049, "top_k": 1}, {"query": "x", "top_k": 1, "bank": "other"}])
def test_invalid_search_inputs_refuse(tools, arguments):
    with pytest.raises(PolicyRefusal):
        tools.invoke("protected_memory_search", arguments)


def test_closed_handle_cannot_use_prior_tool_result(tools):
    assert "PRIVATE-REPOSITORY-CANARY" in tools.invoke("protected_memory_get", {"kind": "working_memory", "record_id": "w"})
    tools._binding.close(tools._handle)
    with pytest.raises(PolicyRefusal):
        tools.invoke("protected_memory_get", {"kind": "working_memory", "record_id": "w"})


def test_registry_revocation_fences_existing_tools(tools, registered):
    _, _, _, owner, registry, profile, _ = registered
    owner.publish((profile,), previous=owner.current().revision, operation_id="revoke-tools",
                  registry=replace(registry, grants=()))
    with pytest.raises(PolicyRefusal):
        tools.invoke("protected_memory_get", {"kind": "working_memory", "record_id": "w"})


@pytest.mark.parametrize("record_id", ["w", "missing"])
def test_revocation_during_serialization_prevents_return(tools, registered, monkeypatch, record_id):
    import mnemosyne_hermes.restricted_tools as module
    _, _, _, owner, registry, profile, _ = registered
    original = json.dumps
    revoked = []
    def encode(value, *args, **kwargs):
        text = original(value, *args, **kwargs)
        if type(value) is dict and set(value) == {"found", "memory"}:
            revoked.append(True)
            owner.publish((profile,), previous=owner.current().revision, operation_id="revoke-encoding",
                          registry=replace(registry, grants=()))
        return text
    monkeypatch.setattr(module.json, "dumps", encode)
    with pytest.raises(PolicyRefusal):
        tools.invoke("protected_memory_get", {"kind": "working_memory", "record_id": record_id})
    assert revoked == [True]


def test_revocation_after_adapter_unwinds_prevents_return(tools, registered, monkeypatch):
    _, adapter, _, owner, registry, profile, _ = registered
    original = adapter.invoke
    def invoke(*args, **kwargs):
        original(*args, **kwargs)
        owner.publish((profile,), previous=owner.current().revision, operation_id="revoke-after-adapter",
                      registry=replace(registry, grants=()))
    monkeypatch.setattr(adapter, "invoke", invoke)
    with pytest.raises(PolicyRefusal):
        tools.invoke("protected_memory_get", {"kind": "working_memory", "record_id": "w"})


def test_unrelated_adapter_cannot_mix_authorities(registered):
    binding, adapter, request, *_ = registered
    handle = binding.admit(request)
    unrelated = ProtectedHostAdapter(adapter_id="unrelated", issuer="test-host",
        load_snapshot=lambda _: binding.load_snapshot(handle), resolve_store=adapter._resolve)
    try:
        with pytest.raises(PolicyRefusal):
            RestrictedMemoryTools(binding=binding, adapter=unrelated, handle=handle)
    finally:
        binding.close(handle)


def test_schema_matches_only_explicit_read_names(tools):
    schemas = tools.definitions()
    assert {s["function"]["name"] for s in schemas} == {"protected_memory_get", "protected_memory_search"}
    schemas.clear()
    assert len(tools.definitions()) == 2


def test_missing_native_boundary_refuses_not_legacy_install(tools, monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "agent.tool_dispatch_boundary", None)
    with pytest.raises(PolicyRefusal):
        tools.dispatcher()


def test_actual_fts_search_never_emits_forbidden_hit(registered, lexical):
    from mnemosyne.core.policy_lifecycle import PolicyLifecycle
    from tests.test_protected_snapshot import identity
    beam, store, *_ = lexical
    seed(lexical, "allowed", "orion gateway allowed")
    seed(lexical, "denied", "orion gateway DENIED-RESTRICTED-TOOLS-CANARY", owner="person:b")
    PolicyLifecycle(store).prepare()
    binding, adapter, request, owner, registry, profile, _ = registered
    repository, _ = adapter._resolve("a" * 32)
    repository.publish(beam.conn, identity(generation=3), previous=repository._current("a" * 32),
                       operation_id="lexical-generation")
    operations = frozenset({"read:bank", "recall:lexical"})
    registry = replace(registry,
        conversations=(replace(registry.conversations[0], operations=operations),),
        grants=tuple(replace(grant, operations=operations) for grant in registry.grants))
    owner.publish((profile,), previous=owner.current().revision, operation_id="lexical-grants", registry=registry)
    handle = binding.admit(request)
    try:
        tools = RestrictedMemoryTools(binding=binding, adapter=adapter, handle=handle)
        result = tools.invoke("protected_memory_search", {"query": "orion gateway", "top_k": 10})
        assert "DENIED-RESTRICTED-TOOLS-CANARY" not in result
        assert json.loads(result) == {"memories": [{"kind": "working_memory", "record_id": "allowed",
                                                   "content": "orion gateway allowed"}]}
    finally:
        binding.close(handle)


@pytest.mark.parametrize("entry", ["facade", "sequential", "concurrent", "segmented", "invoke"])
@pytest.mark.parametrize("allowed", [True, False])
def test_pinned_native_dispatch_to_actual_encrypted_memory(tools, monkeypatch, entry, allowed):
    source = os.environ.get("MNEMOSYNE_HERMES_DISPATCH_SOURCE")
    expected = os.environ.get("MNEMOSYNE_HERMES_DISPATCH_REVISION")
    if not source:
        pytest.skip("explicit qualified native Hermes source required for cross-repository dispatch")
    source = Path(source).resolve(strict=True)
    assert expected and len(expected) == 40
    actual = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    assert actual == expected
    assert not subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True).strip()
    monkeypatch.syspath_prepend(str(source))
    from agent import tool_executor
    from agent.tool_dispatch_boundary import ToolDispatchRefusal
    from agent.tool_invocation import invoke_tool
    from run_agent import AIAgent
    agent = SimpleNamespace(_exclusive_tool_dispatcher=tools.dispatcher())
    name = "protected_memory_get" if allowed else "terminal"
    arguments = {"kind": "working_memory", "record_id": "w"}
    call = SimpleNamespace(id="synthetic-call", function=SimpleNamespace(name=name, arguments=json.dumps(arguments)))
    messages = []
    def run():
        if entry == "invoke":
            return invoke_tool(agent, name, arguments, "synthetic-task", skip_tool_execution_middleware=True)
        message = SimpleNamespace(tool_calls=[call])
        if entry == "facade":
            return AIAgent._execute_tool_calls(agent, message, messages, "synthetic-task")
        return getattr(tool_executor, "execute_tool_calls_" + entry)(agent, message, messages, "synthetic-task")
    if allowed:
        result = run()
        if entry != "invoke":
            result = json.dumps(messages)
        assert "PRIVATE-REPOSITORY-CANARY" in result
        assert "DENIED-SESSION-CANARY" not in result
    else:
        with pytest.raises(ToolDispatchRefusal):
            run()
        assert messages == []
