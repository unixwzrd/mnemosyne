"""Explicit read-only tools for a separately qualified restricted Hermes host.

Not registered by the legacy plugin. No shell, files, writes, fallback, or
activation is exposed here; provider/output/history qualification is separate.
"""

import json

from mnemosyne.core.host_request_binding import LocalRequestBinding, RequestHandle
from mnemosyne.core.policy import PolicyRefusal, RefusalReason
from mnemosyne.core.policy_host import ProtectedHostAdapter
from mnemosyne.core.policy_lexical import AuthorizedLexicalRecall
from mnemosyne.core.policy_read import AuthorizedMemory
from mnemosyne.core.policy_store import RecordKind


def _text(value, maximum):
    if type(value) is not str or not value or len(value) > maximum:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE) from None
    return value


def _get_arguments(arguments):
    if set(arguments) != {"kind", "record_id"}:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
    try:
        kind = RecordKind(arguments["kind"])
    except (TypeError, ValueError):
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE) from None
    if kind not in {RecordKind.WORKING, RecordKind.EPISODIC, RecordKind.CANONICAL}:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
    record_id = arguments["record_id"]
    if type(record_id) is str:
        _text(record_id, 256)
    elif type(record_id) is not int or not 0 <= record_id <= 2**63 - 1:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
    return "get", {"kind": kind.value, "record_id": record_id}


def _search_arguments(arguments):
    if set(arguments) != {"query", "top_k"}:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
    query = _text(arguments["query"], 2048)
    top_k = arguments["top_k"]
    if type(top_k) is not int or not 1 <= top_k <= 10:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
    return "lexical", {"query": query, "top_k": top_k, "candidate_limit": 200}


class RestrictedMemoryTools:
    """Host-owned handle and routing; model arguments only narrow read inputs.

    This capability must not be exposed as an object to a model-controlled
    interpreter. The host retains its request handle, authority and lifecycle.
    """

    def __init__(self, *, binding, adapter, handle):
        if (type(binding) is not LocalRequestBinding or type(adapter) is not ProtectedHostAdapter
                or type(handle) is not RequestHandle):
            raise TypeError("explicit protected binding, adapter and opaque handle required")
        # An unrelated adapter/loader could otherwise deliver another store's data
        # while this binding merely supplies a fresh but unrelated authorization.
        if adapter._load != binding.load_snapshot or adapter._issuer != binding._issuer:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        binding.load_snapshot(handle)
        self._binding, self._adapter, self._handle = binding, adapter, handle

    def definitions(self):
        return [
            {"type": "function", "function": {
                "name": "protected_memory_get", "description": "Read an authorized memory by identity.",
                "parameters": {"type": "object", "additionalProperties": False,
                    "properties": {"kind": {"type": "string", "enum": ["working_memory", "episodic_memory", "canonical_facts"]},
                                   "record_id": {"anyOf": [{"type": "string", "minLength": 1, "maxLength": 256},
                                                           {"type": "integer", "minimum": 0, "maximum": 2**63 - 1}]}},
                    "required": ["kind", "record_id"]}}},
            {"type": "function", "function": {
                "name": "protected_memory_search", "description": "Search only currently authorized memories.",
                "parameters": {"type": "object", "additionalProperties": False,
                    "properties": {"query": {"type": "string", "minLength": 1, "maxLength": 2048},
                                   "top_k": {"type": "integer", "minimum": 1, "maximum": 10}},
                    "required": ["query", "top_k"]}}},
        ]

    def invoke(self, name, arguments):
        if type(arguments) is not dict or any(type(key) is not str for key in arguments):
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        validators = {"protected_memory_get": _get_arguments, "protected_memory_search": _search_arguments}
        if type(name) is not str or name not in validators:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        operation, intent = validators[name](arguments)
        output = []

        def consume(result):
            if operation == "get":
                if result is not None and type(result) is not AuthorizedMemory:
                    raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
                value = {"found": result is not None, "memory": None if result is None else _memory(result)}
            else:
                if type(result) is not AuthorizedLexicalRecall or len(result.hits) > intent["top_k"]:
                    raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
                value = {"memories": [_memory(hit) for hit in result.hits]}
            text = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
            if len(text) > 65536:
                raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
            self._binding.load_snapshot(self._handle)
            output.append(text)

        self._adapter.invoke(self._handle, operation, intent, consume)
        self._binding.load_snapshot(self._handle)
        if len(output) != 1:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        return output[0]

    def dispatcher(self):
        try:
            from agent.tool_dispatch_boundary import (
                EXCLUSIVE_TOOL_DISPATCH_VERSION,
                ExclusiveToolDispatcher,
            )
        except ImportError:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE) from None
        if EXCLUSIVE_TOOL_DISPATCH_VERSION != 1:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        return ExclusiveToolDispatcher(self.definitions(), self.invoke)


def _memory(hit):
    if type(hit.content) is not str or len(hit.content) > 65536:
        raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
    return {"kind": hit.record_kind.value, "record_id": hit.record_id, "content": hit.content}
