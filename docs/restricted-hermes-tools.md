# Restricted Hermes Tool Boundary

Development prerequisite H5, based on H4 `d299731`. This explicitly selected consumer is not registered by the normal Mnemosyne Hermes plugin and does not activate protected operation. The native Hermes topic is `contrib/protected-tool-boundary-20261021`, based on the retained `a3f697334a894fe2d690572611100ebaa298d791` source, not current upstream main. No backend, model, live configuration or store is changed.

## API

`RestrictedMemoryTools(binding=..., adapter=..., handle=...)` requires the exact existing `LocalRequestBinding`, `ProtectedHostAdapter` and process-owned request handle. The adapter must use that binding's snapshot loader and issuer. The trusted resolver, authentication callback and host retain their existing contracts; this check does not prove their deployment or credential handling. The caller owns admission and closes the handle after the request, including errors and cancellation.

`tools.invoke(name, arguments)` accepts only these exact operations:

| Tool | Arguments | Result |
| --- | --- | --- |
| `protected_memory_get` | Exact `kind` and bounded `record_id`; working, episodic or canonical native memory only | `found` and an authorized `memory`, or the same null shape for missing/denied |
| `protected_memory_search` | Nonempty query up to 2,048 characters and integer `top_k` from 1 to 10 | Authorized lexical hits only, using the existing indexed native reader and a fixed candidate budget of 200 |

Results contain only record kind, identity and content. They contain no raw key, file locator, owner object, policy/grant handle, total restricted-object count, audit handle or arbitrary metadata dump. Responses are bounded to 65,536 JSON characters; an oversized native memory refuses rather than becoming a hidden full-document transport. Search uses the existing authorized lexical path; no source fetch, embedding call or LLM call is introduced. All authority, bank, destination and scope come from the host, never tool arguments. Extra fields, aliases, source/media expansion, writes, export/sync, administration, legacy recall and unknown operations refuse.

The adapter performs current request checks around the existing audited encrypted reader and before returning encoded text. It does not cache plaintext as reusable authority. A later prompt/provider submission needs its own fresh gate; this tool result is not a permanent lease.

```python
from mnemosyne_hermes.restricted_tools import RestrictedMemoryTools

# binding, adapter and authenticated_request come from the qualified trusted host.
handle = binding.admit(authenticated_request)
try:
    tools = RestrictedMemoryTools(binding=binding, adapter=adapter, handle=handle)
    text = tools.invoke("protected_memory_get", {
        "kind": "working_memory", "record_id": "synthetic-record",
    })
finally:
    binding.close(handle)
```

This is an API fragment for an already constructed trusted host, not a CLI command or an activation recipe. The tests provide the complete disposable registry, witnessed authority, encrypted native records and audit fixture.

## Native Dispatch Contract

`tools.definitions()` returns fresh schema copies. `tools.dispatcher()` additionally requires native `agent.tool_dispatch_boundary.EXCLUSIVE_TOOL_DISPATCH_VERSION == 1` and returns an `ExclusiveToolDispatcher` bound to these fixed read operations. Missing/older native support refuses; there is no plugin installation, monkeypatch, ordinary `MemoryManager` fallback or model-supplied callback. Hosts must verify the exact qualified native artifact as well as negotiate its capability version.

The native boundary handles the actual AIAgent batch facade, sequential/concurrent/segmented entrypoints and direct `_invoke_tool` exclusively. It executes admitted tools synchronously, without native worker pools, middleware, approvals, tool search, aliases, registry/inline/delegation or provider fallback. This preserves H4's owner-thread restriction. An empty allowlist means no tools, not native defaults. A whole batch is checked before any handler runs. The native module enforces 32 calls, unique bounded call IDs, 65,536 input bytes per call, strict object JSON and bounded text output. Handler exceptions are fixed content-free refusals; no callback traceback is logged by this boundary.

This is not an OS/process sandbox. Arbitrary same-owner code, trusted plugin initialization and direct lower-level Python APIs remain trusted owner capabilities. The initial protected profile must not expose shell, Python, file access, debugging, delegation, remote connector/MCP execution or any other path that can reach those capabilities. Admitting another tool requires its own qualification, not adding a familiar name to a denylist.

## Not Yet An Enabled Protected Profile

Real transport authentication, complete audience enforcement, clean conversation/history admission, provider queues/retries/fallbacks, prompt/output/stream gates, transcript persistence and capability negotiation at all frontends are not completed by H5. Ordinary Hermes can still prefetch memory or persist tool results outside this boundary. Do not attach protected memories to those unqualified paths. Normal legacy plugin initialization and unprotected operation remain unchanged, and this module is deliberately absent from automatic registration.

No deployed configuration flag is added. H09-H15/H23 and V1-V10 remain cross-path gates, not checked boxes because an exclusive dispatcher or synthetic example passed. The private upstream submission/CLA hold remains unchanged; local source qualification is separate from fork publication and deployment.
