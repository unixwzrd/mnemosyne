# Registry-Backed Request Binding

Downstream opt-in Python API, not an installed Hermes/MCP/CLI authentication system. This implements the fresh `load_snapshot` boundary using the host authorization registry and existing `ProtectedHostAdapter`. No service, legacy endpoint, default bank, model or live authority is activated.

## Trusted Inputs

The application supplies `authenticate(opaque_transport_request) -> AuthenticatedAudience`. It must authenticate the issuer/subject, bind platform/conversation and exact route revision, attest every recipient and participating agent, and supply a current positive `session_epoch`. That epoch must advance on relevant audience/session changes, including A/B/A transitions. Names, titles, request dictionaries and model arguments cannot substitute for this hook. Both the hook and raw owner capabilities stay outside model tools. The callback is synchronous and is rechecked, not cached as authority.

The registry's exact issuer/subject mappings, enabled principals, destination recipients and registered conversation must all agree with the attested complete audience. Every participant needs a current grant for the selected store. The existing host contract then computes the minimum ceiling and permission intersections. Grants from another store, a broader agent or a missing audience member cannot widen the decision. No matching registry or grant refuses; there is no legacy fallback.

## API

```python
binding = LocalRequestBinding(
    owner,
    authority_id=expected_authority_id,
    issuer=expected_issuer,
    authenticate=trusted_transport_authentication,
)
adapter = ProtectedHostAdapter(
    adapter_id="application-memory",
    issuer=expected_issuer,
    load_snapshot=binding.load_snapshot,
    resolve_store=trusted_owner_registry,
)
handle = binding.admit(authenticated_transport_request)
try:
    adapter.invoke(handle, "get", {"kind": "working_memory", "record_id": "example"},
                   trusted_synchronous_consumer)
finally:
    binding.close(handle)
```

This wiring example requires the application's explicit authenticated hooks; it is not executable standalone login/configuration syntax. A failed load invalidates its handle; `close` is idempotent for exact handle objects so cleanup does not mask that refusal. The trusted store resolver must qualify actual repository/audit ownership and capability independently of the registry record. No model tool receives that resolver, owner, keys or decrypted objects.

Handles are exact object-identity capabilities, bound to one issuer instance, process and thread. They are not serialized bearer tokens. At most 64 can be pending. Default lifetime is 900 seconds, explicitly configurable from 1 to 3,600; expiration is not a permission cache. `load_snapshot` reauthenticates and reads the independently witnessed current registry on every call, including after projection. Any registry revision, route/audience/session change or expiry fences the handle permanently. New admission after an authorized change uses a new snapshot; the transport epoch also changes the effective context fingerprint without pretending the registry changed.

## Remaining Boundary

This callback does not implement provider cancellation, clean model-session creation, old-transcript visibility, actual egress fencing or a tool sandbox. The real frontend must supply and qualify those hooks before serving protected memory. Already emitted text cannot be recalled. A new handle or fingerprint alone does not erase old model state. Grant administration, arbitrary writes, graph, export/sync, maintenance and unsupported domain predicates are not enabled through this API.
