"""Cross-transport request context (identity plumbing).

Holds per-request values that transports (e.g. the SSE bearer-token
middleware) record and tool handlers consume. Kept in a dedicated module
so ``mcp_tools`` can read it without importing the (MCP-dependent)
``mcp_server`` module -- avoiding a circular import.

Entries:
- ``request_token_name``: name of the authenticated multi-token entry
  (``MNEMOSYNE_MCP_TOKENS``). ``mcp_tools._create_instance`` uses it as
  the author identity fallback so memories are attributed to the calling
  agent. Defaults to None everywhere (stdio transport, single-token
  mode) -- fully backward compatible.
- Optional host-bound access context: scoped policy claims remain separate
  from token attribution. No existing retrieval path consumes these claims
  or becomes protected just because they are bound.
"""
from __future__ import annotations

import contextvars
from contextlib import contextmanager

request_token_name: contextvars.ContextVar = contextvars.ContextVar(
    "mnemosyne_request_token_name", default=None
)


def set_request_token_name(name: str) -> None:
    """Record the authenticated token name for the current task."""
    request_token_name.set(name)


def get_request_token_name():
    """Return the authenticated token name (or None outside SSE/multi-token)."""
    return request_token_name.get()


# Separate from token attribution: an authenticated token name is not a grant.
_access_context: contextvars.ContextVar = contextvars.ContextVar(
    "mnemosyne_access_context", default=None,
)


def get_access_context(*, required: bool = False):
    """Return host-bound claims, never infer them from token/tool metadata.

    Legacy callers can observe None. Future protected entry points must request
    and validate a context explicitly; no retrieval path is changed here.
    """
    if type(required) is not bool:
        raise ValueError("required must be a boolean")
    context = _access_context.get()
    if required and context is None:
        from mnemosyne.core.policy import PolicyRefusal, RefusalReason

        raise PolicyRefusal(RefusalReason.MISSING_CONTEXT)
    return context


@contextmanager
def bind_access_context(context):
    """Scope authenticated host claims and restore the previous binding.

    This is an owner-mode Python seam, not an authentication method. Adapters
    must resolve participants/grants before calling it and must not feed tool
    dictionaries into it. None explicitly clears an inherited binding.
    """
    from mnemosyne.core.policy import AccessContext

    if context is not None and not isinstance(context, AccessContext):
        raise TypeError("context must be an AccessContext or None")
    token = _access_context.set(context)
    try:
        yield context
    finally:
        _access_context.reset(token)
