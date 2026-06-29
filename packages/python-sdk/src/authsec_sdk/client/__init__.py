"""AuthSec client-side helpers.

The ``runtime`` package protects an MCP *server*. This ``client`` package
sits on the *agent* side — code calling an AuthSec-protected MCP server —
and turns the raw 401 / 403 responses into typed, actionable Python
exceptions.

**LangGraph users** — use ``wrap_for_langgraph`` and never worry about
ToolException crashes again::

    from authsec_sdk.client import wrap_for_langgraph

    tool_node = wrap_for_langgraph(tools)
    agent = create_react_agent(model, tool_node)

**Manual error handling**::

    from authsec_sdk.client import parse_mcp_error, TokenRevokedError

    try:
        result = await agent.ainvoke({"messages": messages})
    except Exception as exc:
        access_err = parse_mcp_error(exc)
        if access_err is not None:
            print(access_err.format_for_user())
            if isinstance(access_err, (TokenRevokedError, AuthRequiredError)):
                re_authenticate()
        else:
            raise
"""

from .errors import (
    AuthRequiredError,
    AuthSecAccessError,
    ClientRegistrationRevokedError,
    InsufficientScopeError,
    TokenRevokedError,
    parse_mcp_error,
)
from .langgraph import wrap_for_langgraph

__all__ = [
    "AuthSecAccessError",
    "InsufficientScopeError",
    "TokenRevokedError",
    "ClientRegistrationRevokedError",
    "AuthRequiredError",
    "parse_mcp_error",
    "wrap_for_langgraph",
]
