"""AuthSec client-side helpers.

The ``runtime`` package protects an MCP *server*. This ``client`` package
sits on the *agent* side — code calling an AuthSec-protected MCP server —
and turns the raw 401 / 403 responses into typed, actionable Python
exceptions.

**LangChain / LangGraph users** — per-tool middleware (recommended)::

    from authsec_sdk.client import authsec_tool_error_handler

    tools = await client.get_tools()
    for t in tools:
        t.handle_tool_error = authsec_tool_error_handler
    agent = create_react_agent(model, tools)

Or use the ToolNode wrapper::

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

Bearer-token separation
~~~~~~~~~~~~~~~~~~~~~~~
AuthSec bearer tokens authenticate the *agent* to the AuthSec authorization
layer.  If the MCP server itself requires a separate upstream credential
(e.g. a GitHub PAT or Slack bot token), that credential must travel as a
server-owned env var (``UPSTREAM_API_TOKEN``) — never in the same
``Authorization`` header.  The SDKs never mix the two layers.
"""

from .errors import (
    AuthRequiredError,
    AuthSecAccessError,
    ClientRegistrationRevokedError,
    InsufficientScopeError,
    TokenRevokedError,
    parse_mcp_error,
)
# Canonical home is authsec_sdk.integrations; re-exported here for back-compat.
from ..integrations.langgraph import wrap_for_langgraph

__all__ = [
    "AuthSecAccessError",
    "InsufficientScopeError",
    "TokenRevokedError",
    "ClientRegistrationRevokedError",
    "AuthRequiredError",
    "parse_mcp_error",
    "authsec_tool_error_handler",
    "wrap_for_langgraph",
]
