"""LangGraph / LangChain v1 integration helpers for AuthSec-protected MCP tools.

Two approaches, both crash-proof:

**Per-tool middleware (recommended)**::

    from authsec_sdk.client.langgraph import authsec_tool_error_handler

    tools = await client.get_tools()
    for t in tools:
        t.handle_tool_error = authsec_tool_error_handler
    agent = create_react_agent(model, tools)

**ToolNode wrapper (legacy)**::

    from authsec_sdk.client.langgraph import wrap_for_langgraph

    tool_node = wrap_for_langgraph(tools)
    agent = create_react_agent(model, tool_node)

Both ensure that AuthSec 401/403 denials become actionable ``ToolMessage``
strings the LLM can read and relay — instead of crashing the agent loop with
a traceback.

Example LLM-visible denial::

    "Tool 'slugify' cannot be called with this token. Required scope:
     demo_server:Admin. Your token has: demo_server:read, demo_server:write.
     Ask an admin to grant the required scope to your role."
"""

from __future__ import annotations

from typing import Any

from .errors import (
    AuthRequiredError,
    AuthSecAccessError,
    ClientRegistrationRevokedError,
    InsufficientScopeError,
    TokenRevokedError,
    parse_mcp_error,
)


def authsec_tool_error_handler(error: Exception) -> str:
    """Convert any tool exception into an actionable LLM-readable string.

    Assign to ``tool.handle_tool_error`` on each LangChain tool so that
    AuthSec 401/403 denials become ``ToolMessage`` strings instead of
    crashing the agent loop.  Falls back to a generic representation for
    non-AuthSec errors.
    """
    access_err = parse_mcp_error(error)
    if access_err is not None:
        return access_err.format_for_user()

    # Non-AuthSec tool error — return as plain text so the LLM can respond.
    return f"Tool call failed: {error}"


# Backward-compat alias (was underscore-prefixed before v4.5).
_authsec_tool_error_handler = authsec_tool_error_handler


def wrap_for_langgraph(tools: list[Any]) -> Any:
    """Wrap MCP tools in a LangGraph ToolNode with AuthSec-aware error handling.

    Args:
        tools: A list of LangChain tools, typically from
               ``langchain_mcp_adapters`` ``client.get_tools()``.

    Returns:
        A ``langgraph.prebuilt.ToolNode`` configured so that AuthSec 401/403
        responses surface as actionable LLM messages, never as unhandled
        exceptions.

    Raises:
        ImportError: If ``langgraph`` is not installed.
    """
    try:
        from langgraph.prebuilt import ToolNode  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "langgraph is required for wrap_for_langgraph. "
            "Install it with: pip install langgraph"
        ) from exc

    return ToolNode(tools, handle_tool_errors=_authsec_tool_error_handler)


__all__ = [
    "authsec_tool_error_handler",
    "wrap_for_langgraph",
    # Backward compat — the underscore-prefixed name was public in v4.4.
    "_authsec_tool_error_handler",
]
