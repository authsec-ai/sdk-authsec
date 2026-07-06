"""LangGraph integration helpers for AuthSec-protected MCP tools.

Provides ``wrap_for_langgraph`` — a one-liner that takes any list of MCP tools
(from ``langchain_mcp_adapters``) and returns a ``ToolNode`` whose error
handler converts AuthSec 401/403 denials into actionable LLM messages instead
of crashing the graph.

Usage::

    from langchain_mcp_adapters.client import MultiServerMCPClient
    from authsec_sdk.client.langgraph import wrap_for_langgraph

    async with MultiServerMCPClient(...) as client:
        tools = client.get_tools()
        tool_node = wrap_for_langgraph(tools)
        agent = create_react_agent(model, tool_node)
        result = await agent.ainvoke({"messages": [...]})

The agent will never crash on a scope denial or token revocation.  Instead the
LLM receives an actionable message like:

    "Tool 'slugify' cannot be called with this token. Required scope:
     demo_server:Admin. Your token has: demo_server:read, demo_server:write.
     Ask an admin to grant the required scope to your role."

and can relay it to the user naturally.
"""

from __future__ import annotations

from typing import Any

from ..client.errors import (
    AuthRequiredError,
    AuthSecAccessError,
    ClientRegistrationRevokedError,
    InsufficientScopeError,
    TokenRevokedError,
    parse_mcp_error,
)


def _authsec_tool_error_handler(error: Exception) -> str:
    """Convert any tool exception into an actionable LLM-readable string.

    Tries to parse the error as an AuthSec access error first; falls back to a
    generic representation so the LLM can still respond instead of the graph
    crashing.
    """
    access_err = parse_mcp_error(error)
    if access_err is not None:
        return access_err.format_for_user()

    # Non-AuthSec tool error — return as plain text so the LLM can respond.
    return f"Tool call failed: {error}"


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
    "wrap_for_langgraph",
    "_authsec_tool_error_handler",
]
