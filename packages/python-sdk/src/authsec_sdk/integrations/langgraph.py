"""LangChain/LangGraph helpers for AuthSec-protected MCP tools.

For a standard ReAct agent, use LangChain's ``create_agent`` and attach
``authsec_tool_error_handler`` to each MCP tool.  This is the current
LangChain API and keeps the normal list-of-tools contract intact::

    from langchain.agents import create_agent
    from authsec_sdk.integrations import authsec_tool_error_handler

    tools = await client.get_tools()
    for tool in tools:
        tool.handle_tool_error = authsec_tool_error_handler

    agent = create_agent(model, tools)
    result = await agent.ainvoke({"messages": [...]})

``wrap_for_langgraph`` remains available for callers building a custom graph
that needs a ``ToolNode`` directly.  Do not pass that ``ToolNode`` to
``create_agent``; ``create_agent`` accepts the original tools and constructs
its own execution node.

The agent will never crash on a scope denial or token revocation.  Instead the
LLM receives an actionable message like:

    "Tool 'slugify' cannot be called with this token. Required scope:
     demo_server:Admin. Your token has: demo_server:read, demo_server:write.
     Ask an admin to grant the required scope to your role."

and can relay it to the user naturally.
"""

from __future__ import annotations

from typing import Any

from ..client.errors import parse_mcp_error


def authsec_tool_error_handler(error: Exception) -> str:
    """Convert any tool exception into an actionable LLM-readable string.

    Assign this callable to ``tool.handle_tool_error`` before passing the tool
    to ``langchain.agents.create_agent``.  AuthSec access failures become
    useful tool observations for the model; unrelated tool failures retain a
    generic, truthful error message.
    """
    access_err = parse_mcp_error(error)
    if access_err is not None:
        return access_err.format_for_user()

    # Non-AuthSec tool error — return as plain text so the LLM can respond.
    return f"Tool call failed: {error}"


# Compatibility for callers that imported the old private-looking name.  The
# public name above is canonical; this alias can be removed in the next major
# SDK release after the normal deprecation window.
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

    return ToolNode(tools, handle_tool_errors=authsec_tool_error_handler)


__all__ = [
    "authsec_tool_error_handler",
    "wrap_for_langgraph",
    # Backward compatibility with the name exposed by earlier 4.x releases.
    "_authsec_tool_error_handler",
]
