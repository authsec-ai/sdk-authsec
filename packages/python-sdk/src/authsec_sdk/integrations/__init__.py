"""Framework integrations — glue between the AuthSec SDK and agent frameworks.

Current public helpers:

- :func:`authsec_tool_error_handler` — attach to each LangChain MCP tool, then
  pass the normal tool list to ``langchain.agents.create_agent``.
- :func:`wrap_for_langgraph` — compatibility helper for custom graphs that
  explicitly require a LangGraph ``ToolNode``.

Usage::

    from authsec_sdk.integrations import authsec_tool_error_handler
"""

from .langgraph import authsec_tool_error_handler, wrap_for_langgraph

__all__ = ["authsec_tool_error_handler", "wrap_for_langgraph"]
