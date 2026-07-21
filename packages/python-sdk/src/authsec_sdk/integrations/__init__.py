"""Framework integrations — glue between the AuthSec SDK and agent frameworks.

Currently:

- :func:`wrap_for_langgraph` — wrap MCP tools in a LangGraph ``ToolNode``
  whose error handler converts AuthSec 401/403 denials into readable
  LLM messages instead of crashing the graph.

Usage::

    from authsec_sdk.integrations import wrap_for_langgraph
"""

from .langgraph import wrap_for_langgraph

__all__ = ["wrap_for_langgraph"]
