"""Reference LangChain/LangGraph agent against an AuthSec-protected MCP server.

This is the *canonical, crash-proof* agent example. The point it demonstrates:

    An AuthSec auth denial (insufficient scope, revoked token, expired token)
    must NEVER crash the agent loop. It should surface to the LLM as an
    actionable message so the model can tell the user what to do — while the
    denial itself stays a hard, observable error on the wire.

The single line that makes this work is ``wrap_for_langgraph(tools)``. Without
it, ``create_react_agent(model, tools)`` builds a ToolNode whose default error
handler RE-RAISES ``ToolException`` — so an auth denial tears down the whole
``ainvoke`` call with a traceback (see the langchain-mcp-adapters issue on
Python 3.14 / LangGraph v1). With it, the denial becomes a ToolMessage the LLM
reads and relays.

Why we do NOT "soft-deny" (return a fake success): that would blind audit logs
and anomaly detection — denials would look like successful calls. We keep the
denial a true error and fix the *handling*, not the *truth*.

Run:
    pip install "authsec-sdk" langchain-mcp-adapters langgraph langchain-openai
    python langchain_agent.py
"""

from __future__ import annotations

import asyncio
import os

# The one import that makes auth denials graceful instead of fatal.
from authsec_sdk.client import wrap_for_langgraph


MCP_URL = os.environ.get("MCP_URL", "https://mcp-dev.mcpauthz.com/mcp")


async def main() -> None:
    # These imports are deferred so the file documents its own dependencies
    # without forcing them at import time for readers who just want the pattern.
    from langchain.agents import create_agent  # LangGraph v1 location
    from langchain_mcp_adapters.client import MultiServerMCPClient

    # Bring your own auth: obtain a bearer token however your flow does it
    # (the demo CLI's OAuth dance, a cached token, etc.) and pass it as a
    # header to the MCP transport.
    token = os.environ["AUTHSEC_ACCESS_TOKEN"]

    client = MultiServerMCPClient(
        {
            "demo": {
                "url": MCP_URL,
                "transport": "streamable_http",
                "headers": {"Authorization": f"Bearer {token}"},
            }
        }
    )

    tools = await client.get_tools()

    # ── The crash-proof bit ──────────────────────────────────────────────
    # wrap_for_langgraph returns a ToolNode whose error handler converts any
    # AuthSec 401/403 into an actionable string for the LLM. Pass THIS to the
    # agent instead of the raw tools list.
    tool_node = wrap_for_langgraph(tools)

    model = os.environ.get("LLM_MODEL", "gpt-4o-mini")
    agent = create_agent(model, tool_node)

    print("Type a message ('exit' to quit).")
    messages: list = []
    while True:
        user = input("you> ").strip()
        if user in {"exit", "quit"}:
            break
        messages.append({"role": "user", "content": user})

        # No try/except needed for auth denials — wrap_for_langgraph already
        # turned them into tool messages. The loop never dies on a 401/403.
        result = await agent.ainvoke({"messages": messages})
        messages = result["messages"]
        print(f"agent> {messages[-1].content}")


if __name__ == "__main__":
    asyncio.run(main())
