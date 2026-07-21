"""Reference LangChain/LangGraph agent against an AuthSec-protected MCP server.

This is the *canonical, crash-proof* agent example. The point it demonstrates:

    An AuthSec auth denial (insufficient scope, revoked token, expired token)
    must NEVER crash the agent loop. It should surface to the LLM as an
    actionable message so the model can tell the user what to do — while the
    denial itself stays a hard, observable error on the wire.

Each tool is individually wrapped with ``handle_tool_error`` set to
``authsec_tool_error_handler`` so that AuthSec 401/403 denials become
actionable ToolMessages the LLM can read and relay — instead of crashing the
agent loop with a traceback.

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

from authsec_sdk.client import authsec_tool_error_handler


MCP_URL = os.environ.get("MCP_URL", "https://mcp-dev.app.authsec.ai/mcp")


async def main() -> None:
    from langgraph.prebuilt import create_react_agent
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
    # Enable LangChain v1 tool-error middleware on every tool so that any
    # AuthSec 401/403 becomes an actionable ToolMessage for the LLM instead
    # of crashing the agent loop. Pass the normal tool sequence to the agent.
    for t in tools:
        t.handle_tool_error = authsec_tool_error_handler

    model = os.environ.get("LLM_MODEL", "gpt-4o-mini")
    agent = create_react_agent(model, tools)

    print("Type a message ('exit' to quit).")
    messages: list = []
    while True:
        user = input("you> ").strip()
        if user in {"exit", "quit"}:
            break
        messages.append({"role": "user", "content": user})

        # No try/except needed for auth denials — handle_tool_error on each
        # tool turns them into tool messages. The loop never dies on a 401/403.
        result = await agent.ainvoke({"messages": messages})
        messages = result["messages"]
        print(f"agent> {messages[-1].content}")


if __name__ == "__main__":
    asyncio.run(main())
