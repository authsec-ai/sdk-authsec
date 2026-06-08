"""Wrap an existing MCP HTTP handler with AuthSec — the Python equivalent of
the Go SDK's ``authsecsdk.MountMCP`` example.

Paste the AuthSec admin UI's "Show Python config" values into the env vars at
the top, run this file, and your previously-unauthenticated MCP server now:

* Returns ``401 Unauthorized`` with an RFC 6750/9728 Bearer challenge on
  unauthenticated requests.
* Publishes ``/.well-known/oauth-protected-resource/mcp`` for AI clients to
  discover the authorization server.
* Pushes the tool manifest to AuthSec at startup so the admin UI knows
  which tools exist.
* Enforces tool-level scopes per the Scope Matrix configured in AuthSec
  (fail-closed if the matrix is unreachable, per
  ``PolicyMode.REMOTE_REQUIRED``).

Run::

    pip install authsec-sdk uvicorn
    export AUTHSEC_INTROSPECTION_CLIENT_SECRET=...
    python protect_existing_mcp_server.py
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from authsec_sdk.runtime import Config, PolicyMode, ValidationMode, mount_mcp


# ─── Replace with env vars or values from your AuthSec admin UI ──────
ISSUER = os.environ.get("AUTHSEC_ISSUER", "https://your-authsec-api.example.com")
AUTHORIZATION_SERVER = ISSUER
JWKS_URL = ISSUER + "/oauth/jwks"
INTROSPECTION_URL = ISSUER + "/oauth/introspect"
INTROSPECTION_CLIENT_ID = os.environ.get("AUTHSEC_INTROSPECTION_CLIENT_ID", "your-client-id")
RESOURCE_SERVER_ID = os.environ.get("AUTHSEC_RESOURCE_SERVER_ID", "your-resource-server-id")
RESOURCE_URI = os.environ.get("AUTHSEC_RESOURCE_URI", "https://your-mcp-server.example.com/mcp")
RESOURCE_NAME = os.environ.get("AUTHSEC_RESOURCE_NAME", "My MCP Server")


# ─── Your existing MCP handler ────────────────────────────────────────
# In production this is whatever you already have (mcp-python-sdk's ASGI app,
# a hand-written FastAPI route, etc.). Here we ship a trivial one for demo.
async def my_existing_mcp_handler(request: Request) -> JSONResponse:
    """Pretend this is your real MCP JSON-RPC handler.

    For the purpose of the example we just echo back the request body and
    a synthetic tools list response.
    """
    body = await request.json()
    method = body.get("method", "")

    if method == "tools/list":
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": {
                    "tools": [
                        {
                            "name": "echo",
                            "description": "Echoes input back",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"msg": {"type": "string"}},
                                "required": ["msg"],
                            },
                        },
                        {
                            "name": "delete_repo",
                            "description": "Dangerous — deletes a repository",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"repo": {"type": "string"}},
                                "required": ["repo"],
                            },
                            "annotations": {"destructiveHint": True},
                        },
                    ]
                },
            }
        )

    if method == "tools/call":
        params = body.get("params", {})
        tool = params.get("name", "")
        # If we got here, AuthSec already authorized the call.
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": {
                    "content": [{"type": "text", "text": f"executed {tool}"}],
                    "isError": False,
                },
            }
        )

    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "error": {"code": -32601, "message": "method not found"},
        }
    )


# ─── Build the AuthSec config + protected app ─────────────────────────
cfg = Config(
    issuer=ISSUER,
    authorization_server=AUTHORIZATION_SERVER,
    jwks_url=JWKS_URL,
    introspection_url=INTROSPECTION_URL,
    introspection_client_id=INTROSPECTION_CLIENT_ID,
    introspection_client_secret=os.environ.get(
        "AUTHSEC_INTROSPECTION_CLIENT_SECRET", "<<set me>>"
    ),
    resource_server_id=RESOURCE_SERVER_ID,
    resource_uri=RESOURCE_URI,
    resource_name=RESOURCE_NAME,
    policy_mode=PolicyMode.REMOTE_REQUIRED,
    validation_mode=ValidationMode.JWT_AND_INTROSPECT,
    publish_manifest=True,
    tool_scope_suggestions={
        # Optional: ship default scope recommendations for the admin UI.
        "echo": ["mcp:tools:read"],
        "delete_repo": ["mcp:tools:admin"],
    },
)

app = FastAPI()
mount_mcp(app, "/mcp", my_existing_mcp_handler, cfg)


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
