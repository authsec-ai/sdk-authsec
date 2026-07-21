#!/usr/bin/env python3
"""Small AuthSec-protected server built with the official MCP Python SDK.

This is executable SDK documentation, not the multi-component product demo.
It proves the server-side integration with three ordinary ``FastMCP`` tools:

* AuthSec validates the caller's bearer token.
* AuthSec's remote tool-to-scope policy controls ``tools/list`` and
  ``tools/call``.
* The SDK publishes the real ``FastMCP`` tool inventory to AuthSec at startup.
* The SDK serves RFC 9728 protected-resource metadata for ``/mcp``.

Install and run::

    pip install authsec-sdk "mcp>=1.27,<2" uvicorn
    export AUTHSEC_ISSUER=<your-authsec-api-origin>
    export AUTHSEC_INTROSPECTION_CLIENT_ID=<your-client-id>
    export AUTHSEC_INTROSPECTION_CLIENT_SECRET=<your-secret>
    export AUTHSEC_RESOURCE_SERVER_ID=<your-resource-server-id>
    export AUTHSEC_RESOURCE_URI=https://your-public-host/mcp
    python demo_mcp_server.py

The ``mcp<2`` upper bound follows the official MCP SDK guidance while v2 is a
prerelease. All deployment-specific values come from environment variables.
"""

from __future__ import annotations

import os
import time
from typing import Any

from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP

from authsec_sdk.runtime import Config, PolicyMode, ValidationMode, mount_mcp
from authsec_sdk.runtime.server import principal_from_context


# FastMCP owns JSON-RPC, protocol negotiation, schemas, and Streamable HTTP.
# AuthSec wraps its HTTP boundary below; the tool implementations stay normal.
mcp = FastMCP("AuthSec protected example")

_notes: list[dict[str, Any]] = []
_started_at = time.time()


@mcp.tool()
def demo_status() -> dict[str, Any]:
    """Return server status plus the AuthSec identity calling this tool."""
    principal = principal_from_context()
    return {
        "status": "ok",
        "uptime_seconds": round(time.time() - _started_at),
        "caller": principal.subject if principal else "anonymous",
        "scopes": list(principal.scopes) if principal else [],
    }


@mcp.tool()
def add_note(note: str) -> dict[str, Any]:
    """Add a note to this process's in-memory store."""
    note = note.strip()
    if not note:
        raise ValueError("note must not be empty")

    principal = principal_from_context()
    entry = {
        "note": note,
        "author": principal.subject if principal else "anonymous",
        "created_at": time.time(),
    }
    _notes.append(entry)
    return {"stored": len(_notes), "latest": entry}


@mcp.tool()
def list_notes() -> dict[str, Any]:
    """List the twenty most recently added notes."""
    return {"count": len(_notes), "notes": _notes[-20:]}


issuer = os.environ["AUTHSEC_ISSUER"].rstrip("/")

config = Config(
    issuer=issuer,
    authorization_server=issuer,
    jwks_url=f"{issuer}/oauth/jwks",
    introspection_url=f"{issuer}/oauth/introspect",
    introspection_client_id=os.environ["AUTHSEC_INTROSPECTION_CLIENT_ID"],
    introspection_client_secret=os.environ[
        "AUTHSEC_INTROSPECTION_CLIENT_SECRET"
    ],
    resource_server_id=os.environ["AUTHSEC_RESOURCE_SERVER_ID"],
    resource_uri=os.environ["AUTHSEC_RESOURCE_URI"],
    resource_name=os.environ.get(
        "AUTHSEC_RESOURCE_NAME",
        "AuthSec protected example",
    ),
    policy_mode=PolicyMode.REMOTE_REQUIRED,
    validation_mode=ValidationMode.JWT_AND_INTROSPECT,
    publish_manifest=True,
    # Suggestions describe the intended vocabulary. AuthSec's stored scope
    # matrix remains authoritative for every runtime authorization decision.
    tool_scope_suggestions={
        "demo_status": ["demo:read"],
        "add_note": ["demo:write"],
        "list_notes": ["demo:read"],
    },
)

app = FastAPI(title="AuthSec protected MCP example")
mount_mcp(app, "/mcp", mcp, config)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8000")),
    )
