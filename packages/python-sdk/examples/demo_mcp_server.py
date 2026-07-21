#!/usr/bin/env python3
"""AuthSec-protected demo MCP server — standards-compliant runtime API.

A narrow MCP server with three tools that demonstrates every AuthSec runtime
capability needed for a live demo:

  1. **Token validation** — bearer tokens issued by AuthSec are verified via
     JWT + introspection.
  2. **Scope-matrix enforcement** — each tool/call is authorized against the
     scope matrix fetched from the AuthSec admin API.
  3. **Manifest publishing** — the tool inventory is pushed to AuthSec at
     startup so the admin UI can see the tools.
  4. **RFC 9728 PRM** — ``/.well-known/oauth-protected-resource/mcp`` is
     served automatically for MCP-client discovery.

Run::

    pip install authsec-sdk uvicorn fastapi
    export AUTHSEC_ISSUER=https://app.authsec.ai/api
    export AUTHSEC_INTROSPECTION_CLIENT_ID=<your-client-id>
    export AUTHSEC_INTROSPECTION_CLIENT_SECRET=<your-secret>
    export AUTHSEC_RESOURCE_SERVER_ID=<your-rs-id>
    export AUTHSEC_RESOURCE_URI=https://your-host:8000/mcp
    python demo_mcp_server.py

All config comes from env vars so there are zero secrets in this file.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from authsec_sdk.runtime import Config, PolicyMode, ValidationMode, mount_mcp
from authsec_sdk.runtime.server import principal_from_context

# ─── In-memory state (resets on restart) ──────────────────────────────

_notes: list[dict[str, Any]] = []
_start_time = time.time()


# ─── MCP JSON-RPC handler ────────────────────────────────────────────

async def mcp_handler(request: Request) -> JSONResponse:
    """Standards-compliant MCP JSON-RPC handler with three demo tools."""
    body = await request.json()
    method = body.get("method", "")
    rpc_id = body.get("id")

    if method == "initialize":
        return _jsonrpc_ok(rpc_id, {
            "protocolVersion": "2025-03-26",
            "serverInfo": {"name": "authsec-demo", "version": "1.0.0"},
            "capabilities": {"tools": {"listChanged": False}},
        })

    if method == "notifications/initialized":
        return _jsonrpc_ok(rpc_id, None)

    if method == "tools/list":
        return _jsonrpc_ok(rpc_id, {"tools": _TOOLS})

    if method == "tools/call":
        params = body.get("params", {})
        name = params.get("name", "")
        args = params.get("arguments", {})
        principal = principal_from_context()

        if name == "demo_status":
            return _tool_result(rpc_id, {
                "status": "ok",
                "server": "authsec-demo",
                "uptime_seconds": round(time.time() - _start_time),
                "caller": principal.subject if principal else "anonymous",
                "scopes": list(principal.scopes) if principal else [],
            })

        if name == "add_note":
            note_text = (args.get("note") or "").strip()
            if not note_text:
                return _tool_error(rpc_id, "note is required")
            entry = {
                "note": note_text,
                "author": principal.subject if principal else "anonymous",
                "ts": time.time(),
            }
            _notes.append(entry)
            return _tool_result(rpc_id, {
                "stored": len(_notes),
                "latest": note_text,
            })

        if name == "list_notes":
            return _tool_result(rpc_id, {
                "count": len(_notes),
                "notes": _notes[-20:],
            })

        return _jsonrpc_err(rpc_id, -32601, f"unknown tool: {name}")

    return _jsonrpc_err(rpc_id, -32601, f"method not found: {method}")


# ─── Tool definitions ────────────────────────────────────────────────

_TOOLS = [
    {
        "name": "demo_status",
        "description": "Show demo server status, uptime, and caller identity",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "add_note",
        "description": "Add a note to the demo server's in-memory store",
        "inputSchema": {
            "type": "object",
            "properties": {
                "note": {
                    "type": "string",
                    "description": "The note text to store",
                },
            },
            "required": ["note"],
        },
    },
    {
        "name": "list_notes",
        "description": "List the most recent notes stored in the demo server",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
]


# ─── JSON-RPC helpers ────────────────────────────────────────────────

def _jsonrpc_ok(rpc_id: Any, result: Any) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": result})


def _jsonrpc_err(rpc_id: Any, code: int, message: str) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}})


def _tool_result(rpc_id: Any, data: Any) -> JSONResponse:
    return _jsonrpc_ok(rpc_id, {
        "content": [{"type": "text", "text": json.dumps(data)}],
        "isError": False,
    })


def _tool_error(rpc_id: Any, message: str) -> JSONResponse:
    return _jsonrpc_ok(rpc_id, {
        "content": [{"type": "text", "text": json.dumps({"error": message})}],
        "isError": True,
    })


# ─── App + config ────────────────────────────────────────────────────

ISSUER = os.environ.get("AUTHSEC_ISSUER", "https://app.authsec.ai/api")

cfg = Config(
    issuer=ISSUER,
    authorization_server=ISSUER,
    jwks_url=ISSUER + "/oauth/jwks",
    introspection_url=ISSUER + "/oauth/introspect",
    introspection_client_id=os.environ.get("AUTHSEC_INTROSPECTION_CLIENT_ID", ""),
    introspection_client_secret=os.environ.get("AUTHSEC_INTROSPECTION_CLIENT_SECRET", ""),
    resource_server_id=os.environ.get("AUTHSEC_RESOURCE_SERVER_ID", ""),
    resource_uri=os.environ.get("AUTHSEC_RESOURCE_URI", "https://localhost:8000/mcp"),
    resource_name=os.environ.get("AUTHSEC_RESOURCE_NAME", "AuthSec Demo Server"),
    policy_mode=PolicyMode.REMOTE_REQUIRED,
    validation_mode=ValidationMode.JWT_AND_INTROSPECT,
    publish_manifest=True,
    tool_scope_suggestions={
        "demo_status": ["demo:read"],
        "add_note": ["demo:write"],
        "list_notes": ["demo:read"],
    },
)

app = FastAPI(title="AuthSec Demo MCP Server")
mount_mcp(app, "/mcp", mcp_handler, cfg)


if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    print(f"[AuthSec Demo] Starting on {host}:{port}")
    print(f"[AuthSec Demo] Issuer: {ISSUER}")
    print(f"[AuthSec Demo] Resource: {cfg.resource_uri}")
    uvicorn.run(app, host=host, port=port)
