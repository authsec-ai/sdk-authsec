#!/usr/bin/env python3

import json
import os
import sys

from authsec_sdk import protected_by_AuthSec, run_mcp_server_with_oauth

DEFAULT_AUTH_SERVICE_URL = "https://prod.api.authsec.ai/sdkmgr/mcp-auth"
DEFAULT_SERVICES_URL = "https://prod.api.authsec.ai/sdkmgr/services"


@protected_by_AuthSec(
    "demo_status",
    description="Show local demo server status",
    inputSchema={
        "type": "object",
        "properties": {},
        "required": [],
    },
)
async def demo_status(arguments, session):
    payload = {
        "status": "ok",
        "server": "authsec-python-local-demo",
        "message": "Protected tools are available because this session is authenticated.",
        "user_id": session.user_id,
        "tenant_id": session.tenant_id,
    }
    return [{"type": "text", "text": json.dumps(payload)}]


@protected_by_AuthSec(
    "list_demo_notes",
    description="List the protected local demo notes",
    inputSchema={
        "type": "object",
        "properties": {},
        "required": [],
    },
)
async def list_demo_notes(arguments, session):
    notes = [
        "AuthSec local MCP demo is running.",
        "This tool is only callable after oauth_start completes.",
        f"Authenticated user: {session.user_id or 'unknown'}",
    ]
    return [{"type": "text", "text": json.dumps({"notes": notes})}]


@protected_by_AuthSec(
    "remember_note",
    description="Persist a note in process memory for the current demo session",
    inputSchema={
        "type": "object",
        "properties": {
            "note": {
                "type": "string",
                "description": "The note to remember",
            }
        },
        "required": ["note"],
    },
)
async def remember_note(arguments, session):
    note = (arguments or {}).get("note", "").strip()
    if not note:
        return [{"type": "text", "text": json.dumps({"error": "note is required"})}]

    notes = getattr(remember_note, "_notes", [])
    notes.append(
        {
            "note": note,
            "user_id": session.user_id,
            "tenant_id": session.tenant_id,
        }
    )
    remember_note._notes = notes
    return [{"type": "text", "text": json.dumps({"stored": len(notes), "latest": note})}]


@protected_by_AuthSec(
    "read_notes_memory",
    description="Read all notes captured in the current Python demo process",
    inputSchema={
        "type": "object",
        "properties": {},
        "required": [],
    },
)
async def read_notes_memory(arguments, session):
    notes = getattr(remember_note, "_notes", [])
    return [{"type": "text", "text": json.dumps({"count": len(notes), "notes": notes})}]


def main():
    client_id = os.getenv("AUTHSEC_CLIENT_ID")
    if not client_id:
        raise RuntimeError("Set AUTHSEC_CLIENT_ID before running the local Python MCP demo")

    app_name = os.getenv("AUTHSEC_APP_NAME", "authsec-python-local-demo")
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "3006"))

    print("[AuthSec] Python MCP demo configuration")
    print(f"[AuthSec] appName: {app_name}")
    print(f"[AuthSec] host: {host}")
    print(f"[AuthSec] port: {port}")
    print(
        f"[AuthSec] auth service: {os.getenv('AUTHSEC_AUTH_SERVICE_URL', DEFAULT_AUTH_SERVICE_URL)}"
    )
    print(
        f"[AuthSec] services URL: {os.getenv('AUTHSEC_SERVICES_URL', DEFAULT_SERVICES_URL)}"
    )

    run_mcp_server_with_oauth(
        sys.modules[__name__],
        client_id=client_id,
        app_name=app_name,
        host=host,
        port=port,
    )


if __name__ == "__main__":
    main()
