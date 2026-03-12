# AuthSec Python SDK (`authsec-sdk`)

Add OAuth + authorization enforcement to MCP tools.

## Install

```bash
python3 -m pip install authsec-sdk
```

Import path:

```python
from authsec_sdk import protected_by_AuthSec, run_mcp_server_with_oauth
```

Legacy import path is also supported in this release:

```python
from AuthSec_SDK import protected_by_AuthSec, run_mcp_server_with_oauth
```

## Trust Delegation SDK

Pull a delegated JWT-SVID for an AI agent and use it for downstream API calls.

```python
from authsec_sdk import DelegationClient


client = DelegationClient(
    client_id="YOUR_AGENT_CLIENT_ID",
    userflow_url="https://api.authsec.ai/uflow",
)

token_info = await client.pull_token()

if client.has_permission("users:read"):
    users = await client.request_json("GET", "https://api.example.com/users")
```

## Minimal Integration (your MCP server)

```python
from authsec_sdk import mcp_tool, protected_by_AuthSec, run_mcp_server_with_oauth


@mcp_tool(
    name="ping",
    description="Health check",
    inputSchema={"type": "object", "properties": {}, "required": []},
)
async def ping(arguments: dict) -> list:
    return [{"type": "text", "text": "pong"}]


@protected_by_AuthSec(
    tool_name="delete_invoice",
    permissions=["tool:delete_invoice"],  # optional; remove for auth-only
    require_all=True,
    description="Delete invoice",
    inputSchema={
        "type": "object",
        "properties": {
            "invoice_id": {"type": "string"},
            "session_id": {"type": "string"},
        },
        "required": ["invoice_id"],
    },
)
async def delete_invoice(arguments: dict) -> list:
    user = (arguments.get("_user_info") or {}).get("email_id", "unknown")
    return [{"type": "text", "text": f"Deleted {arguments.get('invoice_id')} by {user}"}]


if __name__ == "__main__":
    import __main__

    run_mcp_server_with_oauth(
        user_module=__main__,
        client_id="YOUR_CLIENT_ID",
        app_name="my-mcp-server",
        host="127.0.0.1",
        port=3005,
    )
```

## Run

```bash
python3 server.py
```

Default endpoints (production):
- Auth API: `https://prod.api.authsec.ai/sdkmgr/mcp-auth`
- Services API: `https://prod.api.authsec.ai/sdkmgr/services`

Optional endpoint overrides (self-hosted gateway):

```bash
export AUTHSEC_AUTH_SERVICE_URL="http://localhost:8000/sdkmgr/mcp-auth"
export AUTHSEC_SERVICES_URL="http://localhost:8000/sdkmgr/services"
python3 server.py
```

## Verify

```bash
npx @modelcontextprotocol/inspector http://127.0.0.1:3005
```

Flow:
- Call `oauth_start`
- Complete login in browser
- Call your protected tool with `session_id`

For browser auto-open from your local SDK server process:

```bash
export AUTHSEC_AUTO_OPEN_BROWSER=1
```

## Troubleshooting

- `ModuleNotFoundError: No module named 'authsec_sdk'`
  - You are using a different Python than the one where you installed the package. Use `python3 -m pip ...` and run with the same `python3`.
- `ModuleNotFoundError: No module named 'AuthSec_SDK'`
  - Upgrade to this release (`4.0.4+`) or use canonical import `authsec_sdk`.
- Server exits with cleanup event-loop error on Ctrl+C
  - Fixed in this release (`4.0.4+`).
- `oauth_start` returns `browser_opened: false`
  - Set `AUTHSEC_AUTO_OPEN_BROWSER=1` or call `oauth_start` with `{"open_browser": true}`.
- MCP Inspector shows `MCP error -32001: Request timed out`
  - Reduce upstream wait with `AUTHSEC_OAUTH_TOOL_TIMEOUT_SECONDS` (default `8`).
  - Example: `export AUTHSEC_OAUTH_TOOL_TIMEOUT_SECONDS=5`
- OAuth completes in browser but tool calls still unauthorized
  - Check `callback_url` in `oauth_start` response.
  - Recommended callback URI is `https://prod.api.authsec.ai/sdkmgr/mcp-auth/callback` (SDK Manager-hosted callback).
  - Local fallback `http://localhost:3005/oauth/callback` is also supported by this SDK server.

## Publishing (maintainer)

1. Set credentials:

```bash
export TWINE_USERNAME="__token__"
export TWINE_PASSWORD="pypi-..."
```

2. Build and upload:

```bash
cd /absolute/path/to/sdk-authsec/packages/python-sdk
python3 -m pip install --upgrade build twine
python3 -m build
python3 -m twine check dist/*
# Optional TestPyPI:
# python3 -m twine upload --repository testpypi dist/*
# Publish:
python3 -m twine upload dist/*
```
