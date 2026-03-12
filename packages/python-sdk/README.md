# AuthSec Python SDK (`authsec-sdk`)

AuthSec Python SDK covers:

- MCP OAuth + RBAC enforcement
- Trust delegation for AI agents
- Hosted service credential access
- CIBA / passwordless authentication
- SPIFFE workload identity helpers

## Install

```bash
python3 -m pip install -U authsec-sdk
```

From this repo during development:

```bash
python3 -m pip install -e packages/python-sdk
```

## Import Paths

Canonical package import:

```python
from authsec_sdk import protected_by_AuthSec, run_mcp_server_with_oauth
```

Trust delegation, top-level import:

```python
from authsec_sdk import DelegationClient
```

Trust delegation, direct submodule import:

```python
from authsec_sdk.delegation_sdk import (
    DelegationClient,
    DelegationError,
    DelegationTokenExpired,
    DelegationTokenNotFound,
)
```

Legacy compatibility shim:

```python
from AuthSec_SDK import protected_by_AuthSec, run_mcp_server_with_oauth
```

## MCP Quick Start

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
    permissions=["tool:delete_invoice"],
    require_all=True,
    description="Delete invoice by id",
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
    return [{"type": "text", "text": f"Deleted {arguments['invoice_id']} by {user}"}]


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

## Trust Delegation for Agents

Use trust delegation when an AI agent should pull a delegated JWT-SVID and gate its own tools from delegated permissions.

```python
from authsec_sdk import DelegationClient


client = DelegationClient(
    client_id="YOUR_AGENT_CLIENT_ID",
    userflow_url="https://prod.api.authsec.ai/uflow",
)

token_info = await client.pull_token()

if client.has_permission("users:read"):
    result = await client.request_json(
        "GET",
        "https://api.example.com/users",
    )
```

Available delegation surface:

- `pull_token()`
- `ensure_token()`
- `has_permission()`
- `has_any_permission()`
- `has_all_permissions()`
- `request()`
- `request_json()`
- `get_auth_header()`
- `decode_token_claims()`
- properties: `token`, `permissions`, `spiffe_id`, `is_expired`, `expires_in_seconds`, `client_id`

`request()` returns a buffered `DelegationHTTPResponse` with:

- `status`
- `headers`
- `body`
- `url`
- `ok`
- `text()`
- `json()`

Refresh behavior:

- If the cached token is near expiry, `ensure_token()` re-pulls it automatically.
- If a downstream request returns `401`, the client refreshes once and retries once.

Error behavior:

- `DelegationTokenNotFound`: no active delegation token for this client
- `DelegationTokenExpired`: server reports expired delegation
- `DelegationError`: network, parsing, or generic API failures

## Agent Compatibility Note

The compatibility benchmark for trust delegation is the external example agent at `/Users/pc/Downloads/generic_agent.py`.

This package is compatible with that style of usage:

- direct import from `authsec_sdk.delegation_sdk`
- permission checks via `has_permission()`
- token access via `ensure_token()`
- identity inspection via `decode_token_claims()`

Important:

- The SDK does not require any repo-local `sys.path` hack.
- A normal `pip install authsec-sdk` is sufficient.
- If your agent uses OpenAI, `openai` is an application dependency. It is not bundled with this SDK.

## Other Surfaces

Hosted service access:

```python
from authsec_sdk import ServiceAccessSDK
```

CIBA:

```python
from authsec_sdk import CIBAClient
```

SPIFFE:

```python
from authsec_sdk import QuickStartSVID, WorkloadAPIClient, WorkloadSVID
```

## Environment Variables

MCP SDK runtime:

- `AUTHSEC_AUTH_SERVICE_URL`
- `AUTHSEC_SERVICES_URL`
- `AUTHSEC_TIMEOUT_SECONDS`
- `AUTHSEC_RETRIES`
- `AUTHSEC_TOOLS_LIST_TIMEOUT_SECONDS`
- `AUTHSEC_OAUTH_TOOL_TIMEOUT_SECONDS`

Typical trust delegation app config:

- `CLIENT_ID`
- `USERFLOW_URL`
- `BASE_API_URL`

## Troubleshooting

- `ModuleNotFoundError: No module named 'authsec_sdk'`
  - Install the package into the same Python interpreter you use to run the app.
- `ModuleNotFoundError: No module named 'AuthSec_SDK'`
  - Upgrade to a current release or switch to the canonical `authsec_sdk` import path.
- `DelegationTokenNotFound`
  - No delegation exists yet for the agent client. An admin must delegate first.
- `DelegationTokenExpired`
  - Pull a fresh delegated token or have an admin renew the delegation.
- Downstream request fails after refresh
  - Inspect the downstream API, audience, and delegated permissions. The SDK retries only once after `401`.

## Publishing

```bash
cd /absolute/path/to/sdk-authsec/packages/python-sdk
python3 -m pip install --upgrade build twine
python3 -m build
python3 -m twine check dist/*
python3 -m twine upload dist/*
```
