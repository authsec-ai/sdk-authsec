# AuthSec Python SDK

OAuth + RBAC protection for MCP servers, and delegated token acquisition for AI agents.

One SDK, two sides of the same protocol:

| You are building | You need | Start here |
|---|---|---|
| An **agent** that calls a protected MCP server | A token (M2M or on-behalf-of a user via ID-JAG) | [Agent side](#agent-side--get-a-token) |
| An **MCP server** that must be protected | Token validation + per-tool RBAC | [Server side](#server-side--protect-your-mcp-server) |

```bash
pip install authsec-sdk
```

Requires Python ≥ 3.10. Fully typed (`py.typed` shipped — mypy/pyright see all hints).

---

## Package layout

The package is organized by function:

```
authsec_sdk/
├── identity/        # AGENT SIDE — get tokens
│   ├── agent.py     #   AgentIdentity (M2M + XAA/ID-JAG), browser_login,
│   │                #   poll_until_approved
│   └── spiffe.py    #   SpiffeWorkloadIdentity (JWT-SVID → Bearer token)
├── runtime/         # SERVER SIDE — protect an MCP server
│                    #   mount_mcp, Config, from_env, HybridValidator,
│                    #   ScopeMatrixClient, publish_manifest, PRM (RFC 9728)
├── client/          # typed errors for parsing AuthSec 401/403 responses
├── integrations/    # framework glue (LangGraph)
├── spiffe/          # SPIFFE Workload API — X.509-SVIDs, mTLS material
├── ciba.py          # CIBA push / TOTP authentication
├── delegation.py    # delegation-token client
├── _legacy/         # original decorator API (back-compat only)
└── cli.py           # `authsec` CLI (init / config show / doctor)
```

## Import options

**Option 1 — top level (recommended for 95% of use).** Everything commonly
needed is re-exported from `authsec_sdk` directly:

```python
from authsec_sdk import (
    # agent side
    AgentIdentity, browser_login, poll_until_approved,
    PendingApprovalError, ApprovalDeniedError,
    SpiffeWorkloadIdentity, SpiffeConfig,
    # server side
    mount_mcp, Config, from_env, Runtime, ManifestTool,
    # misc
    CIBAClient, DelegationClient, parse_mcp_error,
)
```

**Option 2 — by subpackage.** Same objects, explicit origin. Useful in larger
codebases where import provenance matters:

```python
from authsec_sdk.identity import AgentIdentity, browser_login
from authsec_sdk.runtime import mount_mcp, Config, from_env
from authsec_sdk.client import parse_mcp_error, TokenRevokedError
from authsec_sdk.integrations import wrap_for_langgraph   # ← only home of this one
from authsec_sdk.spiffe import QuickStartSVID, WorkloadAPIClient
from authsec_sdk.ciba import CIBAClient
from authsec_sdk.delegation import DelegationClient
```

Both options reference the **same objects** — `authsec_sdk.AgentIdentity is
authsec_sdk.identity.AgentIdentity` is `True`. Pick per taste.

**Option 3 — deprecated paths (existing code only).** These still work but emit
a `DeprecationWarning` and will be removed in v5:

| Deprecated | Use instead |
|---|---|
| `authsec_sdk.agent_identity` | `authsec_sdk.identity` (or top level) |
| `authsec_sdk.spiffe_identity` | `authsec_sdk.identity` (or top level) |
| `authsec_sdk.core` | top level / `authsec_sdk.runtime` |
| `authsec_sdk.ciba_sdk` | `authsec_sdk.ciba` |
| `authsec_sdk.delegation_sdk` | `authsec_sdk.delegation` |
| `authsec_sdk.spire_sdk` | `authsec_sdk.spiffe` |
| `authsec_sdk.spiffe_workload_api` (+ `.client`, `.simple`, `.api`) | `authsec_sdk.spiffe` |
| `authsec_sdk.client.langgraph` | `authsec_sdk.integrations` |

No action is required today — old imports keep working through v4.

---

## Agent side — get a token

### On behalf of a user (XAA / ID-JAG delegation)

The common case: a chatbot/copilot acting for a logged-in user.

```python
import asyncio
from authsec_sdk import (
    AgentIdentity, browser_login,
    PendingApprovalError, ApprovalDeniedError, poll_until_approved,
)

ISSUER  = "https://mcpauthz.com"
MCP_URL = "https://your-mcp-server.example.com/mcp"

async def main():
    # 1. User identity. CLI/desktop: browser_login opens a PKCE flow.
    #    Web apps: skip this — pass the id_token from your own OIDC login.
    id_token = await browser_login(
        issuer=ISSUER, client_id="YOUR_AGENT_CLIENT_ID", resource=MCP_URL,
    )

    # 2. Agent identity — one instance per process, reuse it.
    agent = AgentIdentity(
        issuer=ISSUER,
        client_id="YOUR_AGENT_CLIENT_ID",
        client_secret="YOUR_AGENT_CLIENT_SECRET",
        idp_issuer=ISSUER,
    )

    # 3. Token for the MCP server, delegated from the user.
    async with agent:
        try:
            token = await agent.access_for(
                MCP_URL,
                user_session={"subject_token": id_token},
                requested_scopes=["mcp:tools:read"],
            )
        except PendingApprovalError as e:
            # First-time access — an admin must approve in the AuthSec portal.
            token = await poll_until_approved(
                agent, MCP_URL, e.status_url,
                user_session={"subject_token": id_token},
                requested_scopes=["mcp:tools:read"],
            )
        except ApprovalDeniedError:
            raise SystemExit("Admin declined access.")

    # token → Authorization: Bearer {token} on MCP requests.
    # Claims: sub = the user, act.client_id = this agent (auditable delegation).

asyncio.run(main())
```

What `access_for()` does internally — you never handle any of this:
discovery (PRM → AS metadata), `requester-bootstrap` flow decision,
token-exchange → **ID-JAG** → jwt-bearer, token caching until expiry.

Things worth knowing:

- **Caching** — `access_for()` is cheap to call repeatedly; it returns the
  cached token until near expiry. On a 401 from the MCP server, call
  `agent.clear_cache(MCP_URL)` and retry once.
- **Scopes must exist on the target server** (see its
  `/.well-known/oauth-protected-resource` document, `scopes_supported`).
  Requesting unknown scopes is indistinguishable from "waiting for approval".
- **`preferred_mode`** (`"auto"` default | `"direct-only"` | `"xaa-allowed"`):
  leave on `auto`. `direct-only` skips delegation entirely (pure M2M
  services); `xaa-allowed` hard-errors instead of silently downgrading to
  M2M when the bootstrap endpoint is unreachable.

### As itself (M2M, no user) — three authentication methods

A machine can prove its identity to AuthSec in three ways. All three end at
the same place (an access token); they differ in how the machine
authenticates:

| Method | Class | How it proves identity | Secret on the wire? |
|---|---|---|---|
| Client secret | `ClientSecretAuth` | ID + shared secret (HTTP Basic) | ⚠️ every request |
| Private-key JWT | `PrivateKeyJwtAuth` | Signs an RFC 7523 assertion with its private key | ✅ never — key stays local |
| SPIFFE SVID | `SpiffeSvidAuth` / `SpiffeWorkloadIdentity` | Platform-attested workload identity (SPIRE) | ✅ no stored credential at all |

```python
from authsec_sdk import (
    AgentIdentity, ClientSecretAuth, PrivateKeyJwtAuth, SpiffeSvidAuth,
)

# 1. Client secret — simple deployments
agent = AgentIdentity(ISSUER, CLIENT_ID, auth=ClientSecretAuth("sk-..."))
# (shorthand also works: AgentIdentity(ISSUER, CLIENT_ID, client_secret="sk-..."))

# 2. Private-key JWT — enterprise / secret-averse security postures.
#    PEM string or path to a .pem file; kid = key ID registered in the portal.
agent = AgentIdentity(ISSUER, CLIENT_ID,
                      auth=PrivateKeyJwtAuth("private_key.pem", kid="key-1"))

# 3. SPIFFE SVID (low-level) — when you already hold a JWT-SVID
agent = AgentIdentity(ISSUER, CLIENT_ID, auth=SpiffeSvidAuth(svid))
#    Inside Kubernetes, prefer SpiffeWorkloadIdentity instead — it fetches
#    and renews SVIDs from the SPIRE agent automatically (see SPIFFE section).

async with agent:
    token = await agent.access_for(MCP_URL,
                                   requested_scopes=["mcp:tools:read"])
```

Security ladder: 1 → 2 → 3 goes from "shared password" to "asymmetric keys"
to "no stored credential — the infrastructure vouches for the workload".
Each private-key assertion is 5-minute, single-use (random ``jti``), and
audience-bound to the token endpoint, so interception is useless.

#### Portal setup per method

All three need a **service account** in the AuthSec portal with an **access
assignment** (role + scopes) for your target resource server. Without the
assignment, authentication succeeds but every token request fails with
`access_denied: client not authorized for this resource server`.

**Client secret** — create the service account, copy the generated secret
(64 hex chars — copy-paste it, don't retype), assign access. Done.

**Private-key JWT** — generate a keypair and register the public key:

```bash
# 1. generate the pair
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

```python
# 2. build the JWKS from the public key (one-time)
from cryptography.hazmat.primitives import serialization
import base64, json

pub = serialization.load_pem_public_key(open("public_key.pem", "rb").read())
n = pub.public_numbers().n
e = pub.public_numbers().e
b64u = lambda i, l: base64.urlsafe_b64encode(i.to_bytes(l, "big")).rstrip(b"=").decode()
print(json.dumps({"keys": [{
    "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "key-1",
    "n": b64u(n, (n.bit_length() + 7) // 8), "e": b64u(e, 3),
}]}, indent=2))
```

3. In the portal, register the JWKS for the service account — either paste
   the JSON directly, or host it and set a `jwks_uri`. **The URI must return
   raw JSON**, not an HTML page: a GitHub gist works only via its
   `gist.githubusercontent.com/.../raw/...` URL — the regular
   `gist.github.com/...` page URL serves HTML and breaks verification.
4. The `kid` you pass to `PrivateKeyJwtAuth(..., kid=...)` must match the
   `kid` in the registered JWKS.

**SPIFFE SVID** — register a workload client with your exact `spiffe_id` and
the trust domain's JWKS. The SVID's **audience must be the AuthSec token
endpoint** (e.g. `https://mcpauthz.com/oauth/token`) — an SVID minted with
only the issuer as audience is rejected. `SpiffeWorkloadIdentity` handles
this automatically; only low-level `SpiffeSvidAuth` users minting their own
SVIDs need to care.

#### M2M troubleshooting

Real error → cause → fix:

| Error (from `access_for()`) | Cause | Fix |
|---|---|---|
| `invalid_client: invalid client secret` | Wrong/rotated secret (often a copy-paste typo — secrets are 64 hex chars) | Re-copy from the portal |
| `access_denied: client not authorized for this resource server` | Credentials are **valid**, but the service account has no access assignment for this resource server | Portal → service account → assign role + scopes for the target RS |
| `invalid_client: JWKS resolution failed: parse JWKS: invalid character '<'` | The registered `jwks_uri` returns HTML, not JSON (classic: gist page URL instead of raw URL) | Point `jwks_uri` at raw JSON, or paste the JWKS into the portal |
| `invalid_client: token aud must include this token endpoint` | SVID minted with the wrong audience | Mint with `audience = <issuer>/oauth/token` |
| `invalid_client: ... token is expired` | JWT-SVIDs live ~5 minutes | Mint immediately before use, or use `SpiffeWorkloadIdentity` (auto-renews) |

### Which client type do I register in the portal?

`AgentIdentity` handles both delegation (XAA) and plain M2M — but the
**portal registration decides what the server allows** for your client
(`client_kind` in the bootstrap response). Match the registration to the
flow you need:

| You register (portal) | `client_kind` | Server permits |
|---|---|---|
| **Agent** | `agent` | Delegation (XAA/ID-JAG, with `user_session`); plain M2M only if a service account is linked to it |
| **Service account** | service | Direct M2M (`client_credentials`) — secret or private-key JWT |
| **Kubernetes workload** | workload | Direct M2M via SPIFFE SVID assertion |

Symptom of a mismatch: an *agent*-registered client calling `access_for()`
**without** a `user_session` fails with
``CredentialInvalidError: no service account linked to this client`` — the
fix is to register a service account (or link one to the agent), not to
change SDK code.

### From a Kubernetes workload (SPIFFE)

```python
from authsec_sdk import SpiffeWorkloadIdentity, SpiffeConfig

spiffe = SpiffeWorkloadIdentity(SpiffeConfig(
    mcp_server_url=MCP_URL,
    client_id="YOUR_SPIFFE_CLIENT_ID",
    spiffe_id="spiffe://your-domain/your-workload",
    scopes=["mcp:tools:read"],
))
async with spiffe:
    token = await spiffe.access_for()   # JWT-SVID from SPIRE agent → Bearer token
```

See the dedicated [SPIFFE / SPIRE](#spiffe--spire) section for prerequisites
and the X.509/mTLS side.

---

## Server side — protect your MCP server

```python
import os
from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP
from authsec_sdk import from_env, mount_mcp, ManifestTool
from dotenv import load_dotenv

mcp = FastMCP("my-server")

@mcp.tool()
def add_no(a: float, b: float) -> float:
    return a + b

@mcp.tool()
def multiply_no(a: float, b: float) -> float:
    return a * b

def my_tools():
    return [
        ManifestTool(
            name="add_no",
            description="Add two numbers",
            input_schema={
                "type": "object",
                "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
                "required": ["a", "b"],
            },
        ),
        ManifestTool(
            name="multiply_no",
            description="Multiply two numbers",
            input_schema={
                "type": "object",
                "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
                "required": ["a", "b"],
            },
        ),
    ]

load_dotenv()
cfg = from_env()                       # reads AUTHSEC_* env vars (below)
cfg.tool_inventory_provider = my_tools # explicit manifest (optional, see note)

app = FastAPI()
mount_mcp(app, "/mcp", mcp, cfg)       # FastMCP instances are auto-detected
```

Run it: `uvicorn server:app --host 0.0.0.0 --port 8000`

> **Note — `tool_inventory_provider` is optional.** If you omit it, the SDK
> enumerates your tools automatically at startup by performing a synthetic
> MCP handshake (`initialize` → `tools/list`) against your own handler, so
> the schemas come straight from your `@mcp.tool()` type hints — one source
> of truth. Set it explicitly (as above) when you want a deterministic,
> hand-curated manifest.

`handler` (third argument to `mount_mcp`) accepts three forms:

1. A **FastMCP instance** — auto-detected, wrapped for you (shown above).
2. A plain **request handler** — `async def handler(request) -> Response`,
   your existing hand-written MCP route.
3. Any **ASGI app** — `mount_mcp(app, "/mcp", wrap_asgi_handler(asgi_app), cfg)`.

What `mount_mcp` gives you:

- `401` + RFC 6750/9728 `WWW-Authenticate` challenge on missing/bad tokens
- `/.well-known/oauth-protected-resource/mcp` (PRM) served automatically,
  with `scopes_supported` synced live from the AuthSec portal
- Per-tool scope enforcement on `tools/call`, and `tools/list` responses
  filtered to what the caller's scopes allow
- Tool **manifest publishing** at startup (`AUTHSEC_PUBLISH_MANIFEST=true`) —
  your tools appear in the portal for an admin to assign scopes; changes
  propagate to your running server within ~30 s, no redeploy

### How tools get protected (no code per tool)

```
your server boots ──publishes manifest──▶ AuthSec portal shows your tools
                                              │  admin assigns scopes per tool
your server polls ◀──scope matrix (30s)──────┘  and publishes the policy
     └─▶ enforces:  tools/call add_no  needs  mcp:tools:read
```

Until the admin completes setup the policy endpoint reports
`state: needs_setup` — with `AUTHSEC_POLICY_MODE=remote_required` the SDK
**fails closed** (denies all tool calls) rather than guessing. That is the
recommended production mode.

### Environment variables (`from_env()`)

```bash
AUTHSEC_ISSUER=https://mcpauthz.com
AUTHSEC_AUTHORIZATION_SERVER=https://mcpauthz.com
AUTHSEC_JWKS_URL=https://mcpauthz.com/oauth/jwks
AUTHSEC_INTROSPECTION_URL=https://mcpauthz.com/oauth/introspect
AUTHSEC_INTROSPECTION_CLIENT_ID=<resource-server-uuid>
AUTHSEC_INTROSPECTION_CLIENT_SECRET=<sec_...>
AUTHSEC_RESOURCE_SERVER_ID=<resource-server-uuid>
AUTHSEC_RESOURCE_URI=https://your-public-url/mcp
AUTHSEC_RESOURCE_NAME=my-server
AUTHSEC_POLICY_MODE=remote_required          # fail closed (recommended)
AUTHSEC_VALIDATION_MODE=jwt_and_introspect   # strict (recommended)
AUTHSEC_PUBLISH_MANIFEST=true
```

All values come from the AuthSec admin UI when you register the resource
server.

---

## SPIFFE / SPIRE

SPIFFE gives workloads (pods, VMs, containers) a cryptographic identity
(`spiffe://trust-domain/workload`) issued by a SPIRE server and delivered by
the SPIRE agent running on each node — no hardcoded secrets in the workload.

The SDK covers **two distinct SPIFFE use cases** — pick by what you need:

| You need | Class | Import | Credential type |
|---|---|---|---|
| A **Bearer token** to call a protected MCP server | `SpiffeWorkloadIdentity` | `authsec_sdk.identity` (or top level) | JWT-SVID → OAuth token |
| **X.509 certs / mTLS** between services | `QuickStartSVID`, `WorkloadAPIClient` | `authsec_sdk.spiffe` | X.509-SVID |

### Use case 1 — workload identity → MCP access token

The Kubernetes equivalent of `AgentIdentity`: instead of a client secret, the
workload proves who it is with a JWT-SVID from the local SPIRE agent, which
AuthSec exchanges for a scoped Bearer token.

```
SPIRE agent socket ──JWT-SVID──▶ AuthSec /oauth/token ──▶ Bearer token ──▶ MCP server
```

```python
from authsec_sdk import SpiffeWorkloadIdentity, SpiffeConfig

spiffe = SpiffeWorkloadIdentity(SpiffeConfig(
    mcp_server_url = "https://your-mcp-server.example.com/mcp",
    client_id      = "YOUR_SPIFFE_CLIENT_ID",     # registered in AuthSec portal
    spiffe_id      = "spiffe://your-domain/your-workload",
    scopes         = ["mcp:tools:read"],
    # agent_socket_path="/run/spire/sockets/agent.sock",  # default: /tmp/spire-agent/public/api.sock
))
async with spiffe:
    token = await spiffe.access_for()
    # cached until near expiry; call clear_cache() + retry on a 401
```

Prerequisites:

1. SPIRE agent running on the node, workload registered (a registration entry
   mapping your pod's selectors to the `spiffe_id`)
2. In the AuthSec portal: a SPIFFE client registered with that exact
   `spiffe_id` and the trust domain's JWKS configured
3. The token endpoint is auto-discovered from `mcp_server_url` (PRM → AS
   metadata) — no URL configuration needed

**Testing outside a pod:** pass `svid_override="<jwt-svid>"` in
`SpiffeConfig` with an SVID minted manually (e.g. via
`kubectl exec spire-agent -- /opt/spire/bin/spire-agent api fetch jwt ...`).
SVIDs are short-lived (~5 min) — mint fresh ones.

Errors are typed and actionable: `SpiffeSvidFetchError` (agent socket /
registration problems) and `SpiffeTokenExchangeError` (exchange rejected —
the message tells you whether it's a missing JWKS, unregistered SPIFFE ID,
audience mismatch, or no granted scopes).

### Use case 2 — X.509-SVIDs for mTLS

Infrastructure-level: fetch X.509 certificates from the Workload API for
mutual TLS between your own services (no AuthSec/OAuth involved).

```python
from authsec_sdk.spiffe import QuickStartSVID

svid = await QuickStartSVID.initialize()        # fetch + write certs + auto-renew (30 min)
print(svid.spiffe_id)

ssl_ctx = svid.create_ssl_context_for_server()  # or ..._for_client()
# use with uvicorn / httpx / aiohttp for mTLS
await QuickStartSVID.shutdown()                 # on process exit
```

For full control (streaming updates, JWT-SVID fetch/validate, trust bundles),
use the lower-level client:

```python
from authsec_sdk.spiffe import WorkloadAPIClient

client = WorkloadAPIClient(socket_path="unix:///run/spire/sockets/agent.sock")
await client.connect()
ok = await client.fetch_x509_svid_once()
if not ok:
    raise client.last_error            # typed cause: connection vs no-SVIDs vs protocol
```

> Naming note: `spiffe://...` IDs and SVIDs are **SPIFFE** (the standard);
> **SPIRE** is the reference implementation (server + agent) that issues
> them. The SDK talks to the SPIRE agent's Workload API socket.

## Error handling (agent side)

All identity errors are typed — catch what you can act on:

| Exception | Meaning | Action |
|---|---|---|
| `PendingApprovalError` | Access requested, admin approval pending | `poll_until_approved(...)` |
| `ApprovalDeniedError` | Admin declined | Inform user; don't retry |
| `ConnectionRevokedError` | Previously granted access was revoked | Re-request / inform |
| `CredentialInvalidError` | Bad client credentials | Fix config |
| `TrustedIssuerMissingError` | IdP not trusted by the AS | Portal setup |
| `ResourceNotRegisteredError` | MCP URL unknown to the AS | Register the RS |
| `AuthSecIdentityError` | Base class for all of the above | Catch-all |

For parsing errors the **MCP server** returns to a calling agent
(401/403 bodies, `WWW-Authenticate`), use `authsec_sdk.client`:

```python
from authsec_sdk.client import parse_mcp_error, TokenRevokedError

err = parse_mcp_error(response)          # Response | dict | str | Exception
if err is not None:
    print(err.format_for_user())
```

LangGraph users get this wired up in one line:

```python
from authsec_sdk.integrations import wrap_for_langgraph
tool_node = wrap_for_langgraph(tools)    # denials become readable LLM messages
```

---

## CLI

```bash
authsec init          # interactive setup — writes .authsec.json
authsec config show   # print current config
authsec doctor        # inspect cached JWTs (client_id, scopes, expiry)
```

## Examples

- `examples/protect_existing_mcp_server.py` — wrap an existing MCP handler
  with `mount_mcp` (server side, runnable)
- `examples/local_authsec_demo_server.py` — legacy decorator-API demo

## Development

```bash
cd packages/python-sdk
pip install -e ".[dev]"
pytest tests/test_runtime.py tests/test_config_flow.py   # unit tests
# tests/test_integration.py and tests/test_browser.py need live services
```

## Versioning

Current: **4.7.0** (adds the three M2M client-auth methods —
`ClientSecretAuth`, `PrivateKeyJwtAuth`, `SpiffeSvidAuth`). Deprecated
import paths (see table above) are kept throughout v4 and removed in v5.
