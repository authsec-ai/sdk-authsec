# AuthSec Go SDK

Go SDK for protecting MCP Streamable HTTP servers with AuthSec OAuth, RBAC, tool inventory, and per-tool authorization.

Use this package when you already have an MCP HTTP handler and want AuthSec to own:

- OAuth protected-resource metadata
- `WWW-Authenticate` bearer challenges with `resource_metadata`
- JWT/JWKS validation and optional introspection
- principal hydration in `context.Context`
- `tools/list` filtering
- `tools/call` authorization
- tool inventory publishing into the AuthSec dashboard
- remote tool-to-scope policy fetching from AuthSec

The SDK does not call your upstream application APIs. Your MCP server should keep its own upstream credential, such as a GitHub App token or server-side PAT. The caller's bearer token should be an AuthSec access token only.

## Mental Model

There are three systems in the integration:

| System | Responsibility |
|---|---|
| Your MCP server | Serves MCP tools and executes work with its own upstream credential. |
| AuthSec | Handles OAuth, users, clients, scopes, RBAC, consent, resource-server setup, and policy state. |
| AuthSec Go SDK | Sits at the MCP boundary and enforces AuthSec decisions before `tools/list` and `tools/call` reach your server. |

The normal request flow is:

1. MCP client calls your MCP endpoint without a token.
2. SDK returns `401` with `WWW-Authenticate: Bearer resource_metadata="..."`.
3. Client reads the protected-resource metadata.
4. Client authenticates with AuthSec.
5. Client retries with an AuthSec access token.
6. SDK validates the token and enforces tool policy.
7. Your MCP handler receives the request only after authentication and authorization.

## Endpoints Expected From AuthSec

Use these placeholders throughout the guide:

- `<AUTHSEC_API_ORIGIN>`: public AuthSec API and OAuth issuer, for example `https://dev.api.authsec.dev`
- `<RESOURCE_SERVER_ORIGIN>`: public origin of your MCP server, for example `https://mcp.example.com`
- `<RESOURCE_URI>`: exact protected resource URI, usually `<RESOURCE_SERVER_ORIGIN>/mcp`

AuthSec must expose:

- `<AUTHSEC_API_ORIGIN>/.well-known/oauth-authorization-server`
- `<AUTHSEC_API_ORIGIN>/.well-known/openid-configuration`
- `<AUTHSEC_API_ORIGIN>/oauth/authorize`
- `<AUTHSEC_API_ORIGIN>/oauth/token`
- `<AUTHSEC_API_ORIGIN>/oauth/jwks`
- `<AUTHSEC_API_ORIGIN>/oauth/introspect`
- `<AUTHSEC_API_ORIGIN>/oauth/par`
- `<AUTHSEC_API_ORIGIN>/authsec/resource-servers`

Your MCP server, via this SDK, exposes protected-resource metadata:

- Root resource, `ResourceURI = https://mcp.example.com`: `/.well-known/oauth-protected-resource`
- Path resource, `ResourceURI = https://mcp.example.com/mcp`: `/.well-known/oauth-protected-resource/mcp`

Do not assume the bare well-known path for path-based resources. Use:

```go
authsecsdk.BuildResourceMetadataURL(cfg.ResourceURI)
```

## Quick Start

Install:

```bash
go get github.com/authsec-ai/sdk-authsec/packages/go-sdk
```

Wrap your MCP handler:

```go
package main

import (
	"log"
	"net/http"
	"time"

	authsecsdk "github.com/authsec-ai/sdk-authsec/packages/go-sdk"
)

func main() {
	mcpHandler := buildYourMCPHandler()

	cfg := authsecsdk.Config{
		Issuer:                    "<AUTHSEC_API_ORIGIN>",
		AuthorizationServer:       "<AUTHSEC_API_ORIGIN>",
		JWKSURL:                   "<AUTHSEC_API_ORIGIN>/oauth/jwks",
		IntrospectionURL:          "<AUTHSEC_API_ORIGIN>/oauth/introspect",
		IntrospectionClientID:     "<resource-server-id>",
		IntrospectionClientSecret: "<introspection-secret>",
		ResourceURI:               "<RESOURCE_SERVER_ORIGIN>/mcp",
		ResourceName:              "GitHub MCP Server",
		ResourceServerID:          "<resource-server-id>",
		SupportedScopes: []string{
			"repos:read",
			"repos:write",
			"issues:read",
			"issues:write",
			"pull_requests:read",
			"pull_requests:write",
			"actions:read",
			"actions:write",
			"security:read",
			"admin:write",
		},
		PolicyMode:     authsecsdk.PolicyModeRemoteWithLocalFallback,
		ValidationMode: authsecsdk.ValidationModeJWTAndIntrospect,
		ScopeMatrixTTL: 5 * time.Minute,

		// Recommended for production. This pushes tool inventory to AuthSec
		// so the setup wizard can show and map tools even when /mcp is protected.
		PublishManifest: true,
		ToolScopeSuggestions: map[string][]string{
			"search_repositories": {"repos:read"},
			"create_issue":        {"issues:write"},
		},

		// Optional local fallback used only when AuthSec policy is temporarily
		// unavailable and PolicyModeRemoteWithLocalFallback is selected.
		ToolScopes: authsecsdk.ToolScopeMap{
			"search_repositories": {"repos:read"},
			"create_issue":        {"issues:write"},
		},
	}

	mux := http.NewServeMux()
	if err := authsecsdk.MountMCP(mux, "/mcp", mcpHandler, cfg); err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

`MountMCP` registers both:

- the protected-resource metadata route derived from `ResourceURI`
- the protected MCP route, for example `/mcp`

## Step 1: Create The Resource Server In AuthSec

In the AuthSec dashboard, create a resource server:

- `Name`: human-readable name, for example `GitHub MCP Server`
- `Public base URL`: `<RESOURCE_SERVER_ORIGIN>`
- `Protected base path`: `/mcp`
- `Supported scopes`: the OAuth scopes users may receive for this server
- `Registration modes`: usually `dcr`, `prereg`, and `cimd`

Example supported scopes for a GitHub MCP server:

```text
repos:read
repos:write
issues:read
issues:write
pull_requests:read
pull_requests:write
actions:read
actions:write
security:read
admin:write
```

AuthSec computes:

```text
resource_uri = public_base_url + protected_base_path
```

For example:

```text
https://mcp.example.com/mcp
```

Save the values AuthSec returns:

- resource server `id`
- `resource_url`
- `jwks_uri`
- `introspection_endpoint`
- one-time `introspection_secret`
- `scopes_supported`

The plaintext `introspection_secret` is returned once. If you lose it, rotate it in AuthSec and update the MCP server config.

API equivalent:

```bash
curl -X POST '<AUTHSEC_API_ORIGIN>/authsec/resource-servers' \
  -H 'Authorization: Bearer <admin_jwt>' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "GitHub MCP Server",
    "public_base_url": "<RESOURCE_SERVER_ORIGIN>",
    "protected_base_path": "/mcp",
    "scopes_supported": [
      "repos:read",
      "repos:write",
      "issues:read",
      "issues:write",
      "pull_requests:read",
      "pull_requests:write",
      "actions:read",
      "actions:write",
      "security:read",
      "admin:write"
    ],
    "registration_modes": ["dcr", "prereg", "cimd"]
  }'
```

## Step 2: Configure The SDK

Use the AuthSec resource server values directly:

| SDK field | Value |
|---|---|
| `Issuer` | JWT issuer, normally `<AUTHSEC_API_ORIGIN>` |
| `AuthorizationServer` | AuthSec base used for metadata and SDK admin calls |
| `JWKSURL` | `<AUTHSEC_API_ORIGIN>/oauth/jwks` |
| `IntrospectionURL` | `<AUTHSEC_API_ORIGIN>/oauth/introspect` |
| `IntrospectionClientID` | the AuthSec resource server UUID |
| `IntrospectionClientSecret` | the resource server introspection secret |
| `ResourceURI` | exact AuthSec `resource_uri` |
| `ResourceName` | display name shown in metadata |
| `ResourceServerID` | the same resource server UUID |
| `SupportedScopes` | same list as AuthSec `scopes_supported` |

Important:

- `IntrospectionClientID` is the resource server ID.
- `ResourceURI` must exactly match the AuthSec resource URI and the JWT audience.
- `AuthorizationServer` is also used for SDK calls like `/authsec/resource-servers/<id>/sdk-policy` and `/sdk-manifest`.
- `SupportedScopes` should not contain GitHub PAT scopes like `repo` or `workflow`; use the product scopes you created in AuthSec, such as `repos:read` and `actions:write`.

## Step 3: Publish Tool Inventory

AuthSec needs tool inventory before admins can map tools to scopes and activate the resource server.

There are three ways to populate inventory:

1. SDK manifest publish: recommended for protected MCP servers.
2. Authenticated scan: admin provides a token and AuthSec calls `tools/list`.
3. Manual entry: admin creates tools in the dashboard.

For production, prefer SDK manifest publish:

```go
cfg.PublishManifest = true
```

When `PublishManifest` is true, `MountMCP` and `WrapMCPHTTP` call `PublishManifest` in the background. The SDK sends:

```text
PUT <AUTHSEC_API_ORIGIN>/authsec/resource-servers/<resource-server-id>/sdk-manifest
Authorization: Basic base64(<resource-server-id>:<introspection-secret>)
```

The manifest contains:

```json
{
  "tools": [
    {
      "name": "search_repositories",
      "title": "Search repositories",
      "description": "Find GitHub repositories...",
      "input_schema": {},
      "annotations": {
        "readOnlyHint": true
      },
      "suggested_scopes": ["repos:read"]
    }
  ]
}
```

### Synthetic Enumeration

By default, the SDK enumerates tools from the unwrapped MCP handler:

1. `initialize`
2. `notifications/initialized`
3. paginated `tools/list`

This bypasses the AuthSec wrapper but still goes through your inner MCP handler. It works for most HTTP MCP servers.

### ToolInventoryProvider

Use `ToolInventoryProvider` when synthetic enumeration does not fit your server, for example:

- your handler requires custom internal auth even before AuthSec wrapping
- your MCP server uses a router that does not behave correctly under `httptest`
- your inventory is static and available from an internal registry
- you want exact suggested scopes per tool

Example:

```go
cfg.PublishManifest = true
cfg.ToolInventoryProvider = func() ([]authsecsdk.ManifestTool, error) {
	return []authsecsdk.ManifestTool{
		{
			Name:            "search_repositories",
			Description:     "Find repositories by name, topic, or metadata.",
			SuggestedScopes: []string{"repos:read"},
		},
		{
			Name:            "create_issue",
			Description:     "Create a GitHub issue.",
			SuggestedScopes: []string{"issues:write"},
		},
	}, nil
}
```

If a provider tool has `SuggestedScopes`, those suggestions are published as-is. If not, the SDK falls back to `ToolScopeSuggestions[tool.Name]`.

### ToolScopeSuggestions vs ToolScopes

These fields are intentionally different:

| Field | Purpose |
|---|---|
| `ToolScopeSuggestions` | Admin-facing suggestions sent in the SDK manifest. They are advisory only. |
| `ToolScopes` | Runtime local fallback policy used by the SDK when configured. |

Suggested scopes do not grant access by themselves. In AuthSec, admins still need to apply mappings or explicitly mark tools public before activation.

## Step 4: Configure Tool Policy In AuthSec

After the server starts, check the Resource Server onboarding wizard:

1. Register: resource server exists.
2. Tool inventory: tools arrived through SDK manifest or scan.
3. Define scopes: scopes exist.
4. Map tools to scopes: every non-public tool has at least one effective mapping.
5. Default role: default access policy grants at least one scope.
6. Activate: resource server can be moved to `ready`.

For SDK manifest tools:

- `suggested_scopes` are displayed as suggestions.
- Runtime policy only uses effective admin mappings.
- Suggested mappings should not be treated as grants until accepted by an admin.
- If a tool should require no scope, mark it public intentionally.

When the resource server is not `ready`, `/sdk-policy` returns `policy_complete=false`; the SDK treats this as deny-all for remote policy.

## Step 5: Runtime Enforcement

At startup the SDK fetches policy:

```text
GET <AUTHSEC_API_ORIGIN>/authsec/resource-servers/<resource-server-id>/sdk-policy
Authorization: Basic base64(<resource-server-id>:<introspection-secret>)
```

Expected response:

```json
{
  "state": "ready",
  "policy_complete": true,
  "rs_id": "<resource-server-id>",
  "generation": 12,
  "tool_policy": [
    {
      "name": "search_repositories",
      "is_public": false,
      "required_scopes": ["repos:read"]
    }
  ],
  "ttl_seconds": 300
}
```

The `tool_policy` array is authoritative.

Runtime behavior:

- `tools/list`: SDK filters the server response to tools the caller can see.
- `tools/call`: SDK blocks unauthorized tool calls before they reach your handler.
- unknown tool in policy mode: denied.
- explicitly public tool: allowed for any valid AuthSec token.
- policy unavailable and no usable cache: HTTP 503.
- insufficient scope: HTTP 403 with `WWW-Authenticate: Bearer error="insufficient_scope"`.

## Policy Modes

| Mode | Behavior |
|---|---|
| `PolicyModeRemoteRequired` | Fetch AuthSec policy. Startup fails unless initial fetch succeeds, except when `PublishManifest=true` and the RS is still being set up. |
| `PolicyModeRemoteWithLocalFallback` | Prefer AuthSec policy. If unavailable, use `ToolScopes`. Requires non-nil `ToolScopes`. |
| `PolicyModeLocalOnly` | Use only local `ToolScopes`. |
| `PolicyModeOpen` | No per-tool authorization; any valid AuthSec token can call tools. |

Recommended production default:

```go
PolicyMode: authsecsdk.PolicyModeRemoteWithLocalFallback
```

Use `PolicyModeRemoteRequired` after onboarding if you want the server to hard-fail when AuthSec policy cannot be fetched.

## Validation Modes

| Mode | Behavior |
|---|---|
| `ValidationModeJWTAndIntrospect` | JWT-shaped tokens must pass JWKS verification, then introspection. Opaque tokens use introspection. Recommended. |
| `ValidationModeJWTOrIntrospect` | Either JWT verification or introspection may pass. Use only for migration. |
| `ValidationModeJWTOnly` | JWKS validation only; revocation visibility is bounded by token lifetime. |
| `ValidationModeIntrospectionOnly` | Introspection only. |

Recommended:

```go
ValidationMode: authsecsdk.ValidationModeJWTAndIntrospect
```

Security note: in `ValidationModeJWTAndIntrospect`, introspection cannot rescue a JWT-shaped token that fails local signature verification.

## Principal Context

After validation, the SDK stores the AuthSec principal in the request context:

```go
principal, ok := authsecsdk.PrincipalFromContext(r.Context())
if ok {
	log.Printf("subject=%s scopes=%v", principal.Subject, principal.Scopes)
}
```

Use this for audit logs, tenant routing, or application-level context. Do not use it to bypass SDK authorization.

## Manual Wiring

Use `MountMCP` unless you need custom router behavior.

If you use `WrapMCPHTTP` directly, also mount metadata:

```go
rt, err := authsecsdk.NewRuntime(cfg)
if err != nil {
	log.Fatal(err)
}

protected := rt.Wrap(mcpHandler)

mux.Handle(authsecsdk.BuildResourceMetadataPath(cfg.ResourceURI), rt.ProtectedResourceHandler())
mux.Handle("/mcp", protected)
```

Omitting protected-resource metadata breaks OAuth discovery for MCP clients.

## Verification Checklist

### 1. Metadata

```bash
curl -i '<RESOURCE_SERVER_ORIGIN>/.well-known/oauth-protected-resource/mcp'
```

Expected:

- `200 OK`
- JSON includes `resource: "<RESOURCE_URI>"`
- JSON includes `authorization_servers: ["<AUTHSEC_API_ORIGIN>"]`

### 2. Unauthenticated Challenge

```bash
curl -i -X POST '<RESOURCE_SERVER_ORIGIN>/mcp' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

Expected:

- `401 Unauthorized`
- `WWW-Authenticate` contains `Bearer`
- `WWW-Authenticate` contains `resource_metadata=`

### 3. SDK Manifest

In AuthSec:

- Resource Server -> Onboarding -> Tool inventory
- or `GET /authsec/resource-servers/<id>/sdk-manifest-status`

Expected:

- `never_seen=false`
- latest attempt `status=success`
- `tool_count > 0`

### 4. Scope Matrix

Expected after manifest publish:

- tools visible in the matrix
- suggestions visible for tools that published `suggested_scopes`
- activation still blocked until mappings are effective

### 5. Authorized Tool List

With a valid token that only resolves to `repos:read`:

- read-only repository tools are visible
- write tools are hidden

### 6. Unauthorized Tool Call

Call a write tool with a read-only token.

Expected:

- HTTP 403
- `WWW-Authenticate` includes `insufficient_scope`

## Common Failure Modes

### AuthSec shows zero tools

Likely causes:

- `PublishManifest` is false.
- `ToolInventoryProvider` returns an empty list.
- synthetic enumeration cannot call your inner MCP handler.
- `IntrospectionClientID` or secret is wrong, so `/sdk-manifest` returns 401.
- `AuthorizationServer` points to the wrong AuthSec origin.
- the server was deployed before the SDK manifest code ran.

Fix:

- enable `PublishManifest`
- check server logs for `manifest publish failed`
- check `/sdk-manifest-status`
- use `ToolInventoryProvider` for static inventory or custom routing

### Protected unauthenticated scan returns success but zero tools

This is expected only for the background registration probe of a correctly protected MCP server. AuthSec cannot list tools anonymously when your MCP server returns `401`. An operator-triggered **Refresh Tools** requires a successful live `tools/list`; the console asks for a one-shot bearer token when the server challenges the scan. Since that token can receive a scope-filtered tool list, authenticated refresh merges visible tools without deleting unseen inventory. The SDK manifest remains the authoritative complete snapshot.

### Tools appear but activation is blocked

Inventory is present, but one or more gates are incomplete:

- tools are unmapped
- scopes do not exist
- default access role grants no scopes
- non-public tools have only suggestions, not effective mappings

Apply suggested mappings or manually map each tool to at least one scope, then activate.

### `tools/list` returns no tools for a user

Likely causes:

- resource server is not `ready`
- user has no role binding
- role has permissions, but permissions are not linked to OAuth scopes
- requested OAuth scope does not intersect with user effective scopes
- token audience does not match `ResourceURI`

AuthSec effective scopes are:

```text
requested_scopes ∩ resource_server.scopes_supported ∩ user_effective_scopes
```

### Startup fails fetching policy

If the resource server is still in onboarding, either:

- set `PublishManifest=true`, so the SDK can start while policy is incomplete
- or use `PolicyModeRemoteWithLocalFallback` with non-nil `ToolScopes`

### Metadata path is 404

Check `ResourceURI`.

- `https://mcp.example.com/mcp` -> `/.well-known/oauth-protected-resource/mcp`
- `https://mcp.example.com` -> `/.well-known/oauth-protected-resource`

## Production Checklist

- Resource server exists in AuthSec.
- `ResourceURI` exactly matches the public MCP endpoint and token audience.
- `IntrospectionClientID` is the resource server ID.
- `IntrospectionClientSecret` is stored securely.
- `SupportedScopes` matches AuthSec `scopes_supported`.
- `PublishManifest=true`.
- `ToolScopeSuggestions` or `ToolInventoryProvider` provides sensible suggestions.
- Every non-public tool is mapped in AuthSec before activation.
- Default access policy grants at least one useful scope.
- `ValidationModeJWTAndIntrospect` is used unless there is a specific reason not to.
- Server logs manifest publish success on startup.
- `/sdk-manifest-status` shows success.
- `tools/list` and `tools/call` are tested with read-only and write-capable users.

## Development Example

For the current dev environment:

```text
AUTHSEC_API_ORIGIN=https://dev.api.authsec.dev
RESOURCE_SERVER_ORIGIN=https://20-106-226-245.sslip.io
RESOURCE_URI=https://20-106-226-245.sslip.io/mcp
```

Metadata URL:

```text
https://20-106-226-245.sslip.io/.well-known/oauth-protected-resource/mcp
```

Protected MCP endpoint:

```text
https://20-106-226-245.sslip.io/mcp
```

AuthSec SDK policy:

```text
https://dev.api.authsec.dev/authsec/resource-servers/<resource-server-id>/sdk-policy
```

SDK manifest:

```text
https://dev.api.authsec.dev/authsec/resource-servers/<resource-server-id>/sdk-manifest
```

## Client-Side Error Handling (Agent Side)

The `client` sub-package (`client/errors.go`) provides typed, actionable error helpers for code *calling* an AuthSec-protected MCP server. Use `ParseMCPError` to translate raw 401/403 responses into structured errors, and `ToolErrorHandler` to convert any tool-call error into an LLM-readable string:

```go
import "github.com/authsec-ai/sdk-authsec/packages/go-sdk/client"

// In your agent's tool-call loop:
msg := client.ToolErrorHandler(err)
// msg is always a non-empty, LLM-readable string
```

## Bearer-Token Separation

AuthSec bearer tokens authenticate the *agent* to the AuthSec authorization layer. If the MCP server itself requires a separate upstream credential (e.g. a GitHub PAT, Slack bot token, or database password), that credential must live as a server-owned environment variable (e.g. `UPSTREAM_API_TOKEN`) — **never in the same `Authorization` header** as the AuthSec token. The SDK enforces this by never forwarding the caller's bearer to upstream services.

## What You Should Not Build Yourself

When using this SDK, do not separately implement:

- OAuth protected-resource metadata
- bearer challenge construction
- AuthSec JWT parsing
- introspection calls
- `tools/list` filtering middleware
- `tools/call` scope checks
- SDK manifest upload logic

Keep your MCP server focused on MCP tools and upstream execution. Let AuthSec and the SDK own identity, OAuth, RBAC, consent, inventory, and enforcement at the boundary.
