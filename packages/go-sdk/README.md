# AuthSec Go SDK

Go package for turning an MCP HTTP server into an AuthSec-protected resource.

This SDK is wrapper-first. The developer should not have to hand-build:

- `/.well-known/oauth-protected-resource`
- MCP bearer challenges with `resource_metadata`
- JWT/JWKS validation
- introspection fallback
- principal hydration
- `tools/list` filtering
- `tools/call` authorization checks

The intended model is:

1. You register your MCP server as a Resource Server in AuthSec.
2. You wrap your MCP HTTP handler with this SDK.
3. MCP clients authenticate against AuthSec.
4. AuthSec users, scopes, RBAC, and consent live in the AuthSec console.
5. Your MCP server receives only AuthSec access tokens from clients and never uses those tokens as upstream API credentials.

## AuthSec endpoints

This package expects an AuthSec deployment that exposes:

- OAuth authorization server metadata
- OIDC discovery
- OAuth authorize and token endpoints
- JWKS and introspection
- resource server administration

Use the following placeholders throughout this guide:

- `<AUTHSEC_API_ORIGIN>` — public AuthSec API and OAuth/OIDC issuer host
- `<RESOURCE_SERVER_ORIGIN>` — public origin of the MCP server

The SDK expects AuthSec to expose:

- Authorization server metadata: `<AUTHSEC_API_ORIGIN>/.well-known/oauth-authorization-server`
- OIDC discovery: `<AUTHSEC_API_ORIGIN>/.well-known/openid-configuration`
- Authorize: `<AUTHSEC_API_ORIGIN>/oauth/authorize`
- Token: `<AUTHSEC_API_ORIGIN>/oauth/token`
- Introspection: `<AUTHSEC_API_ORIGIN>/oauth/introspect`
- JWKS: `<AUTHSEC_API_ORIGIN>/oauth/jwks`
- PAR: `<AUTHSEC_API_ORIGIN>/oauth/par`
- Resource server admin API: `<AUTHSEC_API_ORIGIN>/authsec/resource-servers`

The SDK owns the protected-resource metadata contract on your MCP server. The exact
path depends on the `ResourceURI`:

- **Root resource** (e.g. `https://mcp.example.com`): the SDK serves the metadata at
  `/.well-known/oauth-protected-resource` (bare path).
- **Path-based resource** (e.g. `https://mcp.example.com/mcp`): the SDK serves the
  metadata only at the path-derived alias `/.well-known/oauth-protected-resource/mcp`.
  The bare `/.well-known/oauth-protected-resource` path is **not** registered for
  path-based resources.

Use `BuildResourceMetadataURL(cfg.ResourceURI)` to compute the correct discovery URL
for your resource, rather than assuming the bare well-known path.

The `ResourceURI` value is the source of truth for the metadata payload and the
challenge target.

## What AuthSec owns vs what the SDK owns

### AuthSec owns

- login and identity provider flows
- OAuth/OIDC discovery and token issuance
- PAR-backed authorization
- DCR / preregistered client registration
- scopes, RBAC, and consent
- tool→scope mapping (Scope Matrix)
- JWKS and introspection with live RBAC resolution
- user and tenant administration
- auditability and policy control

### The SDK owns

- protected-resource metadata on your MCP server
- bearer challenge responses for unauthenticated MCP requests
- AuthSec token validation (JWT + introspection)
- principal creation and request context hydration
- tool visibility filtering on `tools/list` (using AuthSec's tool→scope mapping)
- tool call authorization on `tools/call` (using AuthSec's tool→scope mapping)

## What the package provides

This package is generic. It is not tied to a single MCP server implementation.

It currently provides:

- a high-level HTTP wrapper
- protected-resource metadata mounting
- hybrid JWT + introspection validation
- principal context injection
- tool authorization via AuthSec's scope matrix (remote fetch + cache)
- optional local tool→scope fallback for defense-in-depth

It does not include:

- server-specific bootstrap helpers
- CLI provisioning
- automatic admin-side resource server creation

Provisioning happens in AuthSec, then you point the SDK at the resulting values.

## Step 1: Register your MCP server in AuthSec

You can do this in the AuthSec UI or via the AuthSec admin API.

For example, for a GitHub MCP server at:

- public server origin: `<RESOURCE_SERVER_ORIGIN>`
- protected MCP endpoint: `<RESOURCE_SERVER_ORIGIN>/mcp`

use these values.

### In the AuthSec UI

Go to `Resource Servers` and create a new resource server with:

- `Name`: `GitHub MCP Server`
- `Public base URL`: `<RESOURCE_SERVER_ORIGIN>`
- `Protected base path`: `/mcp`
- `Supported scopes`:
  - `issues:read`
  - `issues:write`
  - `pull_requests:read`
  - `pull_requests:write`
  - `repos:read`
  - `repos:write`
  - `actions:read`
  - `actions:write`
  - `security:read`
  - `admin:write`
- `Registration modes`:
  - `dcr`
  - `prereg`
  - `cimd`

What this means:

- `Public base URL` is the public origin of your MCP server.
- `Protected base path` is the path the MCP protocol is actually served on.
- AuthSec computes the protected resource URI as:
  - `resource_uri = public_base_url + protected_base_path`
  - for this example: `<RESOURCE_SERVER_ORIGIN>/mcp`

After creation, AuthSec returns:

- `id` (resource server UUID — **save this for the SDK config**)
- `resource_url`
- `jwks_uri`
- `introspection_endpoint`
- `introspection_secret`
- `scopes_supported`

You need those values for the SDK config.

### Via the AuthSec admin API

The same setup can be created with:

```bash
curl -X POST '<AUTHSEC_API_ORIGIN>/authsec/resource-servers' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <admin_jwt>' \
  -d '{
    "name": "GitHub MCP Server",
    "public_base_url": "<RESOURCE_SERVER_ORIGIN>",
    "protected_base_path": "/mcp",
    "scopes_supported": [
      "issues:read",
      "issues:write",
      "pull_requests:read",
      "pull_requests:write",
      "repos:read",
      "repos:write",
      "actions:read",
      "actions:write",
      "security:read",
      "admin:write"
    ],
    "registration_modes": ["dcr", "prereg", "cimd"]
  }'
```

Expected response shape:

```json
{
  "id": "<resource-server-id>",
  "issuer_url": "<AUTHSEC_API_ORIGIN>",
  "resource_url": "<RESOURCE_SERVER_ORIGIN>/mcp",
  "jwks_uri": "<AUTHSEC_API_ORIGIN>/oauth/jwks",
  "introspection_endpoint": "<AUTHSEC_API_ORIGIN>/oauth/introspect",
  "introspection_secret": "<one-time-secret>",
  "validation_mode": "auto",
  "scopes_supported": [
    "issues:read",
    "issues:write",
    "pull_requests:read",
    "pull_requests:write",
    "repos:read",
    "repos:write",
    "actions:read",
    "actions:write",
    "security:read",
    "admin:write"
  ]
}
```

Important:

- save the `id` — you need it for `ResourceServerID` in the SDK config
- store `introspection_secret` immediately
- AuthSec only returns the plaintext secret once
- if lost, rotate it from:
  - `POST /authsec/resource-servers/:id/rotate-introspection-secret`
- use the returned `scopes_supported` as the source of truth for the SDK's
  `SupportedScopes` configuration; those same values are emitted back to clients
  as `scopes_supported` in protected-resource metadata

## Step 2: Decide how MCP clients will register

For most MCP resources, the default should be:

- `dcr` enabled for standard MCP/OAuth clients
- `prereg` enabled if you want explicit admin-approved clients
- `cimd` only if you need client metadata discovery workflows

For initial testing, `dcr + prereg + cimd` is a practical default.

If you want to pre-register a client explicitly:

```bash
curl -X POST '<AUTHSEC_API_ORIGIN>/authsec/resource-servers/<resource-server-id>/clients' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <admin_jwt>' \
  -d '{
    "client_name": "Claude Desktop",
    "redirect_uris": ["http://127.0.0.1:8787/callback"],
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "resource": "<RESOURCE_SERVER_ORIGIN>/mcp",
    "scope": "issues:read pull_requests:read repos:read"
  }'
```

## Step 3: Add the SDK to your Go MCP server

Add the module:

```bash
go get github.com/authsec-ai/sdk-authsec/packages/go-sdk
```

Then wrap your MCP HTTP handler.

### Configure AuthSec values

Before you wire the SDK into your server, collect these values from your AuthSec deployment:

- `Issuer`
- `AuthorizationServer`
- `JWKSURL`
- `IntrospectionURL`
- `IntrospectionClientID`
- `IntrospectionClientSecret`
- `ResourceURI`
- `ResourceName`
- `ResourceServerID`

For example:

```text
Issuer=<AUTHSEC_API_ORIGIN>
AuthorizationServer=<AUTHSEC_API_ORIGIN>
JWKSURL=<AUTHSEC_API_ORIGIN>/oauth/jwks
IntrospectionURL=<AUTHSEC_API_ORIGIN>/oauth/introspect
ResourceURI=<RESOURCE_SERVER_ORIGIN>/mcp
ResourceName=GitHub MCP Server
ResourceServerID=<resource-server-uuid>
```

These fields are not interchangeable:

- `Issuer` is the JWT `iss` value that the SDK validates on incoming access tokens.
- `AuthorizationServer` is the public AuthSec API base used in protected-resource
  metadata and for derived SDK admin calls such as
  `{AuthorizationServer}/authsec/resource-servers/{ResourceServerID}/sdk-policy`.

If your deployment uses the same host for both, set them to the same value. If not,
configure them separately.

### Minimal integration example

Use `MountMCP` — it is the canonical integration path. It registers exactly one
protected-resource metadata route (derived from your `ResourceURI`) and the MCP
handler in a single call, so you cannot accidentally skip the metadata route.

```go
package main

import (
	"log"
	"net/http"

	authsecsdk "github.com/authsec-ai/sdk-authsec/packages/go-sdk"
)

func main() {
	mcpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Replace this with your actual MCP handler.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"tools":[]}}`))
	})

	cfg := authsecsdk.Config{
		Issuer:                    "<AUTHSEC_API_ORIGIN>",
		AuthorizationServer:       "<AUTHSEC_API_ORIGIN>",
		JWKSURL:                   "<AUTHSEC_API_ORIGIN>/oauth/jwks",
		IntrospectionURL:          "<AUTHSEC_API_ORIGIN>/oauth/introspect",
		IntrospectionClientID:     "resource-server",
		IntrospectionClientSecret: "<introspection-secret-from-authsec>",
		ResourceURI:               "<RESOURCE_SERVER_ORIGIN>/mcp",
		ResourceName:              "GitHub MCP Server",
		ResourceServerID:          "<resource-server-uuid>",
		SupportedScopes: []string{
			"issues:read",
			"issues:write",
			"pull_requests:read",
			"pull_requests:write",
			"repos:read",
			"repos:write",
			"actions:read",
			"actions:write",
			"security:read",
			"admin:write",
		},
	}

	mux := http.NewServeMux()
	if err := authsecsdk.MountMCP(mux, "/mcp", mcpHandler, cfg); err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

`MountMCP` registers:
- `/.well-known/oauth-protected-resource/mcp` — the metadata route for this
  path-based resource (derived from `ResourceURI`)
- `/mcp` — the protected MCP handler

For a root resource (e.g. `ResourceURI: https://mcp.example.com`), the metadata
route is `/.well-known/oauth-protected-resource` (bare path).

**Path-uniqueness constraint**: each resource registered on the same `http.ServeMux`
must have a distinct URI path component. Two resources with identical paths on
different hosts (e.g. `/mcp` on two different origins) would produce duplicate
metadata routes on a shared mux. For host-based routing or multi-host setups, wire
`rt.ProtectedResourceHandler()` at `BuildResourceMetadataPath(cfg.ResourceURI)` and
`rt.Wrap(handler)` at your chosen pattern manually instead of using `MountMCP`.

### Advanced: manual mux wiring with WrapMCPHTTP

`WrapMCPHTTP` is available for advanced cases where you manage your own mux, use a
framework router, or need to customize handler chaining. If you use it directly,
**you are responsible for separately mounting the metadata handler**:

```go
protected, err := authsecsdk.WrapMCPHTTP(mcpHandler, cfg)
if err != nil {
    log.Fatal(err)
}

rt, err := authsecsdk.NewRuntime(cfg)
if err != nil {
    log.Fatal(err)
}

mux := http.NewServeMux()
// Mount the metadata route explicitly — MountMCP does this for you automatically.
mux.Handle(authsecsdk.BuildResourceMetadataPath(cfg.ResourceURI), rt.ProtectedResourceHandler())
mux.Handle("/mcp", protected)
mux.Handle("/mcp/", protected)
```

Omitting the metadata handler means MCP clients cannot discover the authorization
server and the OAuth flow will not start correctly.

### What this does automatically

With the SDK in place:

- the protected-resource metadata route is registered at the correct path (see above)
- unauthenticated clients receive `WWW-Authenticate: Bearer ... resource_metadata=...`
- AuthSec access tokens are validated (JWT + introspection, configurable via `ValidationMode`)
- the authenticated principal is injected into request context
- the tool→scope mapping is fetched from AuthSec at startup and cached (5-minute TTL by default)
- unauthorized tools are filtered out of `tools/list` responses
- unauthorized `tools/call` requests are rejected with HTTP 403 `insufficient_scope`
- policy backend failures return HTTP 503 (distinct from authorization failures)

Keep `SupportedScopes` aligned with the resource server's `scopes_supported` values
in AuthSec; those values are echoed back to clients in the protected-resource metadata.

## Step 4: How tool authorization works

AuthSec is the single source of truth for which scopes each MCP tool requires. This
mapping is managed in the AuthSec Scope Matrix UI (see Step 6).

### How it works at runtime

1. **Startup**: The SDK fetches the tool→scope mapping from
   `{AuthorizationServer}/authsec/resource-servers/{ResourceServerID}/sdk-policy`
   using the same credentials as introspection. The mapping is cached with a
   5-minute TTL by default.

2. **`tools/list`**: The SDK intercepts the response from your MCP server, checks
   each tool against the principal's RBAC-resolved scopes, and filters out tools the
   user cannot access.

3. **`tools/call`**: The SDK checks whether the principal has the required scopes for
   the requested tool. If not, it returns HTTP 403 with
   `WWW-Authenticate: Bearer error="insufficient_scope"`.

4. **Live RBAC**: When `IntrospectionURL` is configured, the SDK introspects on each
   request and AuthSec re-resolves the user's RBAC permissions on every introspection
   call. If an admin revokes a role, the next MCP request can be rejected as inactive
   or returned with reduced scopes depending on the introspection result. If
   `IntrospectionURL` is not configured, revocation visibility is bounded by token
   lifetime.

### Deny-by-default

When a tool policy exists (any `PolicyMode` other than `PolicyModeOpen`), tools
absent from the mapping are **denied**. This is intentional and distinct from
explicitly-public tools:

| Tool entry in mapping | Result |
|---|---|
| `"tool": {"scope:a"}` — scoped | allowed only if principal has `scope:a` |
| `"tool": {}` — explicit empty slice | allowed for any valid token (public tool) |
| *(absent from map)* | denied — HTTP 403 |

To mark a tool as intentionally public (no scope required), add an explicit empty
slice entry:

```go
authsecsdk.ToolScopeMap{
    "get_status":    {},           // explicitly public — any valid token
    "list_issues":   {"issues:read"},
    "create_issue":  {"issues:write"},
}
```

Omitting a tool name entirely is different: it is treated as an unknown tool and
denied when any policy is active.

### PolicyMode

`PolicyMode` controls which policy source the SDK uses. Set it explicitly for clarity;
when unset it is inferred from the other config fields.

| Mode | Behavior |
|---|---|
| `PolicyModeRemoteRequired` *(default when `ResourceServerID` set)* | Fetch from AuthSec at startup; startup fails if the fetch fails or credentials are missing. Serve from cache at runtime; return HTTP 503 if cache is unavailable. |
| `PolicyModeRemoteWithLocalFallback` | Same startup fetch; on failure, fall back to `ToolScopes`. Requires both `ResourceServerID` and a non-nil `ToolScopes`. |
| `PolicyModeLocalOnly` *(default when only `ToolScopes` set)* | Use `ToolScopes` only; `ResourceServerID` is ignored. |
| `PolicyModeOpen` *(default when neither is set)* | No tool-level policy; all tools are allowed for any valid token. |

```go
authsecsdk.Config{
    // ... other fields ...
    PolicyMode: authsecsdk.PolicyModeRemoteWithLocalFallback,
    ResourceServerID: "<resource-server-uuid>",
    ToolScopes: authsecsdk.ToolScopeMap{
        "list_issues":  {"issues:read"},
        "create_issue": {"issues:write"},
    },
}
```

**`PolicyModeRemoteWithLocalFallback` requires both sides of the contract**: if
`ToolScopes` is nil the SDK returns an error at startup — there is no local fallback
to fall back to.

### Policy backend failures

When the remote scope matrix is unavailable (fetch error, cache expired past the
stale bound), the SDK returns **HTTP 503** rather than silently allowing or denying
requests. This is distinct from an authorization failure (HTTP 403). Monitor for 503s
as a sign of a degraded policy backend, not a token or scope problem.

### Cache TTL and stale serving

The default cache TTL is 5 minutes. Stale data is served during background refresh
for up to 30 minutes after the last successful fetch. After 30 minutes of persistent
fetch failures, the SDK returns 503 rather than serving indefinitely stale policy.

```go
authsecsdk.Config{
    // ... other fields ...
    ScopeMatrixTTL: 2 * time.Minute,
}
```

## Step 5: Validation and revocation semantics

### ValidationMode

`ValidationMode` controls how the SDK combines JWT verification and token
introspection. Set it explicitly for clarity; when unset it is inferred from the
available URLs.

| Mode | Behavior |
|---|---|
| `ValidationModeJWTAndIntrospect` *(default when both URLs set)* | **JWT-shaped tokens**: local JWT verification must pass first — a JWT that fails signature verification is **not** rescued by introspection. On JWT success, introspection is called for revocation check. **Opaque tokens**: introspection is used directly. Requires both `JWKSURL` and `IntrospectionURL`. |
| `ValidationModeJWTOrIntrospect` | Either path may succeed independently (legacy permissive mode). A JWT that fails local verification can be rescued by a passing introspection response. Use this only during migration from the old behavior. |
| `ValidationModeJWTOnly` *(default when only `JWKSURL` set)* | Local JWT verification only. Revocation is bounded by token lifetime. Requires `JWKSURL`. |
| `ValidationModeIntrospectionOnly` *(default when only `IntrospectionURL` set)* | Token introspection only. Supports opaque tokens. Requires `IntrospectionURL` and credentials. |

```go
authsecsdk.Config{
    // ... other fields ...
    // Explicit strict mode (also the inferred default when both URLs are set):
    ValidationMode: authsecsdk.ValidationModeJWTAndIntrospect,
    JWKSURL:        "<AUTHSEC_API_ORIGIN>/oauth/jwks",
    IntrospectionURL: "<AUTHSEC_API_ORIGIN>/oauth/introspect",
    IntrospectionClientID:     "resource-server",
    IntrospectionClientSecret: "<introspection-secret-from-authsec>",
}
```

For strong revocation behavior, configure both `JWKSURL` and `IntrospectionURL`
(default mode: `ValidationModeJWTAndIntrospect`). If you omit introspection, the SDK
validates JWTs locally only and revocation is bounded by token lifetime.

The key security property of `ValidationModeJWTAndIntrospect`: **introspection cannot
rescue a JWT-shaped token that fails local signature verification**. If a token
presents as a JWT (three dot-separated segments) and the local JWKS check fails, the
request is rejected immediately — introspection is not attempted. This prevents a
compromised or misconfigured introspection endpoint from being used to bypass local
cryptographic verification.

For opaque tokens (not JWT-shaped) in `ValidationModeJWTAndIntrospect` mode,
introspection is used directly since there is no local JWT to verify.

## Step 6: Keep upstream credentials separate

The client access token presented to your MCP server should be an AuthSec token.

Do not forward that token to your upstream system.

The intended production model is:

- incoming bearer token: AuthSec access token
- upstream application credential: server-side PAT, API key, GitHub App token, or org-managed credential

That separation matters because:

- AuthSec token proves who the MCP client user is and what they can do
- upstream credential is the server-side operational identity used to execute real work

Those are different concerns and should remain separate.

AuthSec manages consent grants. The MCP server never stores consent state. Consent can be viewed, managed, and revoked in the AuthSec console under **Consent Grants** (accessible from Authz / RBAC in the sidebar).

## Step 7: Configure scopes and RBAC in AuthSec

This is the critical step that connects your resource server to the full AuthSec authorization model. All of this happens in the AuthSec console — the MCP server itself does not need changes.

### 1. Scopes: auto-discover and map tools

Navigate to **Resource Servers** → select your RS → **Scope Matrix**.

AuthSec auto-discovers your MCP tools by calling `tools/list` on your resource server. Click **Rescan** to trigger discovery. The Scope Matrix shows a grid of tools × scopes:

- Each row is a discovered MCP tool
- Each column pill is an OAuth scope mapped to that tool
- `auto_matched` scopes are shown with an indicator
- Click a scope pill to edit its metadata (display name, description, risk level)
- Use the **Map Scope** dropdown per tool to assign or remove scopes

You can also create custom scopes from this page if the auto-discovered set is insufficient.

### 2. Permissions: create resource:action pairs

Navigate to **Authz / RBAC** → **Permissions**.

Create permissions that represent fine-grained actions, for example:

- `github:issues:read`
- `github:repos:write`

### 3. Roles: group permissions into roles

Navigate to **Authz / RBAC** → **Roles**.

Create roles that bundle permissions, for example:

- `github-viewer` → `github:issues:read`, `github:repos:read`
- `github-admin` → all permissions

### 4. Role Bindings: assign roles to users

Navigate to **Authz / RBAC** → **Role Bindings**.

Bind roles to specific users. This determines what each user is allowed to do.

### 5. Scope-Permission mapping: link permissions to OAuth scopes

In the Scope Matrix, scopes can be linked to permissions. When a scope is granted, the associated permissions are included in the resolved access.

### 6. Resolution chain

When a token is issued, AuthSec resolves the effective scopes as:

```
effective_scopes = requested_scopes ∩ RS.scopes_supported ∩ user_effective_scopes
```

Where `user_effective_scopes` is derived from the user's role bindings → permissions → scope mappings.

### 7. Live revocation

With introspection enabled, role removal is reflected on the next introspection
call. Without introspection, revocation is bounded by JWT lifetime because the
SDK is validating locally from JWKS only.

## Step 8: Point MCP clients at your server

Once your MCP server is wrapped and deployed at:

- `<RESOURCE_SERVER_ORIGIN>/mcp`

standard MCP clients should discover AuthSec through the SDK-emitted protected-resource metadata.

The intended flow is:

1. client hits the MCP endpoint unauthenticated
2. SDK returns a bearer challenge with `resource_metadata`
3. client discovers the AuthSec authorization server
4. client completes OAuth against AuthSec
5. client retries with an AuthSec access token
6. SDK validates the token and enforces tool authorization

This is why the SDK owns the `.well-known` protected-resource behavior.

The MCP developer should not have to wire that manually.

## Step 9: Manage users and access in AuthSec

After the SDK is in front of your MCP server, user and access management should move to AuthSec.

In the AuthSec console, the relevant areas are:

- **Users** — create or manage operator identities
- **Identity Providers** — configure Google, GitHub, Microsoft, OIDC, SAML, and other upstream login methods
- **Resource Servers** — register the MCP server, view the Scope Matrix for tool-scope mappings, view nested OAuth clients, rotate introspection secrets
- **Permissions** — define fine-grained resource:action pairs
- **Roles** — group permissions into named roles
- **Role Bindings** — assign roles to users with optional conditions
- **Consent Grants** — view and revoke user-granted consents per client per resource server

The operational model should be:

- your MCP server stays thin
- AuthSec decides who the caller is
- AuthSec decides which scopes are granted (via RBAC resolution)
- the SDK enforces those grants at the MCP boundary
- consent and access can be revoked in real time from the console

## Step 9: Verify the integration

### Check the protected-resource metadata

For a path-based resource (e.g. `ResourceURI: <RESOURCE_SERVER_ORIGIN>/mcp`), the
metadata is served at the path-derived alias:

```bash
curl -i '<RESOURCE_SERVER_ORIGIN>/.well-known/oauth-protected-resource/mcp'
```

For a root resource (no path in `ResourceURI`), it is at the bare path:

```bash
curl -i '<RESOURCE_SERVER_ORIGIN>/.well-known/oauth-protected-resource'
```

Use `authsecsdk.BuildResourceMetadataURL(cfg.ResourceURI)` to compute the correct
URL programmatically. The bare `/.well-known/oauth-protected-resource` path is **not**
served for path-based resources.

### Check the AuthSec discovery document

```bash
curl '<AUTHSEC_API_ORIGIN>/.well-known/oauth-authorization-server'
curl '<AUTHSEC_API_ORIGIN>/.well-known/openid-configuration'
```

### Check the server challenge

Call the MCP endpoint without a bearer token and inspect the response headers:

```bash
curl -i -X POST '<RESOURCE_SERVER_ORIGIN>/mcp' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

You should see a bearer challenge with a `resource_metadata` reference.

### Check authorized vs unauthorized tools

With a valid AuthSec token that lacks write scopes:

- `tools/list` should hide write tools
- `tools/call` for a write tool should fail with `insufficient_scope`

### Verify RBAC end-to-end

1. Create a permission (e.g., `github:issues:read`)
2. Create a role that includes that permission
3. Create a role binding assigning the role to a user
4. Map the permission to an OAuth scope in the Scope Matrix
5. Obtain a token for that user — verify the token includes the expected scope
6. Remove the role binding
7. Call introspect — verify the token returns `active: false`

### Verify consent management

1. Authorize a client against your resource server
2. Check the consent grant appears in the AuthSec console under **Consent Grants**
3. Revoke the consent grant from the console
4. Verify the client is re-prompted for authorization on next access

### Verify tool filtering with RBAC

1. Obtain a token with limited scopes (e.g., only `issues:read`)
2. Call `tools/list` — verify only tools mapped to `issues:read` are visible
3. Call `tools/call` on an unauthorized tool (e.g., one requiring `admin:write`) — verify the SDK returns `insufficient_scope`

## Example development configuration

Use values like these unless your deployment topology differs:

```text
Issuer=<AUTHSEC_API_ORIGIN>
AuthorizationServer=<AUTHSEC_API_ORIGIN>
JWKSURL=<AUTHSEC_API_ORIGIN>/oauth/jwks
IntrospectionURL=<AUTHSEC_API_ORIGIN>/oauth/introspect
ResourceURI=<RESOURCE_SERVER_ORIGIN>/mcp
ResourceName=GitHub MCP Server
ResourceServerID=<resource-server-uuid>
```

For introspection:

- `IntrospectionClientID`: use `resource-server`
- `IntrospectionClientSecret`: use the `introspection_secret` returned by AuthSec when you created or rotated the resource server secret

If your AuthSec deployment uses a different introspection client ID convention, update that field accordingly.

## Explicit dev example

For the current dev environment described in this repo, the placeholders above map to:

```text
AUTHSEC_API_ORIGIN=https://dev.api.authsec.dev
RESOURCE_SERVER_ORIGIN=https://20-106-226-245.sslip.io
```

## What you do not need to build yourself

If you use this SDK, you should not need to separately implement:

- PRM metadata routes
- bearer challenge construction
- AuthSec token parsing and validation
- per-tool scope filtering boilerplate
- tool→scope mapping maintenance (AuthSec manages this)

That is the whole point of the SDK.

## Integration model

This package is intended to be integrated into a Go-based MCP server.

The integration sequence is:

1. register the resource server in AuthSec
2. configure scopes and RBAC in the AuthSec console
3. wrap the server with the SDK
4. deploy it
5. let AuthSec handle users, scopes, and access

For a GitHub MCP server, the next integration step is to connect:

- SDK principal and tool authorization
- existing server-side GitHub credential handling

without changing the AuthSec endpoint contract documented above.
