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

For a development environment, that might look like:

- API base: `https://dev.api.authsec.dev`
- Authorization server metadata: `https://dev.api.authsec.dev/.well-known/oauth-authorization-server`
- OIDC discovery: `https://dev.api.authsec.dev/.well-known/openid-configuration`
- Authorize: `https://dev.api.authsec.dev/oauth/authorize`
- Token: `https://dev.api.authsec.dev/oauth/token`
- Introspection: `https://dev.api.authsec.dev/oauth/introspect`
- JWKS: `https://dev.api.authsec.dev/oauth/jwks`
- PAR: `https://dev.api.authsec.dev/oauth/par`
- Resource server admin API: `https://dev.api.authsec.dev/authsec/resource-servers`

The only fixed path the SDK itself owns is the protected-resource metadata path:

- `/.well-known/oauth-protected-resource`

That is correct and expected for an OAuth-protected MCP resource.

## What AuthSec owns vs what the SDK owns

### AuthSec owns

- login and identity provider flows
- OAuth/OIDC discovery and token issuance
- PAR-backed authorization
- DCR / preregistered client registration
- scopes, RBAC, and consent
- JWKS and introspection
- user and tenant administration
- auditability and policy control

### The SDK owns

- protected-resource metadata on your MCP server
- bearer challenge responses for unauthenticated MCP requests
- AuthSec token validation
- principal creation and request context hydration
- tool visibility filtering on `tools/list`
- tool call authorization on `tools/call`

## What the package provides

This package is generic. It is not tied to a single MCP server implementation.

It currently provides:

- a high-level HTTP wrapper
- protected-resource metadata mounting
- hybrid JWT + introspection validation
- principal context injection
- tool policy enforcement
- generic policy primitives (`StaticPolicy`, `OverrideToolPolicy`, `RequiredScopesForTool`)

It does not include:

- server-specific bootstrap helpers
- CLI provisioning
- automatic admin-side resource server creation

Provisioning happens in AuthSec, then you point the SDK at the resulting values.

## Step 1: Register your MCP server in AuthSec

You can do this in the AuthSec UI or via the AuthSec admin API.

For example, for a GitHub MCP server at:

- public server origin: `https://20-106-226-245.sslip.io`
- protected MCP endpoint: `https://20-106-226-245.sslip.io/mcp`

use these values.

### In the AuthSec UI

Go to `Resource Servers` and create a new resource server with:

- `Name`: `GitHub MCP Server`
- `Public base URL`: `https://20-106-226-245.sslip.io`
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
  - for this example: `https://20-106-226-245.sslip.io/mcp`

After creation, AuthSec returns:

- `resource_url`
- `jwks_uri`
- `introspection_endpoint`
- `introspection_secret`

You need those values for the SDK config.

### Via the AuthSec admin API

The same setup can be created with:

```bash
curl -X POST 'https://dev.api.authsec.dev/authsec/resource-servers' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <admin_jwt>' \
  -d '{
    "name": "GitHub MCP Server",
    "public_base_url": "https://20-106-226-245.sslip.io",
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
  "issuer_url": "https://dev.api.authsec.dev",
  "resource_url": "https://20-106-226-245.sslip.io/mcp",
  "jwks_uri": "https://dev.api.authsec.dev/oauth/jwks",
  "introspection_endpoint": "https://dev.api.authsec.dev/oauth/introspect",
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

- store `introspection_secret` immediately
- AuthSec only returns the plaintext secret once
- if lost, rotate it from:
  - `POST /authsec/resource-servers/:id/rotate-introspection-secret`

## Step 2: Decide how MCP clients will register

For most MCP resources, the default should be:

- `dcr` enabled for standard MCP/OAuth clients
- `prereg` enabled if you want explicit admin-approved clients
- `cimd` only if you need client metadata discovery workflows

For initial testing, `dcr + prereg + cimd` is a practical default.

If you want to pre-register a client explicitly:

```bash
curl -X POST 'https://dev.api.authsec.dev/authsec/resource-servers/<resource-server-id>/clients' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <admin_jwt>' \
  -d '{
    "client_name": "Claude Desktop",
    "redirect_uris": ["http://127.0.0.1:8787/callback"],
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "resource": "https://20-106-226-245.sslip.io/mcp",
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
- `IntrospectionClientSecret`
- `ResourceURI`
- `ResourceName`
- `SupportedScopes`

For example:

```text
Issuer=https://dev.api.authsec.dev
AuthorizationServer=https://dev.api.authsec.dev
JWKSURL=https://dev.api.authsec.dev/oauth/jwks
IntrospectionURL=https://dev.api.authsec.dev/oauth/introspect
ResourceURI=https://20-106-226-245.sslip.io/mcp
ResourceName=GitHub MCP Server
```

### Minimal wrapper example

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

	protected, err := authsecsdk.WrapMCPHTTP(mcpHandler, authsecsdk.Config{
		Issuer:                    "https://dev.api.authsec.dev",
		AuthorizationServer:       "https://dev.api.authsec.dev",
		JWKSURL:                   "https://dev.api.authsec.dev/oauth/jwks",
		IntrospectionURL:          "https://dev.api.authsec.dev/oauth/introspect",
		IntrospectionClientID:     "resource-server",
		IntrospectionClientSecret: "<introspection-secret-from-authsec>",
		ResourceURI:               "https://20-106-226-245.sslip.io/mcp",
	ResourceName:              "GitHub MCP Server",
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
		Policy: authsecsdk.StaticPolicy{
			"list_issues":  {AnyOfScopes: []string{"issues:read"}},
			"create_issue": {AnyOfScopes: []string{"issues:write"}},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/mcp", protected)
	mux.Handle("/mcp/", protected)

	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

### What this does automatically

With the wrapper in place, the SDK:

- serves `/.well-known/oauth-protected-resource`
- serves resource metadata for the protected MCP resource
- challenges unauthenticated clients with `WWW-Authenticate: Bearer ... resource_metadata=...`
- validates AuthSec access tokens
- adds the authenticated principal to request context
- filters unauthorized tools out of `tools/list`
- rejects unauthorized `tools/call` requests with `insufficient_scope`

You do not need to hand-build the protected-resource metadata endpoints yourself.

## Step 4: Understand the policy model

AuthSec is the source of truth for scopes. When you register a resource server in AuthSec and trigger a rescan, AuthSec auto-discovers your MCP tools (via `tools/list`) and creates OAuth scopes in its registry. The authoritative scope-to-tool mapping lives in the AuthSec Scope Matrix UI.

The `StaticPolicy` in the SDK is a **local defense-in-depth fallback**, not the primary authorization model. It provides a safety net at the MCP boundary so that even if AuthSec is unreachable or misconfigured, the server enforces minimum scope requirements locally.

```go
// StaticPolicy is a LOCAL defense-in-depth fallback.
// The authoritative scope→tool mapping lives in AuthSec (Scope Matrix).
// This ensures the server enforces minimum scope requirements even if
// AuthSec is unreachable.
Policy: authsecsdk.StaticPolicy{
	"list_issues":  {AnyOfScopes: []string{"issues:read"}},
	"create_issue": {AnyOfScopes: []string{"issues:write"}},
}
```

If you want to override or extend a base policy:

```go
basePolicy := authsecsdk.StaticPolicy{
	"list_issues":  {AnyOfScopes: []string{"issues:read"}},
	"create_issue": {AnyOfScopes: []string{"issues:write"}},
}

// Add local overrides on top of the base policy
policy := authsecsdk.OverrideToolPolicy(basePolicy, map[string]authsecsdk.ToolRule{
	"create_repository": {
		AnyOfScopes: []string{"admin:write"},
	},
})
```

Then use:

```go
Policy: policy
```

If you want the GitHub preset package as a convenience starter (not required):

```go
import (
	authsecsdk "github.com/authsec-ai/sdk-authsec/packages/go-sdk"
	githubpreset "github.com/authsec-ai/sdk-authsec/packages/go-sdk/presets/github"
)

policy := githubpreset.DefaultPolicy()
```

## Step 5: Keep upstream credentials separate

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

## Step 6: Configure scopes and RBAC in AuthSec

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

Role removed → next introspection call → `active: false`. The MCP server's token is immediately invalidated. There is no caching delay because the SDK uses introspection against AuthSec.

## Step 7: Point MCP clients at your server

Once your MCP server is wrapped and deployed at:

- `https://20-106-226-245.sslip.io/mcp`

standard MCP clients should discover AuthSec through the SDK-emitted protected-resource metadata.

The intended flow is:

1. client hits the MCP endpoint unauthenticated
2. SDK returns a bearer challenge with `resource_metadata`
3. client discovers the AuthSec authorization server
4. client completes OAuth against AuthSec
5. client retries with an AuthSec access token
6. SDK validates the token and enforces tool policy

This is why the SDK owns the `.well-known` protected-resource behavior.

The MCP developer should not have to wire that manually.

## Step 8: Manage users and access in AuthSec

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

After wrapping your server, this should respond:

```bash
curl -i 'https://20-106-226-245.sslip.io/.well-known/oauth-protected-resource'
```

Depending on how your server is mounted, clients may also reach the metadata path variant associated with the protected resource path.

### Check the AuthSec discovery document

```bash
curl 'https://dev.api.authsec.dev/.well-known/oauth-authorization-server'
curl 'https://dev.api.authsec.dev/.well-known/openid-configuration'
```

### Check the server challenge

Call the MCP endpoint without a bearer token and inspect the response headers:

```bash
curl -i -X POST 'https://20-106-226-245.sslip.io/mcp' \
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
Issuer=https://dev.api.authsec.dev
AuthorizationServer=https://dev.api.authsec.dev
JWKSURL=https://dev.api.authsec.dev/oauth/jwks
IntrospectionURL=https://dev.api.authsec.dev/oauth/introspect
ResourceURI=https://20-106-226-245.sslip.io/mcp
ResourceName=GitHub MCP Server
```

For introspection:

- `IntrospectionClientID`: use `resource-server`
- `IntrospectionClientSecret`: use the `introspection_secret` returned by AuthSec when you created or rotated the resource server secret

If your AuthSec deployment uses a different introspection client ID convention, update that field accordingly.

## What you do not need to build yourself

If you use this SDK, you should not need to separately implement:

- PRM metadata routes
- bearer challenge construction
- AuthSec token parsing and validation
- per-tool scope filtering boilerplate

That is the whole point of the SDK.

## Integration model

This package is intended to be integrated into a Go-based MCP server.

The integration sequence is:

1. wrap the server
2. deploy it
3. create the resource server in AuthSec
4. let AuthSec handle users and access

For a GitHub MCP server, the next integration step is to connect:

- SDK principal and tool authorization
- existing server-side GitHub credential handling

without changing the AuthSec endpoint contract documented above.
