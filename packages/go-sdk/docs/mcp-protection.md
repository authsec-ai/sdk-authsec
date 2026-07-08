# Guide 1 — Protect your MCP server

*You'll go from an unprotected MCP server to one where every tool call
requires a valid OAuth token with the right scopes — and admins control
access from the AuthSec dashboard without touching your code.*

[← Docs home](README.md) | [Guide 2: M2M auth →](m2m-auth.md)

---

## What you'll have at the end

```
BEFORE                                AFTER
──────                                ─────
POST /mcp tools/call  ──▶ runs 😱     POST /mcp (no token)      ──▶ 401 + how-to-auth
                                      POST /mcp (bad token)     ──▶ 401
anyone on the network                 POST /mcp (missing scope) ──▶ denied for that tool
can call every tool                   POST /mcp (valid + scoped)──▶ tool runs ✅

                                      + your tools listed in the dashboard
                                      + admins assign per-tool permissions there
                                      + policy changes live in ~30s, no redeploy
```

## How it works

The SDK wraps your MCP endpoint. Nothing reaches your tool code until three
gates pass:

```
        agent request: POST /mcp  (Authorization: Bearer eyJ...)
                              │
            ┌─────────────────▼──────────────────┐
            │  go-sdk (MountMCP / rt.Wrap)        │
            │                                     │
            │  GATE 1  token valid?               │──✘──▶ 401 + WWW-Authenticate
            │          (JWT signature + live      │       (tells the agent where
            │           introspection)            │        to get a token)
            │                                     │
            │  GATE 2  which tool is being        │
            │          called? (parses tools/call)│
            │                                     │
            │  GATE 3  do the token's scopes      │──✘──▶ insufficient_scope
            │          cover that tool?           │
            │          (live policy from the      │
            │           dashboard, 30s cache)     │
            └─────────────────┬──────────────────┘
                              │ all pass
                              ▼
                      your MCP handler runs
```

Two things happen automatically at startup:

- **PRM publishing** — your server self-describes at
  `/.well-known/oauth-protected-resource/mcp` (RFC 9728) so agents can
  discover where to get tokens. You never write this endpoint.
- **Manifest publishing** — when `PublishManifest` is enabled, the SDK
  enumerates your tools and registers them with the dashboard, so admins see
  each tool by name and assign scopes to it.

---

## Prerequisites

- An AuthSec workspace on [https://mcpauthz.com](https://mcpauthz.com).
- Go ≥ 1.24 and `go get github.com/authsec-ai/sdk-authsec/packages/go-sdk`.
- A **public URL** for your server. For local dev use an
  [ngrok](https://ngrok.com) tunnel: `ngrok http 8000` →
  `https://xxxx.ngrok-free.app`.

---

## Step 1 — Create the application (resource server) in the dashboard

Sign in at [https://mcpauthz.com](https://mcpauthz.com). In the sidebar open
**Applications** (an *Application* is a protected MCP server; in OAuth terms,
a *resource server*) and click **＋ Create application**. Provide:

- **Application name** — a human label, e.g. `my-mcp-server`.
- **Public base URL** — where your server is reachable, e.g.
  `https://xxxx.ngrok-free.app`.
- **Protected path** — the MCP endpoint path, typically `/mcp`.

The **Resource URI preview** shows the combination
(`https://xxxx.ngrok-free.app/mcp`). This URI is the anchor for everything —
it must **exactly** match the URL agents call (scheme, host, path), because
tokens are bound to it (RFC 8707 resource indicators).

Pick an **access vocabulary** (scope preset). For most servers, **Read +
Write** with an app namespace of `my_mcp` generates:

```
my_mcp:read   my_mcp:write   my_mcp:tools:read   my_mcp:tools:write
```

Click **Create and protect**. On the application's **Setup** tab, copy the
generated values (they're unique per application):

- `RESOURCE_SERVER_ID` (a UUID)
- `INTROSPECTION_CLIENT_SECRET` (**shown once** — copy it now; rotate from
  this tab if lost)

> The introspection client ID **is** the resource-server UUID — the same
> value is used for both `ResourceServerID` and `IntrospectionClientID`.

## Step 2 — Configure the environment

Two ways to configure the SDK: a literal `Config{}` struct, or `FromEnv()`
which reads `AUTHSEC_*` variables. This guide uses `FromEnv()`.

```bash
# Who issues tokens
AUTHSEC_ISSUER=https://mcpauthz.com
AUTHSEC_AUTHORIZATION_SERVER=https://mcpauthz.com
AUTHSEC_JWKS_URL=https://mcpauthz.com/oauth/jwks
AUTHSEC_INTROSPECTION_URL=https://mcpauthz.com/oauth/introspect

# From the Setup tab (unique per application)
AUTHSEC_RESOURCE_SERVER_ID=<resource-server-uuid>
AUTHSEC_INTROSPECTION_CLIENT_ID=<resource-server-uuid>
AUTHSEC_INTROSPECTION_CLIENT_SECRET=<sec_...>

# Your server's identity — must match the Resource URI from step 1
AUTHSEC_RESOURCE_URI=https://xxxx.ngrok-free.app/mcp
AUTHSEC_RESOURCE_NAME=my-mcp-server

# Recommended production posture
AUTHSEC_POLICY_MODE=remote_required          # fail CLOSED if policy unavailable
AUTHSEC_VALIDATION_MODE=jwt_and_introspect   # signature check + live revocation check
AUTHSEC_PUBLISH_MANIFEST=true                # keep tool inventory synced to the dashboard
```

> **Why `remote_required`?** If your server can't fetch the tool→scope policy
> from AuthSec, it **denies all tool calls** rather than guessing. The
> alternative (fail open) means a network hiccup silently disables your
> security. Fail closed is the production default for a reason.

> **Why `jwt_and_introspect`?** A JWT signature check alone can't detect a
> token that was **revoked** five minutes ago. Introspection asks AuthSec
> live. Belt and suspenders.

The full list of variables — including legacy aliases — is in the
[configuration reference](configuration.md).

## Step 3 — Write the server

`MountMCP` is the whole integration. It takes a standard `*http.ServeMux`,
the path to protect, your MCP handler, and the config — and registers **both**
the protected MCP route and the PRM metadata route.

```go
// server.go
package main

import (
	"encoding/json"
	"log"
	"net/http"

	authsec "github.com/authsec-ai/sdk-authsec/packages/go-sdk"
)

func main() {
	cfg := authsec.FromEnv() // reads all AUTHSEC_* vars from step 2

	// Optional but recommended: a hand-curated manifest with suggested scopes.
	// Omit this and the SDK enumerates your tools automatically (see the note
	// below).
	cfg.ToolInventoryProvider = func() ([]authsec.ManifestTool, error) {
		return []authsec.ManifestTool{
			{
				Name:            "add_no",
				Description:     "Add two numbers",
				InputSchema:     json.RawMessage(`{"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}},"required":["a","b"]}`),
				SuggestedScopes: []string{"my_mcp:tools:read"},
			},
			{
				Name:            "multiply_no",
				Description:     "Multiply two numbers",
				InputSchema:     json.RawMessage(`{"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}},"required":["a","b"]}`),
				SuggestedScopes: []string{"my_mcp:tools:write"},
			},
		}, nil
	}

	mux := http.NewServeMux()
	if err := authsec.MountMCP(mux, "/mcp", myMCPHandler(), cfg); err != nil {
		log.Fatal(err) // Config.Validate failed, or remote policy required and unreachable
	}

	log.Printf("listening on :8000 — resource_uri=%s", cfg.ResourceURI)
	log.Fatal(http.ListenAndServe(":8000", mux))
}

// myMCPHandler returns YOUR MCP Streamable-HTTP handler. Any http.Handler
// that speaks MCP JSON-RPC works — hand-rolled, or from an MCP framework.
func myMCPHandler() http.Handler { /* ... your MCP implementation ... */ }
```

Notice what you did **not** write: no token parsing, no JWKS fetching, no
scope checks, no metadata endpoint, no per-tool guards. `MountMCP` owns all
of it; your handler stays a plain MCP handler.

> **`ToolInventoryProvider` is optional.** If you omit it, the SDK enumerates
> your tools automatically at startup by performing a synthetic MCP handshake
> (`initialize` → `notifications/initialized` → paginated `tools/list`)
> against your *unwrapped* handler, so the schemas come straight from your
> tool definitions. Set the provider explicitly when synthetic enumeration
> doesn't fit your server (custom internal auth, a router that misbehaves
> under `httptest`, a static registry) or when you want exact suggested
> scopes per tool.

### `MountMCP` vs `WrapMCPHTTP` — which to use

`MountMCP` is the one-call install and what you should use unless you need
custom router behavior. `WrapMCPHTTP` wraps a handler but leaves you to mount
the metadata route yourself — use it when you're composing middleware by hand
or not using `*http.ServeMux`.

```go
// Equivalent manual wiring — only if you can't use MountMCP:
rt, err := authsec.NewRuntime(cfg)
if err != nil {
	log.Fatal(err)
}
mux.Handle(authsec.BuildResourceMetadataPath(cfg.ResourceURI), rt.ProtectedResourceHandler())
mux.Handle("/mcp", rt.Wrap(myMCPHandler()))
```

`WrapMCPHTTP` returns just the wrapped handler:

```go
protected, err := authsec.WrapMCPHTTP(myMCPHandler(), cfg)
if err != nil {
	log.Fatal(err)
}
mux.Handle(authsec.BuildResourceMetadataPath(cfg.ResourceURI), must(authsec.ProtectedResourceHandler(cfg)))
mux.Handle("/mcp", protected)
```

> ⚠️ **Never skip the metadata route.** For a path-based resource
> (`.../mcp`), PRM is served at `/.well-known/oauth-protected-resource/mcp`,
> **not** the bare well-known path. Always derive it with
> `authsec.BuildResourceMetadataPath(cfg.ResourceURI)` — hardcoding the bare
> path breaks OAuth discovery for MCP clients.

## Step 4 — Run and verify

```bash
go run .        # or: go build && ./server
# in another terminal, if local:
ngrok http 8000
```

**Check 1 — the PRM document is served** (agents discover your server here):

```bash
curl -s https://xxxx.ngrok-free.app/.well-known/oauth-protected-resource/mcp
```

```json
{
  "resource": "https://xxxx.ngrok-free.app/mcp",
  "authorization_servers": ["https://mcpauthz.com"],
  "scopes_supported": ["my_mcp:read", "my_mcp:tools:read", "..."]
}
```

The response also carries `Cache-Control: public, max-age=300`.

**Check 2 — unauthenticated calls are rejected:**

```bash
curl -i -X POST https://xxxx.ngrok-free.app/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://xxxx.ngrok-free.app/.well-known/oauth-protected-resource/mcp", realm="my-mcp-server"
```

The 401 isn't a dead end — the `WWW-Authenticate` header tells a well-behaved
agent exactly where to authenticate. This is the MCP authorization spec
working as designed.

**Check 3 — your tools appeared in the dashboard.** Because
`AUTHSEC_PUBLISH_MANIFEST=true`, the SDK published your tool inventory at
startup (a `PUT` to `.../resource-servers/<id>/sdk-manifest`). Open the
application's **Tools** tab — every tool is listed with its runtime access
state and the suggested scopes you published. Tools you don't map stay
denied — safe by default.

## Step 5 — Configure access in the dashboard

The SDK now serves everything correctly, but a fresh application denies
everyone until an admin makes three decisions:

1. **Default access policy (Access tab).** Mark a role (e.g. `Viewer`) as the
   default and grant it at least one scope, then **Save grants**. Without
   this, new callers authenticate but receive no role.
2. **Map tools to scopes (Tools tab).** Each freshly imported tool shows
   `denied` / *"No label assigned"* — the fail-closed default. Open each tool
   and **Map** it to an access label (scope), e.g. `add_no → my_mcp:tools:read`,
   `multiply_no → my_mcp:tools:write`. Anything left unmapped stays denied.
3. **Launch (Overview tab).** When runtime state reads **Ready**, click
   **Launch application**.

Your running server picks up these changes within **~30 seconds** (it polls
the scope matrix; the cache TTL defaults to 30s) — no restart, no redeploy.

> When the application is not yet `ready`, the policy endpoint returns
> `policy_complete=false`; under `PolicyModeRemoteRequired` the SDK treats
> that as **deny-all**. That is expected during setup — finish steps 1–3 and
> it flips to allow.

## Step 6 — Full-circle test

With a real agent token (from [guide 2](m2m-auth.md) or
[guide 3](idjag-delegation.md)):

```bash
curl -X POST https://xxxx.ngrok-free.app/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"tools/call","id":2,
       "params":{"name":"add_no","arguments":{"a":2,"b":3}}}'
```

- Token has `my_mcp:tools:read` → `add_no` runs, returns `5` ✅
- Same token calls `multiply_no` (needs `:write`) → denied ✅
- `tools/list` responses are also **filtered** — callers only see the tools
  their scopes allow.

---

## Configuration essentials

### Policy modes

`Config.PolicyMode` (env `AUTHSEC_POLICY_MODE`) controls what happens when the
tool→scope policy can't be fetched from AuthSec:

| Constant | Env value | Behavior |
|---|---|---|
| `PolicyModeRemoteRequired` | `remote_required` (or `enforce`) | Fetch AuthSec policy. Startup fails unless the initial fetch succeeds — **except** when `PublishManifest=true` and the RS is still being set up (starts deny-all, refreshes in background). |
| `PolicyModeRemoteWithLocalFallback` | `remote_with_local_fallback` | Prefer AuthSec policy; if unavailable, use `Config.ToolScopes` (which must be non-nil). |
| `PolicyModeLocalOnly` | `local_only` | Use only local `Config.ToolScopes`. |
| `PolicyModeOpen` | `open` (or `observe`) | No per-tool authorization; any valid AuthSec token may call any tool. |

Recommended: `PolicyModeRemoteWithLocalFallback` during onboarding (so the
server starts even while policy is incomplete), then `PolicyModeRemoteRequired`
in production for strict fail-closed behavior.

### Validation modes

`Config.ValidationMode` (env `AUTHSEC_VALIDATION_MODE`) controls how tokens
are checked:

| Constant | Env value | Behavior |
|---|---|---|
| `ValidationModeJWTAndIntrospect` | `jwt_and_introspect` | JWT-shaped tokens pass JWKS verification **then** introspection; opaque tokens use introspection. **Recommended.** |
| `ValidationModeJWTOrIntrospect` | `jwt_or_introspect` | Either check passing is enough. Migration only. |
| `ValidationModeJWTOnly` | `jwt_only` | JWKS signature only; revocation visibility bounded by token lifetime. |
| `ValidationModeIntrospectionOnly` | `introspection_only` | Introspection only. |

> Security note: in `jwt_and_introspect`, introspection **cannot** rescue a
> JWT-shaped token that fails local signature verification. Signature first,
> always.

### Tool manifest publishing

When `Config.PublishManifest` is `true`, `MountMCP` / `WrapMCPHTTP` publish
the tool inventory to AuthSec in the background (a `PUT` to
`{AuthorizationServer}/authsec/resource-servers/{ResourceServerID}/sdk-manifest`,
authenticated with the introspection credentials via HTTP Basic). Each entry
is a `ManifestTool`:

```go
type ManifestTool struct {
	Name            string          // required
	Title           string          // optional display title
	Description     string          // optional
	InputSchema     json.RawMessage // optional JSON Schema
	Annotations     json.RawMessage // optional MCP annotations (e.g. readOnlyHint)
	SuggestedScopes []string        // advisory scopes shown to the admin
}
```

`SuggestedScopes` are **advisory** — they help the admin, they do not grant
anything. If a manifest tool omits `SuggestedScopes`, the SDK falls back to
`Config.ToolScopeSuggestions[toolName]`. Only an admin's *effective* mapping
in the dashboard grants access.

You can also publish manually (rare — the automatic path covers most cases):

```go
if err := authsec.PublishManifest(ctx, cfg, myMCPHandler()); err != nil {
	log.Printf("manifest publish failed: %v", err)
}
```

### Protected Resource Metadata (PRM)

The PRM document (RFC 9728) is what lets an agent discover *where* to get a
token for your server. `MountMCP` serves it automatically; if you wire by
hand, mount `rt.ProtectedResourceHandler()` at the right path:

```go
path := authsec.BuildResourceMetadataPath(cfg.ResourceURI)
// ResourceURI = https://host        → /.well-known/oauth-protected-resource
// ResourceURI = https://host/mcp    → /.well-known/oauth-protected-resource/mcp
```

`scopes_supported` in the PRM is sourced live from the AuthSec scope matrix
when available, falling back to `Config.SupportedScopes`.

### Reading the authenticated principal

After validation, the SDK stores the AuthSec principal in the request
context. Read it for audit logs or tenant routing — **not** to bypass
authorization (the SDK already enforced it):

```go
if p, ok := authsec.PrincipalFromContext(r.Context()); ok {
	log.Printf("subject=%s scopes=%v", p.Subject, p.Scopes)
}
```

`Principal` exposes `Subject`, `Issuer`, `Audience`, `Scopes`, `Claims`,
`Active`, and a `HasAnyScope(required []string) bool` helper.

---

## What enforcement looks like on the wire

| Situation | Response |
|---|---|
| No token / bad token | `401` + `WWW-Authenticate: Bearer resource_metadata="…", realm="…"` |
| Valid token, insufficient scope for the tool | Denied with `insufficient_scope`. For plain (non-JSON-RPC) callers this is an HTTP `403` with `WWW-Authenticate: Bearer error="insufficient_scope"`. For JSON-RPC MCP clients (a token is present and the body is JSON-RPC), the denial is returned **in-band** — HTTP `200` with `result.isError=true` and `_meta.authsec` — so MCP clients render a readable error instead of a raw HTTP failure. |
| Policy backend unreachable, no usable cache | HTTP `503` |
| Valid + scoped | Passes through to your handler |
| `tools/list` | Response filtered to the tools the caller's scopes allow |

The in-band JSON-RPC behavior matches the Python and TypeScript SDKs so the
same MCP clients behave identically across languages.

---

## Validation checklist

Run these before you call a server "protected":

- [ ] **Metadata** — `GET /.well-known/oauth-protected-resource/mcp` returns
      `200` with `resource` and `authorization_servers` set.
- [ ] **401 challenge** — an unauthenticated `POST /mcp` returns `401` with a
      `WWW-Authenticate: Bearer` header containing `resource_metadata=`.
- [ ] **Manifest** — the dashboard's Tools tab lists your tools (or
      `GET /authsec/resource-servers/<id>/sdk-manifest-status` shows
      `status=success`, `tool_count > 0`).
- [ ] **Scope matrix** — tools appear in the dashboard's scope matrix with
      your suggested scopes visible.
- [ ] **Filtered list** — `tools/list` with a read-only token hides write
      tools.
- [ ] **Denied call** — a write tool called with a read-only token is denied
      (`insufficient_scope`).
- [ ] **`ResourceURI` matches** — it is byte-for-byte the URL agents call and
      the token audience.

Use the dashboard's **Run protection check** (Setup tab) to verify most of
this end-to-end.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `MountMCP` returns an error at startup | `Config.Validate` failed, or `PolicyModeRemoteRequired` and the initial policy fetch failed | Read the error; check required fields (below), or set `PublishManifest=true` / use `RemoteWithLocalFallback` during onboarding |
| Every tool call denied, policy state `needs_setup` | Vocabulary exists but tools aren't mapped / no default access | Step 5 — default role + grants, map tools, launch |
| A tool stays `denied` after launch | "No label assigned" — unmapped tools fail closed | Tools tab — open the tool, Map an access label |
| `401` even with a fresh token | `AUTHSEC_RESOURCE_URI` doesn't exactly match the URL agents call (scheme/host/path), so the audience check fails | Make them identical; re-check after an ngrok URL change |
| Metadata path returns `404` | Wrong PRM path for a path-based resource | Use `BuildResourceMetadataPath(cfg.ResourceURI)`; a `.../mcp` resource serves PRM at `/.well-known/oauth-protected-resource/mcp` |
| Dashboard shows zero tools | `PublishManifest` false, empty `ToolInventoryProvider`, synthetic enumeration can't reach your inner handler, or wrong introspection creds (manifest `PUT` 401) | Enable `PublishManifest`; check boot logs for `manifest publish failed`; use `ToolInventoryProvider` for custom routing |
| Scope changes not taking effect | Within the scope-matrix cache window | Wait ~30s (default TTL); confirm the server can reach `mcpauthz.com` |
| Everything breaks when AuthSec is briefly unreachable | `remote_required` failing closed — by design | For dev only, relax `AUTHSEC_POLICY_MODE`; keep fail-closed in production |
| Lost the introspection secret | Shown once at creation | Rotate it from the application's Setup tab and update the env |

More failure modes (agent side, SPIFFE, manifest internals) are in the
consolidated [troubleshooting guide](troubleshooting.md).

### Required config fields

`Config.Validate` (called by `MountMCP`/`NewRuntime`) enforces:

- `Issuer` is set.
- `ResourceURI` is set and is an absolute URI (scheme + host).
- At least one of JWKS validation or introspection is configured.
- Introspection credentials are present when introspection is enabled.
- Remote policy modes require `ResourceServerID`, an authorization server,
  and introspection credentials; `RemoteWithLocalFallback` also requires
  non-nil `ToolScopes`.

---

[← Docs home](README.md) | [Guide 2: M2M auth →](m2m-auth.md)
