# Configuration reference

Everything you can configure, with types, defaults, and what's required.

- [Environment variables (`FromEnv`)](#environment-variables-fromenv)
- [`Config` — server side](#config--server-side)
- [Policy modes](#policy-modes)
- [Validation modes](#validation-modes)
- [`AgentIdentityConfig` — agent side](#agentidentityconfig--agent-side)
- [`SpiffeConfig` — workload identity](#spiffeconfig--workload-identity)
- [`BrowserLoginOptions`](#browserloginoptions)
- [`PollOptions`](#polloptions)

---

## Environment variables (`FromEnv`)

`FromEnv(prefix ...string) Config` builds a server-side `Config` from
environment variables. The default prefix is **`AUTHSEC_`**; pass one argument
to override it (e.g. `FromEnv("MYAPP_")`).

`FromEnv` **parses only** — it does not validate. Call `MountMCP` /
`NewRuntime` (which run `Config.Validate`) to fail loudly on a bad config.

| Environment variable | Legacy alias | `Config` field | Notes |
|---|---|---|---|
| `AUTHSEC_ISSUER` | — | `Issuer` | **Required.** |
| `AUTHSEC_AUTHORIZATION_SERVER` | — | `AuthorizationServer` | Defaults to `Issuer` if empty. |
| `AUTHSEC_JWKS_URL` | `AUTHSEC_JWKS_URI` | `JWKSURL` | |
| `AUTHSEC_INTROSPECTION_URL` | `AUTHSEC_INTROSPECTION_ENDPOINT` | `IntrospectionURL` | |
| `AUTHSEC_INTROSPECTION_CLIENT_ID` | `AUTHSEC_INTROSPECTION_ID` | `IntrospectionClientID` | The resource-server UUID. |
| `AUTHSEC_INTROSPECTION_CLIENT_SECRET` | `AUTHSEC_INTROSPECTION_SECRET` | `IntrospectionClientSecret` | Store securely. |
| `AUTHSEC_RESOURCE_URI` | `AUTHSEC_RESOURCE` | `ResourceURI` | **Required, absolute** (scheme + host). Must match the URL agents call. |
| `AUTHSEC_RESOURCE_NAME` | — | `ResourceName` | Display name in PRM / challenges. |
| `AUTHSEC_RESOURCE_SERVER_ID` | — | `ResourceServerID` | Enables remote scope-matrix + manifest publishing. |
| `AUTHSEC_SUPPORTED_SCOPES` | — | `SupportedScopes` | JSON array, or comma/space-separated list. |
| `AUTHSEC_TOOL_SCOPES_JSON` | — | `ToolScopes` | JSON object `{"tool": ["scope", …]}`. Left `nil` if unset. |
| `AUTHSEC_TOOL_SCOPE_SUGGESTIONS_JSON` | — | `ToolScopeSuggestions` | JSON object of advisory suggestions. |
| `AUTHSEC_POLICY_MODE` | — | `PolicyMode` | See [policy modes](#policy-modes). |
| `AUTHSEC_VALIDATION_MODE` | — | `ValidationMode` | See [validation modes](#validation-modes). |
| `AUTHSEC_PUBLISH_MANIFEST` | — | `PublishManifest` | Truthy = `1`, `true`, `yes` (case-insensitive). |

Anything not represented as an env var (`ToolInventoryProvider`, `HTTPClient`,
`Logger`, `Now`, `ScopeMatrixTTL`, `BearerMethodsSupported`) must be set on the
`Config` struct after `FromEnv()`:

```go
cfg := authsec.FromEnv()
cfg.ToolInventoryProvider = myTools
cfg.ScopeMatrixTTL = 30 * time.Second
```

---

## `Config` — server side

```go
type Config struct { … }
```

| Field | Type | Default (via `normalized()`) | Notes |
|---|---|---|---|
| `Issuer` | `string` | — | **Required.** JWT issuer. |
| `AuthorizationServer` | `string` | `Issuer` | Base for AS metadata and SDK admin calls (`/sdk-policy`, `/sdk-manifest`). |
| `JWKSURL` | `string` | — | Public keys for JWT verification. |
| `IntrospectionURL` | `string` | — | RFC 7662 endpoint. |
| `IntrospectionClientID` | `string` | — | The resource-server UUID. |
| `IntrospectionClientSecret` | `string` | — | Introspection secret. |
| `ResourceURI` | `string` | — | **Required, absolute.** Anchors PRM path + token audience. |
| `ResourceName` | `string` | `"AuthSec Protected MCP Resource"` | Display name. |
| `ResourceServerID` | `string` | — | Enables remote policy fetch + manifest publish. |
| `SupportedScopes` | `[]string` | — | Advertised in PRM (fallback when the live scope matrix is empty). |
| `ToolScopes` | `ToolScopeMap` | — | Local tool→scope fallback (`map[string][]string`). Required for `RemoteWithLocalFallback` / `LocalOnly`. |
| `ScopeMatrixTTL` | `time.Duration` | `30s` | Cache TTL for the remote tool→scope policy. |
| `PolicyMode` | `PolicyMode` | mode-dependent | See below. |
| `ValidationMode` | `ValidationMode` | `jwt_and_introspect` when both are available | See below. |
| `PublishManifest` | `bool` | `false` | Push tool inventory to AuthSec at startup. |
| `ToolScopeSuggestions` | `map[string][]string` | — | Admin-facing suggested scopes (manifest only; advisory). |
| `ToolInventoryProvider` | `func() ([]ManifestTool, error)` | synthetic enumeration | Escape hatch for manifest generation. |
| `BearerMethodsSupported` | `[]string` | `["header"]` | Advertised bearer methods. |
| `HTTPClient` | `*http.Client` | `&http.Client{Timeout: 10s}` | Used for JWKS/introspection/policy/manifest calls. |
| `Logger` | `*slog.Logger` | `slog.Default()` | Structured logging. |
| `Now` | `func() time.Time` | `time.Now` | Clock injection (tests). |

> **Note on `ScopeMatrixTTL`.** The zero value means "use the default", which
> is **30 seconds** — this is the "policy propagates in ~30s" guarantee. (An
> older doc comment mentions 5 minutes; the effective default is 30s. Set the
> field explicitly if you want a different value.)

### What `Config.Validate` requires

`MountMCP` and `NewRuntime` call `Validate`, which enforces:

- `Issuer` is set.
- `ResourceURI` is set and absolute (scheme + host).
- At least one validation path (JWKS **or** introspection) is configured.
- Introspection credentials present when introspection is enabled.
- Remote policy modes (`RemoteRequired`, `RemoteWithLocalFallback`) require
  `ResourceServerID`, an authorization server (or `Issuer`), and introspection
  credentials.
- `RemoteWithLocalFallback` additionally requires non-nil `ToolScopes`.

---

## Policy modes

`Config.PolicyMode` (env `AUTHSEC_POLICY_MODE`):

| Constant | Env string(s) | Behavior |
|---|---|---|
| `PolicyModeRemoteRequired` | `remote_required`, `enforce` | Fetch AuthSec policy; startup fails unless the initial fetch succeeds (unless `PublishManifest=true` during setup). Fail-closed. |
| `PolicyModeRemoteWithLocalFallback` | `remote_with_local_fallback` | Prefer remote policy; fall back to `ToolScopes` when unavailable (requires non-nil `ToolScopes`). |
| `PolicyModeLocalOnly` | `local_only` | Use only local `ToolScopes`. |
| `PolicyModeOpen` | `open`, `observe` | No per-tool authorization; any valid token may call any tool. |
| `PolicyModeUnset` | (empty / unrecognized) | Sentinel; resolved to a concrete mode by `normalized()`. |

---

## Validation modes

`Config.ValidationMode` (env `AUTHSEC_VALIDATION_MODE`):

| Constant | Env string | Behavior |
|---|---|---|
| `ValidationModeJWTAndIntrospect` | `jwt_and_introspect` | JWKS verify **then** introspect (JWT tokens); introspect (opaque). **Recommended.** |
| `ValidationModeJWTOrIntrospect` | `jwt_or_introspect` | Either check passing suffices. Migration only. |
| `ValidationModeJWTOnly` | `jwt_only` | JWKS signature only. |
| `ValidationModeIntrospectionOnly` | `introspection_only` | Introspection only. |
| `ValidationModeUnset` | (empty / `auto`) | Sentinel; resolved by `normalized()` based on which endpoints are configured. |

---

## `AgentIdentityConfig` — agent side

```go
type AgentIdentityConfig struct { … }
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `Issuer` | `string` | — | **Required** — empty panics. |
| `ClientID` | `string` | — | **Required** — empty panics. |
| `Auth` | `ClientAuth` | derived from `ClientSecret` | The credential. Mutually exclusive with `ClientSecret` (both set → panic). |
| `ClientSecret` | `string` | — | Shorthand for `Auth: NewClientSecretAuth(secret)`. |
| `IDPIssuer` | `string` | — | Enterprise IdP issuer, for the ID-JAG path. |
| `PreferredMode` | `string` | `"auto"` | `"auto"` \| `"direct-only"` \| `"xaa-allowed"`. |
| `TokenEndpoint` | `string` | discovered | Overrides token-endpoint discovery. |

`AccessFor` options: `WithRequestedScopes(...)`, `WithUserSession(subjectToken)`,
`WithExtra(key, val)`. Tokens are cached and reused while >~30s of life remain;
`ClearCache(resource ...string)` drops them.

---

## `SpiffeConfig` — workload identity

```go
type SpiffeConfig struct { … }
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `MCPServerURL` | `string` | — | Protected MCP URL; the token endpoint is discovered from it. |
| `ClientID` | `string` | — | **Required.** Workload client UUID. |
| `SpiffeID` | `string` | — | Must start with `spiffe://`. |
| `Scopes` | `string` | — | **Required.** **Space-separated** scope string (not a slice). |
| `TokenEndpoint` | `string` | discovered | If set, must be `https://`. |
| `AgentSocketPath` | `string` | `/run/spire/sockets/agent.sock` | SPIRE agent Unix socket. |
| `SvidOverride` | `string` | — | Pre-minted JWT-SVID; skips the SPIRE subprocess (testing). |

`SpiffeWorkloadIdentity.AccessFor(ctx)` takes no arguments (resource + scopes
come from the config). Tokens are served from cache while >60s remain; SVIDs
are cached ~4.5 min. `ClearCache()` drops both.

---

## `BrowserLoginOptions`

```go
type BrowserLoginOptions struct { … }
```

| Field | Type | Default |
|---|---|---|
| `Resource` | `string` | — (set it to bind the login to your MCP resource, RFC 8707) |
| `Scopes` | `[]string` | `["openid", "email", "profile"]` |
| `Port` | `int` | `8126` (loopback callback port; must match the registered redirect URI) |
| `Timeout` | `time.Duration` | `300s` |
| `OpenBrowser` | `func(url string) error` | per-OS default launcher |

Pass `nil` to `BrowserLogin` to accept all defaults.

---

## `PollOptions`

```go
type PollOptions struct {
	Interval time.Duration // default 3s
	Timeout  time.Duration // default 300s
}
```

Pass `nil` to `PollUntilApproved` for the defaults.

---

[← Docs home](README.md)
