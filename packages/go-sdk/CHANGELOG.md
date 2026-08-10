# Changelog — github.com/authsec-ai/sdk-authsec/packages/go-sdk

## v0.6.0 — M2M credential types + ID-JAG login/poll (Python parity)

Brings the agent-side identity surface toward parity with the Python SDK.
Additive and backward compatible — no exported symbol was removed or changed.
No new dependencies (`golang-jwt/jwt/v5` was already required).

**M2M — pluggable client authentication.** `AgentIdentity` now authenticates
through a `ClientAuth` abstraction, so agents can use any of:

- `ClientSecretAuth` — `client_secret_basic` (unchanged behavior; still the
  `ClientSecret` shorthand).
- `PrivateKeyJwtAuth` — `private_key_jwt` (RFC 7523): a freshly signed RS256
  assertion (5-min lifetime, single-use `jti`, audience = token endpoint). Key
  loaded from PEM content or a file path.
- `SpiffeSvidAuth` — a pre-held SPIFFE JWT-SVID sent as `client_assertion`.

`AgentIdentityConfig` gains an `Auth ClientAuth` field. It is mutually exclusive
with `ClientSecret`; setting both panics in `NewAgentIdentity`. Assertion-based
methods (private_key_jwt / SPIFFE) now also apply on the requester-bootstrap and
token-exchange calls, so the XAA/ID-JAG flow works for non-secret clients.

**M2M — Kubernetes workload identity.** New `SpiffeWorkloadIdentity` +
`SpiffeConfig`: discovers the token endpoint from the MCP server URL (PRM → AS
metadata, using the RFC 9728 alias path), fetches a JWT-SVID from the local
SPIRE agent (`spire-agent api fetch jwt`), exchanges it for a Bearer token, and
caches both. Actionable typed errors: `SpiffeIdentityError`,
`SpiffeSvidFetchError`, `SpiffeTokenExchangeError`. `SvidOverride` skips the
SPIRE subprocess for testing.

**ID-JAG — login + approval helpers.**

- `BrowserLogin` — interactive OAuth PKCE login returning an `id_token`, ready to
  pass as `WithUserSession(idToken)` to `AccessFor`. The browser launcher is
  injectable (`BrowserLoginOptions.OpenBrowser`) for testing.
- `PollUntilApproved` + `PollOptions` — poll an access-request `status_url` after
  a `*PendingApprovalError` until approved (then mint a token), denied, revoked,
  cancelled, or timed out.

**Examples:** `examples/agent-m2m` (all four M2M methods) and
`examples/agent-idjag` (browser login → access_for → poll).

**Deferred to a later phase (unchanged this round):** `DelegationClient`
(delegated JWT-SVID pull) and the SPIFFE Workload API (X.509-SVID / gRPC).

**Known limitation (pre-existing, not addressed here):** `AgentIdentity`'s
client-side PRM discovery fetches the *bare* `/.well-known/oauth-protected-resource`
path, while a Go-protected path-based resource (e.g. `/mcp`) serves PRM only at
the alias (`/.well-known/oauth-protected-resource/mcp`). `SpiffeWorkloadIdentity`
added here uses the correct alias (`BuildResourceMetadataURL`); `AgentIdentity`
still uses the bare path. Tracked as a follow-up.

## v0.5.0 — MCP-client behavior parity with the Python/TS SDKs

Brings the `Wrap` request path to parity with the Python and TypeScript
runtimes. No exported API was removed or changed; `MountMCP`, `WrapMCPHTTP`,
`NewRuntime`, `Runtime.Wrap`, `AuthMiddleware`, and `ProtectedResourceHandler`
keep their signatures. No new dependencies.

**New behavior in `Wrap` (MCP-aware path only):**

- **MCP handshake pass-through.** When a token is *present but invalid*
  (e.g. expired mid-session), `initialize` / `notifications/initialized` /
  `ping` now pass through to the wrapped handler so the MCP session survives a
  token refresh. Unauthenticated (no token) handshake requests are still
  challenged with `401`.
- **In-band JSON-RPC errors.** For JSON-RPC callers with a token present,
  `tools/call` and other auth denials are now returned **in-band** as JSON-RPC
  responses (HTTP `200` with `result.isError=true` + `_meta.authsec`, or a
  JSON-RPC `error` object with code `-32003`/`-32001`) so MCP clients surface a
  structured, readable error. Batch requests return an array of in-band results.

**⚠️ Behavior change to note.** A `tools/call` from a JSON-RPC client with a
valid-but-underscoped token previously returned **HTTP 403**; it now returns an
in-band `200` (`isError=true`, `_meta.authsec.error="insufficient_scope"`).
Non-JSON-RPC callers (no `jsonrpc:"2.0"`) still receive the classic HTTP `403`
challenge, and policy-unavailable still returns HTTP `503`. Consumers that
scripted against the raw `403` should read `_meta.authsec` instead.

**Other parity additions (non-breaking):**

- `WWW-Authenticate` challenges now include `realm="<ResourceName>"` alongside
  the existing `resource_metadata=` (RFC 9728) attribute.
- The protected-resource metadata response sets `Cache-Control: public, max-age=300`.
- **New `FromEnv(prefix ...string) Config`** builds a `Config` from `AUTHSEC_*`
  environment variables (with the dashboard's legacy aliases), mirroring the
  Python SDK's `from_env`. It parses only — call `NewRuntime`/`Config.Validate`
  to fail loudly on a bad config.

## v0.4.0 — Actionable client error helpers + richer server denials

**New `client` package** — import `github.com/authsec-ai/sdk-authsec/packages/go-sdk/client`
for typed, actionable errors on the agent/caller side:

- `ParseMCPError(source any) AccessError` — accepts `*http.Response`, `map[string]any`,
  `[]byte`, `string`, or `error`; returns one of the typed errors below or nil.
- `*ErrInsufficientScope` — tool name, required scopes, granted scopes.
  `FormatForUser()` prints the actionable message ("Tool X requires scope Y; your token has Z").
- `*ErrTokenRevoked` — token was explicitly revoked; re-auth needed.
- `*ErrClientRegistrationRevoked` — OAuth client registration revoked by admin.
- `*ErrAuthRequired` — expired, missing, or invalid token; includes stable `Reason` subcode.

**Server-side improvements:**
- `ErrInsufficientScope` gains `GrantedScopes []string` so the caller always
  sees both what they need and what they have.
- 403 body now includes `granted_scopes`; 401 body now includes a stable `reason`
  subcode (`token_revoked`, `client_registration_revoked`, `token_expired`, etc.).
- `AuthorizeTool` passes the principal's actual scopes into every scope-denial error.
- `classifyAuthReason` maps free-text descriptions from upstream validators to
  the stable subcodes above.

**First-bind race hardened:** `BindClientToRS` now checks `RowsAffected` on the
`home_workspace_id` stamp; a concurrent loser re-reads the actual home workspace
and routes correctly to `pending_approval` instead of auto-approving cross-workspace.

## v0.3.1 — Lower scope-matrix cache TTLs (Phase H-2)

**Lower scope-matrix cache TTLs.** ``defaultScopeMatrixTTL`` drops from 5 min
to 30 s; ``defaultMaxStaleAge`` from 30 min to 2 min; ``defaultRetryBackoff``
from 30 s to 10 s. Closes the "admin revokes a permission, user keeps calling
tools for 5 minutes" gap. Customers who need the old behavior for performance
can override via ``Config.ScopeMatrixTTL``.

**Note on WWW-Authenticate (H-1).** The TS and Python SDKs both shipped a
header-sanitizer hotfix in 4.4.2 to defend against control chars leaking from
upstream error bodies. The Go SDK already uses ``fmt.Sprintf(%q, …)`` for every
attribute, which performs the same escaping by construction — so no equivalent
fix is needed here. The bug class doesn't apply.

No API change. Drop-in upgrade.

## v0.3.0 — Dynamic PRM from AuthSec (admin-driven scopes)

Backend prerequisite: AuthSec ``/sdk-policy`` emits ``scopes_supported`` (live as of this release).

### What's new

- **PRM is now sourced from AuthSec.** The protected-resource metadata's
  ``scopes_supported`` field is populated from the authoritative AuthSec
  scope matrix (TTL-cached, refreshed in the background). Admin changes a
  scope in the AuthSec UI → PRM auto-updates within ≤5 min. **No code
  change, no redeploy.**
- **New ``Runtime.GetAuthoritativeScopes(ctx)`` method** returns the live
  scope list with the same fail-soft semantics as ``GetCached``. Returns
  ``nil`` when the cache is unpopulated or stale-with-error so callers can
  fall back to ``cfg.SupportedScopes``.
- **``ScopeMatrixClient`` now caches ``scopes_supported``** in addition to
  the tool→scope map. New method ``GetScopesSupported(ctx)``.
- **``ProtectedResourceHandler`` is wired** to the runtime's cache
  automatically. Manual users of ``writeMetadata`` should pass the result of
  ``rt.GetAuthoritativeScopes(ctx)``.

### Migration notes

- ``cfg.SupportedScopes`` is now a **fallback** rather than the source of
  truth. Customers using ``PolicyModeRemoteRequired`` or
  ``PolicyModeRemoteWithLocalFallback`` can drop the hardcoded
  ``SupportedScopes`` slice and rely on AuthSec exclusively (recommended).
- ``PolicyModeLocalOnly`` keeps the previous behavior — local
  ``cfg.SupportedScopes`` is authoritative for those deployments.
- Pre-v0.3.0 backends without ``scopes_supported`` in ``/sdk-policy``
  continue to work; the SDK falls back to local config transparently.

## v0.2.0 — Phase A compatibility

Backend prerequisite: AuthSec master migrations 108–112 applied.

### What's new on the backend (no SDK API change required)

- **Tenant membership precheck.** AuthSec's PDP now runs `CheckPrincipalActive` before role binding evaluation. Suspended members and suspended end users fail introspection. Go SDK code consuming token validation surfaces this as the standard `invalid_token` response.
- **Group-mediated role bindings.** Scope resolver UNIONs direct user bindings with bindings on every group the user belongs to. Tokens carry the union of effective scopes.
- **New `/uflow/v2/...` admin endpoints** for `tenant_memberships`, `tenant_end_user_states`, group-subject role bindings, and effective-access. The SDK does not yet wrap these; call them directly via `net/http` until the dedicated `authsec/admin` package ships in Phase B.

### Migration notes

- No breaking changes to the Go module's exported API.
- If your code reads `users.active` directly to determine whether a user is allowed to authenticate, switch to introspecting through the AS or query the new `tenant_memberships` / `tenant_end_user_states` tables — `users.active` becomes only one input to the precheck.

## v0.1.x — Prior versions

See git history.
