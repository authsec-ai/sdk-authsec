# Best practices

Security, deployment, and a production checklist for the Go SDK. These are the
defaults we'd choose for a production deployment; deviate deliberately.

- [Security](#security)
- [Deployment](#deployment)
- [Agent (caller) side](#agent-caller-side)
- [Production checklists](#production-checklists)

---

## Security

**Fail closed.** Run protected servers with `PolicyModeRemoteRequired`. If the
tool→scope policy can't be fetched, the SDK denies every tool call rather than
guessing. Fail-open (via `PolicyModeOpen`) turns a network hiccup into a silent
security outage — keep it out of production.

**Validate signatures *and* revocation.** Use
`ValidationModeJWTAndIntrospect`. A signature check alone can't see a token
revoked five minutes ago; introspection asks the AS live. Never use
`ValidationModeJWTOrIntrospect` outside a migration — it lets a token pass on
introspection even when its signature is invalid.

**Bind tokens to your exact resource.** `ResourceURI` must be byte-for-byte the
URL agents call (scheme, host, path) and the JWT audience. A mismatch is the
most common cause of "valid token, still 401". Re-check it whenever the public
URL changes (ngrok rotation, DNS cutover).

**Prefer credentials that never travel.** On the caller side, the security
ladder is client secret → private-key JWT → SPIFFE. Move up it where you can:
`PrivateKeyJwtAuth` keeps the key on the host and sends only short-lived,
single-use, audience-bound assertions; `SpiffeWorkloadIdentity` stores no
credential at all.

**Treat secrets as secrets.** Introspection secrets and client secrets are
shown once. Keep them out of source control and images; inject them at runtime
(env, secret manager). Rotate from the dashboard if leaked. The SDK's
credential types have `String()` methods that never print secret material — but
don't log raw config either.

**Map every tool.** Unmapped tools fail closed by design. Review the Tools tab;
leave a tool unmapped only when you intend it to be unreachable. Mark a tool
*public* explicitly if it truly needs no scope.

**Least privilege on scopes.** Request only the scopes a caller needs
(`WithRequestedScopes`). Effective access is
`requested ∩ scopes_supported ∩ user_effective` — narrow requests shrink blast
radius and make audits legible.

---

## Deployment

**Publish the manifest.** Set `PublishManifest=true` so your tool inventory
stays in sync with the dashboard and admins can map new tools without you
shipping a config. Confirm success in boot logs
(`manifest publish succeeded`) or via `/sdk-manifest-status`.

**Give the SDK a real HTTP client.** The default has a 10s timeout, which is
fine, but in production set `Config.HTTPClient` with your own transport
(connection pooling, proxy, timeouts) so JWKS/introspection/policy calls behave
like the rest of your egress.

**Wire structured logging.** Set `Config.Logger` to your app's `*slog.Logger`
so SDK events land in your log pipeline with the right attributes.

**Tune the policy cache to your risk tolerance.** `ScopeMatrixTTL` defaults to
30s — the window between an admin changing a permission and your server
enforcing it. Lower it for tighter revocation, raise it to reduce policy-fetch
load. Don't set it so high that revocations linger.

**Keep `ResourceURI` stable.** It's the anchor for tokens and discovery.
Changing it invalidates outstanding tokens and requires a dashboard update. In
dev with ngrok, expect free URLs to rotate — update `AUTHSEC_RESOURCE_URI`, the
application's base URL in the dashboard, and restart.

**Don't rebuild what the SDK owns.** No hand-written bearer challenges, JWT
parsing, introspection calls, `tools/list` filtering, `tools/call` scope
checks, or manifest uploads. Keep your MCP server focused on tools and upstream
execution; let the SDK own the boundary.

---

## Agent (caller) side

**One `AgentIdentity` per process, reused.** It caches tokens internally.
Constructing a new one per request throws the cache away and hammers the token
endpoint.

**Handle `401` with clear-cache-and-retry-once.** A mid-session token can
expire or be revoked. On a `401` from the MCP server, call
`agent.ClearCache(resource)` and retry a single time; if it's a
`*ConnectionRevokedError`, re-request access instead of looping.

**Validate credentials at startup.** `NewPrivateKeyJwtAuth` returns an error —
check it during boot so a bad PEM fails fast, not on the first user request.

**Type-switch on errors.** Agent-side errors are typed (`*PendingApprovalError`,
`*ApprovalDeniedError`, `*CredentialInvalidError`, …). Use `errors.As` to react
correctly — poll on pending, stop on denied, re-auth on revoked.

**Request scopes that exist.** Requesting an undefined scope looks exactly like
"waiting for approval forever". Pull the target's PRM `scopes_supported` and
request from that set.

---

## Production checklists

### Protecting a server

- [ ] Resource server exists in AuthSec; `ResourceURI` matches the public
      endpoint and token audience exactly.
- [ ] `IntrospectionClientID` = the resource-server UUID; secret stored
      securely (not in source/images).
- [ ] `SupportedScopes` matches the dashboard's `scopes_supported`.
- [ ] `PolicyMode = PolicyModeRemoteRequired`.
- [ ] `ValidationMode = ValidationModeJWTAndIntrospect`.
- [ ] `PublishManifest = true`; boot logs show manifest success.
- [ ] Every non-public tool mapped to a scope before launch.
- [ ] Default access policy grants at least one useful scope.
- [ ] `Config.HTTPClient` and `Config.Logger` set for production.
- [ ] `tools/list` and `tools/call` tested with read-only and write-capable
      tokens.
- [ ] Metadata (`/.well-known/oauth-protected-resource/...`) and the 401
      challenge verified on the public URL.

### Building an agent (M2M / ID-JAG)

- [ ] Service account (or agent) registered; role/scopes granted for the target
      RS.
- [ ] Strongest practical credential chosen (prefer private-key JWT / SPIFFE
      over client secret).
- [ ] One reused `AgentIdentity`; `ClearCache` + single retry on `401`.
- [ ] Requested scopes exist on the target (checked against PRM).
- [ ] Typed-error handling (`errors.As`) for pending/denied/revoked/credential.
- [ ] For ID-JAG: redirect URI/port matches the registration; poll on first
      contact; headless-safe `OpenBrowser` where needed.
- [ ] For SPIFFE: SPIRE registration entry maps the pod to the exact
      `spiffe://…` ID; trust-domain JWKS registered in AuthSec; prefer
      `SpiffeWorkloadIdentity` for auto-renew.

---

[← Docs home](README.md)
