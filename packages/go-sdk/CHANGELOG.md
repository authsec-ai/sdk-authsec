# Changelog — github.com/authsec-ai/sdk-authsec/packages/go-sdk

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
