# Changelog — @authsec/sdk (TypeScript)

## 4.4.2 — Hotfixes: header sanitizer + lower cache TTLs (Phase H-1 / H-2)

**1. WWW-Authenticate header sanitizer (H-1).** Node ``TypeError [ERR_INVALID_CHAR]:
Invalid character in header content ["WWW-Authenticate"]`` crashed the response
handler whenever an upstream error body (typically Hydra) leaked CR / LF / control
chars into ``error_description``. The denial we tried to send surfaced as a 500
with an HTML body, defeating the 401-with-PRM-discovery flow.

  Fix: ``buildWwwAuthenticate`` now sanitizes every attribute (realm, error,
  error_description, scope, resource_metadata) before emitting it — control chars
  (0x00–0x1F + 0x7F) become spaces, backslash + double-quote escape per RFC 7230,
  values truncate to 200 chars.

**2. Lower scope-matrix cache TTLs (H-2).** Default ``scopeMatrixCacheTtlSeconds``
drops from 300 s to 30 s; stale-with-error window drops from 1800 s to 120 s;
retry backoff from 30 s to 10 s. Closes the "admin revokes a permission, user
keeps calling tools for 5 minutes" gap. Customers who need the old behavior for
performance can override via ``Config.scopeMatrixCacheTtlSeconds``.

No API changes in either fix. Drop-in upgrade.

## 4.4.0 — Dynamic PRM from AuthSec (admin-driven scopes)

Backend prerequisite: AuthSec ``/sdk-policy`` now emits ``scopes_supported`` (live as of this release).

### What's new

- **PRM is now sourced from AuthSec.** The ``/.well-known/oauth-protected-resource``
  metadata document's ``scopes_supported`` field is now populated from the
  authoritative AuthSec scope matrix (TTL-cached, refreshed in the background).
  Admin adds/removes/renames a scope in the AuthSec UI → PRM auto-updates
  within ≤5 minutes. **No code change, no redeploy.**
- **New ``Runtime.getAuthoritativeScopes()`` method** returns the live scope
  list, with the same fail-soft semantics as ``getCached()``. Returns ``null``
  when the cache is unpopulated or stale-with-error so callers can fall back
  to ``cfg.supportedScopes``.
- **``buildMetadataPayload`` / ``metadataJsonResponse`` accept an
  ``authoritativeScopes`` argument.** The mountMCP PRM handler passes this
  automatically; manual users should call ``runtime.getAuthoritativeScopes()``
  and pass the result.
- **``ScopeMatrixClient`` now caches ``scopes_supported``** in addition to the
  tool→scope map. Same TTL / staleAge / retry semantics.

### Migration notes

- ``cfg.supportedScopes`` is now a **fallback** rather than the source of
  truth. Customers using ``policyMode=remote_required`` or
  ``remote_with_local_fallback`` can drop their hardcoded ``supportedScopes``
  array and rely on AuthSec exclusively (recommended).
- ``policyMode=local_only`` deployments keep the previous behavior — local
  ``cfg.supportedScopes`` is authoritative for them.
- Pre-4.4.0 backends without ``scopes_supported`` in ``/sdk-policy`` will
  continue to work; the SDK falls back to local config transparently.

## 4.1.0 — Phase A compatibility

Backend prerequisite: AuthSec master migrations 108–112 applied.

### What's new on the backend (no SDK API change required)

- **Tenant membership precheck.** `services/rbac_service.go` `CheckPrincipalActive` now runs before any role binding evaluation. Tokens issued to a user whose `tenant_memberships.status` is not `active` (or whose `tenant_end_user_states.status='suspended'`) will fail introspection. Existing SDK-mediated tool calls correctly surface this as `invalid_token` / `inactive_token` from the AS — no client code change needed.
- **Group-mediated role bindings.** `role_bindings.group_id` is a new optional principal column. The scope resolver UNIONs direct user bindings with bindings on every group the user belongs to. Tokens now carry the union; existing SDK flows benefit transparently.
- **New `/uflow/v2/...` admin endpoints** for `tenant_memberships`, `tenant_end_user_states`, group-subject role bindings, and effective-access. The SDK currently does not wrap these — they're admin/operator surfaces typically called from the admin UI via fetch. A dedicated `client.admin.memberships` helper is on the roadmap for Phase B.

### Migration notes

- No breaking changes. The 4.0.x line is wire-compatible with both pre– and post–Phase A backends.
- If you build server-side tooling that introspects user state, the new `/uflow/v2/tenants/:tenant_id/end-users/:user_id` endpoint is the canonical source for plan tier and suspension status (replaces hand-rolled queries on `users.active`).

## 4.0.0 — Major release prior to Phase A

Initial public 4.x release (see git history for details).
