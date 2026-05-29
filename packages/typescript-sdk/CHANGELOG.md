# Changelog — @authsec/sdk (TypeScript)

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
