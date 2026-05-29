# Changelog — github.com/authsec-ai/sdk-authsec/packages/go-sdk

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
