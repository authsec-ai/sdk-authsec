# Changelog — authsec-sdk (Python)

## 4.7.1 — mount_mcp works out of the box with mcp >= 1.27

**E2E-verified against the live AuthSec server (2026-07-15): the documented
one-line `mount_mcp` server, ID-JAG delegation (including live revocation),
and M2M client-secret + private-key-JWT all pass.**

### Fixed
- **`mount_mcp` auto-configures FastMCP instances** — the documented
  `mount_mcp(app, "/mcp", mcp, cfg)` one-liner now works unmodified with
  `mcp >= 1.27`:
  - starts the StreamableHTTP session manager with the host app's lifecycle
    (was: `500 Task group is not initialized` on every request); a
    caller-managed `session_manager.run()` lifespan is detected and honored
  - enables stateless JSON responses so direct JSON-RPC POSTs work without
    an `initialize` handshake (was: `400 Bad Request`)
  - appends the host from `cfg.resource_uri` to FastMCP's DNS-rebinding
    allow-list so requests via the server's public URL are accepted
    (was: `421 Invalid Host header`); protection stays enabled and
    caller-provided `transport_security` entries are preserved
- **`tools/list` scope filtering no longer corrupts responses** — the filtered
  body was sent with the original response's stale `Content-Length`, causing
  uvicorn to abort the connection (`Response content longer than
  Content-Length`); the header is now recomputed

## 4.7.0 — Three M2M auth methods, package restructure, security hardening

**E2E-verified against the live AuthSec server (2026-07-05): ID-JAG delegation
and all three M2M methods pass.**

### Added
- **Three interchangeable M2M credential classes** (`authsec_sdk.identity.credentials`),
  all usable via `AgentIdentity(issuer, client_id, auth=...)`:
  - `ClientSecretAuth` — HTTP Basic (`client_secret_basic`)
  - `PrivateKeyJwtAuth` — RFC 7523 signed assertion (RS256, `kid`, 5-min
    single-use `jti`, audience-bound); accepts a PEM string or file path
  - `SpiffeSvidAuth` — SPIFFE JWT-SVID client assertion
- `py.typed` (PEP 561) — type checkers now see all hints
- Documentation suite: `docs/` (MCP protection, M2M auth, ID-JAG delegation —
  step-by-step with dashboard screenshots); README rewritten

### Changed — package restructure (old imports keep working through v4)
- `agent_identity.py` → `identity/agent.py`; `spiffe_identity.py` → `identity/spiffe.py`
- `core.py` → `_legacy/core.py`; `ciba_sdk.py` → `ciba.py`;
  `delegation_sdk.py` → `delegation.py`; `spire_sdk.py` → `spiffe/spire.py`
- `spiffe_workload_api/` → `spiffe/` (client → `workload_api_client.py`,
  `simple` → `quick_start_svid.py`); `client/langgraph.py` → `integrations/langgraph.py`
- Every old path remains as a deprecation shim emitting `DeprecationWarning`;
  removal planned for v5

### Fixed
- `browser_login`: OAuth `state` validation (CSRF), `resource` indicator
  (RFC 8707) in both auth URL and token exchange, default scopes fixed to
  `openid email profile`, login timeout, port-in-use error, auth URL always
  printed for headless use
- `_discover_prm`: correct RFC 9728 path construction (resource path suffix)
- `poll_until_approved`: no longer clears the ID-JAG cache before the final
  token call; nil-UUID pending entries ignored (server-side bug workaround)
- Token requests with assertion-based auth now include `client_id` in the body
- Scope matrix: refresh race fixed (check-and-set inside the lock); background
  refresh task no longer garbage-collected; TTL default aligned to 30 s
- Validator: JWT/JWKS verification moved off the event loop; pooled
  introspection HTTP session
- Delegation: `request()` returns a `DelegationResponse` with a pre-read body
  (was returning a closed aiohttp response)
- CORS in legacy server: configurable allowlist via `AUTHSEC_CORS_ORIGINS`
- `Config.introspection_client_secret` no longer appears in `repr()`

### Removed
- `preferred_mode="xaa-only"` (Python-only divergence from the TS SDK; caused
  ghost pending requests). Use `"xaa-allowed"`.



**Follow-up to 4.4.2 sanitizer.** The H-1 fix stripped CR / LF / NUL but
allowed everything ≥ 0x80 through. ASGI/uvicorn also rejects non-ASCII bytes
in header values, so localized Hydra error strings, smart quotes, U+00A0
non-breaking space, U+200B zero-width space, and emoji slipped past the
guard and crashed the 401 the same way control chars did. Reproduction in
the wild: revoking a role on the AuthSec Assignments page caused the next
MCP client request to receive an HTML error page instead of a clean 401.

**Fix:** ``_sanitize_header_value`` now keeps only printable ASCII
(0x20–0x7E), converts embedded ``\\`` and ``"`` to apostrophes (some HTTP
stacks reject backslash sequences in header values), and truncates to 200
chars. Matches TS sdk 4.4.3.

No API changes. Drop-in upgrade.

## 4.4.2 — Hotfixes: header sanitizer + lower cache TTLs (Phase H-1 / H-2)

**1. WWW-Authenticate header sanitizer (H-1).** ASGI/WSGI servers reject HTTP
response headers containing CR / LF / NUL (RFC 7230 §3.2.6). When upstream error
bodies leaked control chars into ``error_description``, ``build_www_authenticate``
emitted an unparseable header and the server crashed the 401 response instead
of delivering a clean denial.

  Fix: every attribute in ``build_www_authenticate`` (realm, error,
  error_description, scope, resource_metadata) now passes through
  ``_sanitize_header_value`` — control chars (0x00–0x1F + 0x7F) become spaces,
  backslash + double-quote escape per RFC 7230 quoted-string rules, values
  truncate to 200 chars.

**2. Lower scope-matrix cache TTLs (H-2).** Default ``scope_matrix_ttl`` drops
from 5 min to 30 s; stale-with-error window from 30 min to 2 min; retry backoff
from 30 s to 10 s. Closes the "admin revokes a permission, user keeps calling
tools for 5 minutes" gap. Customers who need the old behavior for performance
can override via ``Config.scope_matrix_ttl``.

No API changes. Drop-in upgrade.

## 4.4.0 — Dynamic PRM from AuthSec (admin-driven scopes)

Backend prerequisite: AuthSec ``/sdk-policy`` emits ``scopes_supported`` (live as of this release).

### What's new

- **PRM is now sourced from AuthSec.** The protected-resource metadata's
  ``scopes_supported`` field is populated from the authoritative AuthSec
  scope matrix (TTL-cached, refreshed in the background). Admin changes a
  scope in the AuthSec UI → PRM auto-updates within ≤5 min. **No code
  change, no redeploy.**
- **New ``Runtime.get_authoritative_scopes()`` method** returns the live
  scope list. Returns ``None`` when the cache is unpopulated or
  stale-with-error so callers can fall back to ``cfg.supported_scopes``.
- **``ScopeMatrixClient`` now caches ``scopes_supported``** in addition to
  the tool→scope map. New method ``get_scopes_supported()``.
- **``mount_mcp`` PRM handler is wired** to the runtime's cache automatically.
  Manual users of ``metadata_json_response`` should pass the result of
  ``await rt.get_authoritative_scopes()``.

### Migration notes

- ``cfg.supported_scopes`` is now a **fallback**. Customers using
  ``policy_mode=remote_required`` or ``remote_with_local_fallback`` can drop
  their hardcoded ``supported_scopes`` and rely on AuthSec exclusively
  (recommended).
- ``policy_mode=local_only`` keeps the previous behavior.
- Pre-4.4.0 backends without ``scopes_supported`` in ``/sdk-policy`` keep
  working; the SDK falls back to local config transparently.

## 4.3.0 — Runtime SDK at Go parity

Major addition: the new ``authsec_sdk.runtime`` subpackage brings the Python
SDK to feature parity with the Go SDK. Customers can now wrap an existing
Python MCP server in 5 lines and get RFC 6750 / RFC 9728 / scope-matrix-aware
token validation that matches the Go SDK behavior bit-for-bit.

### New: ``authsec_sdk.runtime``

* **``Config`` dataclass** — full mirror of ``authsec.Config`` in the Go SDK.
  Fields: ``issuer``, ``authorization_server``, ``jwks_url``,
  ``introspection_url``, ``introspection_client_id``,
  ``introspection_client_secret``, ``resource_uri``, ``resource_name``,
  ``resource_server_id``, ``supported_scopes``, ``tool_scopes``,
  ``scope_matrix_ttl``, ``policy_mode``, ``validation_mode``,
  ``publish_manifest``, ``tool_scope_suggestions``,
  ``tool_inventory_provider``.
* **``PolicyMode`` enum** — ``UNSET``, ``REMOTE_REQUIRED`` (production
  default), ``REMOTE_WITH_LOCAL_FALLBACK``, ``LOCAL_ONLY``, ``OPEN``.
  Same semantics as Go's ``PolicyMode``.
* **``ValidationMode`` enum** — ``UNSET``, ``JWT_ONLY``,
  ``INTROSPECTION_ONLY``, ``JWT_AND_INTROSPECT`` (production default),
  ``JWT_OR_INTROSPECT``. Same semantics as Go's ``ValidationMode``.
* **``HybridValidator``** — JWT signature verification with cached JWKS
  (``PyJWKClient``) + RFC 7662 introspection with HTTP Basic auth.
  ``JWT_AND_INTROSPECT`` enforces the strict path (JWT must pass AND
  introspection must return ``active=true``).
* **``ScopeMatrixClient``** — fetches the authoritative tool→scope map
  from ``/authsec/resource-servers/<rsid>/sdk-policy``, caches with TTL,
  enforces **deny-all** on ``policy_complete=false``, bounded stale
  serving up to 30 minutes on transient transport failures, with CAS-gated
  background refresh on TTL expiry.
* **``Runtime`` + ``mount_mcp``** — the customer-facing entry point.
  Wraps an existing FastAPI / Starlette MCP route with token validation,
  tool-call authorization, and the RFC 9728 protected-resource metadata
  endpoint. Returns ``401`` with a ``WWW-Authenticate: Bearer realm=…,
  resource_metadata=…`` challenge for unauthenticated requests, and
  ``403 insufficient_scope`` for tool-scope failures.
* **``publish_manifest`` / ``publish_manifest_safe``** — best-effort
  one-way push of the tool inventory to AuthSec's ``/sdk-manifest``
  endpoint. Supports synthetic JSON-RPC ``initialize`` →
  ``notifications/initialized`` → paginated ``tools/list`` enumeration
  or a caller-supplied ``ToolInventoryProvider`` escape hatch.
* **``Principal`` + ``principal_from_context()``** — typed identity
  object available to downstream handlers via a contextvar; equivalent
  to Go's ``PrincipalFromContext``.

### Example

```python
from fastapi import FastAPI
from authsec_sdk.runtime import Config, PolicyMode, ValidationMode, mount_mcp

cfg = Config(
    issuer="https://dev.api.authsec.dev",
    authorization_server="https://dev.api.authsec.dev",
    jwks_url="https://dev.api.authsec.dev/oauth/jwks",
    introspection_url="https://dev.api.authsec.dev/oauth/introspect",
    introspection_client_id="525da3b4-4206-4070-ad68-90cc3a6de43b",
    introspection_client_secret=os.environ["AUTHSEC_INTROSPECTION_CLIENT_SECRET"],
    resource_server_id="525da3b4-4206-4070-ad68-90cc3a6de43b",
    resource_uri="https://mcp.example.com/mcp",
    resource_name="GitHub MCP Server",
    policy_mode=PolicyMode.REMOTE_REQUIRED,
    validation_mode=ValidationMode.JWT_AND_INTROSPECT,
    publish_manifest=True,
)

app = FastAPI()
mount_mcp(app, "/mcp", existing_mcp_handler, cfg)
```

A complete working example ships in
``examples/protect_existing_mcp_server.py``.

### Phase A backend compatibility

* The new runtime honors AuthSec's membership precheck: a token issued to a
  suspended ``tenant_membership`` or suspended ``tenant_end_user_state``
  returns ``active=false`` from introspection and the runtime fails closed.
* Group-derived scopes are picked up transparently — the scope matrix from
  ``/sdk-policy`` already reflects the union of direct and group bindings.

### Dependencies

* Added: ``pyjwt[crypto] >= 2.8.0`` for JWT signature verification.
* Added: ``cryptography >= 42.0.0`` (transitively required by PyJWT).
* Added: ``starlette >= 0.36.0`` for the ``mount_mcp`` ASGI implementation.

### Back-compat

* The legacy ``protected_by_AuthSec`` decorator and
  ``run_mcp_server_with_oauth`` entry point are preserved unchanged. Both
  surfaces work side-by-side against the same backend. New deployments
  should use ``mount_mcp``.

### Testing

24 unit tests covering Config validation (happy + every rejection path),
``lookup_tool`` semantics, ``Principal.has_any_scope``, RFC 9728 metadata
path construction, and ``WWW-Authenticate`` header building. All passing.

## 4.2.0 — Phase A backend compatibility (transparent)

Backend prerequisite: AuthSec master migrations 108–112 applied. No SDK API
changes; membership precheck and group-derived scopes flow through
transparently via existing introspection + token paths. See `runtime` in
4.3.0 for the explicit API.

## 4.1.2 — Prior release

See git history.
