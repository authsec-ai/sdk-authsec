# Changelog — authsec-sdk (Python)

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
