"""AuthSec runtime SDK — Python parity port of the TypeScript + Go SDKs.

This module is the modern, recommended way to protect an MCP resource server
in Python. It mirrors the TypeScript SDK's API:

``Config`` / ``PolicyMode`` / ``ValidationMode``
    Configuration with strict mode enums. ``REMOTE_REQUIRED`` is the
    production-recommended setting; it forces the SDK to fail closed if the
    scope matrix is unreachable.

``HybridValidator``
    JWT verification (with cached JWKS) + RFC 7662 introspection. The strict
    ``JWT_AND_INTROSPECT`` mode is the recommended default.

``ScopeMatrixClient``
    Fetches and caches the tool→scope mapping from AuthSec's
    ``/sdk-policy`` endpoint. Enforces deny-all when
    ``policy_complete=false``. Bounded stale serving up to ``max_stale_age``.

``publish_manifest`` / ``publish_manifest_safe``
    Best-effort one-way push of the tool inventory to AuthSec's
    ``/sdk-manifest`` endpoint at startup.

``mount_mcp`` / ``Runtime``
    Customer-facing entry points. ``mount_mcp`` wraps an existing MCP
    Starlette/FastAPI handler with token validation, tool-policy enforcement,
    and RFC 9728 protected-resource metadata. Returns the underlying
    :class:`Runtime` so callers can hook startup themselves.

New in this version (TypeScript parity):
    - :class:`AuthorizeResult` / :class:`AuthorizeDenial` / :attr:`DenialCode`
      — structured result types from ``Runtime.authorize()`` / ``Runtime.authorize_principal()``.
    - :meth:`Runtime.create` — async factory that combines construction + startup.
    - :meth:`Runtime.authorize` — combined token validation + tool auth returning
      ``AuthorizeResult`` (no exceptions for auth failures).
    - :meth:`Runtime.authorize_principal` — per-tool check on an already-validated
      principal (used for ``tools/list`` filtering).
    - :func:`extract_tool_id_from_body` / :func:`extract_tool_ids_from_body`
      — batch-aware tool-id extraction helpers.
    - :class:`LookupResult` / ``ToolPolicyOutcome`` — rich policy lookup result.
    - :func:`tool_scope_map_from_record` — helper to build a ToolScopeMap from a
      plain ``{tool: [scopes]}`` dict.
    - ``PROTECTED_RESOURCE_PREFIX`` — the RFC 9728 well-known path prefix constant.

Legacy decorators (``protected_by_AuthSec``, ``run_mcp_server_with_oauth``)
in ``authsec_sdk.core`` are preserved for back-compat. New deployments
should use ``mount_mcp``.
"""

from __future__ import annotations

from .config import Config, PolicyMode, ValidationMode, from_env
from .manifest import (
    ManifestTool,
    publish_manifest,
    publish_manifest_safe,
)
from .metadata import (
    PROTECTED_RESOURCE_PREFIX,
    build_metadata_payload,
    build_resource_metadata_path,
    build_resource_metadata_url,
    build_www_authenticate,
    is_metadata_request,
    metadata_json_response,
)
from .policy import (
    LookupResult,
    ToolPolicyOutcome,
    ToolPolicyResult,
    ToolScopeMap,
    has_any_required,
    lookup_tool,
    required_scopes,
    tool_scope_map_from_record,
    toolScopeMapFromRecord,
)
from .principal import Principal
from .scope_matrix import (
    CacheStatus,
    PolicyIncompleteError,
    ScopeMatrixClient,
)
from .server import (
    AuthorizeDenial,
    AuthorizeResult,
    DenialCode,
    InsufficientScopeError,
    PolicyUnavailableError,
    Runtime,
    extract_tool_id_from_body,
    extract_tool_ids_from_body,
    extractToolIdFromBody,
    extractToolIdsFromBody,
    mount_mcp,
    principal_from_context,
)
from .validator import (
    HybridValidator,
    TokenInactiveError,
    TokenInvalidError,
    new_validator,
)

__all__ = [
    # ── config ──────────────────────────────────────────────────────────────
    "Config",
    "PolicyMode",
    "ValidationMode",
    "from_env",
    # ── principal + policy ──────────────────────────────────────────────────
    "Principal",
    # New (TypeScript parity)
    "LookupResult",
    "ToolPolicyOutcome",
    "tool_scope_map_from_record",
    "toolScopeMapFromRecord",
    # Legacy (kept for back-compat)
    "ToolPolicyResult",
    "ToolScopeMap",
    "lookup_tool",
    "required_scopes",
    "has_any_required",
    # ── validator ────────────────────────────────────────────────────────────
    "HybridValidator",
    "new_validator",
    "TokenInvalidError",
    "TokenInactiveError",
    # ── scope matrix ─────────────────────────────────────────────────────────
    "ScopeMatrixClient",
    "CacheStatus",
    "PolicyIncompleteError",
    # ── manifest ─────────────────────────────────────────────────────────────
    "ManifestTool",
    "publish_manifest",
    "publish_manifest_safe",
    # ── metadata ─────────────────────────────────────────────────────────────
    "PROTECTED_RESOURCE_PREFIX",
    "build_metadata_payload",
    "build_resource_metadata_path",
    "build_resource_metadata_url",
    "build_www_authenticate",
    "is_metadata_request",
    "metadata_json_response",
    # ── runtime (core) ───────────────────────────────────────────────────────
    "Runtime",
    "mount_mcp",
    "principal_from_context",
    # New (TypeScript parity)
    "AuthorizeResult",
    "AuthorizeDenial",
    "DenialCode",
    "extract_tool_id_from_body",
    "extract_tool_ids_from_body",
    "extractToolIdFromBody",
    "extractToolIdsFromBody",
    # Legacy exceptions (kept for back-compat)
    "InsufficientScopeError",
    "PolicyUnavailableError",
]
