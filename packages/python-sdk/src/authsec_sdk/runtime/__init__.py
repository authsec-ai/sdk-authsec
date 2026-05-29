"""AuthSec runtime SDK — Python parity port of the Go SDK.

This module is the modern, recommended way to protect an MCP resource server
in Python. It mirrors the Go SDK's API one-for-one:

``Config`` / ``PolicyMode`` / ``ValidationMode``
    Configuration with strict mode enums. ``REMOTE_REQUIRED`` is the
    production-recommended setting; it forces the SDK to fail closed if the
    scope matrix is unreachable.

``HybridValidator``
    JWT verification (with cached JWKS) + RFC 7662 introspection. The strict
    ``JWT_AND_INTROSPECT`` mode is what the Go SDK ships by default.

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
    build_metadata_payload,
    build_resource_metadata_path,
    build_resource_metadata_url,
    build_www_authenticate,
    is_metadata_request,
    metadata_json_response,
)
from .policy import (
    ToolPolicyResult,
    ToolScopeMap,
    has_any_required,
    lookup_tool,
    required_scopes,
)
from .principal import Principal
from .scope_matrix import (
    CacheStatus,
    PolicyIncompleteError,
    ScopeMatrixClient,
)
from .server import (
    InsufficientScopeError,
    PolicyUnavailableError,
    Runtime,
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
    # config
    "Config",
    "PolicyMode",
    "ValidationMode",
    "from_env",
    # principal + policy
    "Principal",
    "ToolPolicyResult",
    "ToolScopeMap",
    "lookup_tool",
    "required_scopes",
    "has_any_required",
    # validator
    "HybridValidator",
    "new_validator",
    "TokenInvalidError",
    "TokenInactiveError",
    # scope matrix
    "ScopeMatrixClient",
    "CacheStatus",
    "PolicyIncompleteError",
    # manifest
    "ManifestTool",
    "publish_manifest",
    "publish_manifest_safe",
    # metadata
    "build_metadata_payload",
    "build_resource_metadata_path",
    "build_resource_metadata_url",
    "build_www_authenticate",
    "is_metadata_request",
    "metadata_json_response",
    # runtime
    "Runtime",
    "mount_mcp",
    "principal_from_context",
    "InsufficientScopeError",
    "PolicyUnavailableError",
]
