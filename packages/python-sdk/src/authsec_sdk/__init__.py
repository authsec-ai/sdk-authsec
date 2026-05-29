"""authsec-sdk — Python SDK for AuthSec.

Two API surfaces coexist:

1. :mod:`authsec_sdk.runtime` — the modern, recommended way to protect an MCP
   resource server. Mirrors the Go SDK one-for-one. Use ``mount_mcp(app,
   path, handler, cfg)`` or build a :class:`Runtime` directly. See
   ``examples/local_authsec_demo_server.py`` for a working FastAPI app.

2. Legacy decorators (:func:`protected_by_AuthSec`,
   :func:`run_mcp_server_with_oauth`) — preserved for back-compat. New
   deployments should use the runtime API.

Both surfaces target the same AuthSec backend.
"""

from .core import (
    mcp_tool,
    protected_by_AuthSec,
    run_mcp_server_with_oauth,
    ServiceAccessSDK,
    ServiceAccessError,
    configure_auth,
    get_config,
    is_configured,
    load_config,
    test_auth_service,
    test_services,
)

# ─── Runtime SDK (modern, recommended) ─────────────────────────────────
from .runtime import (
    # config
    Config,
    PolicyMode,
    ValidationMode,
    from_env,
    # principal + policy
    Principal,
    ToolPolicyResult,
    ToolScopeMap,
    lookup_tool,
    required_scopes,
    has_any_required,
    # validator
    HybridValidator,
    new_validator,
    TokenInvalidError,
    TokenInactiveError,
    # scope matrix
    ScopeMatrixClient,
    CacheStatus,
    PolicyIncompleteError,
    # manifest
    ManifestTool,
    publish_manifest,
    publish_manifest_safe,
    # metadata
    build_metadata_payload,
    build_resource_metadata_path,
    build_resource_metadata_url,
    build_www_authenticate,
    is_metadata_request,
    metadata_json_response,
    # runtime
    Runtime,
    mount_mcp,
    principal_from_context,
    InsufficientScopeError,
    PolicyUnavailableError,
)

# Import CIBA SDK for voice clients and passwordless authentication
from .ciba_sdk import CIBAClient

# Import Delegation SDK for AI agent trust delegation
from .delegation_sdk import (
    DelegationClient,
    DelegationError,
    DelegationTokenExpired,
    DelegationTokenNotFound,
)

# Import standalone SPIFFE Workload API SDK
from .spiffe_workload_api import QuickStartSVID, WorkloadAPIClient

# Also import SDK Manager SPIRE integration (optional)
try:
    from .spire_sdk import WorkloadSVID
except ImportError:
    WorkloadSVID = None

__version__ = "4.3.0"
__all__ = [
    # ── Runtime SDK (modern) ────────────────────────────────────
    "Config",
    "PolicyMode",
    "ValidationMode",
    "from_env",
    "Principal",
    "ToolPolicyResult",
    "ToolScopeMap",
    "lookup_tool",
    "required_scopes",
    "has_any_required",
    "HybridValidator",
    "new_validator",
    "TokenInvalidError",
    "TokenInactiveError",
    "ScopeMatrixClient",
    "CacheStatus",
    "PolicyIncompleteError",
    "ManifestTool",
    "publish_manifest",
    "publish_manifest_safe",
    "build_metadata_payload",
    "build_resource_metadata_path",
    "build_resource_metadata_url",
    "build_www_authenticate",
    "is_metadata_request",
    "metadata_json_response",
    "Runtime",
    "mount_mcp",
    "principal_from_context",
    "InsufficientScopeError",
    "PolicyUnavailableError",
    # ── Legacy MCP Auth & Services ──────────────────────────────
    "protected_by_AuthSec",
    "run_mcp_server_with_oauth",
    "mcp_tool",
    "ServiceAccessSDK",
    "ServiceAccessError",
    "configure_auth",
    "get_config",
    "is_configured",
    "load_config",
    "test_auth_service",
    "test_services",
    # ── CIBA / Delegation / SPIFFE ─────────────────────────────
    "CIBAClient",
    "DelegationClient",
    "DelegationError",
    "DelegationTokenExpired",
    "DelegationTokenNotFound",
    "QuickStartSVID",
    "WorkloadAPIClient",
    "WorkloadSVID",
]
