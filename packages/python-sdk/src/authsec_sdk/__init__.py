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
    LookupResult,
    ToolPolicyOutcome,
    ToolPolicyResult,
    ToolScopeMap,
    lookup_tool,
    required_scopes,
    has_any_required,
    tool_scope_map_from_record,
    toolScopeMapFromRecord,
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
    PROTECTED_RESOURCE_PREFIX,
    build_metadata_payload,
    build_resource_metadata_path,
    build_resource_metadata_url,
    build_www_authenticate,
    is_metadata_request,
    metadata_json_response,
    # runtime — new TypeScript-parity APIs
    Runtime,
    mount_mcp,
    principal_from_context,
    AuthorizeResult,
    AuthorizeDenial,
    DenialCode,
    extract_tool_id_from_body,
    extract_tool_ids_from_body,
    extractToolIdFromBody,
    extractToolIdsFromBody,
    # runtime — legacy exception-based API (kept for back-compat)
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

# Client-side error helpers (agent-side: surface AuthSec 401/403 as typed
# Python exceptions instead of opaque ToolException strings).
from .client import (
    AuthRequiredError,
    AuthSecAccessError,
    ClientRegistrationRevokedError,
    InsufficientScopeError as ClientInsufficientScopeError,
    TokenRevokedError,
    parse_mcp_error,
)

# Import standalone SPIFFE Workload API SDK
from .spiffe_workload_api import QuickStartSVID, WorkloadAPIClient

# Also import SDK Manager SPIRE integration (optional)
try:
    from .spire_sdk import WorkloadSVID
except ImportError:
    WorkloadSVID = None

# Agent Identity SDK — client-side flow selection + M2M / XAA token acquisition
from .agent_identity import (
    AgentIdentity,
    AuthSecIdentityError,
    PendingApprovalError,
    ApprovalDeniedError,
    ConnectionRevokedError,
    TrustedIssuerMissingError,
    SubjectMappingFailedError,
    ResourceNotRegisteredError,
    CredentialInvalidError,
    WorkloadNotAttestedError,
    # TypeScript parity: standalone polling helper
    poll_until_approved,
    PollOptions,
)

__version__ = "4.6.0"
__all__ = [
    # ── Runtime SDK (modern) — TypeScript-parity additions ────────────────
    "Config",
    "PolicyMode",
    "ValidationMode",
    "from_env",
    "Principal",
    # Policy — new (TypeScript parity)
    "LookupResult",
    "ToolPolicyOutcome",
    "tool_scope_map_from_record",
    "toolScopeMapFromRecord",
    # Policy — legacy (kept for back-compat)
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
    # Metadata — new (TypeScript parity)
    "PROTECTED_RESOURCE_PREFIX",
    "build_metadata_payload",
    "build_resource_metadata_path",
    "build_resource_metadata_url",
    "build_www_authenticate",
    "is_metadata_request",
    "metadata_json_response",
    # Runtime — new (TypeScript parity)
    "Runtime",
    "mount_mcp",
    "principal_from_context",
    "AuthorizeResult",
    "AuthorizeDenial",
    "DenialCode",
    "extract_tool_id_from_body",
    "extract_tool_ids_from_body",
    "extractToolIdFromBody",
    "extractToolIdsFromBody",
    # Runtime — legacy exceptions (back-compat)
    "InsufficientScopeError",
    "PolicyUnavailableError",
    # ── Legacy MCP Auth & Services ────────────────────────────────────────
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
    # ── Client-side error helpers (agent side) ────────────────────────────
    "AuthSecAccessError",
    "ClientInsufficientScopeError",
    "TokenRevokedError",
    "ClientRegistrationRevokedError",
    "AuthRequiredError",
    "parse_mcp_error",
    # ── CIBA / Delegation / SPIFFE ────────────────────────────────────────
    "CIBAClient",
    "DelegationClient",
    "DelegationError",
    "DelegationTokenExpired",
    "DelegationTokenNotFound",
    "QuickStartSVID",
    "WorkloadAPIClient",
    "WorkloadSVID",
    # ── Agent Identity (M2M / XAA token acquisition) ──────────────────────
    "AgentIdentity",
    "AuthSecIdentityError",
    "PendingApprovalError",
    "ApprovalDeniedError",
    "ConnectionRevokedError",
    "TrustedIssuerMissingError",
    "SubjectMappingFailedError",
    "ResourceNotRegisteredError",
    "CredentialInvalidError",
    "WorkloadNotAttestedError",
    # TypeScript parity: standalone polling helper
    "poll_until_approved",
    "PollOptions",
]
