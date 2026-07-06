"""authsec-sdk — Python SDK for AuthSec.

Package layout (by function):

- :mod:`authsec_sdk.identity` — agent side: acquire tokens to CALL protected
  MCP servers (:class:`AgentIdentity` M2M/XAA, :func:`browser_login`,
  :class:`SpiffeWorkloadIdentity`).
- :mod:`authsec_sdk.runtime` — server side: PROTECT an MCP resource server
  (token validation, RBAC, RFC 9728 metadata). Use ``mount_mcp(app, path,
  handler, cfg)`` or build a :class:`Runtime` directly.
- :mod:`authsec_sdk.client` — typed errors for parsing AuthSec 401/403
  responses on the agent side.
- :mod:`authsec_sdk.integrations` — framework glue (LangGraph).
- :mod:`authsec_sdk.spiffe` — SPIFFE Workload API (X.509-SVIDs, mTLS).
- :mod:`authsec_sdk.ciba` / :mod:`authsec_sdk.delegation` — CIBA push
  auth and delegation tokens.
- :mod:`authsec_sdk._legacy` — the original decorator API
  (:func:`protected_by_AuthSec`, :func:`run_mcp_server_with_oauth`),
  preserved for back-compat; new deployments should use ``runtime``.

Old module paths (``authsec_sdk.agent_identity``, ``.core``, ``.ciba_sdk``,
``.delegation_sdk``, ``.spire_sdk``, ``.spiffe_identity``) still work but
emit ``DeprecationWarning`` and will be removed in v5.
"""

from ._legacy.core import (
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
    wrap_asgi_handler,
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

# CIBA — voice clients and passwordless authentication
from .ciba import CIBAClient

# Delegation — AI agent trust delegation
from .delegation import (
    DelegationClient,
    DelegationError,
    DelegationResponse,
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

# SPIFFE — Workload API (gRPC), quick-start SVID, mTLS material
from .spiffe import QuickStartSVID, WorkloadAPIClient, WorkloadSVID

# Identity — agent-side token acquisition (M2M / XAA / SPIFFE exchange)
from .identity import (
    ClientAuth,
    ClientSecretAuth,
    PrivateKeyJwtAuth,
    SpiffeSvidAuth,
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
    poll_until_approved,
    PollOptions,
    browser_login,
    SpiffeConfig,
    SpiffeWorkloadIdentity,
    SpiffeIdentityError,
    SpiffeSvidFetchError,
    SpiffeTokenExchangeError,
)

__version__ = "4.7.0"
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
    "wrap_asgi_handler",
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
    # ── SPIFFE/SPIRE workload identity ────────────────────────────────────
    "SpiffeConfig",
    "SpiffeWorkloadIdentity",
    "SpiffeIdentityError",
    "SpiffeSvidFetchError",
    "SpiffeTokenExchangeError",
    # ── Agent Identity (M2M / XAA token acquisition) ──────────────────────
    "ClientAuth",
    "ClientSecretAuth",
    "PrivateKeyJwtAuth",
    "SpiffeSvidAuth",
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
    # Browser PKCE login helper
    "browser_login",
]
