from .core import (
    mcp_tool,
    protected_by_AuthSec,
    run_mcp_server_with_oauth,
    ServiceAccessSDK,
    ServiceAccessError,
    configure_auth,
    get_config,
    is_configured,
    test_auth_service,
    test_services
)

# Import CIBA SDK for voice clients and passwordless authentication
from .ciba_sdk import CIBAClient

# Import Delegation SDK for AI agent trust delegation
from .delegation_sdk import (
    DelegationClient,
    DelegationError,
    DelegationHTTPResponse,
    DelegationTokenExpired,
    DelegationTokenNotFound,
)

# Import External Service SDK for Vault credential access
from .exsvc_sdk import (
    ExternalServiceClient,
    ExternalServiceError,
    ExternalServiceAuthError,
    ExternalServiceNotFoundError,
    ServiceCredentials as ExSvcCredentials,
    ServiceInfo,
)

# Import standalone SPIFFE Workload API SDK
from .spiffe_workload_api import QuickStartSVID, WorkloadAPIClient

# Also import SDK Manager SPIRE integration (optional)
try:
    from .spire_sdk import WorkloadSVID
except ImportError:
    WorkloadSVID = None

__version__ = "4.1.0"
__all__ = [
    # MCP Auth & Services
    "protected_by_AuthSec",
    "run_mcp_server_with_oauth",
    "ServiceAccessSDK",
    "ServiceAccessError",
    "configure_auth",
    "get_config",
    "is_configured",
    "test_auth_service",
    "test_services",
    # External Service SDK for Vault Credentials
    "ExternalServiceClient",
    "ExternalServiceError",
    "ExternalServiceAuthError",
    "ExternalServiceNotFoundError",
    "ExSvcCredentials",
    "ServiceInfo",
    # CIBA SDK for Voice Clients
    "CIBAClient",
    # Delegation SDK for AI Agent Trust Delegation
    "DelegationClient",
    "DelegationError",
    "DelegationHTTPResponse",
    "DelegationTokenExpired",
    "DelegationTokenNotFound",
    # SPIRE Workload Identity (Standalone SDK)
    "QuickStartSVID",
    "WorkloadAPIClient",
    "WorkloadSVID",
    "mcp_tool",
]
