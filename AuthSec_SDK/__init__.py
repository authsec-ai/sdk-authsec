from .AuthSec_SDK import (
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

# Import standalone SPIFFE Workload API SDK
from .spiffe_workload_api import QuickStartSVID, WorkloadAPIClient

# Also import SDK Manager SPIRE integration (optional)
try:
    from .spire_sdk import WorkloadSVID
except ImportError:
    WorkloadSVID = None

__version__ = "4.0.3"
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
    # SPIRE Workload Identity (Standalone SDK)
    "QuickStartSVID",
    "WorkloadAPIClient",
    "WorkloadSVID"
]
