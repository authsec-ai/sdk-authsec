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

from .spire_sdk import (
    QuickStartSVID,
    WorkloadSVID
)

__version__ = "3.5.0"
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
    # SPIRE Workload Identity
    "QuickStartSVID",
    "WorkloadSVID"
]
