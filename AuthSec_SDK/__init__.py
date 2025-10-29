from .AuthSec_SDK import (
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

__version__ = "2.0.0"
__all__ = [
    "protected_by_AuthSec",
    "run_mcp_server_with_oauth",
    "ServiceAccessSDK",
    "ServiceAccessError",
    "configure_auth",
    "get_config",
    "is_configured",
    "test_auth_service",
    "test_services"
]
