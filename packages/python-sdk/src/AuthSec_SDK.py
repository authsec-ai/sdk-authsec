"""
Legacy import shim for backward compatibility.

Supports legacy code:
    from AuthSec_SDK import protected_by_AuthSec, run_mcp_server_with_oauth

The canonical package is now:
    import authsec_sdk
"""

import importlib
import sys

from authsec_sdk import (
    mcp_tool,
    protected_by_AuthSec,
    run_mcp_server_with_oauth,
    ServiceAccessSDK,
    ServiceAccessError,
    configure_auth,
    get_config,
    is_configured,
    test_auth_service,
    test_services,
    CIBAClient,
    QuickStartSVID,
    WorkloadAPIClient,
    WorkloadSVID,
    __version__,
)

# Make this module behave like a package for legacy dotted imports.
__path__ = []  # type: ignore
sys.modules.setdefault("AuthSec_SDK.AuthSec_SDK", importlib.import_module("authsec_sdk.core"))
sys.modules.setdefault("AuthSec_SDK.ciba_sdk", importlib.import_module("authsec_sdk.ciba_sdk"))
sys.modules.setdefault("AuthSec_SDK.spire_sdk", importlib.import_module("authsec_sdk.spire_sdk"))
sys.modules.setdefault("AuthSec_SDK.spiffe_workload_api", importlib.import_module("authsec_sdk.spiffe_workload_api"))
sys.modules.setdefault(
    "AuthSec_SDK.spiffe_workload_api.client",
    importlib.import_module("authsec_sdk.spiffe_workload_api.client"),
)
sys.modules.setdefault(
    "AuthSec_SDK.spiffe_workload_api.simple",
    importlib.import_module("authsec_sdk.spiffe_workload_api.simple"),
)
sys.modules.setdefault(
    "AuthSec_SDK.spiffe_workload_api.api",
    importlib.import_module("authsec_sdk.spiffe_workload_api.api"),
)

__all__ = [
    "mcp_tool",
    "protected_by_AuthSec",
    "run_mcp_server_with_oauth",
    "ServiceAccessSDK",
    "ServiceAccessError",
    "configure_auth",
    "get_config",
    "is_configured",
    "test_auth_service",
    "test_services",
    "CIBAClient",
    "QuickStartSVID",
    "WorkloadAPIClient",
    "WorkloadSVID",
]

