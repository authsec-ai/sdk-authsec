"""Deprecated path — moved to :mod:`authsec_sdk._legacy.core`.

The decorator-based API (``protected_by_AuthSec``, ``run_mcp_server_with_oauth``)
is legacy; new deployments should use :mod:`authsec_sdk.runtime` to protect
MCP servers. All names remain importable from the ``authsec_sdk`` top level.
"""
import sys as _sys
import warnings as _warnings

from ._legacy import core as _impl

_warnings.warn(
    "authsec_sdk.core is deprecated; import from the authsec_sdk top level, "
    "or migrate to authsec_sdk.runtime. This alias will be removed in v5.",
    DeprecationWarning,
    stacklevel=2,
)
_sys.modules[__name__] = _impl
