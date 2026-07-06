"""Deprecated path — protobuf stubs moved to :mod:`authsec_sdk.spiffe.api`.

This alias will be removed in v5.
"""
import sys as _sys
import warnings as _warnings

from ...spiffe import api as _impl

_warnings.warn(
    "authsec_sdk.spiffe_workload_api.api is deprecated; use "
    "authsec_sdk.spiffe.api. This alias will be removed in v5.",
    DeprecationWarning,
    stacklevel=2,
)
_sys.modules[__name__] = _impl
