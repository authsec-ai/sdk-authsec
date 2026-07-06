"""Deprecated path — moved to :mod:`authsec_sdk.spiffe.quick_start_svid`.

This alias will be removed in v5.
"""
import sys as _sys
import warnings as _warnings

from ..spiffe import quick_start_svid as _impl

_warnings.warn(
    "authsec_sdk.spiffe_workload_api.simple is deprecated; use "
    "authsec_sdk.spiffe. This alias will be removed in v5.",
    DeprecationWarning,
    stacklevel=2,
)
_sys.modules[__name__] = _impl
