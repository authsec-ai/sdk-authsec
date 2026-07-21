"""Deprecated path — moved to :mod:`authsec_sdk.delegation`.

This alias will be removed in v5.
"""
import sys as _sys
import warnings as _warnings

from . import delegation as _impl

_warnings.warn(
    "authsec_sdk.delegation_sdk is deprecated; use authsec_sdk.delegation. "
    "This alias will be removed in v5.",
    DeprecationWarning,
    stacklevel=2,
)
_sys.modules[__name__] = _impl
