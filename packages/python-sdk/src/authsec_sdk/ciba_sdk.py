"""Deprecated path — moved to :mod:`authsec_sdk.ciba`.

This alias will be removed in v5.
"""
import sys as _sys
import warnings as _warnings

from . import ciba as _impl

_warnings.warn(
    "authsec_sdk.ciba_sdk is deprecated; use authsec_sdk.ciba. "
    "This alias will be removed in v5.",
    DeprecationWarning,
    stacklevel=2,
)
_sys.modules[__name__] = _impl
