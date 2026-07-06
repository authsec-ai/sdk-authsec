"""Deprecated path — moved to :mod:`authsec_sdk.spiffe.spire`.

Prefer :mod:`authsec_sdk.spiffe` (``QuickStartSVID``, ``WorkloadAPIClient``,
``WorkloadSVID``). This alias will be removed in v5.
"""
import sys as _sys
import warnings as _warnings

from .spiffe import spire as _impl

_warnings.warn(
    "authsec_sdk.spire_sdk is deprecated; use authsec_sdk.spiffe. "
    "This alias will be removed in v5.",
    DeprecationWarning,
    stacklevel=2,
)
_sys.modules[__name__] = _impl
