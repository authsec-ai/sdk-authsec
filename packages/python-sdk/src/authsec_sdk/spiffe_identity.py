"""Deprecated path — moved to :mod:`authsec_sdk.identity.spiffe`.

This alias will be removed in v5. Import from ``authsec_sdk`` (top level)
or ``authsec_sdk.identity`` instead.
"""
import sys as _sys
import warnings as _warnings

from .identity import spiffe as _impl

_warnings.warn(
    "authsec_sdk.spiffe_identity is deprecated; use authsec_sdk.identity "
    "(or the authsec_sdk top level). This alias will be removed in v5.",
    DeprecationWarning,
    stacklevel=2,
)
_sys.modules[__name__] = _impl
