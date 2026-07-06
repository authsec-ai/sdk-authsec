"""Deprecated path — moved to :mod:`authsec_sdk.integrations.langgraph`.

This alias will be removed in v5.
"""
import sys as _sys
import warnings as _warnings

from ..integrations import langgraph as _impl

_warnings.warn(
    "authsec_sdk.client.langgraph is deprecated; use "
    "authsec_sdk.integrations.langgraph. This alias will be removed in v5.",
    DeprecationWarning,
    stacklevel=2,
)
_sys.modules[__name__] = _impl
