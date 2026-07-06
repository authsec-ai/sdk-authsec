"""Deprecated path — moved to :mod:`authsec_sdk.spiffe`.

This alias will be removed in v5. Use::

    from authsec_sdk.spiffe import QuickStartSVID, WorkloadAPIClient
"""
import warnings as _warnings

from ..spiffe.workload_api_client import WorkloadAPIClient
from ..spiffe.quick_start_svid import QuickStartSVID

_warnings.warn(
    "authsec_sdk.spiffe_workload_api is deprecated; use authsec_sdk.spiffe. "
    "This alias will be removed in v5.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["WorkloadAPIClient", "QuickStartSVID"]
