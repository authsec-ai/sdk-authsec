"""SPIFFE/SPIRE support — canonical import surface.

- :class:`WorkloadAPIClient` — async gRPC client for the SPIFFE Workload API
  (X.509-SVIDs, JWT-SVIDs, trust bundles).
- :class:`QuickStartSVID` — one-call helper: fetch an X.509-SVID, write cert
  files, build SSL contexts, auto-renew every 30 minutes.
- :class:`WorkloadSVID` — X.509 SVID material holder with SSL-context helpers.

For SPIFFE-based *token* acquisition (JWT-SVID → AuthSec Bearer token for
calling MCP servers), see :class:`authsec_sdk.identity.SpiffeWorkloadIdentity`.

Usage::

    from authsec_sdk.spiffe import QuickStartSVID, WorkloadAPIClient
"""

from .workload_api_client import WorkloadAPIClient
# Canonical QuickStartSVID (classmethod shutdown that clears the singleton).
# The variant in ``spiffe.spire`` is deprecated and kept only for back-compat.
from .quick_start_svid import QuickStartSVID
from .spire import WorkloadSVID

__all__ = ["WorkloadAPIClient", "QuickStartSVID", "WorkloadSVID"]
