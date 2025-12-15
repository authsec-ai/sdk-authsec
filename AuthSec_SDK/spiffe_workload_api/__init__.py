"""
SPIFFE Workload API SDK for Python

This SDK provides interfaces for workloads to fetch X.509-SVIDs
from a SPIFFE Workload API server (e.g., SPIRE Agent or ICP Agent).

Two usage patterns available:

1. QUICK START (4-5 lines of code):
    from spiffe_workload_api import QuickStartSVID

    svid = await QuickStartSVID.initialize()
    print(f"SPIFFE ID: {svid.spiffe_id}")
    print(f"Certificate: {svid.certificate}")

2. ADVANCED (full control):
    from spiffe_workload_api import WorkloadAPIClient

    client = WorkloadAPIClient(socket_path="tcp://127.0.0.1:4000")
    await client.connect()
    success = await client.fetch_x509_svid_once()
    if success:
        print(f"SPIFFE ID: {client.spiffe_id}")
"""

__version__ = "0.1.0"

from .client import WorkloadAPIClient
from .simple import QuickStartSVID

__all__ = ["WorkloadAPIClient", "QuickStartSVID"]
