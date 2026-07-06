"""Legacy API surface, quarantined.

``core`` holds the original decorator-based MCP auth API
(:func:`protected_by_AuthSec`, :func:`run_mcp_server_with_oauth`,
:class:`ServiceAccessSDK`). Preserved for back-compat; new deployments
should use :mod:`authsec_sdk.runtime` to protect servers and
:mod:`authsec_sdk.identity` for agent-side tokens.
"""
