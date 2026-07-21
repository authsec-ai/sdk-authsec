"""Agent-side identity — acquire tokens to call protected MCP servers.

Two ways for an agent to prove who it is:

- :class:`AgentIdentity` (``identity.agent``) — OAuth client credentials or
  XAA/ID-JAG delegation with a user session. Includes :func:`browser_login`
  (PKCE) and :func:`poll_until_approved`.
- :class:`SpiffeWorkloadIdentity` (``identity.spiffe``) — SPIFFE/SPIRE
  JWT-SVID exchanged at AuthSec for a Bearer token (Kubernetes workloads).

Usage::

    from authsec_sdk.identity import AgentIdentity, browser_login
"""

from .credentials import (
    ClientAuth,
    ClientSecretAuth,
    PrivateKeyJwtAuth,
    SpiffeSvidAuth,
)
from .agent import (
    AgentIdentity,
    AuthSecIdentityError,
    PendingApprovalError,
    ApprovalDeniedError,
    ConnectionRevokedError,
    TrustedIssuerMissingError,
    SubjectMappingFailedError,
    ResourceNotRegisteredError,
    CredentialInvalidError,
    WorkloadNotAttestedError,
    PollOptions,
    poll_until_approved,
    browser_login,
)
from .spiffe import (
    SpiffeConfig,
    SpiffeWorkloadIdentity,
    SpiffeIdentityError,
    SpiffeSvidFetchError,
    SpiffeTokenExchangeError,
)

__all__ = [
    "ClientAuth",
    "ClientSecretAuth",
    "PrivateKeyJwtAuth",
    "SpiffeSvidAuth",
    "AgentIdentity",
    "AuthSecIdentityError",
    "PendingApprovalError",
    "ApprovalDeniedError",
    "ConnectionRevokedError",
    "TrustedIssuerMissingError",
    "SubjectMappingFailedError",
    "ResourceNotRegisteredError",
    "CredentialInvalidError",
    "WorkloadNotAttestedError",
    "PollOptions",
    "poll_until_approved",
    "browser_login",
    "SpiffeConfig",
    "SpiffeWorkloadIdentity",
    "SpiffeIdentityError",
    "SpiffeSvidFetchError",
    "SpiffeTokenExchangeError",
]
