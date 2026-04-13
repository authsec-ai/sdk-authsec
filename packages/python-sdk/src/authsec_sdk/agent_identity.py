"""
AuthSec Agent Identity SDK — Unified workload identity for autonomous agents.

Combines SPIFFE workload identity (via SPIRE socket) with delegated JWT-SVID
tokens (via trust delegation) into a single class.

Usage:
    from authsec_sdk import AgentIdentity

    # Initialize once at startup — only client_id required
    agent = await AgentIdentity.initialize(client_id="<your-agent-client-uuid>")

    # Call another agent/service — delegated token attached automatically
    response = await agent.request("POST", "https://agent-b/task", json_body={...})

    # Validate an incoming request from another agent
    claims = await agent.validate(token, audience="my-api")

    # Check permissions before acting
    if agent.has_permission("data:read"):
        ...
"""

import logging
from typing import Any, Dict, List, Optional

from .delegation_sdk import DelegationClient, DelegationError, DelegationHTTPResponse
from .spiffe_workload_api import QuickStartSVID

logger = logging.getLogger(__name__)

# Hardcoded AuthSec service URLs — clients do not need to configure these
_USERFLOW_URL = "https://prod.api.authsec.ai/uflow"

# Default SPIRE agent socket paths
_SOCKET_K8S = "unix:///run/spire/sockets/agent.sock"   # Kubernetes (default)
_SOCKET_DEV = "tcp://127.0.0.1:4000"                    # Local dev / Windows


class AgentIdentityError(Exception):
    """Raised when AgentIdentity initialization or operations fail."""
    pass


class AgentIdentity:
    """
    Unified workload identity for autonomous agents and AI workloads.

    Wraps two SDK modules:
      - QuickStartSVID: connects to the SPIRE agent socket, fetches X.509-SVID,
        auto-renews certificates in the background.
      - DelegationClient: pulls the admin-delegated JWT-SVID from AuthSec
        user-flow, auto-refreshes before expiry.

    The admin must have delegated a token to this client_id via the AuthSec
    UI or API before the workload starts.

    Args:
        client_id:   The agent's client UUID (from clients-microservice registration).
        socket_path: Path to the SPIRE agent socket.
                     Defaults to the Kubernetes standard path.
                     Use AgentIdentity.DEV_SOCKET for local development.
    """

    # Expose socket constants for convenience
    K8S_SOCKET = _SOCKET_K8S
    DEV_SOCKET = _SOCKET_DEV

    def __init__(self, client_id: str, socket_path: str = _SOCKET_K8S):
        self.client_id = client_id
        self.socket_path = socket_path
        self._svid: Optional[QuickStartSVID] = None
        self._delegation: Optional[DelegationClient] = None

    @classmethod
    async def initialize(
        cls,
        client_id: str,
        socket_path: str = _SOCKET_K8S,
    ) -> "AgentIdentity":
        """
        Initialize agent identity at workload startup.

        Connects to the SPIRE agent socket to obtain a workload SVID, then pulls
        the admin-delegated JWT-SVID from AuthSec. Both are kept current
        automatically — no further action needed.

        Args:
            client_id:   The agent's client UUID.
            socket_path: SPIRE agent socket path.
                         Defaults to K8s unix socket.
                         Pass AgentIdentity.DEV_SOCKET for local dev.

        Returns:
            Initialized AgentIdentity ready to make and validate requests.

        Raises:
            AgentIdentityError: If SVID fetch or delegation token pull fails.

        Example:
            # Kubernetes / production
            agent = await AgentIdentity.initialize(client_id="abc-123")

            # Local development
            agent = await AgentIdentity.initialize(
                client_id="abc-123",
                socket_path=AgentIdentity.DEV_SOCKET,
            )
        """
        instance = cls(client_id=client_id, socket_path=socket_path)
        await instance._setup()
        return instance

    async def _setup(self) -> None:
        logger.info("Initializing AgentIdentity for client=%s...", self.client_id[:8])

        # 1. Connect to SPIRE agent — get X.509-SVID with auto-renewal
        try:
            self._svid = await QuickStartSVID.initialize(socket_path=self.socket_path)
            logger.info("SVID ready: %s", self._svid.spiffe_id)
        except Exception as e:
            raise AgentIdentityError(
                f"Failed to connect to SPIRE agent at '{self.socket_path}': {e}"
            ) from e

        # 2. Pull delegated JWT-SVID — auto-refreshes 300s before expiry
        self._delegation = DelegationClient(
            client_id=self.client_id,
            userflow_url=_USERFLOW_URL,
            auto_refresh=True,
            refresh_buffer_seconds=300,
        )
        try:
            await self._delegation.pull_token()
            logger.info(
                "Delegated token ready: perms=%d expires_in=%ds",
                len(self._delegation.permissions),
                self._delegation.expires_in_seconds,
            )
        except DelegationError as e:
            raise AgentIdentityError(
                f"Failed to pull delegated token for client '{self.client_id}': {e}"
            ) from e

        logger.info("AgentIdentity initialized successfully.")

    # -------------------------------------------------------------------------
    # Identity properties
    # -------------------------------------------------------------------------

    @property
    def delegation(self) -> "DelegationClient":
        """
        The underlying DelegationClient — pass this to ExternalServiceClient
        so it reuses the same delegated token without a separate pull.

        Example:
            from authsec_sdk import ExternalServiceClient
            exsvc = ExternalServiceClient(base_url="...", delegation_client=agent.delegation)
        """
        self._require_init()
        return self._delegation

    @property
    def spiffe_id(self) -> Optional[str]:
        """The workload's SPIFFE ID from the SVID (e.g. spiffe://trust-domain/agent/...)."""
        return self._svid.spiffe_id if self._svid else None

    @property
    def token(self) -> Optional[str]:
        """The current delegated JWT-SVID token string."""
        return self._delegation.token if self._delegation else None

    @property
    def permissions(self) -> List[str]:
        """List of delegated permissions (e.g. ['data:read', 'task:execute'])."""
        return self._delegation.permissions if self._delegation else []

    @property
    def expires_in_seconds(self) -> int:
        """Seconds until the delegated token expires (0 if expired)."""
        return self._delegation.expires_in_seconds if self._delegation else 0

    # -------------------------------------------------------------------------
    # Permission checks
    # -------------------------------------------------------------------------

    def has_permission(self, permission: str) -> bool:
        """Check if the delegated token includes a specific permission."""
        return self._delegation.has_permission(permission) if self._delegation else False

    def has_any_permission(self, *permissions: str) -> bool:
        """Check if the token has any of the given permissions."""
        return self._delegation.has_any_permission(*permissions) if self._delegation else False

    def has_all_permissions(self, *permissions: str) -> bool:
        """Check if the token has all of the given permissions."""
        return self._delegation.has_all_permissions(*permissions) if self._delegation else False

    # -------------------------------------------------------------------------
    # Outbound: call another agent or service
    # -------------------------------------------------------------------------

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json_body: Any = None,
        **kwargs,
    ) -> DelegationHTTPResponse:
        """
        Make an authenticated HTTP request to another agent or service.

        Automatically attaches the delegated JWT-SVID as the Authorization
        header. Refreshes token and retries once on 401.

        Args:
            method:    HTTP method (GET, POST, PUT, DELETE, etc.)
            url:       Target URL.
            headers:   Additional request headers (optional).
            json_body: JSON-serializable request body (optional).

        Returns:
            DelegationHTTPResponse with .status, .ok, .text(), .json()

        Example:
            response = await agent.request("POST", "https://agent-b/task", json_body={"query": "..."})
            if response.ok:
                data = response.json()
        """
        self._require_init()
        return await self._delegation.request(method, url, headers=headers, json_body=json_body, **kwargs)

    async def request_json(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json_body: Any = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Like request() but returns the parsed JSON response dict directly."""
        self._require_init()
        return await self._delegation.request_json(method, url, headers=headers, json_body=json_body, **kwargs)

    def get_auth_header(self) -> Dict[str, str]:
        """
        Get the Authorization header dict for manual attachment to requests.

        Returns:
            {"Authorization": "Bearer <token>"}
        """
        self._require_init()
        return self._delegation.get_auth_header()

    # -------------------------------------------------------------------------
    # Inbound: validate a caller's JWT-SVID
    # -------------------------------------------------------------------------

    async def validate(self, token: str, audience: str) -> Optional[Dict[str, Any]]:
        """
        Validate an incoming JWT-SVID from another agent or service.

        Args:
            token:    JWT-SVID bearer token from the incoming request's
                      Authorization header (without "Bearer " prefix).
            audience: Expected audience string — must match the value the
                      caller passed to their issue/fetch call.

        Returns:
            Dict with 'spiffe_id' and 'claims' if valid, None if invalid.

        Example:
            auth = request.headers.get("Authorization", "")
            token = auth.removeprefix("Bearer ")
            claims = await agent.validate(token, audience="my-api")
            if claims:
                caller = claims["spiffe_id"]
        """
        self._require_init()
        return await self._svid.validate_jwt_svid(token, audience)

    # -------------------------------------------------------------------------
    # mTLS support (optional — for certificate-based auth instead of JWT)
    # -------------------------------------------------------------------------

    def ssl_context_for_server(self):
        """
        Create an SSL context for an mTLS server (e.g. uvicorn).

        The context uses the workload's X.509-SVID and auto-reads renewed
        certificates from disk after each renewal cycle.
        """
        self._require_init()
        return self._svid.create_ssl_context_for_server()

    def ssl_context_for_client(self):
        """
        Create an SSL context for an mTLS client (e.g. httpx, requests).
        """
        self._require_init()
        return self._svid.create_ssl_context_for_client()

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _require_init(self) -> None:
        if not self._svid or not self._delegation:
            raise AgentIdentityError(
                "AgentIdentity is not initialized. Call AgentIdentity.initialize() first."
            )

    def __repr__(self) -> str:
        return (
            f"AgentIdentity("
            f"client_id={self.client_id[:8]}..., "
            f"spiffe_id={self.spiffe_id}, "
            f"perms={len(self.permissions)}, "
            f"expires_in={self.expires_in_seconds}s"
            f")"
        )
