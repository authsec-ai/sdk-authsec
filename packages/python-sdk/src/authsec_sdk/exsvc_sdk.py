"""
AuthSec External Service SDK — Fetch service credentials from Vault via delegated JWT-SVID.

Usage with DelegationClient (recommended for AI agents):

    from authsec_sdk import DelegationClient, ExternalServiceClient

    delegation = DelegationClient(
        client_id="your-agent-client-id",
        userflow_url="https://api.authsec.ai/uflow",
    )

    exsvc = ExternalServiceClient(
        base_url="https://api.authsec.ai/exsvc",
        delegation_client=delegation,
    )

    # List all agent-accessible services
    services = await exsvc.list_services()

    # Fetch credentials (secrets from Vault) for a service
    creds = await exsvc.get_credentials("service-uuid")
    print(creds.credentials)  # {"api_key": "...", "access_token": "..."}

Usage with a raw JWT token:

    exsvc = ExternalServiceClient(
        base_url="https://api.authsec.ai/exsvc",
        token="eyJhbGciOiJSUzI1NiIs...",
    )
    creds = await exsvc.get_credentials("service-uuid")
"""

from dataclasses import dataclass, field
import json
import logging
from typing import Any, Dict, List, Optional, Union

import aiohttp

logger = logging.getLogger(__name__)


class ExternalServiceError(Exception):
    """Base error for External Service SDK operations."""
    pass


class ExternalServiceAuthError(ExternalServiceError):
    """Raised when authentication fails (401/403)."""
    pass


class ExternalServiceNotFoundError(ExternalServiceError):
    """Raised when a service is not found (404)."""
    pass


@dataclass
class ServiceInfo:
    """Metadata about a registered external service."""

    id: str
    name: str
    type: str
    url: str
    description: str
    tags: List[str]
    resource_id: str
    auth_type: str
    agent_accessible: bool
    created_by: str
    created_at: str
    updated_at: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServiceInfo":
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            type=data.get("type", ""),
            url=data.get("url", ""),
            description=data.get("description", ""),
            tags=data.get("tags") or [],
            resource_id=data.get("resource_id", ""),
            auth_type=data.get("auth_type", ""),
            agent_accessible=data.get("agent_accessible", False),
            created_by=data.get("created_by", ""),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
        )


@dataclass
class ServiceCredentials:
    """Credentials retrieved from Vault for an external service."""

    service_id: str
    service_name: str
    service_type: str
    auth_type: str
    url: str
    credentials: Dict[str, Any]
    metadata: Dict[str, str] = field(default_factory=dict)
    retrieved_at: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServiceCredentials":
        return cls(
            service_id=data.get("service_id", ""),
            service_name=data.get("service_name", ""),
            service_type=data.get("service_type", ""),
            auth_type=data.get("auth_type", ""),
            url=data.get("url", ""),
            credentials=data.get("credentials") or {},
            metadata=data.get("metadata") or {},
            retrieved_at=data.get("retrieved_at", ""),
        )


class ExternalServiceClient:
    """
    Client for fetching external service metadata and Vault-stored credentials
    using a delegated JWT-SVID token.

    Supports two authentication modes:
    - **DelegationClient** (recommended): auto-manages token pull and refresh.
    - **Raw token**: pass a pre-obtained JWT-SVID string directly.

    Args:
        base_url: Base URL of the external-service API (e.g. "https://api.authsec.ai/exsvc").
        delegation_client: A DelegationClient instance for automatic token management.
        token: A raw JWT-SVID string. Ignored if delegation_client is provided.
        timeout: HTTP request timeout in seconds (default: 15).
    """

    def __init__(
        self,
        base_url: str,
        delegation_client: Optional[Any] = None,
        token: Optional[str] = None,
        timeout: int = 15,
    ):
        self.base_url = base_url.rstrip("/")
        self._delegation_client = delegation_client
        self._static_token = token
        self.timeout = timeout

        if not self._delegation_client and not self._static_token:
            raise ExternalServiceError(
                "Provide either a DelegationClient or a raw JWT token"
            )

    async def _get_token(self) -> str:
        """Resolve the current Bearer token."""
        if self._delegation_client:
            return await self._delegation_client.ensure_token()
        if self._static_token:
            return self._static_token
        raise ExternalServiceAuthError("No token available")

    async def _request(
        self,
        method: str,
        path: str,
        json_body: Any = None,
    ) -> Dict[str, Any]:
        """Make an authenticated request to the external-service API."""
        token = await self._get_token()
        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.request(
                    method, url, headers=headers, json=json_body
                ) as resp:
                    body = await resp.read()

                    if resp.status == 401:
                        # Retry once with refreshed token if using delegation
                        if self._delegation_client and self._delegation_client.auto_refresh:
                            logger.info("Got 401, refreshing delegation token...")
                            token = await self._delegation_client.ensure_token()
                            headers["Authorization"] = f"Bearer {token}"
                            async with session.request(
                                method, url, headers=headers, json=json_body
                            ) as retry_resp:
                                body = await retry_resp.read()
                                if retry_resp.status == 401:
                                    raise ExternalServiceAuthError(
                                        "Authentication failed after token refresh"
                                    )
                                return self._parse_response(
                                    retry_resp.status, body, url
                                )

                        raise ExternalServiceAuthError(
                            "Authentication failed — invalid or expired token"
                        )

                    return self._parse_response(resp.status, body, url)

        except aiohttp.ClientError as e:
            raise ExternalServiceError(f"Network error calling {url}: {e}") from e

    def _parse_response(
        self, status: int, body: bytes, url: str
    ) -> Dict[str, Any]:
        """Parse and validate the HTTP response."""
        try:
            data = json.loads(body) if body else {}
        except (json.JSONDecodeError, ValueError):
            data = {}

        if status == 403:
            raise ExternalServiceAuthError(
                data.get("error", "Insufficient permissions")
            )
        if status == 404:
            raise ExternalServiceNotFoundError(
                data.get("error", "Service not found")
            )
        if status >= 400:
            raise ExternalServiceError(
                f"HTTP {status} from {url}: {data.get('error', body[:200])}"
            )

        return data

    # ── Service Operations ──────────────────────────────────────────────

    async def list_services(self) -> List[ServiceInfo]:
        """
        List all services accessible to the authenticated identity.

        For SPIFFE-authenticated agents, returns services marked agent_accessible=true.
        For regular users, returns services they created.

        Returns:
            List of ServiceInfo objects.
        """
        data = await self._request("GET", "/services")
        services = data if isinstance(data, list) else data.get("services", [])
        return [ServiceInfo.from_dict(s) for s in services]

    async def get_service(self, service_id: str) -> ServiceInfo:
        """
        Get metadata for a specific service.

        Args:
            service_id: UUID of the service.

        Returns:
            ServiceInfo with service metadata (no secrets).
        """
        data = await self._request("GET", f"/services/{service_id}")
        return ServiceInfo.from_dict(data)

    async def get_credentials(self, service_id: str) -> ServiceCredentials:
        """
        Fetch the Vault-stored credentials for a service.

        Requires the ``external-service:credentials`` permission in the
        delegated JWT-SVID.

        Args:
            service_id: UUID of the service.

        Returns:
            ServiceCredentials with the decrypted secret data from Vault.
        """
        data = await self._request("GET", f"/services/{service_id}/credentials")
        return ServiceCredentials.from_dict(data)

    async def get_credentials_by_name(self, name: str) -> ServiceCredentials:
        """
        Convenience method: find a service by name and fetch its credentials.

        Args:
            name: The service name to search for (case-insensitive match).

        Returns:
            ServiceCredentials for the first matching service.

        Raises:
            ExternalServiceNotFoundError: If no service matches the name.
        """
        services = await self.list_services()
        match = next(
            (s for s in services if s.name.lower() == name.lower()), None
        )
        if not match:
            raise ExternalServiceNotFoundError(
                f"No service found with name '{name}'"
            )
        return await self.get_credentials(match.id)

    async def health_check(self) -> Dict[str, Any]:
        """Check if the external-service API is healthy (unauthenticated)."""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(f"{self.base_url}/health") as resp:
                    body = await resp.read()
                    return json.loads(body) if body else {"status": "ok"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def __repr__(self) -> str:
        mode = "delegation" if self._delegation_client else "static-token"
        return f"ExternalServiceClient(base_url={self.base_url!r}, auth={mode})"
