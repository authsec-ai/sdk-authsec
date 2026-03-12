"""
AuthSec Delegation SDK — Pull and use delegated JWT-SVID tokens.

Usage:
    from authsec_sdk.delegation_sdk import DelegationClient

    client = DelegationClient(
        client_id="abc-123-...",
        userflow_url="https://api.authsec.ai/uflow",
    )

    # Pull token (admin must have delegated first)
    token_info = await client.pull_token()
    print(token_info["permissions"])

    # Make authenticated API call using the delegated token
    resp = await client.request("GET", "https://api.example.com/users")

    # Check if a specific permission is available
    if client.has_permission("users:read"):
        ...
"""

from dataclasses import dataclass
import json
import time
import logging
from typing import Dict, Optional, List, Any

import aiohttp

logger = logging.getLogger(__name__)


class DelegationError(Exception):
    """Raised when delegation token operations fail."""
    pass


class DelegationTokenExpired(DelegationError):
    """Raised when the delegation token has expired."""
    pass


class DelegationTokenNotFound(DelegationError):
    """Raised when no delegation token exists for this client."""
    pass


@dataclass
class DelegationHTTPResponse:
    """Buffered HTTP response returned by DelegationClient.request()."""

    status: int
    headers: Dict[str, str]
    body: bytes
    url: str

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def text(self, encoding: str = "utf-8", errors: str = "replace") -> str:
        return self.body.decode(encoding, errors=errors)

    def json(self) -> Any:
        if not self.body:
            return None
        return json.loads(self.body.decode("utf-8"))


class DelegationClient:
    """
    Client for AI agents/SDKs to pull and use delegated JWT-SVID tokens
    from the AuthSec user-flow service.

    The client_id is the SDK's identity — registered as an AI agent client
    via clients-microservice. An admin must have delegated a token to this
    client_id before the SDK can pull it.

    Args:
        client_id: The AI agent's client UUID (from clients-microservice)
        userflow_url: Base URL of the user-flow service (e.g. https://api.authsec.ai/uflow)
        auto_refresh: Automatically re-pull token when it nears expiry (default: True)
        refresh_buffer_seconds: Re-pull when token expires within this many seconds (default: 300)
        timeout: HTTP timeout in seconds (default: 10)
    """

    def __init__(
        self,
        client_id: str,
        userflow_url: str,
        auto_refresh: bool = True,
        refresh_buffer_seconds: int = 300,
        timeout: int = 10,
    ):
        self.client_id = client_id.strip()
        self.userflow_url = userflow_url.rstrip("/")
        if not self.client_id:
            raise DelegationError("client_id must be a non-empty string")
        if not self.userflow_url:
            raise DelegationError("userflow_url must be a non-empty string")
        self.auto_refresh = auto_refresh
        self.refresh_buffer_seconds = refresh_buffer_seconds
        self.timeout = timeout

        # Cached token state
        self._token: Optional[str] = None
        self._token_info: Optional[Dict[str, Any]] = None
        self._permissions: List[str] = []
        self._expires_at: float = 0  # unix timestamp

    @property
    def token(self) -> Optional[str]:
        """The current JWT-SVID token string."""
        return self._token

    @property
    def permissions(self) -> List[str]:
        """List of delegated permission strings (e.g., ['users:read', 'secrets:read'])."""
        return self._permissions

    @property
    def spiffe_id(self) -> Optional[str]:
        """The SPIFFE ID from the token info."""
        if self._token_info:
            return self._token_info.get("spiffe_id")
        return None

    @property
    def is_expired(self) -> bool:
        """Check if the cached token is expired."""
        if self._expires_at == 0:
            return True
        return time.time() >= self._expires_at

    @property
    def expires_in_seconds(self) -> int:
        """Seconds until the token expires (0 if expired)."""
        remaining = self._expires_at - time.time()
        return max(0, int(remaining))

    def _needs_refresh(self) -> bool:
        """Check if the token needs to be refreshed (expired or near expiry)."""
        if self._token is None:
            return True
        if self._expires_at == 0:
            return True
        return time.time() >= (self._expires_at - self.refresh_buffer_seconds)

    async def pull_token(self) -> Dict[str, Any]:
        """
        Pull the delegation token from user-flow.

        Returns:
            Dict with keys: token, spiffe_id, permissions, audience,
            expires_at, ttl_seconds, client_id, tenant_id, status

        Raises:
            DelegationTokenNotFound: No active token for this client_id
            DelegationTokenExpired: Token exists but has expired
            DelegationError: Network or server error
        """
        url = f"{self.userflow_url}/sdk/delegation-token"
        headers = {
            "X-Client-ID": self.client_id,
            "Accept": "application/json",
        }
        params = {"client_id": self.client_id}

        timeout = aiohttp.ClientTimeout(total=self.timeout)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers, params=params) as resp:
                    body = await resp.json()

                    if resp.status == 200:
                        self._token = body.get("token")
                        self._token_info = body
                        self._permissions = body.get("permissions", [])

                        # Parse expires_at (ISO string) to unix timestamp
                        expires_at_str = body.get("expires_at", "")
                        if expires_at_str:
                            from datetime import datetime, timezone
                            try:
                                dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
                                self._expires_at = dt.timestamp()
                            except (ValueError, TypeError):
                                self._expires_at = time.time() + body.get("ttl_seconds", 3600)
                        else:
                            self._expires_at = time.time() + body.get("ttl_seconds", 3600)

                        logger.info(
                            "Delegation token pulled: client=%s perms=%d expires_in=%ds",
                            self.client_id[:8], len(self._permissions), self.expires_in_seconds,
                        )
                        return body

                    elif resp.status == 404:
                        raise DelegationTokenNotFound(
                            body.get("error", "No active delegation token found")
                        )
                    elif resp.status == 410:
                        self._token = None
                        self._permissions = []
                        self._expires_at = 0
                        raise DelegationTokenExpired(
                            body.get("error", "Delegation token has expired")
                        )
                    else:
                        raise DelegationError(
                            f"HTTP {resp.status}: {body.get('error', 'Unknown error')}"
                        )

        except aiohttp.ClientError as e:
            raise DelegationError(f"Network error pulling delegation token: {e}")

    async def ensure_token(self) -> str:
        """
        Ensure we have a valid token, pulling/refreshing if needed.

        Returns:
            The JWT-SVID token string.

        Raises:
            DelegationError: If token cannot be obtained.
        """
        if self._needs_refresh():
            await self.pull_token()
        if not self._token:
            raise DelegationError("Delegation token is unavailable after refresh")
        return self._token

    def has_permission(self, permission: str) -> bool:
        """
        Check if the delegated token includes a specific permission.

        Args:
            permission: Permission string like 'users:read' or 'secrets:write'
        """
        return permission in self._permissions

    def has_any_permission(self, *permissions: str) -> bool:
        """Check if the token has any of the given permissions."""
        return any(p in self._permissions for p in permissions)

    def has_all_permissions(self, *permissions: str) -> bool:
        """Check if the token has all of the given permissions."""
        return all(p in self._permissions for p in permissions)

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json_body: Any = None,
        **kwargs,
    ) -> DelegationHTTPResponse:
        """
        Make an authenticated HTTP request using the delegated JWT-SVID.

        Automatically pulls/refreshes the token if needed.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Target URL
            headers: Additional headers (Authorization will be added)
            json_body: JSON request body
            **kwargs: Additional aiohttp request kwargs

        Returns:
            Buffered response object with `.status`, `.headers`, `.text()`, and `.json()`.
        """
        token = await self.ensure_token()
        req_headers = dict(headers or {})
        req_headers["Authorization"] = f"Bearer {token}"

        response = await self._request_once(method, url, req_headers, json_body=json_body, **kwargs)
        if response.status == 401 and self.auto_refresh:
            logger.info("Got 401, refreshing delegation token...")
            await self.pull_token()
            if not self._token:
                raise DelegationError("Delegation token refresh returned no token")
            req_headers["Authorization"] = f"Bearer {self._token}"
            response = await self._request_once(method, url, req_headers, json_body=json_body, **kwargs)

        return response

    async def request_json(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json_body: Any = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Like request(), but returns the parsed JSON response body.
        """
        response = await self.request(
            method,
            url,
            headers=headers,
            json_body=json_body,
            **kwargs,
        )
        try:
            parsed = response.json()
        except Exception as e:
            raise DelegationError(
                f"Expected JSON object response from {response.url}: {str(e)}"
            ) from e
        if parsed is None:
            return {}
        if not isinstance(parsed, dict):
            raise DelegationError(
                f"Expected JSON object response from {response.url}, got {type(parsed).__name__}"
            )
        return parsed

    def get_auth_header(self) -> Dict[str, str]:
        """
        Get the Authorization header dict for manual use.

        Returns:
            {"Authorization": "Bearer <token>"}

        Raises:
            DelegationError: If no token is cached.
        """
        if not self._token:
            raise DelegationError("No token cached. Call pull_token() or ensure_token() first.")
        return {"Authorization": f"Bearer {self._token}"}

    def decode_token_claims(self) -> Dict[str, Any]:
        """
        Decode the JWT-SVID payload (without signature verification) for inspection.

        Returns:
            Dict of JWT claims (sub, permissions, tenant_id, etc.)
        """
        if not self._token:
            return {}
        try:
            import base64
            parts = self._token.split(".")
            if len(parts) < 2:
                return {}
            payload_b64 = parts[1]
            padding = "=" * (-len(payload_b64) % 4)
            payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
            return json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            return {}

    def __repr__(self) -> str:
        status = "active" if self._token and not self.is_expired else "no token"
        return (
            f"DelegationClient(client_id={self.client_id[:8]}..., "
            f"status={status}, perms={len(self._permissions)}, "
            f"expires_in={self.expires_in_seconds}s)"
        )

    async def _request_once(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        json_body: Any = None,
        **kwargs,
    ) -> DelegationHTTPResponse:
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    json=json_body,
                    **kwargs,
                ) as resp:
                    body = await resp.read()
                    return DelegationHTTPResponse(
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        url=str(resp.url),
                    )
        except aiohttp.ClientError as e:
            raise DelegationError(f"Network error calling delegated endpoint {url}: {e}") from e
