"""SpiffeWorkloadIdentity — JWT-SVID token exchange for Kubernetes workloads.

Fetches a short-lived JWT-SVID from the local SPIRE agent, exchanges it at
the AuthSec token endpoint for a Bearer access token, and caches both for
reuse. No secrets stored anywhere.

The token endpoint is auto-discovered from ``mcp_server_url`` via RFC 9728
Protected Resource Metadata → RFC 8414 AS metadata — the same discovery path
that :class:`AgentIdentity` uses. It is also the exact ``audience`` value the
SVID must be minted with.

Typical Kubernetes usage (minimal config)::

    from authsec_sdk import SpiffeWorkloadIdentity, SpiffeConfig

    cfg = SpiffeConfig(
        mcp_server_url = "https://my-mcp-server.svc/mcp",
        client_id      = "workload-uuid-from-portal",
        spiffe_id      = "spiffe://acme.example/ns/default/sa/my-svc",
        scopes         = "mcp:read mcp:tools:read",
    )
    workload = SpiffeWorkloadIdentity(cfg)
    token = await workload.access_for()

On MCP server 401 (re-fetch SVID + retry once)::

    workload.clear_cache()
    token = await workload.access_for()

Testing outside a pod (svid_override skips the SPIRE agent subprocess)::

    cfg = SpiffeConfig(
        ...,
        svid_override = "eyJ...",   # minted via: kubectl exec ... spire-server jwt mint
    )
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import httpx

__all__ = [
    "SpiffeConfig",
    "SpiffeWorkloadIdentity",
    "SpiffeIdentityError",
    "SpiffeSvidFetchError",
    "SpiffeTokenExchangeError",
]

_SPIFFE_ASSERTION_TYPE = "urn:authsec:params:oauth:client-assertion-type:spiffe-svid"

# ─── Config ───────────────────────────────────────────────────────────────────


@dataclass
class SpiffeConfig:
    """All settings for SPIFFE/SPIRE workload identity auth."""

    mcp_server_url: str
    """Protected MCP server resource URL. Token endpoint is discovered from this."""

    client_id: str
    """Workload client_id from the AuthSec portal (UUID)."""

    spiffe_id: str
    """Exact SPIFFE ID of this workload, e.g. spiffe://acme.example/svc/foo"""

    scopes: str
    """Space-separated scopes to request, e.g. "mcp:read mcp:tools:read"."""

    token_endpoint: Optional[str] = None
    """Override the token endpoint. If None, it is discovered from mcp_server_url
    via RFC 9728 PRM → RFC 8414 AS metadata. The discovered value is also used
    as the SVID audience, so omit this unless you have a specific reason."""

    agent_socket_path: str = "/run/spire/sockets/agent.sock"
    """Unix socket path of the SPIRE agent (Kubernetes default)."""

    svid_override: Optional[str] = None
    """Pre-minted JWT-SVID string; if set, the SPIRE agent subprocess is skipped.
    Useful for testing outside a pod (kubectl exec spire-server jwt mint ...)."""


# ─── Errors ───────────────────────────────────────────────────────────────────


class SpiffeIdentityError(Exception):
    """Base class for all SpiffeWorkloadIdentity errors."""

    def __init__(self, code: str, message: str, http_status: Optional[int] = None) -> None:
        super().__init__(message)
        self.code = code
        self.http_status = http_status

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(code={self.code!r}, "
            f"message={str(self)!r}, http_status={self.http_status!r})"
        )


class SpiffeSvidFetchError(SpiffeIdentityError):
    """Failed to fetch a JWT-SVID from the SPIRE agent."""

    def __init__(self, message: str) -> None:
        super().__init__("svid_fetch_failed", message)


class SpiffeTokenExchangeError(SpiffeIdentityError):
    """AuthSec rejected the JWT-SVID during token exchange."""


# ─── Main class ───────────────────────────────────────────────────────────────


class SpiffeWorkloadIdentity:
    """Obtain short-lived Bearer access tokens using SPIFFE/SPIRE workload identity.

    Flow:
      1. Discover the AuthSec token endpoint from ``mcp_server_url`` (PRM → AS
         metadata). This endpoint is also used as the SVID audience.
      2. Fetch a JWT-SVID from the SPIRE agent via ``spire-agent api fetch jwt``.
      3. Exchange the SVID at the token endpoint for a Bearer access token.
      4. Cache both with their respective TTLs (SVID: ~5 min; token: ~1 hr).

    On MCP server 401: call ``clear_cache()`` then ``access_for()`` again —
    the SDK re-fetches the SVID and re-exchanges. Do not retry more than once.

    Parameters
    ----------
    config:
        :class:`SpiffeConfig` with all required fields.
    session:
        Optional :class:`httpx.AsyncClient` to reuse.
    """

    def __init__(
        self,
        config: SpiffeConfig,
        *,
        session: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self._cfg = config
        self._validate_config()

        self._owns_session = session is None
        self._session: httpx.AsyncClient = (
            session if session is not None else httpx.AsyncClient()
        )

        # Discovered token endpoint (cached permanently — doesn't change).
        self._resolved_token_endpoint: Optional[str] = config.token_endpoint or None

        # (svid_string, expires_at_monotonic)
        self._svid_cache: Optional[tuple[str, float]] = None
        # (token_string, expires_at_monotonic)
        self._token_cache: Optional[tuple[str, float]] = None

    # ─── Public API ───────────────────────────────────────────────────────────

    async def access_for(self) -> str:
        """Return a valid Bearer access token for the configured MCP server.

        Serves from cache when the token has more than 60 seconds remaining.
        On cache miss:
          1. Discovers the token endpoint (once, then cached permanently).
          2. Fetches a JWT-SVID from the SPIRE agent (cached for ~4.5 min).
          3. Exchanges the SVID for a Bearer access token (cached for expires_in).

        Raises
        ------
        SpiffeIdentityError
            When the token endpoint cannot be discovered from the MCP server URL.
        SpiffeSvidFetchError
            When the SPIRE agent is unreachable or SVID fetch fails.
        SpiffeTokenExchangeError
            When AuthSec rejects the SVID (misconfiguration, trust domain
            mismatch, no scopes granted, etc.)
        """
        if self._token_cache is not None:
            token, expires_at = self._token_cache
            if expires_at > time.monotonic() + 60:
                return token

        return await self._exchange_for_token()

    def clear_cache(self) -> None:
        """Clear the SVID and access-token caches (keeps discovered token endpoint).

        Call this when the MCP server returns a 401, then call
        :meth:`access_for` again to retry with a fresh SVID and token.
        """
        self._svid_cache = None
        self._token_cache = None

    # ─── Internal ─────────────────────────────────────────────────────────────

    def _validate_config(self) -> None:
        cfg = self._cfg
        if not cfg.client_id.strip():
            raise ValueError("SpiffeConfig.client_id is required")
        if not cfg.spiffe_id.startswith("spiffe://"):
            raise ValueError("SpiffeConfig.spiffe_id must start with 'spiffe://'")
        if cfg.token_endpoint and not cfg.token_endpoint.startswith("https://"):
            raise ValueError("SpiffeConfig.token_endpoint must start with 'https://'")
        if not cfg.scopes.strip():
            raise ValueError("SpiffeConfig.scopes is required")
        if not cfg.svid_override and not os.path.exists(cfg.agent_socket_path):
            raise SpiffeSvidFetchError(
                f"SPIRE agent socket not found at {cfg.agent_socket_path}. "
                "Is the SPIRE agent running and socket mounted at that path?"
            )

    async def _resolve_token_endpoint(self) -> str:
        """Return the token endpoint, discovering it from mcp_server_url if needed."""
        if self._resolved_token_endpoint:
            return self._resolved_token_endpoint

        # Step 1 — RFC 9728 Protected Resource Metadata
        # Path must include the resource path suffix, e.g. /mcp →
        # /.well-known/oauth-protected-resource/mcp
        from ..runtime.metadata import build_resource_metadata_url
        prm_url = build_resource_metadata_url(self._cfg.mcp_server_url)
        prm_resp = await self._session.get(prm_url, headers={"Accept": "application/json"})
        if not prm_resp.is_success:
            raise SpiffeIdentityError(
                "prm_discovery_failed",
                (
                    f"Protected resource metadata not found at {prm_url} "
                    f"({prm_resp.status_code}). "
                    "Is the MCP server registered in AuthSec?"
                ),
                prm_resp.status_code,
            )
        prm: Dict[str, Any] = prm_resp.json()
        auth_servers: List[str] = prm.get("authorization_servers") or []
        if not auth_servers:
            raise SpiffeIdentityError(
                "no_authorization_server",
                f"No authorization_servers in PRM for {self._cfg.mcp_server_url}. "
                "Is the MCP server registered in AuthSec?",
            )

        # Step 2 — RFC 8414 AS metadata
        as_url = auth_servers[0].rstrip("/")
        as_resp = await self._session.get(
            f"{as_url}/.well-known/oauth-authorization-server",
            headers={"Accept": "application/json"},
        )
        if not as_resp.is_success:
            raise SpiffeIdentityError(
                "as_discovery_failed",
                f"AS metadata discovery failed for {as_url} ({as_resp.status_code})",
                as_resp.status_code,
            )
        as_meta: Dict[str, Any] = as_resp.json()
        token_ep: str = as_meta.get("token_endpoint") or ""
        if not token_ep:
            raise SpiffeIdentityError(
                "token_endpoint_missing",
                f"token_endpoint not found in AS metadata for {as_url}",
            )

        self._resolved_token_endpoint = token_ep
        return token_ep

    async def _exchange_for_token(self) -> str:
        token_endpoint = await self._resolve_token_endpoint()
        svid = await self._get_svid(token_endpoint)

        body: Dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": self._cfg.client_id,
            "client_assertion_type": _SPIFFE_ASSERTION_TYPE,
            "client_assertion": svid,
            "resource": self._cfg.mcp_server_url,
            "scope": self._cfg.scopes,
        }

        resp = await self._session.post(
            token_endpoint,
            content=urlencode(body),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        try:
            json_body: Dict[str, Any] = resp.json()
        except Exception:
            json_body = {}

        if not resp.is_success:
            self._raise_exchange_error(json_body, resp.status_code, token_endpoint)

        token: str = json_body["access_token"]
        expires_in: float = float(json_body.get("expires_in") or 3600)
        # Cache until expires_in - 60 s so we refresh before the server rejects it.
        self._token_cache = (token, time.monotonic() + expires_in - 60)
        return token

    async def _get_svid(self, token_endpoint: str) -> str:
        """Return a valid JWT-SVID from override, cache, or SPIRE agent."""
        if self._cfg.svid_override:
            return self._cfg.svid_override

        if self._svid_cache is not None:
            svid, expires_at = self._svid_cache
            if expires_at > time.monotonic() + 30:
                return svid

        svid = await self._fetch_svid_from_agent(token_endpoint)
        # SVID TTL is 5 minutes; cache for 4.5 min (270 s) to refresh before expiry.
        self._svid_cache = (svid, time.monotonic() + 270)
        return svid

    async def _fetch_svid_from_agent(self, token_endpoint: str) -> str:
        if not os.path.exists(self._cfg.agent_socket_path):
            raise SpiffeSvidFetchError(
                f"SPIRE agent socket not found at {self._cfg.agent_socket_path}. "
                "Is the SPIRE agent running and socket mounted at that path?"
            )

        # audience MUST be the exact token endpoint URL
        cmd = [
            "spire-agent", "api", "fetch", "jwt",
            "-audience", token_endpoint,
            "-socketPath", self._cfg.agent_socket_path,
        ]

        loop = asyncio.get_running_loop()
        try:
            result: subprocess.CompletedProcess = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                ),
            )
        except FileNotFoundError:
            raise SpiffeSvidFetchError(
                "SVID fetch failed: spire-agent CLI not found in PATH. "
                "Ensure SPIRE agent is running and workload is attested."
            )
        except subprocess.TimeoutExpired:
            raise SpiffeSvidFetchError(
                "SVID fetch failed: spire-agent timed out after 10 seconds. "
                "Ensure SPIRE agent is running and workload is attested."
            )
        except Exception as exc:
            raise SpiffeSvidFetchError(
                f"SVID fetch failed: {exc}. "
                "Ensure SPIRE agent is running and workload is attested."
            ) from exc

        if result.returncode != 0:
            err = (result.stderr or result.stdout or "unknown error").strip()
            raise SpiffeSvidFetchError(
                f"SVID fetch failed: {err}. "
                "Ensure SPIRE agent is running and workload is attested."
            )

        svid = _parse_jwt_svid(result.stdout)
        if not svid:
            raise SpiffeSvidFetchError(
                "SVID fetch failed: could not parse JWT from spire-agent output. "
                "Ensure SPIRE agent is running and workload is attested."
            )
        return svid

    def _raise_exchange_error(
        self, body: Dict[str, Any], status: int, token_endpoint: str
    ) -> None:
        """Map AuthSec error responses to typed exceptions with actionable messages."""
        desc: str = (
            body.get("error_description") or body.get("error") or ""
        ).lower()

        if status == 401:
            if "no usable signing keys found in jwks" in desc:
                issuer_base = token_endpoint.split("/oauth")[0]
                raise SpiffeTokenExchangeError(
                    "jwks_unconfigured",
                    (
                        "AuthSec cannot verify SPIRE JWKS. "
                        "Check Workload Identity Provider is configured and OIDC discovery "
                        f"is reachable at {issuer_base}/.well-known/openid-configuration"
                    ),
                    status,
                )
            if "no active service account for spiffe id" in desc:
                raise SpiffeTokenExchangeError(
                    "spiffe_id_not_registered",
                    (
                        f"SPIFFE ID '{self._cfg.spiffe_id}' not registered in AuthSec. "
                        "Complete the Connect Kubernetes workload wizard in the portal."
                    ),
                    status,
                )
            if "token aud must include this token endpoint" in desc:
                raise SpiffeTokenExchangeError(
                    "audience_mismatch",
                    (
                        "SVID audience is wrong. "
                        f"Fetch SVID with audience = '{token_endpoint}' exactly."
                    ),
                    status,
                )
            if "svid trust domain does not match" in desc:
                raise SpiffeTokenExchangeError(
                    "trust_domain_mismatch",
                    (
                        "Trust domain mismatch. "
                        "Check Workload Identity Provider trust domain in portal."
                    ),
                    status,
                )

        if status == 403 and "no scopes granted" in desc:
            raise SpiffeTokenExchangeError(
                "no_scopes_granted",
                (
                    "No scopes granted for this resource. "
                    "Assign a role with required scopes to the workload in the AuthSec portal."
                ),
                status,
            )

        if status == 400 and "client_id is required" in desc:
            raise SpiffeTokenExchangeError(
                "client_id_missing",
                "client_id missing. Pass the workload client_id from the AuthSec portal.",
                status,
            )

        raw = body.get("error_description") or body.get("error") or "Token exchange failed."
        raise SpiffeTokenExchangeError(
            body.get("error") or "token_exchange_failed",
            str(raw),
            status,
        )

    # ─── Context-manager support ──────────────────────────────────────────────

    async def __aenter__(self) -> "SpiffeWorkloadIdentity":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying HTTP session if this instance owns it."""
        if self._owns_session:
            await self._session.aclose()


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _parse_jwt_svid(output: str) -> str:
    """Extract the first JWT (eyJ...) from spire-agent CLI output."""
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("eyJ"):
            return stripped
    return ""
