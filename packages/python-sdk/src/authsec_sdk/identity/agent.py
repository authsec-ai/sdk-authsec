"""AgentIdentity — flow-selection + token acquisition for agent-to-MCP-server access.

Implements §10 of the Agent Identity spec:
  1. Discover Protected Resource Metadata (RFC 9728)
  2. Discover AS metadata (RFC 8414)
  3. Decide direct vs XAA (based on preferred_mode + requester-bootstrap)
  4. Run the chosen path and return a short-lived access token, or raise a
     typed PendingApprovalError when access is still being reviewed.

Usage (service-to-service M2M, API credential)::

    identity = AgentIdentity(
        issuer='https://auth.example.com',
        client_id='my-service-client-id',
        client_secret='sk-...',
    )
    token = await identity.access_for('https://payments.example.com/mcp')
    # → pass token as Bearer in every MCP tool call.

Usage (XAA cross-app, user-delegated)::

    identity = AgentIdentity(
        issuer='https://auth.example.com',
        client_id='my-agent-client-id',
        idp_issuer='https://idp.enterprise.com',
        preferred_mode='auto',
    )
    token = await identity.access_for(
        'https://payments.example.com/mcp',
        user_session={'subject_token': '...'},
        requested_scopes=['tickets.read'],
    )
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlencode, urlparse

import httpx

from ..runtime.metadata import build_resource_metadata_url
from .credentials import ClientAuth, ClientSecretAuth

# ── Error taxonomy (§9) ────────────────────────────────────────────────────────

__all__ = [
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
    # TypeScript parity: standalone polling helper
    "poll_until_approved",
    "PollOptions",
    # Browser PKCE login helper
    "browser_login",
]


class AuthSecIdentityError(Exception):
    """Base class for all AgentIdentity errors."""

    def __init__(self, code: str, message: str, http_status: Optional[int] = None) -> None:
        super().__init__(message)
        self.code = code
        self.http_status = http_status

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(code={self.code!r}, "
            f"message={str(self)!r}, http_status={self.http_status!r})"
        )


class PendingApprovalError(AuthSecIdentityError):
    """Access was requested and is awaiting admin approval. Poll status_url."""

    def __init__(self, request_id: str, status_url: str) -> None:
        super().__init__("access_pending", "Access requested — waiting for an admin.", 202)
        self.request_id = request_id
        self.status_url = status_url


class ApprovalDeniedError(AuthSecIdentityError):
    """An admin declined the access request."""

    def __init__(self) -> None:
        super().__init__("approval_denied", "An admin declined this access.", 403)


class ConnectionRevokedError(AuthSecIdentityError):
    """The agent connection was revoked."""

    def __init__(self) -> None:
        super().__init__("connection_revoked", "Access was revoked.", 401)


class TrustedIssuerMissingError(AuthSecIdentityError):
    """The issuer is not trusted by the AuthSec instance."""

    def __init__(self) -> None:
        super().__init__("trusted_issuer_missing", "This issuer isn't trusted here.", 403)


class SubjectMappingFailedError(AuthSecIdentityError):
    """Subject mapping from external identity to local user failed."""

    def __init__(self) -> None:
        super().__init__("subject_mapping_failed", "Couldn't map your identity.", 403)


class ResourceNotRegisteredError(AuthSecIdentityError):
    """The MCP server URI is not registered."""

    def __init__(self, resource: str) -> None:
        super().__init__(
            "resource_not_registered",
            f"Unknown MCP server: {resource}" if resource else "Unknown MCP server.",
            404,
        )


class CredentialInvalidError(AuthSecIdentityError):
    """The client credential is invalid."""

    def __init__(self, detail: Optional[str] = None) -> None:
        super().__init__("credential_invalid", detail or "Invalid client credential.", 401)


class WorkloadNotAttestedError(AuthSecIdentityError):
    """The workload has not yet attested via SPIFFE."""

    def __init__(self) -> None:
        super().__init__("workload_not_attested", "Workload hasn't attested yet.", 403)


# ── Type aliases ───────────────────────────────────────────────────────────────

PreferredMode = Literal["auto", "direct-only", "xaa-allowed"]

# ── Main class ────────────────────────────────────────────────────────────────


class AgentIdentity:
    """Obtain short-lived access tokens for MCP resource servers.

    Parameters
    ----------
    issuer:
        AuthSec AS issuer URL (e.g. ``https://auth.example.com``).
    client_id:
        OAuth ``client_id`` for this agent.
    auth:
        Client authentication method — any of
        :class:`~authsec_sdk.identity.ClientSecretAuth`,
        :class:`~authsec_sdk.identity.PrivateKeyJwtAuth`, or
        :class:`~authsec_sdk.identity.SpiffeSvidAuth`.
        Mutually exclusive with ``client_secret``.
    client_secret:
        Shorthand for ``auth=ClientSecretAuth(...)`` — the common case.
        Mutually exclusive with ``auth``.
    idp_issuer:
        Enterprise IdP issuer for XAA subject tokens. Required for XAA paths.
    preferred_mode:
        Flow preference — ``"auto"`` (default), ``"direct-only"``, or
        ``"xaa-allowed"``.
    token_endpoint:
        Override the token endpoint (discovered by default).
    session:
        Optional :class:`httpx.AsyncClient` to reuse. If ``None`` a new
        client is created and owned by this instance.
    """

    def __init__(
        self,
        issuer: str,
        client_id: str,
        *,
        auth: Optional[ClientAuth] = None,
        client_secret: Optional[str] = None,
        idp_issuer: Optional[str] = None,
        preferred_mode: PreferredMode = "auto",
        token_endpoint: Optional[str] = None,
        session: Optional[httpx.AsyncClient] = None,
    ) -> None:
        if not issuer:
            raise ValueError("AgentIdentity: issuer is required")
        if not client_id:
            raise ValueError("AgentIdentity: client_id is required")
        if auth is not None and client_secret:
            raise ValueError(
                "AgentIdentity: auth and client_secret are mutually exclusive "
                "— client_secret is shorthand for auth=ClientSecretAuth(...)"
            )

        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret  # kept for back-compat introspection
        self._auth: Optional[ClientAuth] = (
            auth if auth is not None
            else ClientSecretAuth(client_secret) if client_secret
            else None
        )
        self.idp_issuer = idp_issuer
        self.preferred_mode: PreferredMode = preferred_mode
        self.token_endpoint = token_endpoint

        self._owns_session = session is None
        self._session: httpx.AsyncClient = session if session is not None else httpx.AsyncClient(timeout=60.0)

        # In-memory token cache: resource → (token, expires_at)
        # expires_at is a Unix timestamp (float, seconds).
        self._cache: Dict[str, tuple[str, float]] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    async def access_for(
        self,
        resource: str,
        *,
        user_session: Optional[Dict[str, str]] = None,
        requested_scopes: Optional[List[str]] = None,
        extra: Optional[Dict[str, str]] = None,
    ) -> str:
        """Obtain a short-lived access token for *resource*.

        Returns the token string on success.

        Raises
        ------
        PendingApprovalError
            When access is requested but not yet approved.
        AuthSecIdentityError (and subclasses)
            For terminal failures (denied, revoked, credential invalid, …).
        """
        cached = self._cache.get(resource)
        if cached is not None:
            token, expires_at = cached
            # Serve from cache if it won't expire within the next 30 seconds.
            if expires_at > time.monotonic() + 30:
                return token

        return await self._acquire_token(
            resource,
            user_session=user_session,
            requested_scopes=requested_scopes,
            extra=extra,
        )

    def clear_cache(self, resource: Optional[str] = None) -> None:
        """Clear cached tokens.

        Parameters
        ----------
        resource:
            If given, only the entry for that resource is removed. Otherwise
            the entire cache is cleared (e.g. after receiving a 401 to force
            re-mint).
        """
        if resource is not None:
            self._cache.pop(resource, None)
        else:
            self._cache.clear()

    # ── Internal flow selection (§10) ─────────────────────────────────────────

    async def _acquire_token(
        self,
        resource: str,
        *,
        user_session: Optional[Dict[str, str]],
        requested_scopes: Optional[List[str]],
        extra: Optional[Dict[str, str]],
    ) -> str:
        prm = await self._discover_prm(resource)
        auth_servers: List[str] = prm.get("authorization_servers") or []
        if not auth_servers:
            raise ResourceNotRegisteredError(resource)

        as_url: str = auth_servers[0]
        as_meta = await self._discover_as(as_url)
        token_ep: str = self.token_endpoint or as_meta["token_endpoint"]

        mode = self.preferred_mode

        # direct-only: skip bootstrap entirely.
        if mode == "direct-only":
            return await self._direct(
                resource, token_ep,
                requested_scopes=requested_scopes, extra=extra,
            )

        # No XAA support on AS, or no IdP configured, or no user session → direct.
        # XAA is supported when grant_types_supported includes BOTH token-exchange
        # (to mint ID-JAG) AND jwt-bearer (to redeem it), AND the AS advertises the
        # ID-JAG token type — without it the token-exchange step can't produce an
        # ID-JAG, so XAA would fail later.
        grant_types: List[str] = as_meta.get("grant_types_supported") or []
        id_jag_token_types: List[str] = (
            as_meta.get("identity_chaining_requested_token_types_supported") or []
        )
        as_supports_xaa = (
            "urn:ietf:params:oauth:grant-type:token-exchange" in grant_types
            and "urn:ietf:params:oauth:grant-type:jwt-bearer" in grant_types
            and "urn:ietf:params:oauth:token-type:id-jag" in id_jag_token_types
        )
        if not as_supports_xaa or not self.idp_issuer or not user_session:
            return await self._direct(
                resource, token_ep,
                requested_scopes=requested_scopes, extra=extra,
            )

        # requester-bootstrap to decide path.
        try:
            bootstrap = await self._requester_bootstrap(
                resource, token_ep, requested_scopes=requested_scopes,
            )
        except AuthSecIdentityError:
            return await self._handle_bootstrap_unavailable(
                resource, prm, as_meta, token_ep,
                requested_scopes=requested_scopes, extra=extra,
            )

        # Find the target matching this resource. No match → safe default (direct).
        targets: List[Dict[str, Any]] = bootstrap.get("targets") or []
        target = next((t for t in targets if t.get("resource") == resource), None)
        if target is None:
            return await self._direct(
                resource, token_ep,
                requested_scopes=requested_scopes, extra=extra,
            )

        base = token_ep[: -len("/token")] if token_ep.endswith("/token") else token_ep

        # A pending access request for this target → surface PendingApprovalError (TS SDK parity).
        pending_list: List[Dict[str, Any]] = bootstrap.get("pending") or []
        pending = next(
            (
                p for p in pending_list
                if p.get("resource_server_id") == target.get("resource_server_id")
                and p.get("status") == "pending"
            ),
            None,
        )
        if pending is not None:
            request_id = str(pending.get("request_id") or "")
            raise PendingApprovalError(request_id, f"{base}/access-requests/{request_id}")

        if target.get("access_status") == "denied":
            raise ApprovalDeniedError()

        # A user session means the agent is acting on behalf of a user (delegation).
        # Always use XAA in this case, regardless of workspace relationship or bootstrap recommendation.
        if user_session:
            return await self._xaa(
                resource, as_meta, token_ep,
                user_session=user_session,
                requested_scopes=requested_scopes,
                extra=extra,
            )

        # Flow decision from the matched target.
        recommended = target.get("recommended_flow")
        relationship = target.get("relationship")

        if recommended == "id_jag":
            return await self._xaa(
                resource, as_meta, token_ep,
                user_session=user_session,
                requested_scopes=requested_scopes,
                extra=extra,
            )
        if recommended == "direct":
            return await self._direct(
                resource, token_ep,
                requested_scopes=requested_scopes, extra=extra,
            )
        if relationship == "cross_workspace":
            return await self._xaa(
                resource, as_meta, token_ep,
                user_session=user_session,
                requested_scopes=requested_scopes,
                extra=extra,
            )
        if relationship == "same_workspace":
            return await self._direct(
                resource, token_ep,
                requested_scopes=requested_scopes, extra=extra,
            )

        return await self._direct(
            resource, token_ep,
            requested_scopes=requested_scopes, extra=extra,
        )

    # ── Direct path (M2M client_credentials) ──────────────────────────────────

    async def _direct(
        self,
        resource: str,
        token_endpoint: str,
        *,
        requested_scopes: Optional[List[str]],
        extra: Optional[Dict[str, str]],
    ) -> str:
        body: Dict[str, str] = {
            "grant_type": "client_credentials",
            "resource": resource,
        }
        if requested_scopes:
            body["scope"] = " ".join(requested_scopes)
        if extra:
            body.update(extra)

        resp = await self._token_request(token_endpoint, body)
        token: str = resp["access_token"]
        expires_in: float = float(resp.get("expires_in") or 3600)
        self._cache[resource] = (token, time.monotonic() + expires_in)
        return token

    # ── XAA path (subject token → token-exchange → ID-JAG → jwt-bearer) ───────

    async def _xaa(
        self,
        resource: str,
        as_meta: Dict[str, Any],
        token_endpoint: str,
        *,
        user_session: Optional[Dict[str, str]],
        requested_scopes: Optional[List[str]],
        extra: Optional[Dict[str, str]],
    ) -> str:
        if not user_session or not user_session.get("subject_token"):
            raise AuthSecIdentityError(
                "xaa_requires_user_session",
                "XAA path requires a user session (subject_token).",
            )

        # Step 6c: token-exchange → ID-JAG (fresh every call, TS SDK parity).
        id_jag = await self._token_exchange(
            token_endpoint,
            user_session["subject_token"],
            resource,
            requested_scopes=requested_scopes,
        )

        # Step 6d: jwt-bearer redemption → access token.
        body: Dict[str, str] = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": id_jag,
            "resource": resource,
        }
        if requested_scopes:
            body["scope"] = " ".join(requested_scopes)
        if extra:
            body.update(extra)

        resp_body = await self._token_request(token_endpoint, body)

        # access_pending (202 surfaced as a 200 with pending status, or error field).
        if resp_body.get("error") == "access_pending" or resp_body.get("status") == "pending":
            request_id = str(resp_body.get("request_id") or "")
            base = (
                token_endpoint[: -len("/token")]
                if token_endpoint.endswith("/token")
                else token_endpoint
            )
            status_url = str(
                resp_body.get("status_url") or f"{base}/access-requests/{request_id}"
            )
            raise PendingApprovalError(request_id, status_url)

        token: str = resp_body["access_token"]
        expires_in: float = float(resp_body.get("expires_in") or 3600)
        self._cache[resource] = (token, time.monotonic() + expires_in)
        return token

    # ── token-exchange → ID-JAG ────────────────────────────────────────────────

    async def _token_exchange(
        self,
        token_endpoint: str,
        subject_token: str,
        resource: str,
        *,
        requested_scopes: Optional[List[str]],
    ) -> str:
        body: Dict[str, str] = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
            "resource": resource,
        }
        if requested_scopes:
            body["scope"] = " ".join(requested_scopes)

        resp = await self._token_request(token_endpoint, body)
        id_jag: str = resp.get("access_token", "")
        if not id_jag:
            raise AuthSecIdentityError(
                "token_exchange_failed",
                "Token exchange did not return an ID-JAG.",
            )
        return id_jag

    # ── requester-bootstrap ────────────────────────────────────────────────────

    async def _requester_bootstrap(
        self,
        resource: str,
        token_endpoint: str,
        *,
        requested_scopes: Optional[List[str]],
    ) -> Dict[str, Any]:
        # Bootstrap endpoint is on the same base as the token endpoint.
        base = token_endpoint.rstrip("/token").rstrip("/")
        # Handle both /oauth/token and /token paths.
        if token_endpoint.endswith("/token"):
            base = token_endpoint[: -len("/token")]
        bootstrap_url = f"{base}/requester-bootstrap"

        body: Dict[str, str] = {
            "client_id": self.client_id,
            "resource": resource,
            # Assertion-based auth (private_key_jwt / SPIFFE) authenticates via
            # body params; the assertion audience is the token endpoint.
            **self._auth_body_params(token_endpoint),
        }
        if requested_scopes:
            body["scope"] = " ".join(requested_scopes)

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            **self._auth_headers(),
        }
        resp = await self._session.post(
            bootstrap_url,
            content=urlencode(body),
            headers=headers,
        )

        if not resp.is_success:
            text = resp.text
            raise AuthSecIdentityError(
                "bootstrap_failed",
                f"requester-bootstrap failed ({resp.status_code}): {text}",
                resp.status_code,
            )

        return resp.json()

    # ── handleBootstrapUnavailable (§10) ──────────────────────────────────────

    async def _handle_bootstrap_unavailable(
        self,
        resource: str,
        prm: Dict[str, Any],
        as_meta: Dict[str, Any],
        token_endpoint: str,
        *,
        requested_scopes: Optional[List[str]],
        extra: Optional[Dict[str, str]],
    ) -> str:
        mode = self.preferred_mode

        if mode == "xaa-allowed":
            raise AuthSecIdentityError(
                "bootstrap_unavailable",
                "requester-bootstrap is unavailable and preferred_mode=xaa-allowed prevents silent fallback.",
                503,
            )

        # mode=auto: fall back to direct only if AS metadata proves direct is supported.
        bearer_methods: List[str] = prm.get("bearer_methods_supported") or []
        grant_types: List[str] = as_meta.get("grant_types_supported") or []

        # bearer_methods_supported not present → assume header supported.
        header_ok = (not bearer_methods) or ("header" in bearer_methods)
        # grant_types_supported not present → assume client_credentials supported.
        cc_ok = (not grant_types) or ("client_credentials" in grant_types)
        direct_supported = header_ok and cc_ok

        if not direct_supported:
            raise AuthSecIdentityError(
                "bootstrap_unavailable",
                "requester-bootstrap is unavailable and direct auth is not proven supported.",
                503,
            )

        return await self._direct(
            resource, token_endpoint,
            requested_scopes=requested_scopes, extra=extra,
        )

    # ── PRM discovery (RFC 9728) ───────────────────────────────────────────────

    async def _discover_prm(self, resource: str) -> Dict[str, Any]:
        prm_url = build_resource_metadata_url(resource)

        resp = await self._session.get(prm_url, headers={"Accept": "application/json"})
        if not resp.is_success:
            raise ResourceNotRegisteredError(resource)
        return resp.json()

    # ── AS metadata discovery (RFC 8414) ──────────────────────────────────────

    async def _discover_as(self, as_url: str) -> Dict[str, Any]:
        meta_url = f"{as_url.rstrip('/')}/.well-known/oauth-authorization-server"
        resp = await self._session.get(meta_url, headers={"Accept": "application/json"})
        if not resp.is_success:
            raise AuthSecIdentityError(
                "as_discovery_failed",
                f"AS metadata discovery failed for {as_url} ({resp.status_code})",
                resp.status_code,
            )
        return resp.json()

    # ── Token request helper ───────────────────────────────────────────────────

    async def _token_request(
        self,
        token_endpoint: str,
        body: Dict[str, str],
    ) -> Dict[str, Any]:
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            **self._auth_headers(),
        }
        full_body = {**body, **self._auth_body_params(token_endpoint)}
        # Assertion-based auth has no Basic header, so the server needs an
        # explicit client_id in the body (matches the raw protocol).
        if "Authorization" not in headers and "client_id" not in full_body:
            full_body["client_id"] = self.client_id
        resp = await self._session.post(
            token_endpoint,
            content=urlencode(full_body),
            headers=headers,
        )

        try:
            json_body: Dict[str, Any] = resp.json()
        except Exception:
            json_body = {}

        if not resp.is_success:
            self._raise_from_error_body(json_body, resp.status_code)

        return json_body

    def _raise_from_error_body(self, body: Dict[str, Any], status: int) -> None:
        """Inspect an error response body and raise the appropriate typed error."""
        code: str = body.get("error") or "server_error"
        msg: str = body.get("error_description") or "Token request failed."

        # Server uses error=access_denied + error_description=access_pending for pending requests.
        if code == "access_pending" or (code == "access_denied" and msg == "access_pending"):
            raise PendingApprovalError(
                str(body.get("request_id") or ""),
                str(body.get("status_url") or ""),
            )
        if code == "approval_denied":
            raise ApprovalDeniedError()
        if code == "connection_revoked":
            raise ConnectionRevokedError()
        if code == "trusted_issuer_missing":
            raise TrustedIssuerMissingError()
        if code == "subject_mapping_failed":
            raise SubjectMappingFailedError()
        if code == "resource_not_registered":
            raise ResourceNotRegisteredError("")
        if code in ("invalid_client", "credential_invalid"):
            raise CredentialInvalidError(msg)
        if code == "workload_not_attested":
            raise WorkloadNotAttestedError()

        raise AuthSecIdentityError(code, msg, status)

    # ── Client authentication ─────────────────────────────────────────────────

    def _auth_headers(self) -> Dict[str, str]:
        """Headers contributed by the configured auth method (Basic for
        client_secret; assertion-based methods contribute body params instead
        — see :meth:`_auth_body_params`)."""
        return self._auth.headers(self.client_id) if self._auth else {}

    def _auth_body_params(self, token_endpoint: str) -> Dict[str, str]:
        """POST body params contributed by the configured auth method
        (``client_assertion`` for private_key_jwt / SPIFFE SVID)."""
        return (
            self._auth.body_params(self.client_id, token_endpoint)
            if self._auth
            else {}
        )

    # ── Context-manager support ───────────────────────────────────────────────

    async def __aenter__(self) -> "AgentIdentity":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying HTTP session if this instance owns it."""
        if self._owns_session:
            await self._session.aclose()


# ── Standalone polling helper (TypeScript parity) ─────────────────────────────

@dataclass
class PollOptions:
    """Options for :func:`poll_until_approved`.

    TypeScript parity: mirrors ``PollOptions`` in ``agent-identity.ts``.
    """

    interval_seconds: float = 3.0
    """How often to poll the status URL."""

    timeout_seconds: float = 300.0
    """Maximum total time to wait before raising :class:`TimeoutError`."""


async def poll_until_approved(
    identity: "AgentIdentity",
    resource: str,
    status_url: str,
    *,
    opts: Optional[PollOptions] = None,
    user_session: Optional[Dict[str, str]] = None,
    requested_scopes: Optional[List[str]] = None,
) -> str:
    """Poll until access is approved and return the access token.

    Usage::

        try:
            token = await identity.access_for(resource)
        except PendingApprovalError as e:
            token = await poll_until_approved(identity, resource, e.status_url)

    TypeScript parity: mirrors ``pollUntilApproved()`` in ``agent-identity.ts``.
    """
    poll_opts = opts or PollOptions()
    deadline = time.monotonic() + poll_opts.timeout_seconds

    for attempt in range(int(poll_opts.timeout_seconds / poll_opts.interval_seconds) + 1):
        if time.monotonic() >= deadline:
            break

        if attempt > 0:
            await asyncio.sleep(poll_opts.interval_seconds)

        try:
            resp = await identity._session.get(status_url, headers={"Accept": "application/json"})
            if not resp.is_success:
                continue  # transient error — keep polling
            body = resp.json()
        except Exception:
            continue

        status = body.get("status")
        if status == "approved":
            identity.clear_cache(resource)
            return await identity.access_for(
                resource,
                user_session=user_session,
                requested_scopes=requested_scopes,
            )
        if status == "denied":
            raise ApprovalDeniedError()
        if status == "revoked":
            raise ConnectionRevokedError()
        # status=pending → keep polling

    raise TimeoutError(
        f"poll_until_approved: timed out after {poll_opts.timeout_seconds}s "
        f"waiting for approval of access to {resource}"
    )


# ── Browser PKCE login helper ─────────────────────────────────────────────────

async def browser_login(
    issuer: str,
    client_id: str,
    *,
    resource: Optional[str] = None,
    scopes: Optional[List[str]] = None,
    port: int = 8126,
    timeout_seconds: float = 300.0,
) -> str:
    """Open a browser PKCE login and return the ``id_token``.

    Handles everything internally — PKCE pair generation, one-shot local
    callback server, browser launch, and authorization-code exchange.
    The caller gets back a plain ``id_token`` string, ready to pass as
    ``user_session={"subject_token": id_token}`` to
    :meth:`AgentIdentity.access_for`.

    Usage::

        id_token = await browser_login(
            issuer    = os.environ["AUTHSEC_ISSUER"],
            client_id = os.environ["IDP_CLIENT_ID"],
        )

    Parameters
    ----------
    issuer:
        OIDC issuer base URL (e.g. ``https://mcpauthz.com``).
    client_id:
        Public (browser) OAuth client_id — no secret required.
    scopes:
        Scopes to request. Defaults to
        ``["openid", "email", "profile", "mcp:read", "mcp:tools:read"]``.
    port:
        Local port for the redirect callback. Default: ``8126``. Must match
        the redirect URI registered for the OAuth client.
    timeout_seconds:
        How long to wait for the user to complete the browser login before
        raising ``TimeoutError``. Default: 300 (5 minutes).

    Returns
    -------
    str
        The ``id_token`` from the OIDC token response.

    Raises
    ------
    RuntimeError
        If the browser login fails or no ``id_token`` is returned.
    TimeoutError
        If the user does not complete the login within ``timeout_seconds``.
    OSError
        If the callback port is already in use.
    """
    import base64
    import hashlib
    import secrets
    import webbrowser
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread
    from urllib.parse import parse_qs, urlencode, urlparse as _urlparse

    redirect_uri = f"http://localhost:{port}/callback"
    scope = " ".join(scopes or ["openid", "email", "profile"])

    # Discover OIDC endpoints
    discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=30.0) as _client:
        resp = await _client.get(discovery_url)
        if not resp.is_success:
            raise RuntimeError(
                f"browser_login: OIDC discovery failed — "
                f"HTTP {resp.status_code} from {discovery_url}"
            )
        try:
            meta = resp.json()
        except Exception as e:
            raise RuntimeError(
                f"browser_login: OIDC discovery returned non-JSON from "
                f"{discovery_url} (is the issuer reachable?)"
            ) from e

    # Generate PKCE pair
    verifier  = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )

    expected_state = secrets.token_urlsafe(16)
    auth_params: Dict[str, str] = {
        "response_type": "code", "client_id": client_id,
        "redirect_uri": redirect_uri, "scope": scope,
        "state": expected_state, "nonce": secrets.token_urlsafe(16),
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    if resource:
        auth_params["resource"] = resource
    auth_url = meta["authorization_endpoint"] + "?" + urlencode(auth_params)

    # One-shot callback server — shuts down after receiving the first code
    code_queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            query = parse_qs(_urlparse(self.path).query)
            code = query.get("code", [""])[0]
            state = query.get("state", [""])[0]
            if code and state == expected_state:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h2>Login complete &#8212; you can close this tab.</h2>")
                loop.call_soon_threadsafe(code_queue.put_nowait, code)
            elif code:
                # Code present but state mismatch — possible CSRF / stale
                # redirect from an earlier attempt. Reject it.
                self.send_response(400)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h2>Login rejected: state mismatch. Please retry.</h2>")
            else:
                # Prefetch / favicon requests — ignore.
                self.send_response(204)
                self.end_headers()

        def log_message(self, *_):
            pass  # silence request logs

    try:
        server = HTTPServer(("localhost", port), _Handler)
    except OSError as e:
        raise OSError(
            f"browser_login: cannot listen on localhost:{port} — the port is "
            f"already in use (another login in progress?). Original error: {e}"
        ) from e
    Thread(target=server.serve_forever, daemon=True).start()

    print(f"Opening browser for login. If it doesn't open, visit:\n{auth_url}", flush=True)
    webbrowser.open(auth_url)

    try:
        code = await asyncio.wait_for(code_queue.get(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        raise TimeoutError(
            f"browser_login: no login completed within {timeout_seconds:.0f}s"
        ) from None
    finally:
        server.shutdown()

    if not code:
        raise RuntimeError("browser_login: no auth code received")

    # Exchange code → tokens
    token_body: Dict[str, str] = {
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": redirect_uri, "client_id": client_id,
        "code_verifier": verifier,
    }
    if resource:
        token_body["resource"] = resource
    async with httpx.AsyncClient(timeout=30.0) as _client:
        resp = await _client.post(meta["token_endpoint"], data=token_body)
        try:
            tokens = resp.json()
        except Exception as e:
            raise RuntimeError(
                f"browser_login: token endpoint returned non-JSON "
                f"(HTTP {resp.status_code})"
            ) from e

    if "id_token" not in tokens:
        raise RuntimeError(f"browser_login: token exchange failed — {tokens}")

    return tokens["id_token"]
