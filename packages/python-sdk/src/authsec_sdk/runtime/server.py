"""Runtime — the customer-facing entry point for protecting an MCP server.

This is the Python equivalent of go-sdk's :type:`Runtime` and :func:`MountMCP`.
Typical usage with FastAPI / Starlette::

    from fastapi import FastAPI
    from authsec_sdk.runtime import Config, PolicyMode, ValidationMode, mount_mcp

    cfg = Config(
        issuer=os.environ["AUTHSEC_ISSUER"],               # e.g. https://stage.api.authsec.dev
        authorization_server=os.environ["AUTHSEC_ISSUER"],
        jwks_url=os.environ["AUTHSEC_ISSUER"] + "/oauth/jwks",
        introspection_url=os.environ["AUTHSEC_ISSUER"] + "/oauth/introspect",
        introspection_client_id=os.environ["AUTHSEC_INTROSPECTION_CLIENT_ID"],
        introspection_client_secret=os.environ["AUTHSEC_INTROSPECTION_CLIENT_SECRET"],
        resource_server_id=os.environ["AUTHSEC_RESOURCE_SERVER_ID"],
        resource_uri=os.environ["AUTHSEC_RESOURCE_URI"],
        resource_name=os.environ.get("AUTHSEC_RESOURCE_NAME", "My MCP Server"),
        policy_mode=PolicyMode.REMOTE_REQUIRED,
        validation_mode=ValidationMode.JWT_AND_INTROSPECT,
        publish_manifest=True,
    )

    app = FastAPI()
    mount_mcp(app, "/mcp", existing_mcp_handler, cfg)

After mount:

* ``GET /.well-known/oauth-protected-resource`` (RFC 9728) returns the
  metadata document.
* Unauthenticated requests to ``/mcp`` return ``401 Unauthorized`` with a
  ``WWW-Authenticate: Bearer realm=…, resource_metadata=…`` challenge.
* Authenticated requests are wrapped: the principal is attached to
  ``request.state.authsec_principal`` and tool calls are filtered by the
  fetched/cached scope matrix.
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextvars import ContextVar
from typing import Any, Awaitable, Callable, Optional

from .config import Config, PolicyMode
from .manifest import publish_manifest_safe
from .metadata import (
    build_resource_metadata_path,
    build_www_authenticate,
    is_metadata_request,
    metadata_json_response,
)
from .policy import ToolPolicyResult, ToolScopeMap, lookup_tool
from .principal import Principal
from .scope_matrix import PolicyIncompleteError, ScopeMatrixClient
from .validator import HybridValidator, TokenInactiveError, TokenInvalidError, new_validator

_LOG = logging.getLogger("authsec.runtime")

# Context var so async handlers downstream can read the principal without
# threading the ASGI request object through.
_principal_ctx: ContextVar[Optional[Principal]] = ContextVar(
    "authsec_principal", default=None
)


def principal_from_context() -> Optional[Principal]:
    """Return the authenticated :class:`Principal` for the current request."""
    return _principal_ctx.get()


class InsufficientScopeError(Exception):
    """Raised by :meth:`Runtime.authorize_tool` when scopes don't satisfy policy.

    Carries optional ``granted`` so the error response can tell the user
    *what they have* alongside *what they need* — turns an opaque "you can't
    do this" into "you have [a, b], you need [c]; ask your admin to grant c".
    """

    def __init__(self, tool: str, required: list[str], granted: list[str] | None = None) -> None:
        self.tool = tool
        self.required = list(required)
        self.granted = list(granted) if granted is not None else []
        msg = _format_scope_message(tool, self.required, self.granted)
        super().__init__(msg)


def _format_scope_message(tool: str, required: list[str], granted: list[str]) -> str:
    """Build the human-readable error message used in WWW-Authenticate +
    JSON body. langchain-mcp-adapters and similar libraries surface this
    string back to the agent, so it must read like an actionable sentence,
    not a Python repr."""
    req_str = ", ".join(required) if required else "(none discoverable)"
    if granted:
        granted_str = ", ".join(granted)
        return (
            f"Tool '{tool}' requires scope: {req_str}. "
            f"Your token has: {granted_str}. "
            f"Ask an AuthSec admin to grant the missing scope, or use a tool that fits your current scopes."
        )
    return (
        f"Tool '{tool}' requires scope: {req_str}. "
        f"Your token does not include this scope. "
        f"Ask an AuthSec admin to grant it, or use a tool that fits your current scopes."
    )


class PolicyUnavailableError(Exception):
    """Raised when the SDK can't determine tool policy and the mode forbids open."""


class Runtime:
    """The runtime that protects an MCP server.

    Responsibilities:

    * Validate bearer tokens via :class:`HybridValidator`.
    * Maintain the scope matrix (fetch + cache) via :class:`ScopeMatrixClient`.
    * Authorize tool invocations per the resolved :class:`ToolScopeMap`.
    * Serve the RFC 9728 protected-resource metadata.
    * Optionally publish the tool manifest at startup.
    """

    def __init__(self, cfg: Config) -> None:
        cfg.validate()
        self.cfg = cfg.normalized()
        self._validator: HybridValidator = new_validator(self.cfg)
        self._policy_mode = self.cfg.effective_policy_mode()
        self._scope_client: Optional[ScopeMatrixClient] = None
        if self._policy_mode in (
            PolicyMode.REMOTE_REQUIRED,
            PolicyMode.REMOTE_WITH_LOCAL_FALLBACK,
        ):
            self._scope_client = ScopeMatrixClient(self.cfg)

    # ────────────────────────────────────────────────────────────
    # Startup hook — call once from your app's startup event
    # ────────────────────────────────────────────────────────────

    async def startup(
        self,
        *,
        rpc_handler: Optional[Callable[[dict, dict], Awaitable[dict]]] = None,
    ) -> None:
        """Run mandatory startup actions.

        - PolicyMode.REMOTE_REQUIRED: fetch the initial scope matrix and FAIL
          if the fetch errors (per the contract).
        - PolicyMode.REMOTE_WITH_LOCAL_FALLBACK: try the fetch; log on failure
          and serve from ``cfg.tool_scopes`` instead.
        - PublishManifest=True: best-effort manifest publish.
        """
        if self._scope_client is not None:
            try:
                await self._scope_client.fetch_and_cache()
            except PolicyIncompleteError as e:
                if self.cfg.publish_manifest:
                    _LOG.warning(
                        "initial scope matrix fetch failed; starting in deny-all mode "
                        "(publish_manifest=True): %s",
                        e,
                    )
                elif self._policy_mode == PolicyMode.REMOTE_REQUIRED:
                    raise
                else:
                    _LOG.warning("policy incomplete at startup (falling back to local): %s", e)
            except Exception as e:
                if self.cfg.publish_manifest:
                    _LOG.warning(
                        "initial scope matrix fetch failed; starting in deny-all mode "
                        "(publish_manifest=True): %s",
                        e,
                    )
                elif self._policy_mode == PolicyMode.REMOTE_REQUIRED:
                    raise RuntimeError(
                        f"REMOTE_REQUIRED initial scope matrix fetch failed: {e}"
                    ) from e
                else:
                    _LOG.warning(
                        "initial scope matrix fetch failed (falling back to local): %s", e
                    )

        if self.cfg.publish_manifest:
            asyncio.create_task(publish_manifest_safe(self.cfg, rpc_handler=rpc_handler))

    # ────────────────────────────────────────────────────────────
    # Authoritative scope discovery for PRM publishing
    # ────────────────────────────────────────────────────────────

    async def get_authoritative_scopes(self) -> Optional[list[str]]:
        """Return the authoritative ``scopes_supported`` list for this RS,
        fetched from AuthSec via the scope matrix (TTL-cached, refreshed in
        the background).

        The PRM endpoint uses this so admin-side scope edits in the AuthSec UI
        propagate to MCP clients within one refresh cycle (≤5 min) — **no code
        change in the MCP server**.

        Returns ``None`` when:

        * the runtime has no scope matrix client (``policy_mode=local_only`` /
          ``open``),
        * the cache has never been populated, or
        * the cache exceeded ``max_stale_age`` with the last refresh in error.

        Callers (PRM builder) should fall back to ``cfg.supported_scopes``
        when this returns ``None`` so the server still serves a metadata
        document.
        """
        if self._scope_client is None:
            return None
        try:
            return await self._scope_client.get_scopes_supported()
        except Exception:
            return None

    # ────────────────────────────────────────────────────────────
    # Token validation + tool authorization
    # ────────────────────────────────────────────────────────────

    async def validate_token(self, token: str) -> Principal:
        principal = await self._validator.validate(token)
        # Audience check: token must be bound to this resource.
        if self.cfg.resource_uri and principal.audience:
            audience_ok = any(
                aud == self.cfg.resource_uri for aud in principal.audience
            )
            if not audience_ok:
                raise TokenInvalidError(
                    f"audience mismatch: token aud={principal.audience} "
                    f"does not include resource_uri={self.cfg.resource_uri}"
                )
        return principal

    async def authorize_tool(self, principal: Principal, tool_name: str) -> None:
        """Raise :class:`InsufficientScopeError` /
        :class:`PolicyUnavailableError` if the call is not allowed.

        ``InsufficientScopeError`` carries the principal's granted scopes so
        the resulting HTTP/WWW-Authenticate response can tell the caller
        exactly what they have vs. what they need.
        """
        if self._policy_mode == PolicyMode.OPEN:
            return

        tool_map = await self._resolve_tool_map()
        if tool_map is None:
            # In remote-required mode this is a hard failure (deny-all signal).
            if self._policy_mode == PolicyMode.REMOTE_REQUIRED:
                raise PolicyUnavailableError(
                    "tool policy unavailable — refusing in REMOTE_REQUIRED mode"
                )
            tool_map = self.cfg.tool_scopes or {}

        granted = list(principal.scopes)
        result, required = lookup_tool(tool_map, tool_name)
        if result == ToolPolicyResult.PUBLIC:
            return
        if result == ToolPolicyResult.ABSENT:
            # Tool exists in MCP but no AuthSec scope mapping — surface the
            # gap clearly instead of a cryptic "<tool not in policy>".
            raise InsufficientScopeError(
                tool_name,
                required=[f"<no scope mapping for tool '{tool_name}'>"],
                granted=granted,
            )
        granted_set = set(granted)
        if any(s in granted_set for s in required):
            return
        raise InsufficientScopeError(tool_name, required=required, granted=granted)

    async def _resolve_tool_map(self) -> Optional[ToolScopeMap]:
        if self._scope_client is not None:
            try:
                tm = await self._scope_client.get_cached()
                if tm is not None:
                    return tm
            except PolicyIncompleteError:
                return None
            except Exception as e:
                _LOG.warning("scope matrix fetch failed: %s", e)
                if self._policy_mode == PolicyMode.REMOTE_REQUIRED:
                    return None
        return self.cfg.tool_scopes


# ────────────────────────────────────────────────────────────────────
# ASGI middleware — mount_mcp wraps an existing MCP handler
# ────────────────────────────────────────────────────────────────────


def mount_mcp(
    app: Any,
    path: str,
    handler: Callable[..., Awaitable[Any]],
    cfg: Config,
    *,
    rpc_handler: Optional[Callable[[dict, dict], Awaitable[dict]]] = None,
) -> Runtime:
    """Mount an AuthSec-protected MCP route on a FastAPI / Starlette app.

    ``app`` must be a Starlette or FastAPI instance.
    ``path`` is the URL prefix (e.g. ``"/mcp"``).
    ``handler`` is the existing MCP Starlette/FastAPI route handler.

    Returns the constructed :class:`Runtime` so the caller can hook startup
    and customize further (e.g. add custom event handlers).
    """
    try:
        from starlette.requests import Request
        from starlette.responses import JSONResponse, Response
    except ImportError as e:  # pragma: no cover — declared as a dependency
        raise RuntimeError("mount_mcp requires Starlette/FastAPI") from e

    rt = Runtime(cfg)

    # ── Metadata route (RFC 9728) ────────────────────────────────────
    metadata_path = build_resource_metadata_path(cfg.resource_uri)

    async def _metadata(_request: Request) -> Response:
        # PRM is served from the runtime's scope-matrix cache so admin-side
        # scope changes in AuthSec auto-propagate without a redeploy. Falls
        # back to cfg.supported_scopes only when the cache hasn't populated
        # (boot race) or when policy_mode=local_only.
        authoritative = await rt.get_authoritative_scopes()
        body, headers = metadata_json_response(rt.cfg, authoritative)
        return Response(content=body, media_type="application/json", headers=headers)

    # ── Protected MCP route ──────────────────────────────────────────
    async def _protected(request: Request) -> Response:
        # Extract bearer token.
        token = _extract_bearer(request.headers.get("authorization", ""))
        if not token:
            return _unauthorized(rt.cfg, "missing bearer token")

        try:
            principal = await rt.validate_token(token)
        except TokenInactiveError as e:
            return _unauthorized(rt.cfg, str(e), error="invalid_token")
        except TokenInvalidError as e:
            return _unauthorized(rt.cfg, str(e), error="invalid_token")
        except Exception as e:  # noqa: BLE001
            _LOG.exception("unexpected token validation failure")
            return _unauthorized(rt.cfg, "token validation failure", error="invalid_token")

        # Stash on context + request state for downstream handlers.
        request.state.authsec_principal = principal
        token_ctx = _principal_ctx.set(principal)

        # If this is an MCP JSON-RPC call, intercept tools/call for authorization.
        try:
            body_bytes = await request.body()
            if body_bytes and request.method == "POST":
                try:
                    payload = json.loads(body_bytes)
                except json.JSONDecodeError:
                    payload = None
                if isinstance(payload, dict) and payload.get("method") == "tools/call":
                    tool_name = (payload.get("params") or {}).get("name", "")
                    if tool_name:
                        try:
                            await rt.authorize_tool(principal, tool_name)
                        except InsufficientScopeError as e:
                            return _insufficient_scope(rt.cfg, e)
                        except PolicyUnavailableError as e:
                            return _policy_unavailable(rt.cfg, str(e))

            # Hand off to the wrapped handler. We must rebuild the receive
            # channel because we consumed the body above.
            return await _call_with_replayed_body(handler, request, body_bytes)
        finally:
            _principal_ctx.reset(token_ctx)

    # Wire routes into Starlette / FastAPI.
    if hasattr(app, "add_api_route"):  # FastAPI
        app.add_api_route(metadata_path, _metadata, methods=["GET"])
        app.add_api_route(path, _protected, methods=["GET", "POST"])
    else:  # plain Starlette
        from starlette.routing import Route

        app.routes.append(Route(metadata_path, _metadata, methods=["GET"]))
        app.routes.append(Route(path, _protected, methods=["GET", "POST"]))

    # Hook startup so the customer doesn't have to remember.
    if hasattr(app, "on_event"):  # FastAPI / Starlette
        @app.on_event("startup")
        async def _startup() -> None:  # pragma: no cover — exercised at runtime
            await rt.startup(rpc_handler=rpc_handler)

    return rt


# ────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────


def _extract_bearer(authorization_header: str) -> str:
    if not authorization_header:
        return ""
    parts = authorization_header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


def _unauthorized(cfg: Config, message: str, *, error: str = "") -> Any:
    """Return a 401 with a structured `WWW-Authenticate` challenge.

    The body includes a stable ``reason`` field that AuthSec client SDKs can
    parse to disambiguate (a) bad/missing token, (b) expired token, (c)
    revoked token, (d) revoked client registration — without scraping the
    free-text ``error_description``.
    """
    from starlette.responses import JSONResponse

    err_code = error or "invalid_token"
    reason = _classify_auth_reason(message)
    headers = {
        "WWW-Authenticate": build_www_authenticate(
            cfg,
            error=err_code,
            error_description=message,
        ),
    }
    return JSONResponse(
        {
            "error": err_code,
            "error_description": message,
            "reason": reason,
        },
        status_code=401,
        headers=headers,
    )


def _classify_auth_reason(message: str) -> str:
    """Map a free-text 401 message to a stable, parseable reason code."""
    m = (message or "").lower()
    if "revoked" in m and ("registration" in m or "client" in m):
        return "client_registration_revoked"
    if "revoked" in m:
        return "token_revoked"
    if "expired" in m or "expir" in m:
        return "token_expired"
    if "audience" in m:
        return "audience_mismatch"
    if "missing" in m or "bearer" in m:
        return "no_token"
    return "invalid_token"


def _insufficient_scope(cfg: Config, err: InsufficientScopeError) -> Any:
    """Return a 403 with both a human-readable message AND structured fields.

    The human-readable ``error_description`` is what most MCP client libraries
    (e.g. langchain-mcp-adapters) surface back to the agent — so it must
    read like a sentence. The structured fields (``tool``, ``required_scopes``,
    ``granted_scopes``) let well-behaved client SDKs parse the error
    programmatically without scraping strings.
    """
    from starlette.responses import JSONResponse

    scope = " ".join(err.required) if err.required else ""
    description = str(err)  # Uses InsufficientScopeError.__str__ — already actionable.
    headers = {
        "WWW-Authenticate": build_www_authenticate(
            cfg,
            error="insufficient_scope",
            error_description=description,
            scope=scope,
        ),
    }
    return JSONResponse(
        {
            "error": "insufficient_scope",
            "error_description": description,
            "tool": err.tool,
            "required_scopes": err.required,
            "granted_scopes": err.granted,
        },
        status_code=403,
        headers=headers,
    )


def _policy_unavailable(cfg: Config, message: str) -> Any:
    from starlette.responses import JSONResponse

    return JSONResponse(
        {"error": "policy_unavailable", "error_description": message},
        status_code=503,
        headers={
            "WWW-Authenticate": build_www_authenticate(
                cfg,
                error="policy_unavailable",
                error_description=message,
            )
        },
    )


async def _call_with_replayed_body(
    handler: Callable[..., Awaitable[Any]], request: Any, body: bytes
) -> Any:
    """Re-attach the consumed body to ``request`` and dispatch to ``handler``."""
    # We monkey-patch the receive channel so the downstream handler sees the body.
    sent = False

    async def _receive() -> dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    request._receive = _receive  # type: ignore[attr-defined]
    return await handler(request)
