"""Runtime — the customer-facing entry point for protecting an MCP server.

Python parity port of typescript-sdk's ``runtime/runtime.ts`` +
``runtime/server.ts``.

Typical usage with FastAPI / Starlette::

    from fastapi import FastAPI
    from authsec_sdk.runtime import Config, PolicyMode, ValidationMode, mount_mcp

    cfg = Config(
        issuer=os.environ["AUTHSEC_ISSUER"],
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
* Unauthenticated / invalid-token requests to ``/mcp`` return ``401
  Unauthorized`` with a ``WWW-Authenticate: Bearer`` challenge.
* MCP handshake requests (``initialize``, ``notifications/initialized``,
  ``ping``) are passed through even without a valid token so the MCP
  session can be established before authentication is presented.
* ``tools/call`` auth denials are returned **in-band** as JSON-RPC error
  payloads (HTTP 200) so MCP clients receive properly-structured errors.
* ``tools/list`` responses are **filtered by the principal's scopes** —
  tools the caller can't access are stripped from the list.
* Authenticated requests attach the principal to
  ``request.state.authsec_principal`` for downstream handlers.
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Literal, Optional, Union

from .config import Config, PolicyMode
from .manifest import publish_manifest_safe
from .metadata import (
    build_resource_metadata_path,
    build_www_authenticate,
    is_metadata_request,
    metadata_json_response,
)
from .policy import LookupResult, ToolScopeMap, lookup_tool, tool_scope_map_from_record
from .principal import Principal
from .scope_matrix import PolicyIncompleteError, ScopeMatrixClient
from .validator import HybridValidator, TokenInactiveError, TokenInvalidError, new_validator

# Starlette / FastAPI — optional import at module level so the module can be
# imported cleanly without starlette installed; mount_mcp checks _STARLETTE_OK
# at call time.  Having them here also lets get_type_hints() on inner closures
# work correctly in Python 3.14+: annotations are resolved via __globals__
# (the module dict), not the local scope of the enclosing function.
try:
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response, StreamingResponse
    _STARLETTE_OK = True
except ImportError:
    _STARLETTE_OK = False
    Request = None  # type: ignore[misc,assignment]
    JSONResponse = None  # type: ignore[misc,assignment]
    Response = None  # type: ignore[misc,assignment]
    StreamingResponse = None  # type: ignore[misc,assignment]

_LOG = logging.getLogger("authsec.runtime")

# Context var so async handlers downstream can read the principal without
# threading the ASGI request object through.
_principal_ctx: ContextVar[Optional[Principal]] = ContextVar(
    "authsec_principal", default=None
)


def principal_from_context() -> Optional[Principal]:
    """Return the authenticated :class:`Principal` for the current request."""
    return _principal_ctx.get()


# ── Denial / Authorization result types ──────────────────────────────────────
# TypeScript parity: mirrors DenialCode / AuthorizeDenial / AuthorizeResult in
# runtime/runtime.ts.

DenialCode = Literal[
    "invalid_token",
    "invalid_audience",
    "scope_insufficient",
    "policy_unavailable",
]


@dataclass
class AuthorizeDenial:
    """Structured denial that carries everything needed to build a 401/403/503.

    TypeScript parity: mirrors the ``AuthorizeDenial`` interface in
    ``runtime/runtime.ts``.
    """

    code: DenialCode
    description: str
    status: int
    www_authenticate: str
    required_scopes: Optional[list[str]] = None
    granted_scopes: Optional[list[str]] = None
    tool: Optional[str] = None
    # Stable, parseable subreason for 401s — ``token_revoked``,
    # ``client_registration_revoked``, ``token_expired``, ``audience_mismatch``,
    # ``no_token``, ``invalid_token``. Empty for non-401 denials.
    reason: Optional[str] = None


@dataclass
class AuthorizeResult:
    """Discriminated union result from :meth:`Runtime.authorize`.

    TypeScript parity: mirrors ``AuthorizeResult`` in ``runtime/runtime.ts``.

    Check ``allowed`` first::

        result = await runtime.authorize(token, tool_name)
        if not result.allowed:
            # result.denial carries HTTP status, WWW-Authenticate, etc.
            ...
        else:
            # result.principal is the authenticated subject
            ...
    """

    allowed: bool
    principal: Optional[Principal] = None
    denial: Optional[AuthorizeDenial] = None


# ── Error classes (legacy exception-based API kept for backwards compat) ──────

class InsufficientScopeError(Exception):
    """Raised by :meth:`Runtime.authorize_tool` when scopes don't satisfy policy.

    Carries optional ``granted`` so the error response can tell the user
    *what they have* alongside *what they need*.
    """

    def __init__(self, tool: str, required: list[str], granted: list[str] | None = None) -> None:
        self.tool = tool
        self.required = list(required)
        self.granted = list(granted) if granted is not None else []
        msg = _format_scope_message(tool, self.required, self.granted)
        super().__init__(msg)


class PolicyUnavailableError(Exception):
    """Raised when the SDK can't determine tool policy and the mode forbids open."""


# ── Runtime ───────────────────────────────────────────────────────────────────

class Runtime:
    """The runtime that protects an MCP server.

    Responsibilities:

    * Validate bearer tokens via :class:`HybridValidator`.
    * Maintain the scope matrix (fetch + cache) via :class:`ScopeMatrixClient`.
    * Authorize tool invocations per the resolved :class:`ToolScopeMap`.
    * Serve the RFC 9728 protected-resource metadata.
    * Optionally publish the tool manifest at startup.

    TypeScript parity: mirrors ``Runtime`` in ``runtime/runtime.ts``.
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

    # ── Factory (TypeScript parity: Runtime.create()) ────────────────────────

    @classmethod
    async def create(
        cls,
        cfg: Config,
        *,
        rpc_handler: Optional[Callable[[dict, dict], Awaitable[dict]]] = None,
    ) -> "Runtime":
        """Construct and initialize a Runtime in one call.

        Performs the initial scope-matrix fetch (mandatory under
        ``REMOTE_REQUIRED``) so that boot fails loudly on misconfiguration.

        TypeScript parity: mirrors ``Runtime.create()`` in
        ``runtime/runtime.ts``.
        """
        rt = cls(cfg)
        await rt.startup(rpc_handler=rpc_handler)
        return rt

    # ── Startup ──────────────────────────────────────────────────────────────

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

    # ── Authoritative scopes ─────────────────────────────────────────────────

    async def get_authoritative_scopes(self) -> Optional[list[str]]:
        """Return the authoritative ``scopes_supported`` list for this RS."""
        if self._scope_client is None:
            return None
        try:
            return await self._scope_client.get_scopes_supported()
        except Exception:
            return None

    # ── Token validation ─────────────────────────────────────────────────────

    async def validate_token(self, token: str) -> Principal:
        """Pure token validation; raises on failure."""
        principal = await self._validator.validate(token)
        if self.cfg.resource_uri and principal.audience:
            audience_ok = any(aud == self.cfg.resource_uri for aud in principal.audience)
            if not audience_ok:
                raise TokenInvalidError(
                    f"audience mismatch: token aud={principal.audience} "
                    f"does not include resource_uri={self.cfg.resource_uri}"
                )
        return principal

    # ── authorize() — combined validation + tool check ───────────────────────

    async def authorize(self, token: str, tool_id: str) -> AuthorizeResult:
        """Top-level authorization: validate the bearer token AND check tool scope.

        Returns a structured :class:`AuthorizeResult` — never raises.

        TypeScript parity: mirrors ``Runtime.authorize()`` in
        ``runtime/runtime.ts``.
        """
        if not token:
            return self._deny_invalid_token("missing bearer token")

        try:
            principal = await self.validate_token(token)
        except TokenInactiveError as e:
            return self._deny_invalid_token(str(e))
        except TokenInvalidError as e:
            msg = str(e)
            if "audience mismatch" in msg.lower() or "audience" in msg.lower():
                return self._deny_invalid_audience(msg)
            return self._deny_invalid_token(msg)
        except Exception as e:
            return self._deny_invalid_token(f"token validation failure: {e}")

        return await self.authorize_principal(principal, tool_id)

    # ── authorize_principal() — per-tool check on a validated principal ───────

    async def authorize_principal(
        self, principal: Principal, tool_id: str
    ) -> AuthorizeResult:
        """Authorize an already-validated principal for a specific MCP tool.

        Used by the middleware for ``tools/list`` filtering and by custom hosts
        that validate tokens once per request and then check each tool call.

        TypeScript parity: mirrors ``Runtime.authorizePrincipal()`` in
        ``runtime/runtime.ts``.
        """
        if self._policy_mode == PolicyMode.OPEN:
            return AuthorizeResult(allowed=True, principal=principal)

        tool = (tool_id or "").strip()
        if not tool:
            # No tool id (non tools/call request) — let the caller decide.
            return AuthorizeResult(allowed=True, principal=principal)

        tool_map: Optional[ToolScopeMap] = None
        policy_unavailable = False

        if self._scope_client is not None:
            try:
                tool_map = await self._scope_client.get_cached()
            except PolicyIncompleteError as e:
                if self._policy_mode == PolicyMode.REMOTE_REQUIRED:
                    return self._deny_policy_unavailable(str(e))
                policy_unavailable = True
            except Exception as e:
                _LOG.warning("scope matrix fetch failed: %s", e)
                if self._policy_mode == PolicyMode.REMOTE_REQUIRED:
                    return self._deny_policy_unavailable(str(e))
                policy_unavailable = True

        if tool_map is None and self._policy_mode == PolicyMode.REMOTE_REQUIRED:
            return self._deny_policy_unavailable(
                "tool policy unavailable in REMOTE_REQUIRED mode"
            )

        if tool_map is None:
            # Fall back to local toolScopes (local_only or fallback path).
            tool_map = tool_scope_map_from_record(self.cfg.tool_scopes)

        if tool_map is None:
            return self._deny_policy_unavailable("no tool policy configured")

        if policy_unavailable and self._policy_mode == PolicyMode.REMOTE_REQUIRED:
            return self._deny_policy_unavailable("tool policy unavailable")

        result = lookup_tool(tool_map, tool)
        if result.denied == "policy_incomplete":
            return self._deny_policy_unavailable("tool policy incomplete")
        if result.outcome == "public":
            return AuthorizeResult(allowed=True, principal=principal)
        if result.outcome == "absent":
            return self._deny_scope_insufficient(
                tool,
                [f"<no scope mapping for tool '{tool}'>"],
                list(principal.scopes),
            )
        # SCOPED — check if principal has at least one required scope
        granted_set = set(principal.scopes)
        if any(s in granted_set for s in result.required_any):
            return AuthorizeResult(allowed=True, principal=principal)
        return self._deny_scope_insufficient(tool, result.required_any, list(principal.scopes))

    # Camel-case alias for TypeScript parity
    authorizePrincipal = authorize_principal

    # ── Legacy exception-based API (backwards compat) ────────────────────────

    async def authorize_tool(self, principal: Principal, tool_name: str) -> None:
        """Raise :class:`InsufficientScopeError` / :class:`PolicyUnavailableError`
        if the call is not allowed.

        .. deprecated::
            Prefer :meth:`authorize` or :meth:`authorize_principal` which
            return a structured :class:`AuthorizeResult` instead of raising.
        """
        result = await self.authorize_principal(principal, tool_name)
        if not result.allowed:
            denial = result.denial
            if denial.code == "policy_unavailable":
                raise PolicyUnavailableError(denial.description)
            raise InsufficientScopeError(
                denial.tool or tool_name,
                denial.required_scopes or [],
                denial.granted_scopes or [],
            )

    # ── Private denial helpers ────────────────────────────────────────────────

    def _deny_invalid_token(self, description: str) -> AuthorizeResult:
        return AuthorizeResult(
            allowed=False,
            denial=AuthorizeDenial(
                code="invalid_token",
                description=description,
                status=401,
                www_authenticate=build_www_authenticate(
                    self.cfg, error="invalid_token", error_description=description
                ),
                reason=_classify_auth_reason(description),
            ),
        )

    def _deny_invalid_audience(self, description: str) -> AuthorizeResult:
        return AuthorizeResult(
            allowed=False,
            denial=AuthorizeDenial(
                code="invalid_audience",
                description=description,
                status=401,
                www_authenticate=build_www_authenticate(
                    self.cfg, error="invalid_audience", error_description=description
                ),
            ),
        )

    def _deny_scope_insufficient(
        self,
        tool: str,
        required: list[str],
        granted: list[str] | None = None,
    ) -> AuthorizeResult:
        granted = granted or []
        scope = " ".join(required)
        description = _format_scope_message(tool, required, granted)
        return AuthorizeResult(
            allowed=False,
            denial=AuthorizeDenial(
                code="scope_insufficient",
                description=description,
                status=403,
                www_authenticate=build_www_authenticate(
                    self.cfg,
                    error="insufficient_scope",
                    error_description=description,
                    scope=scope,
                ),
                required_scopes=list(required),
                granted_scopes=list(granted),
                tool=tool,
            ),
        )

    def _deny_policy_unavailable(self, description: str) -> AuthorizeResult:
        return AuthorizeResult(
            allowed=False,
            denial=AuthorizeDenial(
                code="policy_unavailable",
                description=description,
                status=503,
                www_authenticate=build_www_authenticate(
                    self.cfg,
                    error="policy_unavailable",
                    error_description=description,
                ),
            ),
        )

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


# ── Tool-id extraction helpers ────────────────────────────────────────────────
# TypeScript parity: mirrors extractToolIdFromBody / extractToolIdsFromBody
# in runtime/server.ts.

def extract_tool_ids_from_body(body: Any) -> list[str]:
    """Extract tool ids from a JSON-RPC request body.

    Handles single requests and batch (array) requests; non tools/call
    requests are ignored.

    TypeScript parity: mirrors ``extractToolIdsFromBody()`` in
    ``runtime/server.ts``.
    """
    if not body:
        return []
    if isinstance(body, list):
        ids: list[str] = []
        for item in body:
            ids.extend(extract_tool_ids_from_body(item))
        return ids
    if not isinstance(body, dict):
        return []
    if body.get("method") != "tools/call":
        return []
    params = body.get("params") or {}
    name = params.get("name") if isinstance(params, dict) else None
    return [name] if isinstance(name, str) and name else []


def extract_tool_id_from_body(body: Any) -> str:
    """Extract a single tool id from a JSON-RPC request body.

    Returns ``""`` for non tools/call requests.

    TypeScript parity: mirrors ``extractToolIdFromBody()`` in
    ``runtime/server.ts``.
    """
    ids = extract_tool_ids_from_body(body)
    return ids[0] if ids else ""


# Camel-case aliases for TypeScript parity
extractToolIdsFromBody = extract_tool_ids_from_body
extractToolIdFromBody = extract_tool_id_from_body


# ── MCP request classification helpers ───────────────────────────────────────

def _is_tools_list_request(body: Any) -> bool:
    if not body:
        return False
    if isinstance(body, list):
        return any(_is_tools_list_request(item) for item in body)
    if not isinstance(body, dict):
        return False
    return body.get("method") == "tools/list"


def _is_tools_call_request(body: Any) -> bool:
    if not body:
        return False
    if isinstance(body, list):
        return any(_is_tools_call_request(item) for item in body)
    if not isinstance(body, dict):
        return False
    return body.get("method") == "tools/call"


def _is_json_rpc_request(body: Any) -> bool:
    if not body:
        return False
    if isinstance(body, list):
        return any(_is_json_rpc_request(item) for item in body)
    if not isinstance(body, dict):
        return False
    return body.get("jsonrpc") == "2.0"


_MCP_HANDSHAKE_METHODS = frozenset(
    {"initialize", "notifications/initialized", "ping"}
)


def _is_mcp_handshake_request(body: Any) -> bool:
    """True iff body is a MCP session-setup request that should pass through
    even when the bearer token is missing / invalid."""
    if not body:
        return False
    if isinstance(body, list):
        return body and all(_is_mcp_handshake_request(item) for item in body)
    if not isinstance(body, dict):
        return False
    return body.get("method") in _MCP_HANDSHAKE_METHODS


def _should_handle_mcp_auth_denial_in_band(
    token: str, body: Any, denial: AuthorizeDenial
) -> bool:
    if not token:
        return False
    if denial.status not in (401, 403):
        return False
    return _is_json_rpc_request(body)


def _should_pass_through_mcp_handshake(
    token: str, body: Any, denial: AuthorizeDenial
) -> bool:
    return (
        _should_handle_mcp_auth_denial_in_band(token, body, denial)
        and _is_mcp_handshake_request(body)
    )


def _should_return_mcp_tool_auth_error(
    token: str, body: Any, denial: AuthorizeDenial
) -> bool:
    return (
        _should_handle_mcp_auth_denial_in_band(token, body, denial)
        and _is_tools_call_request(body)
    )


def _should_return_mcp_json_rpc_auth_error(
    token: str, body: Any, denial: AuthorizeDenial
) -> bool:
    return _should_handle_mcp_auth_denial_in_band(token, body, denial)


# ── In-band JSON-RPC error builders ──────────────────────────────────────────

def _valid_json_rpc_id(id_val: Any) -> bool:
    return id_val is None or isinstance(id_val, (str, int, float))


def _authsec_denial_meta(denial: AuthorizeDenial) -> dict:
    d: dict = {
        "error": "insufficient_scope" if denial.code == "scope_insufficient" else denial.code,
        "status": denial.status,
        "error_description": denial.description,
    }
    if denial.required_scopes:
        d["required_scopes"] = denial.required_scopes
    if denial.tool:
        d["tool"] = denial.tool
    return d


def _friendly_auth_denial_message(denial: AuthorizeDenial) -> str:
    if denial.status == 403:
        parts = []
        if denial.tool:
            parts.append(f"Tool '{denial.tool}' cannot be called with this token.")
        else:
            parts.append("This action cannot be performed with this token.")
        if denial.required_scopes:
            parts.append(f"Required scope: {', '.join(denial.required_scopes)}.")
        if denial.granted_scopes:
            parts.append(f"Your token has: {', '.join(denial.granted_scopes)}.")
        else:
            parts.append("Your token does not include the required scope.")
        parts.append(
            "Ask an admin to grant the required scope to your role, or use a different tool."
        )
        return " ".join(parts)
    if denial.reason == "token_revoked":
        return "Access has been revoked. The user needs to re-authenticate to get a new token."
    if denial.reason == "client_registration_revoked":
        return (
            "This client's registration has been revoked by an admin. "
            "Re-authentication will not help — contact the workspace admin."
        )
    return "Token is invalid or expired. The user needs to sign in again."


def _mcp_tool_auth_error_for_request(
    request: dict, denial: AuthorizeDenial
) -> dict:
    id_val = request.get("id") if _valid_json_rpc_id(request.get("id")) else None
    text = _friendly_auth_denial_message(denial)
    authsec_meta: dict = {
        "error": "insufficient_scope" if denial.code == "scope_insufficient" else denial.code,
        "status": denial.status,
        "error_description": denial.description,
    }
    if denial.required_scopes:
        authsec_meta["required_scopes"] = denial.required_scopes
    if denial.granted_scopes:
        authsec_meta["granted_scopes"] = denial.granted_scopes
    if denial.tool:
        authsec_meta["tool"] = denial.tool
    if denial.reason:
        authsec_meta["reason"] = denial.reason
    return {
        "jsonrpc": "2.0",
        "id": id_val,
        "result": {
            "content": [{"type": "text", "text": text}],
            "isError": True,
            "_meta": {"authsec": authsec_meta},
        },
    }


def _mcp_json_rpc_auth_error_for_request(
    request: dict, denial: AuthorizeDenial
) -> dict:
    id_val = request.get("id") if _valid_json_rpc_id(request.get("id")) else None
    return {
        "jsonrpc": "2.0",
        "id": id_val,
        "error": {
            "code": -32003 if denial.status == 403 else -32001,
            "message": _friendly_auth_denial_message(denial),
            "data": {"authsec": _authsec_denial_meta(denial)},
        },
    }


def _mcp_tool_auth_error_payload(body: Any, denial: AuthorizeDenial) -> Any:
    if isinstance(body, list):
        return [
            _mcp_tool_auth_error_for_request(item, denial)
            for item in body
            if isinstance(item, dict)
        ]
    req = body if isinstance(body, dict) else {}
    return _mcp_tool_auth_error_for_request(req, denial)


def _mcp_json_rpc_auth_error_payload(body: Any, denial: AuthorizeDenial) -> Any:
    if isinstance(body, list):
        return [
            _mcp_json_rpc_auth_error_for_request(item, denial)
            for item in body
            if isinstance(item, dict)
        ]
    req = body if isinstance(body, dict) else {}
    return _mcp_json_rpc_auth_error_for_request(req, denial)


# ── tools/list response filtering ────────────────────────────────────────────

async def _filter_tools_list_payload(
    rt: Runtime, principal: Principal, payload: Any
) -> Any:
    """Filter a tools/list JSON-RPC response to only include tools the
    principal can access."""
    if isinstance(payload, list):
        return [await _filter_tools_list_payload(rt, principal, item) for item in payload]
    if not isinstance(payload, dict):
        return payload
    result_obj = payload.get("result")
    if not isinstance(result_obj, dict):
        return payload
    tools = result_obj.get("tools")
    if not isinstance(tools, list):
        return payload

    filtered = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name")
        if not isinstance(name, str) or not name:
            continue
        decision = await rt.authorize_principal(principal, name)
        if not decision.allowed:
            if decision.denial.code == "policy_unavailable":
                raise decision.denial
            continue
        filtered.append(tool)

    return {**payload, "result": {**result_obj, "tools": filtered}}


# ── WWW-Authenticate defensive setter ────────────────────────────────────────

def _safe_set_www_authenticate(headers: dict, value: str) -> None:
    """Set WWW-Authenticate header defensively.

    TypeScript parity: mirrors ``safeSetWwwAuthenticate()`` in
    ``runtime/server.ts``. Protects against non-ASCII chars in error
    messages that would crash Starlette/uvicorn response header encoding.
    """
    try:
        # Build a test response to check the header is valid ASCII.
        value.encode("latin-1")
        headers["WWW-Authenticate"] = value
    except (UnicodeEncodeError, ValueError):
        try:
            headers["WWW-Authenticate"] = 'Bearer realm="mcp", error="invalid_token"'
        except Exception:
            pass


# ── ASGI-app → Starlette-handler adapter ─────────────────────────────────────


def _wrap_asgi_as_handler(asgi_app: Any) -> Callable[..., Awaitable[Any]]:
    """Convert a raw ASGI callable (scope, receive, send) into a Starlette handler.

    For non-streaming responses (``application/json`` etc.) the body is fully
    buffered so that ``tools/list`` scope-filtering can read and rewrite it.
    For SSE responses (``text/event-stream``) the body is forwarded via a
    :class:`~starlette.responses.StreamingResponse` — ``tools/list`` filtering
    is skipped for those because the body cannot be buffered mid-stream.

    Pass any ASGI app::

        mount_mcp(app, "/mcp", wrap_asgi_handler(mcp.streamable_http_app()), cfg)

    Or let :func:`mount_mcp` detect a FastMCP instance automatically::

        mount_mcp(app, "/mcp", mcp, cfg)
    """
    async def _handler(request: Any) -> Any:
        resp_status: list[int] = [500]
        resp_raw_headers: list[list] = [[]]
        body_parts: list[bytes] = []
        headers_ready: asyncio.Event = asyncio.Event()
        body_done: asyncio.Event = asyncio.Event()
        is_streaming: list[bool] = [False]
        body_queue: asyncio.Queue = asyncio.Queue()

        async def _send(message: dict) -> None:
            if message["type"] == "http.response.start":
                resp_status[0] = message["status"]
                resp_raw_headers[0] = list(message.get("headers", []))
                for k, v in resp_raw_headers[0]:
                    kb = k if isinstance(k, bytes) else k.encode()
                    vb = v if isinstance(v, bytes) else v.encode()
                    if kb.lower() == b"content-type" and b"text/event-stream" in vb:
                        is_streaming[0] = True
                headers_ready.set()
            elif message["type"] == "http.response.body":
                chunk = message.get("body", b"")
                if is_streaming[0]:
                    if chunk:
                        await body_queue.put(chunk)
                    if not message.get("more_body", False):
                        await body_queue.put(None)
                else:
                    if chunk:
                        body_parts.append(chunk)
                    if not message.get("more_body", False):
                        body_done.set()

        task = asyncio.create_task(asgi_app(request.scope, request._receive, _send))

        def _on_done(t: Any) -> None:
            if not headers_ready.is_set():
                headers_ready.set()
            if not body_done.is_set():
                body_done.set()
            body_queue.put_nowait(None)

        task.add_done_callback(_on_done)
        await headers_ready.wait()

        out_headers: dict[str, str] = {}
        content_type = "application/octet-stream"
        for k, v in resp_raw_headers[0]:
            ks = k.decode("latin-1") if isinstance(k, bytes) else k
            vs = v.decode("latin-1") if isinstance(v, bytes) else v
            if ks.lower() == "content-type":
                content_type = vs
            if ks.lower() != "content-length":
                out_headers[ks] = vs

        if is_streaming[0]:
            async def _body_gen():
                while True:
                    chunk = await body_queue.get()
                    if chunk is None:
                        break
                    yield chunk
                if not task.done():
                    await task

            return StreamingResponse(
                _body_gen(), status_code=resp_status[0], headers=out_headers
            )

        await body_done.wait()
        body = b"".join(body_parts)
        return Response(
            content=body,
            status_code=resp_status[0],
            media_type=content_type,
            headers=out_headers,
        )

    return _handler


#: Public alias — pass any ASGI app to get a Starlette-style handler suitable
#: for use with :func:`mount_mcp`.
wrap_asgi_handler = _wrap_asgi_as_handler


# ── ASGI middleware — mount_mcp wraps an existing MCP handler ─────────────────


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
    ``handler`` is the existing MCP route handler.

    Returns the constructed :class:`Runtime` so the caller can hook startup
    and customize further.

    New in this version (TypeScript parity):
    - MCP handshake requests pass through even with missing/bad token.
    - ``tools/call`` auth denials are returned in-band as JSON-RPC errors.
    - ``tools/list`` responses are filtered by the principal's scopes.
    - Batch JSON-RPC requests are handled correctly.
    """
    if not _STARLETTE_OK:
        raise RuntimeError(
            "mount_mcp requires Starlette/FastAPI: pip install starlette"
        )

    # Auto-detect FastMCP instances — callers can pass a FastMCP object
    # directly instead of writing the boilerplate ASGI adapter themselves.
    if hasattr(handler, "streamable_http_app") and callable(
        getattr(handler, "streamable_http_app")
    ):
        handler = _wrap_asgi_as_handler(handler.streamable_http_app())

    rt = Runtime(cfg)

    # ── Metadata route (RFC 9728) ────────────────────────────────────────────
    metadata_path = build_resource_metadata_path(cfg.resource_uri)

    async def _metadata(_request: Request) -> Response:
        authoritative = await rt.get_authoritative_scopes()
        body, headers = metadata_json_response(rt.cfg, authoritative)
        return Response(content=body, media_type="application/json", headers=headers)

    # ── Protected MCP route ──────────────────────────────────────────────────
    async def _protected(request: Request) -> Response:
        token = _extract_bearer(request.headers.get("authorization", ""))

        # ── Initial token validation (no tool context yet) ───────────────────
        auth_result = await rt.authorize(token, "")
        if not auth_result.allowed:
            denial = auth_result.denial

            # Parse body to check MCP request type (needed for pass-through
            # and in-band error logic).
            body_bytes = await request.body()
            payload: Any = None
            if body_bytes and request.method == "POST":
                try:
                    payload = json.loads(body_bytes)
                except json.JSONDecodeError:
                    payload = None

            # MCP handshake pass-through — initialize/notifications/ping
            # must succeed so the MCP session can be established before the
            # client presents a token.
            if _should_pass_through_mcp_handshake(token, payload, denial):
                return await _call_with_replayed_body(handler, request, body_bytes)

            # In-band tools/call auth error
            if _should_return_mcp_tool_auth_error(token, payload, denial):
                return JSONResponse(_mcp_tool_auth_error_payload(payload, denial), status_code=200)

            # In-band generic JSON-RPC auth error
            if _should_return_mcp_json_rpc_auth_error(token, payload, denial):
                return JSONResponse(_mcp_json_rpc_auth_error_payload(payload, denial), status_code=200)

            # Standard HTTP error response
            resp_headers: dict[str, str] = {}
            _safe_set_www_authenticate(resp_headers, denial.www_authenticate)
            body_dict: dict[str, Any] = {
                "error": "insufficient_scope" if denial.code == "scope_insufficient" else denial.code,
                "error_description": denial.description,
            }
            if denial.reason:
                body_dict["reason"] = denial.reason
            if denial.required_scopes:
                body_dict["required_scopes"] = denial.required_scopes
            if denial.granted_scopes:
                body_dict["granted_scopes"] = denial.granted_scopes
            if denial.tool:
                body_dict["tool"] = denial.tool
            return JSONResponse(body_dict, status_code=denial.status, headers=resp_headers)

        principal = auth_result.principal

        # ── Read + parse body once ───────────────────────────────────────────
        body_bytes = await request.body()
        payload = None
        if body_bytes and request.method == "POST":
            try:
                payload = json.loads(body_bytes)
            except json.JSONDecodeError:
                payload = None

        # ── Per-tool authorization for tools/call (batch-aware) ───────────────
        for tool_id in extract_tool_ids_from_body(payload):
            tool_result = await rt.authorize_principal(principal, tool_id)
            if not tool_result.allowed:
                tool_denial = tool_result.denial

                if _should_return_mcp_tool_auth_error(token, payload, tool_denial):
                    return JSONResponse(
                        _mcp_tool_auth_error_payload(payload, tool_denial), status_code=200
                    )
                if _should_return_mcp_json_rpc_auth_error(token, payload, tool_denial):
                    return JSONResponse(
                        _mcp_json_rpc_auth_error_payload(payload, tool_denial), status_code=200
                    )

                resp_headers = {}
                _safe_set_www_authenticate(resp_headers, tool_denial.www_authenticate)
                return JSONResponse(
                    {
                        "error": "insufficient_scope"
                        if tool_denial.code == "scope_insufficient"
                        else tool_denial.code,
                        "error_description": tool_denial.description,
                        "tool": tool_denial.tool,
                        "required_scopes": tool_denial.required_scopes,
                        "granted_scopes": tool_denial.granted_scopes,
                    },
                    status_code=tool_denial.status,
                    headers=resp_headers,
                )

        # ── Stash principal for downstream handlers ──────────────────────────
        request.state.authsec_principal = principal
        token_ctx = _principal_ctx.set(principal)

        try:
            # ── Dispatch to the wrapped handler ─────────────────────────────
            response = await _call_with_replayed_body(handler, request, body_bytes)

            # ── tools/list scope filtering ───────────────────────────────────
            if _is_tools_list_request(payload):
                try:
                    resp_body = _get_response_body(response)
                    if resp_body is not None:
                        resp_payload = json.loads(resp_body)
                        filtered = await _filter_tools_list_payload(rt, principal, resp_payload)
                        filtered_bytes = json.dumps(filtered).encode("utf-8")
                        return Response(
                            content=filtered_bytes,
                            status_code=response.status_code,
                            media_type="application/json",
                            headers=dict(response.headers),
                        )
                except Exception as filter_err:
                    # If filter error is an AuthorizeDenial (policy_unavailable),
                    # surface it as a 503 rather than silently serving unfiltered list.
                    if isinstance(filter_err, AuthorizeDenial):
                        denial_err: AuthorizeDenial = filter_err
                        resp_headers = {}
                        _safe_set_www_authenticate(resp_headers, denial_err.www_authenticate)
                        return JSONResponse(
                            {
                                "error": denial_err.code,
                                "error_description": denial_err.description,
                            },
                            status_code=denial_err.status,
                            headers=resp_headers,
                        )
                    _LOG.warning("tools/list filter error: %s", filter_err)

            return response
        finally:
            _principal_ctx.reset(token_ctx)

    # ── Wire routes into Starlette / FastAPI ─────────────────────────────────
    # Always use add_route (plain Starlette API) rather than add_api_route
    # (FastAPI DI).  FastAPI inherits add_route from Starlette so it always
    # exists, and it skips the get_type_hints / dependency-injection layer
    # that breaks for closures whose annotations can't resolve from __globals__.
    if hasattr(app, "add_route"):
        app.add_route(metadata_path, _metadata, methods=["GET"])
        app.add_route(path, _protected, methods=["GET", "POST"])
    else:
        from starlette.routing import Route
        app.routes.append(Route(metadata_path, _metadata, methods=["GET"]))
        app.routes.append(Route(path, _protected, methods=["GET", "POST"]))

    # Hook startup so the customer doesn't have to remember.
    if hasattr(app, "on_event"):
        @app.on_event("startup")
        async def _startup() -> None:
            await rt.startup(rpc_handler=rpc_handler)

    return rt


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_bearer(authorization_header: str) -> str:
    if not authorization_header:
        return ""
    parts = authorization_header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


def _get_response_body(response: Any) -> Optional[bytes]:
    """Extract body bytes from a Starlette/FastAPI Response, if available."""
    if hasattr(response, "body"):
        body = response.body
        if isinstance(body, (bytes, bytearray)):
            return bytes(body)
    return None


async def _call_with_replayed_body(
    handler: Callable[..., Awaitable[Any]], request: Any, body: bytes
) -> Any:
    """Re-attach the consumed body to ``request`` and dispatch to ``handler``."""
    sent = False

    async def _receive() -> dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    request._receive = _receive
    return await handler(request)


# ── Message formatting helpers ────────────────────────────────────────────────

def _format_scope_message(tool: str, required: list[str], granted: list[str]) -> str:
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


def _classify_auth_reason(description: str) -> str:
    """Map a free-text 401 description to a stable, parseable subreason."""
    m = (description or "").lower()
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
