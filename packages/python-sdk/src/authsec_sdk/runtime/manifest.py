"""PublishManifest — best-effort one-way push of the tool inventory to AuthSec.

Python parity port of go-sdk/manifest_publisher.go.

Enumerates the tools served by an MCP handler via a synthetic JSON-RPC
``initialize`` → ``notifications/initialized`` → paginated ``tools/list``
handshake against the in-process handler (no real network round-trip). The
result is packaged into a manifest and PUT to
``/authsec/resource-servers/<resource_server_id>/sdk-manifest``.

Failure never blocks startup — the runtime SDK works the same whether the
publish succeeded or not. Manifest sync is purely admin-facing inventory data.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

import aiohttp

from .config import Config

_LOG = logging.getLogger("authsec.manifest")
_MANIFEST_PUBLISH_TIMEOUT = 30.0
_PAGINATION_SAFETY_CAP = 100


@dataclass
class ManifestTool:
    """One entry in the manifest payload.

    Mirrors :type:`authsec.ManifestTool` in the Go SDK and the controller-side
    ``ManifestToolPayload`` struct.
    """

    name: str
    title: str = ""
    description: str = ""
    input_schema: Optional[dict[str, Any]] = None
    annotations: Optional[dict[str, Any]] = None
    suggested_scopes: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name}
        if self.title:
            out["title"] = self.title
        if self.description:
            out["description"] = self.description
        if self.input_schema is not None:
            out["input_schema"] = self.input_schema
        if self.annotations is not None:
            out["annotations"] = self.annotations
        if self.suggested_scopes:
            out["suggested_scopes"] = list(self.suggested_scopes)
        return out


# An MCP request handler is any async callable taking a JSON-RPC dict and
# returning a JSON-RPC dict. The Runtime supports both raw HTTP-style handlers
# (a Starlette/FastAPI route) and these in-process JSON-RPC handlers.
McpRpcHandler = Callable[[dict[str, Any], dict[str, str]], Awaitable[dict[str, Any]]]


async def publish_manifest(
    cfg: Config,
    *,
    rpc_handler: Optional[McpRpcHandler] = None,
) -> None:
    """Enumerate tools and PUT the manifest to AuthSec.

    Order of precedence for the tool inventory:

    1. ``cfg.tool_inventory_provider`` — escape hatch; sync or async callable
       returning a list of :class:`ManifestTool` (or equivalent dicts).
    2. ``rpc_handler`` — synthesise an MCP handshake against it.

    Raises on configuration / transport failure. Callers (typically the
    :class:`Runtime` constructor) log-and-ignore.
    """
    if not cfg.resource_server_id:
        raise ValueError("publish_manifest requires resource_server_id")
    if not cfg.introspection_client_id or not cfg.introspection_client_secret:
        raise ValueError(
            "publish_manifest requires introspection client credentials"
        )

    base = (cfg.authorization_server or cfg.issuer).rstrip("/")
    if not base:
        raise ValueError("publish_manifest requires authorization_server or issuer")
    endpoint = f"{base}/authsec/resource-servers/{cfg.resource_server_id}/sdk-manifest"

    tools = await _collect_tools(cfg, rpc_handler)
    payload = _build_payload(tools, cfg.tool_scope_suggestions)

    timeout = aiohttp.ClientTimeout(total=_MANIFEST_PUBLISH_TIMEOUT)
    auth = aiohttp.BasicAuth(cfg.introspection_client_id, cfg.introspection_client_secret)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.put(endpoint, json=payload, auth=auth) as resp:
            if resp.status < 200 or resp.status >= 300:
                body = await resp.text()
                raise RuntimeError(
                    f"manifest publish returned HTTP {resp.status}: {body[:512]}"
                )


# ────────────────────────────────────────────────────────────────────
# Tool collection
# ────────────────────────────────────────────────────────────────────


async def _collect_tools(
    cfg: Config, rpc_handler: Optional[McpRpcHandler]
) -> list[ManifestTool]:
    if cfg.tool_inventory_provider is not None:
        raw = cfg.tool_inventory_provider()
        if inspect.isawaitable(raw):
            raw = await raw
        return [_normalize_tool(t) for t in raw]

    if rpc_handler is None:
        raise ValueError(
            "publish_manifest needs either tool_inventory_provider or an rpc_handler"
        )
    return await _enumerate_via_handshake(rpc_handler)


def _normalize_tool(t: Any) -> ManifestTool:
    if isinstance(t, ManifestTool):
        return t
    if isinstance(t, dict):
        return ManifestTool(
            name=t.get("name", ""),
            title=t.get("title", ""),
            description=t.get("description", ""),
            input_schema=t.get("input_schema") or t.get("inputSchema"),
            annotations=t.get("annotations"),
            suggested_scopes=list(t.get("suggested_scopes") or []),
        )
    raise TypeError(f"tool_inventory_provider returned unsupported type: {type(t)!r}")


async def _enumerate_via_handshake(handler: McpRpcHandler) -> list[ManifestTool]:
    """Synthetic initialize → notifications/initialized → paginated tools/list."""
    session_id = await _synthetic_initialize(handler)
    await _synthetic_initialized(handler, session_id)

    all_tools: list[ManifestTool] = []
    cursor: Optional[str] = None
    for i in range(_PAGINATION_SAFETY_CAP):
        params: dict[str, Any] = {}
        if cursor:
            params["cursor"] = cursor
        req = {
            "jsonrpc": "2.0",
            "id": i + 1,
            "method": "tools/list",
            "params": params,
        }
        headers: dict[str, str] = {}
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        resp = await handler(req, headers)
        if "error" in resp and resp["error"]:
            err = resp["error"]
            raise RuntimeError(
                f"tools/list returned JSON-RPC error {err.get('code')}: {err.get('message')}"
            )
        result = resp.get("result", {}) or {}
        for raw in result.get("tools", []) or []:
            all_tools.append(
                ManifestTool(
                    name=raw.get("name", ""),
                    title=raw.get("title", ""),
                    description=raw.get("description", ""),
                    input_schema=raw.get("inputSchema") or raw.get("input_schema"),
                    annotations=raw.get("annotations"),
                    suggested_scopes=list(raw.get("suggested_scopes") or []),
                )
            )
        cursor = result.get("nextCursor")
        if not cursor:
            break
    return all_tools


async def _synthetic_initialize(handler: McpRpcHandler) -> Optional[str]:
    req = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "authsec-manifest-publisher", "version": "1.0"},
        },
    }
    try:
        resp = await handler(req, {})
    except Exception as e:
        _LOG.debug("synthetic initialize failed: %s", e)
        return None
    if isinstance(resp, dict):
        # Some MCP frameworks return the session id in the response itself; if
        # they put it in a header-equivalent slot, callers can plumb that in.
        return resp.get("_mcp_session_id")
    return None


async def _synthetic_initialized(handler: McpRpcHandler, session_id: Optional[str]) -> None:
    req = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    }
    headers: dict[str, str] = {}
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    try:
        await handler(req, headers)
    except Exception as e:
        # Notifications have no response; failures are non-fatal.
        _LOG.debug("synthetic notifications/initialized failed: %s", e)


def _build_payload(
    tools: list[ManifestTool], suggestions: dict[str, list[str]]
) -> dict[str, Any]:
    out_tools: list[dict[str, Any]] = []
    for t in tools:
        entry = ManifestTool(
            name=t.name,
            title=t.title,
            description=t.description,
            input_schema=t.input_schema,
            annotations=t.annotations,
            suggested_scopes=list(t.suggested_scopes),
        )
        if not entry.suggested_scopes:
            sugg = suggestions.get(entry.name)
            if sugg:
                entry.suggested_scopes = list(sugg)
        out_tools.append(entry.to_json())
    return {"tools": out_tools}


async def publish_manifest_safe(
    cfg: Config,
    *,
    rpc_handler: Optional[McpRpcHandler] = None,
) -> None:
    """Like :func:`publish_manifest` but logs-and-ignores all failures.

    Designed for boot-time use where manifest publish must never block startup.
    """
    try:
        await publish_manifest(cfg, rpc_handler=rpc_handler)
        _LOG.info("authsec manifest published for resource_server_id=%s", cfg.resource_server_id)
    except Exception as e:  # noqa: BLE001
        _LOG.warning("authsec manifest publish failed (non-fatal): %s", e)
