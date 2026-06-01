"""RFC 9728 Protected Resource Metadata.

Provides the discovery document AI clients use to locate the AuthSec
authorization server and learn which scopes the resource server supports.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from .config import Config

PROTECTED_RESOURCE_PREFIX = "/.well-known/oauth-protected-resource"


def build_resource_metadata_path(resource_uri: str) -> str:
    """Compute the RFC 9728 metadata path for the given resource URI.

    Root resources (no path) → ``/.well-known/oauth-protected-resource``.
    Path-based (e.g. ``https://mcp.example.com/mcp``) →
    ``/.well-known/oauth-protected-resource/mcp``.
    """
    parsed = urlparse(resource_uri)
    path = parsed.path.strip().strip("/")
    if not path:
        return PROTECTED_RESOURCE_PREFIX
    return f"{PROTECTED_RESOURCE_PREFIX}/{path}"


def build_resource_metadata_url(resource_uri: str) -> str:
    """Absolute URL of the metadata document for ``resource_uri``."""
    parsed = urlparse(resource_uri)
    scheme = parsed.scheme
    host = parsed.netloc
    return f"{scheme}://{host}".rstrip("/") + build_resource_metadata_path(resource_uri)


def is_metadata_request(resource_uri: str, request_path: str) -> bool:
    """True iff ``request_path`` is the metadata discovery path for the resource.

    Path-based resources match ONLY their derived alias; root resources match
    the bare well-known path.
    """
    metadata_path = build_resource_metadata_path(resource_uri)
    return request_path == metadata_path or request_path == metadata_path + "/"


def build_metadata_payload(
    cfg: Config,
    authoritative_scopes: list[str] | None = None,
) -> dict[str, Any]:
    """Construct the JSON-able metadata payload (RFC 9728).

    The ``scopes_supported`` field is sourced in this order:
      1. ``authoritative_scopes`` (if non-None) — the live list pulled from
         AuthSec via the scope matrix. **This is the canonical source.**
         Admin changes a scope in the AuthSec UI → SDK refreshes the matrix
         → PRM auto-updates. No code change in the MCP server.
      2. ``cfg.supported_scopes`` — local fallback for boot-time PRM
         requests before the scope matrix has been fetched, or for
         ``policy_mode=local_only`` deployments that manage scopes locally.

    Always pass ``authoritative_scopes`` from the runtime when one is
    available.
    """
    scopes = authoritative_scopes if authoritative_scopes is not None else cfg.supported_scopes
    return {
        "resource": cfg.resource_uri,
        "authorization_servers": [cfg.authorization_server or cfg.issuer],
        "resource_name": cfg.resource_name,
        "scopes_supported": list(scopes),
        "bearer_methods_supported": list(cfg.bearer_methods_supported),
    }


def build_www_authenticate(
    cfg: Config,
    *,
    error: str = "",
    error_description: str = "",
    scope: str = "",
) -> str:
    """Build the ``WWW-Authenticate`` header value for a 401 / 403 response.

    Always includes ``Bearer realm`` and ``resource_metadata`` (RFC 9728).
    Optionally includes ``error`` and ``error_description`` for
    insufficient_scope / invalid_token responses.
    """
    realm = cfg.resource_name or "AuthSec Protected Resource"
    parts = [f'Bearer realm="{_sanitize_header_value(realm)}"']
    parts.append(
        f'resource_metadata="{_sanitize_header_value(build_resource_metadata_url(cfg.resource_uri))}"'
    )
    if error:
        parts.append(f'error="{_sanitize_header_value(error)}"')
    if error_description:
        parts.append(f'error_description="{_sanitize_header_value(error_description)}"')
    if scope:
        parts.append(f'scope="{_sanitize_header_value(scope)}"')
    return ", ".join(parts)


def _sanitize_header_value(s: str) -> str:
    """Sanitize a string for an HTTP header field-value (RFC 7230 §3.2.6).

    Field-value MUST NOT contain CR / LF / NUL. ASGI servers + most HTTP
    libraries enforce this and raise on violation. Hydra and other upstream
    auth servers leak control chars into error bodies that end up in our
    ``error_description``; without this guard, the 401 we're trying to send
    crashes instead of being delivered as a clean denial.

    Strategy:
      - Replace every control char (0x00–0x1F + 0x7F) with a single space
      - Escape backslash (must come before quote so we don't double-escape)
      - Escape double-quote (RFC 7230 quoted-string)
      - Hard-truncate to 200 chars so the header stays under server limits
    """
    out = "".join(" " if ord(c) < 0x20 or ord(c) == 0x7F else c for c in s)
    out = out.replace("\\", "\\\\").replace('"', '\\"')
    return out[:200]


def metadata_json_response(
    cfg: Config,
    authoritative_scopes: list[str] | None = None,
) -> tuple[bytes, dict[str, str]]:
    """Return (body, headers) for a 200 OK metadata response.

    Pass ``authoritative_scopes`` from ``Runtime.get_authoritative_scopes()``
    so the PRM advertises the live AuthSec scope list. When omitted (or
    ``None``), falls back to ``cfg.supported_scopes``.
    """
    payload = build_metadata_payload(cfg, authoritative_scopes)
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=300",
    }
    return body, headers
