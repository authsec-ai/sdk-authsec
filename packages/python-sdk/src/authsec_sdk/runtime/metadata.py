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


def build_metadata_payload(cfg: Config) -> dict[str, Any]:
    """Construct the JSON-able metadata payload."""
    return {
        "resource": cfg.resource_uri,
        "authorization_servers": [cfg.authorization_server or cfg.issuer],
        "resource_name": cfg.resource_name,
        "scopes_supported": list(cfg.supported_scopes),
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
    parts = [f'Bearer realm="{cfg.resource_name or "AuthSec Protected Resource"}"']
    parts.append(f'resource_metadata="{build_resource_metadata_url(cfg.resource_uri)}"')
    if error:
        parts.append(f'error="{error}"')
    if error_description:
        # Escape quotes in error_description per RFC 6750.
        safe = error_description.replace('"', '\\"')
        parts.append(f'error_description="{safe}"')
    if scope:
        parts.append(f'scope="{scope}"')
    return ", ".join(parts)


def metadata_json_response(cfg: Config) -> tuple[bytes, dict[str, str]]:
    """Return (body, headers) for a 200 OK metadata response."""
    payload = build_metadata_payload(cfg)
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=300",
    }
    return body, headers
