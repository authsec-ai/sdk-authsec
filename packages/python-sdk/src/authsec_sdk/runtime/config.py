"""Runtime SDK configuration — Python parity port of go-sdk/config.go.

The Config dataclass holds everything required to protect an MCP resource server
with AuthSec. It supports two orthogonal mode enums:

* :class:`PolicyMode` — controls how the tool→scope policy is sourced and enforced.
* :class:`ValidationMode` — controls how JWT verification and RFC 7662 token
  introspection are combined.

Field semantics mirror the Go SDK exactly. See the production AuthSec admin UI
("Application onboarding → Show Go config") for the canonical example values.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlparse


class PolicyMode(enum.Enum):
    """How the SDK selects and enforces its tool→scope policy source."""

    UNSET = "unset"
    """Resolved to a contextual default at runtime."""

    REMOTE_REQUIRED = "remote_required"
    """SDK fails startup if ResourceServerID, AuthorizationServer, or
    introspection credentials are not set, or if the initial remote fetch
    fails. This is the recommended production setting."""

    REMOTE_WITH_LOCAL_FALLBACK = "remote_with_local_fallback"
    """Try remote first; fall back to ``tool_scopes`` on fetch failure.
    Requires both a valid remote configuration AND non-None ``tool_scopes``."""

    LOCAL_ONLY = "local_only"
    """Use ``Config.tool_scopes`` only; ignore ``resource_server_id``."""

    OPEN = "open"
    """No tool-level policy; all tools are allowed for any valid token."""


class ValidationMode(enum.Enum):
    """How JWT and RFC 7662 introspection are combined for token validation."""

    UNSET = "unset"
    JWT_ONLY = "jwt_only"
    """Only local JWT verification; requires ``jwks_url``."""

    INTROSPECTION_ONLY = "introspection_only"
    """Only introspection; requires ``introspection_url`` and credentials."""

    JWT_AND_INTROSPECT = "jwt_and_introspect"
    """Strict combined mode. For JWT-shaped tokens, JWT must pass first;
    introspection failure is terminal. For opaque tokens, introspection is
    used directly. Requires both ``jwks_url`` and ``introspection_url``."""

    JWT_OR_INTROSPECT = "jwt_or_introspect"
    """Either path may succeed independently (legacy behaviour, preserved
    for gradual migration). Requires both ``jwks_url`` and ``introspection_url``."""


# Type alias: a sync or async function returning a list of ManifestTool dicts.
ToolInventoryProvider = Callable[
    [], "list[dict[str, Any]] | Awaitable[list[dict[str, Any]]]"
]


@dataclass
class Config:
    """Configuration for protecting an MCP resource server with AuthSec.

    Mirrors :type:`authsec.Config` in the Go SDK. Construct directly or via
    :func:`from_env`. Pass to :func:`authsec_sdk.runtime.mount_mcp` (FastAPI
    / Starlette) or :class:`authsec_sdk.runtime.Runtime` for full control.

    Example::

        cfg = Config(
            issuer="https://dev.api.authsec.dev",
            authorization_server="https://dev.api.authsec.dev",
            jwks_url="https://dev.api.authsec.dev/oauth/jwks",
            introspection_url="https://dev.api.authsec.dev/oauth/introspect",
            introspection_client_id="525da3b4-4206-4070-ad68-90cc3a6de43b",
            introspection_client_secret=os.environ["AUTHSEC_INTROSPECTION_CLIENT_SECRET"],
            resource_server_id="525da3b4-4206-4070-ad68-90cc3a6de43b",
            resource_uri="https://20-106-226-245.sslip.io/mcp",
            resource_name="GitHub MCP Server",
            policy_mode=PolicyMode.REMOTE_REQUIRED,
            validation_mode=ValidationMode.JWT_AND_INTROSPECT,
            publish_manifest=True,
        )
    """

    issuer: str = ""
    authorization_server: str = ""
    jwks_url: str = ""
    introspection_url: str = ""
    introspection_client_id: str = ""
    introspection_client_secret: str = ""
    resource_uri: str = ""
    resource_name: str = ""

    resource_server_id: str = ""
    """AuthSec resource server UUID. When set, the SDK fetches the authoritative
    tool→scope mapping from AuthSec at startup and refreshes it periodically."""

    supported_scopes: list[str] = field(default_factory=list)
    """OAuth scopes this RS advertises in protected-resource metadata.
    Optional if the RS is already registered in AuthSec."""

    tool_scopes: Optional[dict[str, list[str]]] = None
    """Optional LOCAL tool→scope mapping for defense-in-depth.
    Empty list ``[]`` for a tool key marks it explicitly public.
    Absent key means denied when any policy is active."""

    scope_matrix_ttl: timedelta = timedelta(minutes=5)
    """How long the fetched tool→scope mapping is cached."""

    policy_mode: PolicyMode = PolicyMode.UNSET
    validation_mode: ValidationMode = ValidationMode.UNSET

    publish_manifest: bool = False
    """When True, the SDK pushes its tool inventory to AuthSec at startup."""

    tool_scope_suggestions: dict[str, list[str]] = field(default_factory=dict)
    """SDK author's recommended scope set per tool. Used only for manifest publish."""

    tool_inventory_provider: Optional[ToolInventoryProvider] = None
    """Escape hatch for manifest publishing — bypass synthetic ``tools/list``."""

    bearer_methods_supported: list[str] = field(default_factory=lambda: ["header"])
    request_timeout_seconds: float = 10.0

    # ──────────────────────────────────────────────────────────────────
    # Mode resolution
    # ──────────────────────────────────────────────────────────────────

    def effective_policy_mode(self) -> PolicyMode:
        """Resolve ``PolicyMode.UNSET`` to an inferred default."""
        if self.policy_mode != PolicyMode.UNSET:
            return self.policy_mode
        if self.resource_server_id.strip():
            return PolicyMode.REMOTE_REQUIRED
        if self.tool_scopes is not None:
            return PolicyMode.LOCAL_ONLY
        return PolicyMode.OPEN

    def effective_validation_mode(self) -> ValidationMode:
        """Resolve ``ValidationMode.UNSET`` to an inferred default."""
        if self.validation_mode != ValidationMode.UNSET:
            return self.validation_mode
        has_jwks = bool(self.jwks_url.strip())
        has_introspection = bool(self.introspection_url.strip())
        if has_jwks and has_introspection:
            return ValidationMode.JWT_AND_INTROSPECT
        if has_jwks:
            return ValidationMode.JWT_ONLY
        return ValidationMode.INTROSPECTION_ONLY

    # ──────────────────────────────────────────────────────────────────
    # Validation
    # ──────────────────────────────────────────────────────────────────

    def validate(self) -> None:
        """Raise ``ValueError`` if the config is unusable.

        Always run this before constructing a :class:`Runtime`. The errors are
        deliberately verbose so a misconfigured production deploy fails clearly.
        """
        if not self.issuer.strip():
            raise ValueError("issuer is required")
        if not self.resource_uri.strip():
            raise ValueError("resource_uri is required")

        parsed = urlparse(self.resource_uri)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(
                f"resource_uri must be an absolute URI with scheme and host (got {self.resource_uri!r})"
            )

        if not self.jwks_url.strip() and not self.introspection_url.strip():
            raise ValueError("at least one of jwks_url or introspection_url is required")

        if self.introspection_url.strip() and (
            not self.introspection_client_id.strip()
            or not self.introspection_client_secret.strip()
        ):
            raise ValueError(
                "introspection client credentials are required when introspection is enabled"
            )

        pm = self.effective_policy_mode()
        if pm in (PolicyMode.REMOTE_REQUIRED, PolicyMode.REMOTE_WITH_LOCAL_FALLBACK):
            if not self.resource_server_id.strip():
                raise ValueError(f"{pm.value} requires resource_server_id")
            if not self.authorization_server.strip() and not self.issuer.strip():
                raise ValueError(f"{pm.value} requires authorization_server")
            if (
                not self.introspection_client_id.strip()
                or not self.introspection_client_secret.strip()
            ):
                raise ValueError(
                    f"{pm.value} requires introspection credentials "
                    "(introspection_client_id + introspection_client_secret)"
                )
        if pm == PolicyMode.REMOTE_WITH_LOCAL_FALLBACK and self.tool_scopes is None:
            raise ValueError(
                "PolicyMode.REMOTE_WITH_LOCAL_FALLBACK requires tool_scopes (non-None) "
                "as the local fallback"
            )

        vm = self.effective_validation_mode()
        if vm == ValidationMode.JWT_ONLY and not self.jwks_url.strip():
            raise ValueError(f"{vm.value} requires jwks_url")
        if vm == ValidationMode.INTROSPECTION_ONLY:
            if not self.introspection_url.strip():
                raise ValueError(f"{vm.value} requires introspection_url")
            if (
                not self.introspection_client_id.strip()
                or not self.introspection_client_secret.strip()
            ):
                raise ValueError(f"{vm.value} requires introspection credentials")
        if vm in (ValidationMode.JWT_AND_INTROSPECT, ValidationMode.JWT_OR_INTROSPECT):
            if not self.jwks_url.strip():
                raise ValueError(f"{vm.value} requires jwks_url")
            if not self.introspection_url.strip():
                raise ValueError(f"{vm.value} requires introspection_url")
            if (
                not self.introspection_client_id.strip()
                or not self.introspection_client_secret.strip()
            ):
                raise ValueError(f"{vm.value} requires introspection credentials")

    def normalized(self) -> "Config":
        """Return a copy with sensible defaults filled in (post-validate)."""
        from dataclasses import replace

        out = replace(self)
        if not out.authorization_server:
            out.authorization_server = out.issuer
        if not out.resource_name:
            out.resource_name = "AuthSec Protected MCP Resource"
        if not out.bearer_methods_supported:
            out.bearer_methods_supported = ["header"]
        return out


def from_env(prefix: str = "AUTHSEC_") -> Config:
    """Build a Config from environment variables.

    Conventional env vars (matching the .env block AuthSec UI emits)::

        AUTHSEC_ISSUER
        AUTHSEC_AUTHORIZATION_SERVER
        AUTHSEC_JWKS_URL                  (or legacy AUTHSEC_JWKS_URI)
        AUTHSEC_INTROSPECTION_URL         (or legacy AUTHSEC_INTROSPECTION_ENDPOINT)
        AUTHSEC_INTROSPECTION_CLIENT_ID   (or legacy AUTHSEC_INTROSPECTION_ID)
        AUTHSEC_INTROSPECTION_CLIENT_SECRET
        AUTHSEC_INTROSPECTION_SECRET      (legacy alias)
        AUTHSEC_RESOURCE_URI
        AUTHSEC_RESOURCE                  (legacy alias)
        AUTHSEC_RESOURCE_NAME
        AUTHSEC_RESOURCE_SERVER_ID
        AUTHSEC_SUPPORTED_SCOPES         (space-separated)
        AUTHSEC_POLICY_MODE              ('remote_required', etc.)
        AUTHSEC_VALIDATION_MODE          ('jwt_and_introspect', etc.)
        AUTHSEC_PUBLISH_MANIFEST         ('true' | 'false')
    """
    import json
    import os

    def g(key: str, default: str = "") -> str:
        return os.environ.get(prefix + key, default)

    def first(*keys: str) -> str:
        for key in keys:
            value = g(key)
            if value:
                return value
        return ""

    def parse_mode(value: str, cls):
        if not value:
            return cls.UNSET
        normalized = value.strip().lower()
        if cls is PolicyMode:
            if normalized == "enforce":
                return PolicyMode.REMOTE_REQUIRED
            if normalized == "observe":
                return PolicyMode.OPEN
        if cls is ValidationMode and normalized == "auto":
            return ValidationMode.UNSET
        try:
            return cls(normalized)
        except ValueError:
            return cls.UNSET

    def parse_string_list(value: str) -> list[str]:
        trimmed = value.strip()
        if not trimmed:
            return []
        if trimmed.startswith("["):
            try:
                parsed = json.loads(trimmed)
                if isinstance(parsed, list):
                    return [str(item) for item in parsed if str(item)]
            except json.JSONDecodeError:
                pass
        return [part for part in trimmed.replace(",", " ").split() if part]

    def parse_string_list_map(value: str) -> dict[str, list[str]]:
        if not value.strip():
            return {}
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        if not isinstance(parsed, dict):
            return {}
        out: dict[str, list[str]] = {}
        for key, raw in parsed.items():
            if isinstance(raw, list):
                out[str(key)] = [str(item) for item in raw if str(item)]
            elif isinstance(raw, str):
                out[str(key)] = parse_string_list(raw)
        return out

    cfg = Config(
        issuer=g("ISSUER"),
        authorization_server=g("AUTHORIZATION_SERVER"),
        jwks_url=first("JWKS_URL", "JWKS_URI"),
        introspection_url=first("INTROSPECTION_URL", "INTROSPECTION_ENDPOINT"),
        introspection_client_id=first("INTROSPECTION_CLIENT_ID", "INTROSPECTION_ID"),
        introspection_client_secret=first(
            "INTROSPECTION_CLIENT_SECRET", "INTROSPECTION_SECRET"
        ),
        resource_uri=first("RESOURCE_URI", "RESOURCE"),
        resource_name=g("RESOURCE_NAME"),
        resource_server_id=g("RESOURCE_SERVER_ID"),
        supported_scopes=parse_string_list(g("SUPPORTED_SCOPES")),
        tool_scopes=parse_string_list_map(g("TOOL_SCOPES_JSON")) or None,
        tool_scope_suggestions=parse_string_list_map(g("TOOL_SCOPE_SUGGESTIONS_JSON")),
        policy_mode=parse_mode(g("POLICY_MODE"), PolicyMode),
        validation_mode=parse_mode(g("VALIDATION_MODE"), ValidationMode),
        publish_manifest=g("PUBLISH_MANIFEST").strip().lower() in {"1", "true", "yes"},
    )
    return cfg
