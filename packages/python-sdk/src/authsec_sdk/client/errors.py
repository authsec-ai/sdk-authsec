"""Typed, actionable client-side errors for AuthSec-protected MCP calls.

Server-side, ``authsec_sdk.runtime.server`` emits structured 401/403
responses with a stable ``reason`` (401) or explicit ``tool`` +
``required_scopes`` + ``granted_scopes`` (403). On the *agent* side, the
MCP client transport often hides those details — langchain-mcp-adapters,
for example, raises a generic ``ToolException`` whose ``str(exc)`` carries
only the ``error_description``. This module reverses that loss: hand it
the exception (or response object, or dict, or raw string) and get back a
typed Python exception with the structured fields restored.

Use ``parse_mcp_error(thing)`` for parsing — it accepts:

* ``httpx.Response`` / ``requests.Response`` / ``starlette.Response`` —
  reads the JSON body and the ``WWW-Authenticate`` header.
* a ``dict`` — already-parsed JSON body.
* an ``Exception`` — calls ``str(exc)`` and parses that.
* a ``str`` — parses the message directly.

Returns ``None`` if the input doesn't look like an AuthSec access error
(so callers can re-raise).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional


# ─── Exception hierarchy ─────────────────────────────────────────────────


@dataclass
class AuthSecAccessError(Exception):
    """Base for any AuthSec-side denial. Carries the human-readable
    description and any structured fields the server included."""

    description: str = ""
    raw_body: Optional[dict[str, Any]] = field(default=None, repr=False)
    www_authenticate: Optional[str] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        super().__init__(self.description)

    def format_for_user(self) -> str:
        """Return a single, human-readable line suitable for printing to a
        terminal or surfacing in agent output. Subclasses override."""
        return self.description or self.__class__.__name__


@dataclass
class InsufficientScopeError(AuthSecAccessError):
    """The token is valid but lacks a scope the tool requires."""

    tool: Optional[str] = None
    required_scopes: list[str] = field(default_factory=list)
    granted_scopes: list[str] = field(default_factory=list)

    def format_for_user(self) -> str:
        req = ", ".join(self.required_scopes) if self.required_scopes else "(unknown)"
        if self.granted_scopes:
            granted = ", ".join(self.granted_scopes)
            tail = f" Your token has: {granted}."
        else:
            tail = " Your token does not include this scope."
        tool_part = f" '{self.tool}'" if self.tool else ""
        return (
            f"Insufficient scope: tool{tool_part} requires {req}.{tail} "
            f"Ask an AuthSec admin to grant the missing scope, or use a tool that fits your current scopes."
        )


@dataclass
class TokenRevokedError(AuthSecAccessError):
    """The bearer token has been revoked (e.g. admin revoked the session).

    Calling code should clear cached tokens and re-authenticate."""

    def format_for_user(self) -> str:
        return (
            "Your AuthSec access token has been revoked. "
            "Clear your cached tokens and re-run the authentication flow."
        )


@dataclass
class ClientRegistrationRevokedError(AuthSecAccessError):
    """The OAuth *client* registration was revoked by an admin.

    A fresh token cannot fix this — the admin must re-approve the client
    in the AuthSec console."""

    def format_for_user(self) -> str:
        return (
            "Your OAuth client registration has been revoked by an AuthSec admin. "
            "Re-running the auth flow will not help — ask the admin to approve "
            "the client in the AuthSec console (Applications → Clients tab)."
        )


@dataclass
class AuthRequiredError(AuthSecAccessError):
    """No token, invalid token, expired token, or audience mismatch.

    Calling code should re-run the OAuth flow."""

    reason: str = "invalid_token"

    def format_for_user(self) -> str:
        if self.reason == "no_token":
            return "Authentication required — no bearer token was sent. Run the AuthSec auth flow."
        if self.reason == "token_expired":
            return "Your AuthSec token has expired. Refresh or re-authenticate."
        if self.reason == "audience_mismatch":
            return (
                "Your token was issued for a different MCP server. "
                "Re-authenticate against the correct resource."
            )
        return f"Authentication failed ({self.reason}). Re-run the AuthSec auth flow."


# ─── Parser ──────────────────────────────────────────────────────────────


_WWW_AUTH_KV = re.compile(r'(\w+)=("([^"]*)"|([^,]*))')


def _parse_www_authenticate(header: str) -> dict[str, str]:
    """Best-effort parser for `WWW-Authenticate: Bearer key="value", key=value`."""
    out: dict[str, str] = {}
    if not header:
        return out
    body = header.split(None, 1)[1] if header.lower().startswith("bearer ") else header
    for match in _WWW_AUTH_KV.finditer(body):
        key = match.group(1)
        value = match.group(3) if match.group(3) is not None else match.group(4) or ""
        out[key.lower()] = value.strip()
    return out


def _classify_from_text(text: str) -> Optional[type[AuthSecAccessError]]:
    t = (text or "").lower()
    # Scope phrasing — match both server-side ("requires scope") and
    # langchain-mcp-adapters' legacy passthrough ("does not include the
    # required scope" / "insufficient scope").
    if (
        "insufficient_scope" in t
        or "insufficient scope" in t
        or "requires scope" in t
        or "required scope" in t
        or "does not include the required scope" in t
        or "lacks required" in t
        or "no scope mapping for tool" in t
    ):
        return InsufficientScopeError
    if "client" in t and "revoked" in t:
        return ClientRegistrationRevokedError
    if "registration" in t and ("revoked" in t or "pending" in t):
        return ClientRegistrationRevokedError
    if "revoked" in t:
        return TokenRevokedError
    if "expired" in t:
        return AuthRequiredError
    if "invalid_token" in t or ("missing" in t and "bearer" in t):
        return AuthRequiredError
    if "audience" in t:
        return AuthRequiredError
    return None


def _coerce_body(source: Any) -> tuple[Optional[dict[str, Any]], Optional[str], Optional[str]]:
    """Return (body_dict, raw_text, www_authenticate_header) from various inputs."""
    # Response-like (httpx, requests, starlette).
    if hasattr(source, "headers") and hasattr(source, "status_code"):
        headers = getattr(source, "headers", {}) or {}
        www = headers.get("WWW-Authenticate") or headers.get("www-authenticate")
        body_dict: Optional[dict[str, Any]] = None
        raw_text: Optional[str] = None
        # Try .json() first, fall back to .text.
        json_fn = getattr(source, "json", None)
        if callable(json_fn):
            try:
                body_dict = json_fn()
            except Exception:
                body_dict = None
        if body_dict is None:
            raw_text = getattr(source, "text", None)
            if raw_text:
                try:
                    body_dict = json.loads(raw_text)
                except Exception:
                    body_dict = None
        return body_dict, raw_text, www
    # Already a dict.
    if isinstance(source, dict):
        return source, None, source.get("www_authenticate") or source.get("WWW-Authenticate")
    # Exception → take str(exc).
    if isinstance(source, BaseException):
        return None, str(source), None
    # Plain string.
    if isinstance(source, str):
        # Try parsing as JSON first.
        try:
            obj = json.loads(source)
            if isinstance(obj, dict):
                return obj, source, None
        except Exception:
            pass
        return None, source, None
    return None, None, None


def parse_mcp_error(source: Any) -> Optional[AuthSecAccessError]:
    """Best-effort: turn whatever-the-MCP-transport-handed-you into a typed
    :class:`AuthSecAccessError`. Returns ``None`` if the input doesn't look
    like an AuthSec access denial — caller should re-raise."""
    body, raw_text, www_header = _coerce_body(source)
    www_fields = _parse_www_authenticate(www_header or "")

    # 1) Structured 403 from runtime/server.py _insufficient_scope.
    if body and body.get("error") == "insufficient_scope":
        return InsufficientScopeError(
            description=str(body.get("error_description") or ""),
            raw_body=body,
            www_authenticate=www_header,
            tool=body.get("tool"),
            required_scopes=list(body.get("required_scopes") or []),
            granted_scopes=list(body.get("granted_scopes") or []),
        )

    # 2) Structured 401 from runtime/server.py _unauthorized.
    if body and body.get("error") in ("invalid_token", "missing_token"):
        reason = str(body.get("reason") or "invalid_token")
        description = str(body.get("error_description") or "")
        if reason == "client_registration_revoked":
            return ClientRegistrationRevokedError(
                description=description, raw_body=body, www_authenticate=www_header,
            )
        if reason == "token_revoked":
            return TokenRevokedError(
                description=description, raw_body=body, www_authenticate=www_header,
            )
        return AuthRequiredError(
            description=description,
            raw_body=body,
            www_authenticate=www_header,
            reason=reason,
        )

    # 3) WWW-Authenticate header was rich but the body wasn't.
    if www_fields.get("error") == "insufficient_scope":
        return InsufficientScopeError(
            description=www_fields.get("error_description", ""),
            www_authenticate=www_header,
            required_scopes=[s for s in (www_fields.get("scope", "")).split() if s] or [],
        )

    # 4) Plain-text fallback: classify by keywords. Useful when an MCP
    # transport flattens the structured response into ToolException(str).
    text_source = ""
    if raw_text:
        text_source = raw_text
    elif body:
        text_source = str(body.get("error_description") or body.get("error") or "")
    if not text_source:
        return None

    cls = _classify_from_text(text_source)
    if cls is None:
        return None
    if cls is InsufficientScopeError:
        # Try to recover tool + scopes from message shape: "Tool 'x' requires scope: a, b. ..."
        tool_match = re.search(r"[Tt]ool ['\"]?([^'\"]+?)['\"]?[\s,]+(?:requires|needs)", text_source)
        scope_match = re.search(r"(?:requires? scope:?|requires?|needs)[\s:]*([^\.]+)", text_source)
        granted_match = re.search(r"(?:has|granted)[\s:]*([^\.]+)", text_source)
        return InsufficientScopeError(
            description=text_source.strip(),
            tool=tool_match.group(1).strip() if tool_match else None,
            required_scopes=_split_scopes(scope_match.group(1)) if scope_match else [],
            granted_scopes=_split_scopes(granted_match.group(1)) if granted_match else [],
        )
    if cls is AuthRequiredError:
        return AuthRequiredError(description=text_source.strip(), reason="invalid_token")
    return cls(description=text_source.strip())


def _split_scopes(blob: str) -> list[str]:
    """Extract scope tokens from a sentence fragment like 'demo_server:admin, demo_server:read'."""
    parts = re.split(r"[\s,;]+", (blob or "").strip())
    return [p for p in parts if ":" in p or "_" in p or "." in p]
