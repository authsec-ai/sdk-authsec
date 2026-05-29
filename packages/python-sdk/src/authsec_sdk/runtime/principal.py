"""Principal — the authenticated subject extracted from a validated token."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Principal:
    """The identity behind a validated token.

    Populated by :class:`HybridValidator` after JWT verification and/or RFC
    7662 introspection succeed. Available downstream via ASGI context (see
    :func:`authsec_sdk.runtime.principal_from_context`).
    """

    subject: str = ""
    """The token's ``sub`` claim — the user or service-account identifier."""

    issuer: str = ""
    """The token's ``iss`` claim — the authorization server."""

    audience: list[str] = field(default_factory=list)
    """The token's ``aud`` claim, normalized to a list."""

    scopes: list[str] = field(default_factory=list)
    """OAuth scopes carried by the token."""

    claims: dict[str, Any] = field(default_factory=dict)
    """Raw claim map for downstream consumers that need extra attributes."""

    active: bool = True
    """False indicates introspection returned ``active=false`` — the token is
    revoked / suspended / expired even if the JWT signature was valid."""

    def has_any_scope(self, required: list[str]) -> bool:
        """True if the principal holds at least one of ``required``.

        An empty ``required`` list always returns True (no requirement).
        """
        if not required:
            return True
        granted = set(self.scopes)
        return any(scope in granted for scope in required)
