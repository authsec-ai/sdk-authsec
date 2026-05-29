"""HybridValidator — JWT verification + RFC 7662 introspection.

Mirrors :type:`authsec.HybridValidator` in the Go SDK. Supports four
:class:`ValidationMode` shapes; the strict ``JWT_AND_INTROSPECT`` mode is the
production-recommended setting.

JWT verification uses cached JWKS keys, refreshed on `kid` miss. Introspection
uses HTTP Basic auth with the configured ``introspection_client_id`` /
``introspection_client_secret``.
"""

from __future__ import annotations

import time
from typing import Any, Optional

import aiohttp
import jwt
from jwt import PyJWKClient

from .config import Config, ValidationMode
from .principal import Principal


class TokenInvalidError(Exception):
    """Raised when the token fails validation (signature, expiry, audience, …)."""


class TokenInactiveError(Exception):
    """Raised when introspection returns ``active=false`` (revoked / suspended)."""


class HybridValidator:
    """Validates bearer tokens via JWT + introspection.

    Construct with :func:`new_validator`; the constructor configures HTTP
    clients, the JWKS cache, and validates the config against the chosen mode.

    Validation flow per mode:

    JWT_ONLY
        Verify signature + claims locally via JWKS. No backend call.

    INTROSPECTION_ONLY
        POST to ``introspection_url``. Token is whatever the AS returns.

    JWT_AND_INTROSPECT (recommended)
        For JWT-shaped tokens, JWT verification must succeed AND introspection
        must return ``active=true``. For opaque tokens, introspection alone.
        Both failures are terminal.

    JWT_OR_INTROSPECT
        Either path may succeed independently. Use only during gradual migration.
    """

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg.normalized()
        self._mode = self.cfg.effective_validation_mode()
        self._jwks_client: Optional[PyJWKClient] = None
        if self.cfg.jwks_url.strip():
            # PyJWKClient caches per-kid keys and refreshes on miss.
            self._jwks_client = PyJWKClient(
                self.cfg.jwks_url,
                cache_keys=True,
                lifespan=3600,
            )

    # ────────────────────────────────────────────────────────────
    # Public entry point
    # ────────────────────────────────────────────────────────────

    async def validate(self, token: str) -> Principal:
        """Validate ``token`` and return a populated :class:`Principal`.

        Raises :class:`TokenInvalidError` if validation fails or
        :class:`TokenInactiveError` if introspection signals inactive.
        """
        mode = self._mode
        if mode == ValidationMode.JWT_ONLY:
            return self._validate_jwt(token)
        if mode == ValidationMode.INTROSPECTION_ONLY:
            return self._check_active(await self._introspect(token))
        if mode == ValidationMode.JWT_AND_INTROSPECT:
            return await self._validate_jwt_and_introspect(token)
        if mode == ValidationMode.JWT_OR_INTROSPECT:
            return await self._validate_jwt_or_introspect(token)
        raise TokenInvalidError(f"unsupported validation mode: {mode}")

    # ────────────────────────────────────────────────────────────
    # Mode implementations
    # ────────────────────────────────────────────────────────────

    async def _validate_jwt_and_introspect(self, token: str) -> Principal:
        """Strict: JWT must pass, then introspection must return active.

        For opaque (non-JWT) tokens, JWT verification is skipped and
        introspection alone decides.
        """
        looks_like_jwt = token.count(".") == 2
        jwt_principal: Optional[Principal] = None
        if looks_like_jwt:
            jwt_principal = self._validate_jwt(token)

        introspected = await self._introspect(token)
        active = self._check_active(introspected)

        if jwt_principal is None:
            return active
        return self._merge_principals(jwt_principal, active)

    async def _validate_jwt_or_introspect(self, token: str) -> Principal:
        """Either succeeds independently (legacy compatibility)."""
        jwt_err: Optional[Exception] = None
        try:
            return self._validate_jwt(token)
        except Exception as e:  # noqa: BLE001 — we deliberately catch every JWT failure
            jwt_err = e

        try:
            return self._check_active(await self._introspect(token))
        except Exception as introspect_err:
            raise TokenInvalidError(
                f"JWT verify failed ({jwt_err}); introspection failed ({introspect_err})"
            ) from introspect_err

    # ────────────────────────────────────────────────────────────
    # JWT path
    # ────────────────────────────────────────────────────────────

    def _validate_jwt(self, token: str) -> Principal:
        if self._jwks_client is None:
            raise TokenInvalidError("JWT verification requested but no jwks_url configured")
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token).key
        except Exception as e:  # JWK lookup / key parse failure
            raise TokenInvalidError(f"could not resolve signing key: {e}") from e

        try:
            decoded = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384"],
                # We deliberately verify aud in the higher-level
                # request-handling layer (against resource_uri) rather than
                # via PyJWT's audience matcher, so we can produce richer
                # error messages.
                options={"verify_aud": False, "verify_iss": True},
                issuer=self.cfg.issuer or None,
            )
        except jwt.ExpiredSignatureError as e:
            raise TokenInvalidError("token expired") from e
        except jwt.InvalidIssuerError as e:
            raise TokenInvalidError(f"invalid issuer: {e}") from e
        except jwt.InvalidTokenError as e:
            raise TokenInvalidError(f"invalid JWT: {e}") from e

        return Principal(
            subject=_str(decoded.get("sub")),
            issuer=_str(decoded.get("iss")),
            audience=_audience_list(decoded.get("aud")),
            scopes=_scope_list(decoded.get("scope")) or _scope_list(decoded.get("scopes")),
            claims=decoded,
            active=True,
        )

    # ────────────────────────────────────────────────────────────
    # Introspection path
    # ────────────────────────────────────────────────────────────

    async def _introspect(self, token: str) -> Principal:
        if not self.cfg.introspection_url.strip():
            raise TokenInvalidError("introspection requested but no introspection_url configured")

        auth = aiohttp.BasicAuth(
            self.cfg.introspection_client_id, self.cfg.introspection_client_secret
        )
        timeout = aiohttp.ClientTimeout(total=self.cfg.request_timeout_seconds)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                self.cfg.introspection_url,
                data={"token": token},
                auth=auth,
                headers={"Accept": "application/json"},
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    raise TokenInvalidError(
                        f"introspection returned HTTP {resp.status}: {body[:200]}"
                    )
                payload = await resp.json()

        return Principal(
            subject=_str(payload.get("sub") or payload.get("subject")),
            issuer=_str(payload.get("iss")),
            audience=_audience_list(payload.get("aud") or payload.get("resource")),
            scopes=_scope_list(payload.get("scope")) or _scope_list(payload.get("scopes")),
            claims=dict(payload),
            active=bool(payload.get("active", False)),
        )

    # ────────────────────────────────────────────────────────────
    # Helpers
    # ────────────────────────────────────────────────────────────

    def _check_active(self, principal: Principal) -> Principal:
        if not principal.active:
            raise TokenInactiveError(
                "introspection returned active=false — token revoked, "
                "suspended, expired, or principal membership inactive"
            )
        return principal

    def _merge_principals(self, jwt_p: Principal, introspected: Principal) -> Principal:
        """Combine a JWT-derived principal with the introspection result.

        Introspection is authoritative for ``active`` and scope set; JWT
        contributes claims that may not be re-emitted by introspection.
        """
        merged_claims = dict(jwt_p.claims)
        merged_claims.update(introspected.claims)
        return Principal(
            subject=introspected.subject or jwt_p.subject,
            issuer=introspected.issuer or jwt_p.issuer,
            audience=introspected.audience or jwt_p.audience,
            scopes=introspected.scopes or jwt_p.scopes,
            claims=merged_claims,
            active=introspected.active,
        )


# ────────────────────────────────────────────────────────────────────
# Module-level helpers (mirror Go's stringClaim / audienceFromClaims / etc.)
# ────────────────────────────────────────────────────────────────────


def _str(value: Any) -> str:
    if isinstance(value, str):
        return value
    return ""


def _audience_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v]
    return [str(value)]


def _scope_list(value: Any) -> list[str]:
    """Accept space-separated string OR list[str]."""
    if value is None:
        return []
    if isinstance(value, str):
        return [s for s in value.split() if s]
    if isinstance(value, (list, tuple)):
        return [str(s) for s in value if s]
    return []


def new_validator(cfg: Config) -> HybridValidator:
    """Construct a :class:`HybridValidator` after validating the config."""
    cfg.validate()
    return HybridValidator(cfg)
