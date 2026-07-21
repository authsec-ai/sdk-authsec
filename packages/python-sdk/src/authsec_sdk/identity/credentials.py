"""Client authentication methods for machine-to-machine (M2M) auth.

AuthSec accepts three ways for a machine to prove who it is at the token
endpoint. All three end the same way — ``POST /oauth/token`` → access token —
they differ only in the proof:

==================  ============================================  =====================
Method              Wire mechanism                                Best for
==================  ============================================  =====================
ClientSecretAuth    ``Authorization: Basic id:secret``            simple deployments
PrivateKeyJwtAuth   signed JWT assertion (RFC 7523) in the body   secret-averse security
                                                                  postures; key never
                                                                  leaves the machine
SpiffeSvidAuth      SPIFFE JWT-SVID assertion in the body         you already hold an
                                                                  SVID; for automatic
                                                                  SVID fetching use
                                                                  SpiffeWorkloadIdentity
==================  ============================================  =====================

Usage with :class:`~authsec_sdk.identity.AgentIdentity`::

    from authsec_sdk import AgentIdentity
    from authsec_sdk.identity import ClientSecretAuth, PrivateKeyJwtAuth

    agent = AgentIdentity(issuer, client_id, auth=ClientSecretAuth("sk-..."))
    agent = AgentIdentity(issuer, client_id,
                          auth=PrivateKeyJwtAuth("private_key.pem", kid="key-1"))

For Kubernetes workloads, prefer :class:`authsec_sdk.identity.SpiffeWorkloadIdentity`
which fetches and renews SVIDs from the SPIRE agent automatically.
"""

from __future__ import annotations

import base64
import secrets
import time
from typing import Any, Dict, Optional

from jwt import encode as _jwt_encode


class ClientAuth:
    """Base class for client authentication methods.

    Subclasses contribute HTTP Basic headers and/or POST body parameters to
    every request that authenticates the client (token requests and
    requester-bootstrap).
    """

    def headers(self, client_id: str) -> Dict[str, str]:
        """Extra HTTP headers for client authentication."""
        return {}

    def body_params(self, client_id: str, token_endpoint: str) -> Dict[str, str]:
        """Extra POST body parameters for client authentication."""
        return {}


class ClientSecretAuth(ClientAuth):
    """``client_secret_basic`` — ID + shared secret via HTTP Basic auth.

    The simplest method. The secret crosses the wire on every request, so
    protect it like a password and rotate it periodically.
    """

    def __init__(self, client_secret: str):
        if not client_secret:
            raise ValueError("ClientSecretAuth: client_secret is required")
        self._secret = client_secret

    def headers(self, client_id: str) -> Dict[str, str]:
        raw = f"{client_id}:{self._secret}".encode()
        return {"Authorization": f"Basic {base64.b64encode(raw).decode()}"}

    def __repr__(self) -> str:  # never leak the secret in logs
        return "ClientSecretAuth(***)"


class PrivateKeyJwtAuth(ClientAuth):
    """``private_key_jwt`` (RFC 7523) — signed JWT assertion, no shared secret.

    Each request carries a freshly signed assertion: 5-minute lifetime,
    single-use ``jti``, audience-bound to the token endpoint. The private key
    never leaves the machine; AuthSec verifies with the public key registered
    in the portal JWKS.

    Parameters
    ----------
    private_key:
        RSA private key — a PEM string or a filesystem path to a ``.pem``
        file (generate a pair with the portal's instructions or
        ``cryptography``; register the public key in the AuthSec portal).
    kid:
        Key ID matching the registered public key in the portal JWKS.
    """

    def __init__(self, private_key: str, *, kid: str):
        if not private_key:
            raise ValueError("PrivateKeyJwtAuth: private_key is required")
        if not kid:
            raise ValueError(
                "PrivateKeyJwtAuth: kid is required (the key ID of the public "
                "key registered in the AuthSec portal)"
            )
        self._key = _load_pem_private_key(private_key)
        self._kid = kid

    def body_params(self, client_id: str, token_endpoint: str) -> Dict[str, str]:
        now = int(time.time())
        assertion = _jwt_encode(
            {
                "iss": client_id,
                "sub": client_id,
                "aud": token_endpoint,
                "jti": secrets.token_hex(16),
                "iat": now,
                "exp": now + 300,
            },
            self._key,
            algorithm="RS256",
            headers={"kid": self._kid},
        )
        return {
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
        }

    def __repr__(self) -> str:  # never leak key material in logs
        return f"PrivateKeyJwtAuth(kid={self._kid!r})"


class SpiffeSvidAuth(ClientAuth):
    """SPIFFE JWT-SVID assertion — platform-attested workload identity.

    Low-level: use this when you already hold a JWT-SVID (e.g. minted for
    testing). Inside Kubernetes, prefer
    :class:`authsec_sdk.identity.SpiffeWorkloadIdentity`, which fetches and
    renews SVIDs from the SPIRE agent automatically.

    Note: SVIDs are short-lived (typically ~5 minutes) — this class does NOT
    refresh them.
    """

    _ASSERTION_TYPE = "urn:authsec:params:oauth:client-assertion-type:spiffe-svid"

    def __init__(self, svid: str):
        if not svid:
            raise ValueError("SpiffeSvidAuth: svid is required")
        self._svid = svid

    def body_params(self, client_id: str, token_endpoint: str) -> Dict[str, str]:
        return {
            "client_assertion_type": self._ASSERTION_TYPE,
            "client_assertion": self._svid,
        }

    def __repr__(self) -> str:
        return "SpiffeSvidAuth(***)"


def _load_pem_private_key(private_key: str) -> Any:
    """Load an RSA private key from a PEM string or a path to a PEM file."""
    from cryptography.hazmat.primitives import serialization

    if "-----BEGIN" in private_key:
        pem = private_key.encode()
    else:
        try:
            with open(private_key, "rb") as f:
                pem = f.read()
        except OSError as e:
            raise ValueError(
                f"private_key is neither PEM content nor a readable file "
                f"path: {e}"
            ) from e
    try:
        return serialization.load_pem_private_key(pem, password=None)
    except Exception as e:
        raise ValueError(f"could not parse private_key PEM: {e}") from e
