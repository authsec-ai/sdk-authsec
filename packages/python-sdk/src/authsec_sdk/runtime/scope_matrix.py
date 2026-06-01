"""ScopeMatrixClient — fetches tool→scope mapping from AuthSec, caches with TTL.

Python parity port of go-sdk/scope_matrix_client.go. Endpoint:
``GET {authorization_server}/authsec/resource-servers/{id}/sdk-policy``.

Behavior:

* On success with ``policy_complete=true`` → cache the map, clear errors.
* On ``policy_complete=false`` → enforce **deny-all** by clearing the cached
  map; record the lifecycle reason for observability. Never serve stale data
  in this case.
* On transport / decode failure → leave the previously-cached map intact and
  serve it until ``max_stale_age``; after that, refuse with the cached error.
* Background refresh on TTL expiry with a CAS gate so only one refresh runs
  at a time.
"""

from __future__ import annotations

import asyncio
import dataclasses
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

import aiohttp

from .config import Config
from .policy import ToolScopeMap

# Tightened defaults in 4.4.2 to close the "revoke a permission, user still has access
# for 5 min" gap. With these values, admin RBAC changes propagate to MCP servers within
# <=30 s in the common case; stale-with-error window is capped at 2 min so a misbehaving
# AS doesn't leave a server running on outdated policy for half an hour. Customers who
# want the old behavior for performance can override via Config.scope_matrix_ttl.
_DEFAULT_SCOPE_MATRIX_TTL = timedelta(seconds=30)
_DEFAULT_MAX_STALE_AGE = timedelta(minutes=2)
_DEFAULT_RETRY_BACKOFF = timedelta(seconds=10)


class PolicyIncompleteError(Exception):
    """Returned when the backend signals ``policy_complete=false``.

    Callers must treat this as deny-all and must NOT fall back to a stale
    local cache for tool authorization.
    """

    def __init__(self, state: str, reason: str):
        self.state = state
        self.reason = reason
        msg = f"authsec policy incomplete: state={state}"
        if reason:
            msg += f" reason={reason}"
        super().__init__(msg)


@dataclass
class CacheStatus:
    """Snapshot of the current cache state — useful for observability."""

    has_data: bool = False
    fetched_at: Optional[datetime] = None
    stale_age: timedelta = timedelta(0)
    last_err: Optional[Exception] = None
    last_err_at: Optional[datetime] = None
    policy_state: str = ""
    policy_complete: bool = False
    generation: int = 0


@dataclass
class _CacheState:
    tool_map: Optional[ToolScopeMap] = None
    # Authoritative scope list for this RS, served from AuthSec. Used to
    # populate the PRM (RFC 9728) scopes_supported field so admin changes
    # in the AuthSec UI reach MCP clients via discovery without a code
    # change. None = never fetched; [] = fetched but empty.
    scopes_supported: Optional[list[str]] = None
    fetched_at: Optional[datetime] = None
    last_err: Optional[Exception] = None
    last_err_at: Optional[datetime] = None
    next_refresh_at: Optional[datetime] = None
    policy_state: str = ""
    policy_complete: bool = False
    generation: int = 0


class ScopeMatrixClient:
    """Fetches and caches the authoritative tool→scope map from AuthSec."""

    def __init__(self, cfg: Config) -> None:
        if not cfg.resource_server_id or not cfg.authorization_server:
            raise ValueError(
                "ScopeMatrixClient requires resource_server_id and authorization_server"
            )
        if not cfg.introspection_client_id or not cfg.introspection_client_secret:
            raise ValueError(
                "ScopeMatrixClient requires introspection client credentials"
            )
        base = cfg.authorization_server.rstrip("/")
        self.endpoint = f"{base}/authsec/resource-servers/{cfg.resource_server_id}/sdk-policy"
        self._client_id = cfg.introspection_client_id
        self._client_secret = cfg.introspection_client_secret
        self._ttl = cfg.scope_matrix_ttl or _DEFAULT_SCOPE_MATRIX_TTL
        self._max_stale_age = _DEFAULT_MAX_STALE_AGE
        self._retry_backoff = _DEFAULT_RETRY_BACKOFF
        self._request_timeout = cfg.request_timeout_seconds

        self._state = _CacheState()
        self._lock = asyncio.Lock()
        self._refreshing = False

    # ────────────────────────────────────────────────────────────
    # Public API
    # ────────────────────────────────────────────────────────────

    async def fetch(self) -> tuple[Optional[ToolScopeMap], dict]:
        """One-shot fetch. Does NOT touch the cache.

        Returns (tool_map, payload). ``tool_map`` is ``None`` when the
        backend signals ``policy_complete=false`` — caller must treat that
        as deny-all. Raises on transport / HTTP / decode failures.
        """
        auth = aiohttp.BasicAuth(self._client_id, self._client_secret)
        timeout = aiohttp.ClientTimeout(total=self._request_timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(self.endpoint, auth=auth) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    raise RuntimeError(
                        f"scope matrix fetch: HTTP {resp.status}: {body[:200]}"
                    )
                payload = await resp.json()

        # Back-compat shim: pre-migration backends emit the legacy shape
        # {"tools": {...}} with no state/policy_complete/tool_policy.
        legacy_shape = (
            not payload.get("state")
            and not payload.get("tool_policy")
            and payload.get("tools")
        )
        if legacy_shape:
            payload["state"] = "ready"
            payload["policy_complete"] = True

        if not payload.get("policy_complete"):
            raise PolicyIncompleteError(
                state=payload.get("state", ""),
                reason=payload.get("reason", ""),
            )

        # Build the authoritative map from tool_policy when present,
        # otherwise fall back to the legacy `tools` flat map.
        tool_map: ToolScopeMap = {}
        tool_policy = payload.get("tool_policy") or []
        if tool_policy:
            for t in tool_policy:
                name = t.get("name")
                if not name:
                    continue
                if t.get("is_public"):
                    tool_map[name] = []  # ToolPolicyPublic
                elif t.get("required_scopes"):
                    tool_map[name] = list(t["required_scopes"])
                # else: omit → deny
        else:
            # Legacy flat map: copy verbatim, empty list = public.
            for name, scopes in (payload.get("tools") or {}).items():
                tool_map[name] = list(scopes or [])

        return tool_map, payload

    async def fetch_and_cache(self) -> None:
        """Fetch and update the cache.

        On policy_complete=false, clears the cache (deny-all) and records the
        reason. On transport failure, leaves the cache intact so previously-
        good policy keeps serving until ``max_stale_age``.
        """
        try:
            tool_map, payload = await self.fetch()
        except PolicyIncompleteError as e:
            async with self._lock:
                self._state.tool_map = None
                # policy_complete=false means RS has no published scopes;
                # clear the PRM cache to match.
                self._state.scopes_supported = None
                self._state.fetched_at = None
                self._state.policy_state = e.state
                self._state.policy_complete = False
                self._state.last_err = e
                self._state.last_err_at = _now()
                self._state.next_refresh_at = _now() + self._retry_backoff
            raise
        except Exception as e:
            async with self._lock:
                # Don't touch tool_map or scopes_supported; let stale serving
                # rules apply so the PRM keeps publishing the last good list.
                self._state.last_err = e
                self._state.last_err_at = _now()
                self._state.next_refresh_at = _now() + self._retry_backoff
            raise

        async with self._lock:
            self._state.tool_map = tool_map
            # Backend always emits scopes_supported on policy_complete=true.
            # If a pre-migration backend omits it, leave the previous value
            # so PRM keeps publishing what it last knew.
            raw_scopes = payload.get("scopes_supported")
            if isinstance(raw_scopes, list):
                self._state.scopes_supported = list(raw_scopes)
            self._state.fetched_at = _now()
            self._state.policy_state = payload.get("state", "ready")
            self._state.policy_complete = True
            self._state.generation = int(payload.get("generation", 0))
            self._state.last_err = None
            self._state.last_err_at = None
            self._state.next_refresh_at = None

    async def get_cached(self) -> Optional[ToolScopeMap]:
        """Return the cached map.

        Triggers a background refresh on TTL expiry. Raises if the cache was
        never populated successfully OR the cache exceeded ``max_stale_age``
        with the last refresh in error.
        """
        async with self._lock:
            tool_map = self._state.tool_map
            fetched_at = self._state.fetched_at
            last_err = self._state.last_err
            next_refresh_at = self._state.next_refresh_at

        now = _now()
        if fetched_at is not None:
            age = now - fetched_at
        else:
            age = timedelta.max

        expired = age > self._ttl
        if expired and (next_refresh_at is None or now > next_refresh_at):
            if not self._refreshing:
                self._refreshing = True
                asyncio.create_task(self._background_refresh())

        if tool_map is None and last_err is not None:
            raise last_err

        if tool_map is not None and last_err is not None and age > self._max_stale_age:
            raise RuntimeError(
                f"scope matrix cache stale (age={age}) and last refresh failed: {last_err}"
            )

        return tool_map

    async def get_scopes_supported(self) -> Optional[list[str]]:
        """Return the cached scopes_supported list (authoritative from AuthSec).

        Triggers a background refresh on TTL expiry, same as ``get_cached``.
        Returns ``None`` when the cache has never been populated successfully
        OR exceeded ``max_stale_age`` with the last refresh in error. Callers
        (PRM builder) should fall back to ``cfg.supported_scopes`` in that
        case so the server still serves a metadata document at boot.
        """
        async with self._lock:
            scopes = self._state.scopes_supported
            fetched_at = self._state.fetched_at
            last_err = self._state.last_err
            next_refresh_at = self._state.next_refresh_at

        now = _now()
        age = (now - fetched_at) if fetched_at is not None else timedelta.max

        expired = age > self._ttl
        if expired and (next_refresh_at is None or now > next_refresh_at):
            if not self._refreshing:
                self._refreshing = True
                asyncio.create_task(self._background_refresh())

        # Same stale-then-error rule as get_cached: never serve data older
        # than max_stale_age with a known error condition.
        if scopes is None and last_err is not None:
            return None
        if scopes is not None and last_err is not None and age > self._max_stale_age:
            return None
        return list(scopes) if scopes is not None else None

    async def cache_status(self) -> CacheStatus:
        async with self._lock:
            s = self._state
            stale = (_now() - s.fetched_at) if s.fetched_at else timedelta(0)
            return CacheStatus(
                has_data=s.tool_map is not None,
                fetched_at=s.fetched_at,
                stale_age=stale,
                last_err=s.last_err,
                last_err_at=s.last_err_at,
                policy_state=s.policy_state,
                policy_complete=s.policy_complete,
                generation=s.generation,
            )

    # ────────────────────────────────────────────────────────────
    # Internals
    # ────────────────────────────────────────────────────────────

    async def _background_refresh(self) -> None:
        try:
            await self.fetch_and_cache()
        except Exception:
            # Errors are already recorded in cache state; swallow here so
            # background tasks never propagate.
            pass
        finally:
            self._refreshing = False


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)
