/**
 * ScopeMatrixClient — fetches the tool→scope mapping from AuthSec, caches
 * with TTL.
 *
 * TypeScript parity port of python/runtime/scope_matrix.py.
 *
 * Endpoint: ``GET {authorizationServer}/authsec/resource-servers/{id}/sdk-policy``.
 *
 * Behaviour:
 *
 *  - On success with ``policy_complete=true`` → cache the map, clear errors.
 *  - On ``policy_complete=false`` → enforce deny-all by clearing the cached
 *    map; record the lifecycle reason for observability. Never serve stale
 *    data in this case.
 *  - On transport / decode failure → leave the previously-cached map intact
 *    and serve it until ``maxStaleAgeSeconds``; after that, refuse with the
 *    cached error.
 *  - Background refresh on TTL expiry with a guard so only one refresh runs
 *    at a time.
 */

import type { Config } from './config.js';
import {
  lookupTool,
  type ToolPolicyResult,
  type ToolScopeMap,
} from './policy.js';

// Tightened defaults in 4.4.2 to close the "revoke a permission, user still has access
// for 5 min" gap. With these values, admin RBAC changes propagate to MCP servers within
// ≤30 s in the common case; stale-with-error window is capped at 2 min so a misbehaving
// AS doesn't leave a server running on outdated policy for half an hour. Customers who
// want the old behavior for performance can override via Config.scopeMatrixCacheTtlSeconds.
const DEFAULT_SCOPE_MATRIX_TTL_SECONDS = 30;
const DEFAULT_MAX_STALE_AGE_SECONDS = 120;
const DEFAULT_RETRY_BACKOFF_SECONDS = 10;

/**
 * Returned when the backend signals ``policy_complete=false``. Callers must
 * treat this as deny-all and must NOT fall back to a stale local cache for
 * tool authorization.
 */
export class PolicyIncompleteError extends Error {
  readonly state: string;
  readonly reason: string;
  constructor(state: string, reason: string) {
    let msg = `authsec policy incomplete: state=${state}`;
    if (reason) msg += ` reason=${reason}`;
    super(msg);
    this.name = 'PolicyIncompleteError';
    this.state = state;
    this.reason = reason;
  }
}

/** Snapshot of the current cache state — useful for observability. */
export interface CacheStatus {
  hasData: boolean;
  fetchedAt: Date | null;
  staleAgeMs: number;
  lastErr: Error | null;
  lastErrAt: Date | null;
  policyState: string;
  policyComplete: boolean;
  generation: number;
}

interface CacheState {
  toolMap: ToolScopeMap | null;
  /**
   * Authoritative scope list for this RS, served straight from the AuthSec
   * admin DB. Used to populate the PRM (RFC 9728) ``scopes_supported`` field
   * so admin-side changes (add/remove/rename a scope in the AuthSec UI) reach
   * MCP clients via discovery without any code change to the server.
   *
   * ``null`` means "never fetched" (boot before first refresh); empty array
   * means "fetched successfully but no scopes registered" — both are
   * distinguishable from each other so the PRM builder can decide whether to
   * fall back to local config.
   */
  scopesSupported: string[] | null;
  fetchedAt: Date | null;
  lastErr: Error | null;
  lastErrAt: Date | null;
  nextRefreshAt: Date | null;
  policyState: string;
  policyComplete: boolean;
  generation: number;
}

interface RawPolicyResponse {
  state?: string;
  policy_complete?: boolean;
  reason?: string;
  generation?: number;
  scopes_supported?: string[];
  tool_policy?: Array<{
    name?: string;
    is_public?: boolean;
    required_scopes?: string[];
  }>;
  tools?: Record<string, string[]>;
}

export class ScopeMatrixClient {
  readonly endpoint: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly ttlMs: number;
  private readonly maxStaleAgeMs: number;
  private readonly retryBackoffMs: number;
  private readonly requestTimeoutMs: number;

  private state: CacheState = {
    toolMap: null,
    scopesSupported: null,
    fetchedAt: null,
    lastErr: null,
    lastErrAt: null,
    nextRefreshAt: null,
    policyState: '',
    policyComplete: false,
    generation: 0,
  };
  private refreshing = false;

  constructor(cfg: Config) {
    if (!cfg.resourceServerId || !cfg.authorizationServer) {
      throw new Error(
        'ScopeMatrixClient requires resourceServerId and authorizationServer',
      );
    }
    if (!cfg.introspectionClientId || !cfg.introspectionClientSecret) {
      throw new Error('ScopeMatrixClient requires introspection client credentials');
    }
    const base = cfg.authorizationServer.replace(/\/+$/, '');
    this.endpoint = `${base}/authsec/resource-servers/${cfg.resourceServerId}/sdk-policy`;
    this.clientId = cfg.introspectionClientId;
    this.clientSecret = cfg.introspectionClientSecret;
    const ttlSec = cfg.scopeMatrixCacheTtlSeconds || DEFAULT_SCOPE_MATRIX_TTL_SECONDS;
    this.ttlMs = ttlSec * 1000;
    this.maxStaleAgeMs = DEFAULT_MAX_STALE_AGE_SECONDS * 1000;
    this.retryBackoffMs = DEFAULT_RETRY_BACKOFF_SECONDS * 1000;
    this.requestTimeoutMs = Math.max(1, cfg.requestTimeoutSeconds) * 1000;
  }

  /**
   * One-shot fetch. Does NOT touch the cache. Throws
   * ``PolicyIncompleteError`` when the backend signals
   * ``policy_complete=false``; throws Error on transport/decode failures.
   */
  async fetch(): Promise<{ toolMap: ToolScopeMap; payload: RawPolicyResponse }> {
    const credentials = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    let resp: Response;
    try {
      resp = await fetch(this.endpoint, {
        method: 'GET',
        headers: {
          Authorization: `Basic ${credentials}`,
          Accept: 'application/json',
        },
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    if (resp.status !== 200) {
      const body = await resp.text().catch(() => '');
      throw new Error(`scope matrix fetch: HTTP ${resp.status}: ${body.slice(0, 200)}`);
    }
    const payload = (await resp.json()) as RawPolicyResponse;

    // Back-compat shim: pre-migration backends emit {"tools": {...}} only.
    const legacyShape =
      !payload.state && !payload.tool_policy && payload.tools;
    if (legacyShape) {
      payload.state = 'ready';
      payload.policy_complete = true;
    }

    if (!payload.policy_complete) {
      throw new PolicyIncompleteError(payload.state ?? '', payload.reason ?? '');
    }

    const tools: Record<string, { required_any: string[] }> = {};
    if (payload.tool_policy && payload.tool_policy.length > 0) {
      for (const t of payload.tool_policy) {
        if (!t.name) continue;
        if (t.is_public) {
          tools[t.name] = { required_any: [] };
        } else if (t.required_scopes && t.required_scopes.length > 0) {
          tools[t.name] = { required_any: [...t.required_scopes] };
        }
        // else: omit → deny
      }
    } else {
      for (const [name, scopes] of Object.entries(payload.tools ?? {})) {
        tools[name] = { required_any: [...(scopes ?? [])] };
      }
    }
    const toolMap: ToolScopeMap = { policy_complete: true, tools };
    return { toolMap, payload };
  }

  /**
   * Fetch and update the cache. On policy_complete=false, clears the cache
   * (deny-all) and records the reason. On transport failure, leaves the
   * cache intact so previously-good policy keeps serving until
   * ``maxStaleAge``.
   */
  async fetchAndCache(): Promise<void> {
    try {
      const { toolMap, payload } = await this.fetch();
      this.state.toolMap = toolMap;
      // Cache the authoritative scope list so the PRM endpoint can serve it.
      // Backend always emits scopes_supported on policy_complete=true; if a
      // pre-migration backend omits it, leave the prior cache value alone so
      // PRM keeps publishing what it last knew.
      if (Array.isArray(payload.scopes_supported)) {
        this.state.scopesSupported = [...payload.scopes_supported];
      }
      this.state.fetchedAt = new Date();
      this.state.policyState = payload.state ?? 'ready';
      this.state.policyComplete = true;
      this.state.generation = Number(payload.generation ?? 0);
      this.state.lastErr = null;
      this.state.lastErrAt = null;
      this.state.nextRefreshAt = null;
    } catch (e) {
      if (e instanceof PolicyIncompleteError) {
        this.state.toolMap = null;
        // policy_complete=false means deny-all for tools, AND that the RS
        // hasn't published any scopes yet. Clear the PRM cache too so we
        // don't keep advertising scopes for an RS that is no longer ready.
        this.state.scopesSupported = null;
        this.state.fetchedAt = null;
        this.state.policyState = e.state;
        this.state.policyComplete = false;
        this.state.lastErr = e;
        this.state.lastErrAt = new Date();
        this.state.nextRefreshAt = new Date(Date.now() + this.retryBackoffMs);
        throw e;
      }
      // Transport / decode failure: leave both toolMap and scopesSupported
      // intact so previously-good data keeps serving until maxStaleAge.
      this.state.lastErr = e instanceof Error ? e : new Error(String(e));
      this.state.lastErrAt = new Date();
      this.state.nextRefreshAt = new Date(Date.now() + this.retryBackoffMs);
      throw e;
    }
  }

  /**
   * Return the cached ``scopes_supported`` list (authoritative from AuthSec).
   * Triggers a background refresh on TTL expiry, same as ``getCached()``.
   * Returns ``null`` when the cache has never been populated successfully —
   * callers (like the PRM builder) should fall back to local ``cfg.supportedScopes``
   * in that case so the server still serves a metadata document at boot.
   */
  async getScopesSupported(): Promise<string[] | null> {
    const { scopesSupported, fetchedAt, lastErr, nextRefreshAt } = this.state;
    const now = Date.now();
    const ageMs = fetchedAt ? now - fetchedAt.getTime() : Number.POSITIVE_INFINITY;

    const expired = ageMs > this.ttlMs;
    if (expired && (nextRefreshAt === null || now > nextRefreshAt.getTime())) {
      if (!this.refreshing) {
        this.refreshing = true;
        void this.backgroundRefresh();
      }
    }

    // Same stale-then-error rule as getCached: never serve data older than
    // maxStaleAge with a known error condition.
    if (scopesSupported === null && lastErr !== null) return null;
    if (scopesSupported !== null && lastErr !== null && ageMs > this.maxStaleAgeMs) {
      return null;
    }
    return scopesSupported ? [...scopesSupported] : null;
  }

  /**
   * Return the cached map. Triggers a background refresh on TTL expiry.
   * Throws if the cache was never populated successfully OR exceeded
   * ``maxStaleAge`` with the last refresh in error.
   */
  async getCached(): Promise<ToolScopeMap | null> {
    const { toolMap, fetchedAt, lastErr, nextRefreshAt } = this.state;
    const now = Date.now();
    const ageMs = fetchedAt ? now - fetchedAt.getTime() : Number.POSITIVE_INFINITY;

    const expired = ageMs > this.ttlMs;
    if (expired && (nextRefreshAt === null || now > nextRefreshAt.getTime())) {
      if (!this.refreshing) {
        this.refreshing = true;
        void this.backgroundRefresh();
      }
    }

    if (toolMap === null && lastErr !== null) {
      throw lastErr;
    }
    if (toolMap !== null && lastErr !== null && ageMs > this.maxStaleAgeMs) {
      throw new Error(
        `scope matrix cache stale (age=${ageMs}ms) and last refresh failed: ${lastErr.message}`,
      );
    }
    return toolMap;
  }

  /** Convenience: look up a single tool through the cached map. */
  async lookupTool(toolId: string): Promise<ToolPolicyResult> {
    const map = await this.getCached();
    return lookupTool(map, toolId);
  }

  cacheStatus(): CacheStatus {
    const s = this.state;
    const staleAgeMs = s.fetchedAt ? Date.now() - s.fetchedAt.getTime() : 0;
    return {
      hasData: s.toolMap !== null,
      fetchedAt: s.fetchedAt,
      staleAgeMs,
      lastErr: s.lastErr,
      lastErrAt: s.lastErrAt,
      policyState: s.policyState,
      policyComplete: s.policyComplete,
      generation: s.generation,
    };
  }

  private async backgroundRefresh(): Promise<void> {
    try {
      await this.fetchAndCache();
    } catch {
      // Errors are already recorded in cache state; swallow here so
      // background tasks never propagate.
    } finally {
      this.refreshing = false;
    }
  }
}
