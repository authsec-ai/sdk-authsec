/**
 * Runtime — the customer-facing entry point for protecting an MCP server.
 *
 * TypeScript parity port of python/runtime/server.py and go-sdk's Runtime.
 *
 * Composes the HybridValidator + ScopeMatrixClient + manifest publisher into
 * a single facade with a single ``authorize(token, toolId)`` method.
 */

import {
  effectivePolicyMode,
  normalizeConfig,
  validateConfig,
  type Config,
  type ManifestToolInput,
  type PolicyMode,
} from './config.js';
import { publishManifestSafe } from './manifest.js';
import { buildWwwAuthenticate } from './metadata.js';
import { lookupTool, type ToolScopeMap, toolScopeMapFromRecord } from './policy.js';
import type { Principal } from './principal.js';
import {
  PolicyIncompleteError,
  ScopeMatrixClient,
} from './scopeMatrix.js';
import {
  HybridValidator,
  ValidationError,
  newValidator,
} from './validator.js';

/** Denial codes mirror python/runtime — AI clients depend on cross-SDK parity. */
export type DenialCode =
  | 'invalid_token'
  | 'invalid_audience'
  | 'scope_insufficient'
  | 'policy_unavailable';

export interface AuthorizeDenial {
  code: DenialCode;
  description: string;
  status: number;
  wwwAuthenticate: string;
  /** Set when denial code is ``scope_insufficient`` so the caller can echo it. */
  requiredScopes?: string[];
  tool?: string;
}

export type AuthorizeResult =
  | { allowed: true; principal: Principal }
  | { allowed: false; denial: AuthorizeDenial };

/** Runtime that protects an MCP server. */
export class Runtime {
  readonly cfg: Config;
  private readonly validator: HybridValidator;
  private readonly policyMode: PolicyMode;
  private readonly scopeClient: ScopeMatrixClient | null;

  private constructor(cfg: Config) {
    validateConfig(cfg);
    this.cfg = normalizeConfig(cfg);
    this.validator = newValidator(this.cfg);
    this.policyMode = effectivePolicyMode(this.cfg);
    this.scopeClient =
      this.policyMode === 'remote_required' ||
      this.policyMode === 'remote_with_local_fallback'
        ? new ScopeMatrixClient(this.cfg)
        : null;
  }

  /**
   * Construct and initialize a Runtime. Performs the initial scope-matrix
   * fetch (mandatory under ``remote_required``) so that boot fails loudly on
   * misconfiguration.
   */
  static async create(cfg: Config): Promise<Runtime> {
    const rt = new Runtime(cfg);
    await rt.startup();
    return rt;
  }

  /**
   * Run mandatory startup actions. Idempotent; safe to call once during
   * boot. Manifest publish is fire-and-forget.
   */
  async startup(opts: { tools?: ManifestToolInput[] } = {}): Promise<void> {
    if (this.scopeClient !== null) {
      try {
        await this.scopeClient.fetchAndCache();
      } catch (e) {
        if (this.cfg.publishManifest) {
          const msg = e instanceof Error ? e.message : String(e);
          console.warn(
            `[authsec] initial scope matrix fetch failed; starting in deny-all mode (publishManifest=true): ${msg}`,
          );
        } else if (e instanceof PolicyIncompleteError) {
          if (this.policyMode === 'remote_required') throw e;
          // remote_with_local_fallback: log + continue
          console.warn(
            `[authsec] policy incomplete at startup (falling back to local): ${e.message}`,
          );
        } else {
          if (this.policyMode === 'remote_required') {
            const msg = e instanceof Error ? e.message : String(e);
            throw new Error(`REMOTE_REQUIRED initial scope matrix fetch failed: ${msg}`);
          }
          const msg = e instanceof Error ? e.message : String(e);
          console.warn(
            `[authsec] initial scope matrix fetch failed (falling back to local): ${msg}`,
          );
        }
      }
    }
    if (this.cfg.publishManifest) {
      // fire-and-forget; never blocks startup
      void publishManifestSafe(this.cfg, opts.tools ?? []);
    }
  }

  /**
   * Return the authoritative ``scopes_supported`` list for this RS, fetched
   * from AuthSec via the scope matrix (TTL-cached, refreshed in the
   * background). The PRM endpoint uses this so admin-side scope edits in the
   * AuthSec UI propagate to MCP clients within one refresh cycle (≤5 min) —
   * **no code change in the MCP server**.
   *
   * Returns ``null`` when:
   *  - the runtime has no scope matrix client (policyMode=local_only / open),
   *  - the cache has never been populated and there's no usable fallback,
   *  - the cache exceeded ``maxStaleAge`` with the last refresh in error.
   *
   * Callers (PRM builder) should fall back to ``cfg.supportedScopes`` when
   * this returns ``null`` so the server still serves a metadata document.
   */
  async getAuthoritativeScopes(): Promise<string[] | null> {
    if (this.scopeClient === null) return null;
    try {
      return await this.scopeClient.getScopesSupported();
    } catch {
      // getScopesSupported is fail-soft and shouldn't throw, but defend.
      return null;
    }
  }

  /** Pure token validation; throws ValidationError on failure. */
  async validateToken(token: string): Promise<Principal> {
    const principal = await this.validator.validate(token);
    // Audience check: token must be bound to this resource.
    if (this.cfg.resourceUri && principal.audience.length > 0) {
      const audOk = principal.audience.some((a) => a === this.cfg.resourceUri);
      if (!audOk) {
        throw new ValidationError(
          'invalid_token',
          `audience mismatch: token aud=${JSON.stringify(principal.audience)} does not include resource_uri=${this.cfg.resourceUri}`,
        );
      }
    }
    return principal;
  }

  /**
   * Top-level authorization: validate the bearer token AND check tool scope.
   * Returns a structured result with everything needed to build a 401/403/503.
   */
  async authorize(token: string, toolId: string): Promise<AuthorizeResult> {
    if (!token) {
      return this.denyInvalidToken('missing bearer token');
    }
    let principal: Principal;
    try {
      principal = await this.validateToken(token);
    } catch (e) {
      if (e instanceof ValidationError) {
        if (
          e.message.toLowerCase().includes('audience mismatch') ||
          e.message.toLowerCase().includes('audience')
        ) {
          // We surface audience failures with their own code per the denial taxonomy.
          if (e.message.toLowerCase().includes('audience mismatch')) {
            return this.denyInvalidAudience(e.message);
          }
        }
        return this.denyInvalidToken(e.message);
      }
      const msg = e instanceof Error ? e.message : String(e);
        return this.denyInvalidToken(`token validation failure: ${msg}`);
    }

    return this.authorizePrincipal(principal, toolId);
  }

  /**
   * Authorize an already-validated principal for a specific MCP tool. This is
   * used by server middleware for tools/list filtering and by custom hosts
   * that validate tokens once per request.
   */
  async authorizePrincipal(principal: Principal, toolId: string): Promise<AuthorizeResult> {
    // OPEN mode: any valid token may call any tool.
    if (this.policyMode === 'open') {
      return { allowed: true, principal };
    }

    const tool = (toolId ?? '').trim();
    if (!tool) {
      // No tool id supplied (e.g. non tools/call request) — let the caller decide.
      return { allowed: true, principal };
    }

    let toolMap: ToolScopeMap | null = null;
    let policyUnavailable = false;
    if (this.scopeClient !== null) {
      try {
        toolMap = await this.scopeClient.getCached();
      } catch (e) {
        if (e instanceof PolicyIncompleteError) {
          if (this.policyMode === 'remote_required') {
            return this.denyPolicyUnavailable(e.message);
          }
          policyUnavailable = true;
        } else {
          const msg = e instanceof Error ? e.message : String(e);
          console.warn(`[authsec] scope matrix fetch failed: ${msg}`);
          if (this.policyMode === 'remote_required') {
            return this.denyPolicyUnavailable(msg);
          }
          policyUnavailable = true;
        }
      }
    }
    if (toolMap === null && this.policyMode === 'remote_required') {
      return this.denyPolicyUnavailable('tool policy unavailable in remote_required mode');
    }
    if (toolMap === null) {
      // Fall back to local toolScopes (local_only or fallback path).
      toolMap = toolScopeMapFromRecord(this.cfg.toolScopes);
    }
    if (toolMap === null) {
      // local_only with no toolScopes set is a bug surfaced at validateConfig,
      // but be defensive.
      return this.denyPolicyUnavailable('no tool policy configured');
    }
    // If a fetched map signalled incomplete but we got here via fallback,
    // surface that.
    if (policyUnavailable && this.policyMode === 'remote_required') {
      return this.denyPolicyUnavailable('tool policy unavailable');
    }

    const result = lookupTool(toolMap, tool);
    if (result.denied === 'policy_incomplete') {
      return this.denyPolicyUnavailable('tool policy incomplete');
    }
    if (result.outcome === 'public') {
      return { allowed: true, principal };
    }
    if (result.outcome === 'absent') {
      return this.denyScopeInsufficient(tool, ['<tool not in policy>']);
    }
    // SCOPED
    const granted = new Set(principal.scopes);
    if (result.required_any.some((s) => granted.has(s))) {
      return { allowed: true, principal };
    }
    return this.denyScopeInsufficient(tool, result.required_any);
  }

  // ── Denial helpers ────────────────────────────────────────────────

  private denyInvalidToken(description: string): AuthorizeResult {
    return {
      allowed: false,
      denial: {
        code: 'invalid_token',
        description,
        status: 401,
        wwwAuthenticate: buildWwwAuthenticate(this.cfg, {
          error: 'invalid_token',
          errorDescription: description,
        }),
      },
    };
  }

  private denyInvalidAudience(description: string): AuthorizeResult {
    return {
      allowed: false,
      denial: {
        code: 'invalid_audience',
        description,
        status: 401,
        wwwAuthenticate: buildWwwAuthenticate(this.cfg, {
          error: 'invalid_audience',
          errorDescription: description,
        }),
      },
    };
  }

  private denyScopeInsufficient(tool: string, required: string[]): AuthorizeResult {
    const scope = required.join(' ');
    return {
      allowed: false,
      denial: {
        code: 'scope_insufficient',
        description: `tool ${JSON.stringify(tool)} requires one of ${JSON.stringify(required)}`,
        status: 403,
        wwwAuthenticate: buildWwwAuthenticate(this.cfg, {
          error: 'insufficient_scope',
          errorDescription: `tool ${JSON.stringify(tool)} requires ${JSON.stringify(required)}`,
          scope,
        }),
        requiredScopes: [...required],
        tool,
      },
    };
  }

  private denyPolicyUnavailable(description: string): AuthorizeResult {
    return {
      allowed: false,
      denial: {
        code: 'policy_unavailable',
        description,
        status: 503,
        wwwAuthenticate: buildWwwAuthenticate(this.cfg, {
          error: 'policy_unavailable',
          errorDescription: description,
        }),
      },
    };
  }
}
