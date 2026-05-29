/**
 * HybridValidator — JWT verification + RFC 7662 introspection.
 *
 * TypeScript parity port of python/runtime/validator.py.
 *
 * Supports four ValidationMode shapes; ``jwt_and_introspect`` is the
 * production-recommended setting. JWT verification uses cached JWKS keys via
 * the ``jose`` package; introspection uses HTTP Basic auth with the
 * configured introspectionClientId / introspectionClientSecret.
 */

import type { JWTPayload, JWTVerifyGetKey } from 'jose' with { 'resolution-mode': 'import' };

import {
  effectiveValidationMode,
  normalizeConfig,
  validateConfig,
  type Config,
  type ValidationMode,
} from './config.js';
import { newPrincipal, type Principal } from './principal.js';

// `jose` is ESM-only. We import it lazily so this module can be consumed
// from both CommonJS and ESM TS configurations without a top-level await.
type JoseModule = typeof import('jose', { with: { 'resolution-mode': 'import' } });
let _josePromise: Promise<JoseModule> | null = null;
async function loadJose(): Promise<JoseModule> {
  if (_josePromise === null) {
    _josePromise = import('jose') as Promise<JoseModule>;
  }
  return _josePromise;
}

/** Denial-taxonomy code attached to ValidationError. */
export type ValidationErrorCode =
  | 'invalid_token'
  | 'invalid_audience'
  | 'token_inactive';

/** Error raised when the token fails validation or introspection. */
export class ValidationError extends Error {
  readonly code: ValidationErrorCode;
  constructor(code: ValidationErrorCode, message: string) {
    super(message);
    this.name = 'ValidationError';
    this.code = code;
  }
}

/**
 * Validates bearer tokens via JWT + introspection.
 *
 * Construct with ``newValidator()`` which validates the config first, or
 * directly via ``new HybridValidator(cfg)``.
 */
export class HybridValidator {
  readonly cfg: Config;
  private readonly mode: ValidationMode;
  private jwks: JWTVerifyGetKey | null = null;
  private jwksInit: Promise<void> | null = null;

  constructor(cfg: Config) {
    this.cfg = normalizeConfig(cfg);
    this.mode = effectiveValidationMode(this.cfg);
  }

  private async ensureJwks(): Promise<JWTVerifyGetKey | null> {
    if (!this.cfg.jwksUrl.trim()) return null;
    if (this.jwks !== null) return this.jwks;
    if (this.jwksInit === null) {
      this.jwksInit = (async () => {
        const jose = await loadJose();
        this.jwks = jose.createRemoteJWKSet(new URL(this.cfg.jwksUrl), {
          cacheMaxAge: 3600 * 1000,
          cooldownDuration: 30 * 1000,
        });
      })();
    }
    await this.jwksInit;
    return this.jwks;
  }

  /**
   * Validate ``token`` and return a populated Principal.
   *
   * Throws ``ValidationError`` with ``.code`` ∈ ``invalid_token`` /
   * ``token_inactive`` on failure.
   */
  async validate(token: string): Promise<Principal> {
    switch (this.mode) {
      case 'jwt_only':
        return await this.validateJwt(token);
      case 'introspection_only': {
        const p = await this.introspect(token);
        return this.checkActive(p);
      }
      case 'jwt_and_introspect':
        return await this.validateJwtAndIntrospect(token);
      case 'jwt_or_introspect':
        return await this.validateJwtOrIntrospect(token);
      default:
        throw new ValidationError('invalid_token', `unsupported validation mode: ${this.mode}`);
    }
  }

  // ── Mode implementations ──────────────────────────────────────────

  private async validateJwtAndIntrospect(token: string): Promise<Principal> {
    const looksLikeJwt = token.split('.').length === 3;
    let jwtPrincipal: Principal | null = null;
    if (looksLikeJwt) {
      jwtPrincipal = await this.validateJwt(token);
    }
    const introspected = await this.introspect(token);
    const active = this.checkActive(introspected);
    if (jwtPrincipal === null) return active;
    return this.mergePrincipals(jwtPrincipal, active);
  }

  private async validateJwtOrIntrospect(token: string): Promise<Principal> {
    let jwtErr: unknown;
    try {
      return await this.validateJwt(token);
    } catch (e) {
      jwtErr = e;
    }
    try {
      const p = await this.introspect(token);
      return this.checkActive(p);
    } catch (introspectErr) {
      const jm = jwtErr instanceof Error ? jwtErr.message : String(jwtErr);
      const im = introspectErr instanceof Error ? introspectErr.message : String(introspectErr);
      throw new ValidationError(
        'invalid_token',
        `JWT verify failed (${jm}); introspection failed (${im})`,
      );
    }
  }

  // ── JWT path ───────────────────────────────────────────────────────

  private async validateJwt(token: string): Promise<Principal> {
    const jwks = await this.ensureJwks();
    if (jwks === null) {
      throw new ValidationError(
        'invalid_token',
        'JWT verification requested but no jwksUrl configured',
      );
    }
    const jose = await loadJose();
    let payload: JWTPayload;
    try {
      const result = await jose.jwtVerify(token, jwks, {
        // We deliberately verify aud in the higher-level request-handling
        // layer (Runtime.validateToken) against resourceUri, so we can
        // produce richer error messages.
        issuer: this.cfg.issuer || undefined,
        algorithms: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384'],
      });
      payload = result.payload;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      // jose throws JWTExpired with code 'ERR_JWT_EXPIRED'
      if (e && typeof e === 'object' && 'code' in e && (e as { code?: string }).code === 'ERR_JWT_EXPIRED') {
        throw new ValidationError('invalid_token', 'token expired');
      }
      throw new ValidationError('invalid_token', `invalid JWT: ${msg}`);
    }
    return newPrincipal({
      subject: asString(payload.sub),
      issuer: asString(payload.iss),
      audience: audienceList(payload.aud),
      scopes:
        scopeList((payload as Record<string, unknown>).scope) ||
        scopeList((payload as Record<string, unknown>).scopes),
      claims: payload as Record<string, unknown>,
      active: true,
    });
  }

  // ── Introspection path ────────────────────────────────────────────

  private async introspect(token: string): Promise<Principal> {
    if (!this.cfg.introspectionUrl.trim()) {
      throw new ValidationError(
        'invalid_token',
        'introspection requested but no introspectionUrl configured',
      );
    }
    const credentials = Buffer.from(
      `${this.cfg.introspectionClientId}:${this.cfg.introspectionClientSecret}`,
    ).toString('base64');

    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      Math.max(1, this.cfg.requestTimeoutSeconds) * 1000,
    );
    let resp: Response;
    try {
      resp = await fetch(this.cfg.introspectionUrl, {
        method: 'POST',
        headers: {
          Authorization: `Basic ${credentials}`,
          Accept: 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ token }).toString(),
        signal: controller.signal,
      });
    } catch (e) {
      throw new ValidationError(
        'invalid_token',
        `introspection request failed: ${e instanceof Error ? e.message : String(e)}`,
      );
    } finally {
      clearTimeout(timer);
    }
    if (resp.status !== 200) {
      const body = await resp.text().catch(() => '');
      throw new ValidationError(
        'invalid_token',
        `introspection returned HTTP ${resp.status}: ${body.slice(0, 200)}`,
      );
    }
    let payload: Record<string, unknown>;
    try {
      payload = (await resp.json()) as Record<string, unknown>;
    } catch (e) {
      throw new ValidationError(
        'invalid_token',
        `introspection returned non-JSON body: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
    return newPrincipal({
      subject: asString(payload.sub ?? payload.subject),
      issuer: asString(payload.iss),
      audience: audienceList(payload.aud ?? payload.resource),
      scopes: scopeList(payload.scope) || scopeList(payload.scopes),
      claims: { ...payload },
      active: Boolean(payload.active),
    });
  }

  // ── Helpers ────────────────────────────────────────────────────────

  private checkActive(principal: Principal): Principal {
    if (!principal.active) {
      throw new ValidationError(
        'token_inactive',
        'introspection returned active=false — token revoked, suspended, expired, or principal membership inactive',
      );
    }
    return principal;
  }

  private mergePrincipals(jwtP: Principal, introspected: Principal): Principal {
    return {
      subject: introspected.subject || jwtP.subject,
      issuer: introspected.issuer || jwtP.issuer,
      audience: introspected.audience.length > 0 ? introspected.audience : jwtP.audience,
      scopes: introspected.scopes.length > 0 ? introspected.scopes : jwtP.scopes,
      claims: { ...jwtP.claims, ...introspected.claims },
      active: introspected.active,
    };
  }
}

// ── Module-level helpers ─────────────────────────────────────────────

function asString(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

function audienceList(v: unknown): string[] {
  if (v === null || v === undefined) return [];
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) return v.filter(Boolean).map(String);
  return [String(v)];
}

function scopeList(v: unknown): string[] {
  if (v === null || v === undefined) return [];
  if (typeof v === 'string') return v.split(/\s+/).filter(Boolean);
  if (Array.isArray(v)) return v.filter(Boolean).map(String);
  return [];
}

/** Construct a HybridValidator after validating the config. */
export function newValidator(cfg: Config): HybridValidator {
  validateConfig(cfg);
  return new HybridValidator(cfg);
}
