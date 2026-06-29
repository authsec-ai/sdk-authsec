/**
 * AuthSec client-side errors — typed, actionable replacements for the raw
 * 401/403 a MCP transport hands back.
 *
 * The runtime SDK (server-side) emits structured JSON responses:
 *
 *   403: { error:"insufficient_scope", error_description, tool,
 *          required_scopes, granted_scopes }
 *   401: { error:"invalid_token", error_description, reason }
 *
 * On the agent side, transports like @modelcontextprotocol/sdk often flatten
 * those into a `ToolException`/`Error` whose `.message` is just the
 * `error_description`. This module gives operators a single helper —
 * `parseMcpError(thing)` — that accepts a Response, a parsed body, a raw
 * string, or an Error, and returns one of the typed subclasses below (or
 * `null` if the input doesn't look like an AuthSec denial).
 *
 * Example:
 *
 *     import { parseMcpError, TokenRevokedError } from '@authsec/sdk/client';
 *
 *     try {
 *       await client.callTool('slugify', {});
 *     } catch (e) {
 *       const accessErr = parseMcpError(e);
 *       if (accessErr) {
 *         console.error(accessErr.formatForUser());
 *         if (accessErr instanceof TokenRevokedError) reAuth();
 *         return;
 *       }
 *       throw e;
 *     }
 */

export type AuthSecReason =
  | 'no_token'
  | 'invalid_token'
  | 'token_expired'
  | 'token_revoked'
  | 'client_registration_revoked'
  | 'audience_mismatch';

export interface AuthSecAccessErrorInit {
  description?: string;
  rawBody?: Record<string, unknown>;
  wwwAuthenticate?: string;
}

/** Base class for any AuthSec-side denial surfaced to the agent. */
export class AuthSecAccessError extends Error {
  readonly rawBody?: Record<string, unknown>;
  readonly wwwAuthenticate?: string;

  constructor(init: AuthSecAccessErrorInit = {}) {
    super(init.description ?? new.target.name);
    this.name = new.target.name;
    this.rawBody = init.rawBody;
    this.wwwAuthenticate = init.wwwAuthenticate;
  }

  formatForUser(): string {
    return this.message || this.name;
  }
}

export interface InsufficientScopeInit extends AuthSecAccessErrorInit {
  tool?: string;
  requiredScopes?: string[];
  grantedScopes?: string[];
}

/** The token is valid but lacks a scope the tool requires. */
export class InsufficientScopeError extends AuthSecAccessError {
  readonly tool?: string;
  readonly requiredScopes: string[];
  readonly grantedScopes: string[];

  constructor(init: InsufficientScopeInit = {}) {
    super(init);
    this.tool = init.tool;
    this.requiredScopes = init.requiredScopes ?? [];
    this.grantedScopes = init.grantedScopes ?? [];
  }

  override formatForUser(): string {
    const req = this.requiredScopes.length > 0 ? this.requiredScopes.join(', ') : '(unknown)';
    const tail =
      this.grantedScopes.length > 0
        ? ` Your token has: ${this.grantedScopes.join(', ')}.`
        : ' Your token does not include this scope.';
    const toolPart = this.tool ? ` '${this.tool}'` : '';
    return (
      `Insufficient scope: tool${toolPart} requires ${req}.${tail} ` +
      `Ask an AuthSec admin to grant the missing scope, or use a tool that fits your current scopes.`
    );
  }
}

/** The bearer token was revoked. Agent should clear cached tokens & re-auth. */
export class TokenRevokedError extends AuthSecAccessError {
  override formatForUser(): string {
    return (
      'Your AuthSec access token has been revoked. ' +
      'Clear your cached tokens and re-run the authentication flow.'
    );
  }
}

/** The OAuth client registration itself was revoked. Re-auth won't help. */
export class ClientRegistrationRevokedError extends AuthSecAccessError {
  override formatForUser(): string {
    return (
      'Your OAuth client registration has been revoked by an AuthSec admin. ' +
      'Re-running the auth flow will not help — ask the admin to approve ' +
      'the client in the AuthSec console (Applications → Clients tab).'
    );
  }
}

export interface AuthRequiredInit extends AuthSecAccessErrorInit {
  reason?: AuthSecReason;
}

/** No token / invalid / expired / wrong audience. Agent should re-auth. */
export class AuthRequiredError extends AuthSecAccessError {
  readonly reason: AuthSecReason;

  constructor(init: AuthRequiredInit = {}) {
    super(init);
    this.reason = init.reason ?? 'invalid_token';
  }

  override formatForUser(): string {
    switch (this.reason) {
      case 'no_token':
        return 'Authentication required — no bearer token was sent. Run the AuthSec auth flow.';
      case 'token_expired':
        return 'Your AuthSec token has expired. Refresh or re-authenticate.';
      case 'audience_mismatch':
        return (
          'Your token was issued for a different MCP server. ' +
          'Re-authenticate against the correct resource.'
        );
      default:
        return `Authentication failed (${this.reason}). Re-run the AuthSec auth flow.`;
    }
  }
}

// ─── Parsing ─────────────────────────────────────────────────────────────

interface ResponseLike {
  headers?: Headers | Record<string, string | string[] | undefined>;
  status?: number;
  text?(): Promise<string> | string;
  json?(): Promise<unknown> | unknown;
}

function readHeader(
  headers: Headers | Record<string, string | string[] | undefined> | undefined,
  name: string,
): string | undefined {
  if (!headers) return undefined;
  if (typeof (headers as Headers).get === 'function') {
    const v = (headers as Headers).get(name);
    return v === null ? undefined : v;
  }
  const obj = headers as Record<string, string | string[] | undefined>;
  const v = obj[name] ?? obj[name.toLowerCase()] ?? obj[name.toUpperCase()];
  if (Array.isArray(v)) return v[0];
  return v;
}

function parseWwwAuthenticate(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  const body = header.match(/^bearer\s+/i) ? header.replace(/^bearer\s+/i, '') : header;
  const re = /(\w+)=("([^"]*)"|([^,]+))/g;
  for (let m: RegExpExecArray | null; (m = re.exec(body)) !== null; ) {
    const key = m[1].toLowerCase();
    const value = (m[3] ?? m[4] ?? '').trim();
    out[key] = value;
  }
  return out;
}

function classifyFromText(text: string): typeof AuthSecAccessError | null {
  const t = (text || '').toLowerCase();
  if (
    t.includes('insufficient_scope') ||
    t.includes('insufficient scope') ||
    t.includes('requires scope') ||
    t.includes('required scope') ||
    t.includes('does not include the required scope') ||
    t.includes('lacks required') ||
    t.includes('no scope mapping for tool')
  ) {
    return InsufficientScopeError;
  }
  if (t.includes('client') && t.includes('revoked')) return ClientRegistrationRevokedError;
  if (t.includes('registration') && (t.includes('revoked') || t.includes('pending'))) {
    return ClientRegistrationRevokedError;
  }
  if (t.includes('revoked')) return TokenRevokedError;
  if (t.includes('expired')) return AuthRequiredError;
  if (t.includes('invalid_token') || (t.includes('missing') && t.includes('bearer'))) {
    return AuthRequiredError;
  }
  if (t.includes('audience')) return AuthRequiredError;
  return null;
}

function splitScopes(blob: string): string[] {
  return (blob || '')
    .trim()
    .split(/[\s,;]+/)
    .filter((p) => p && (p.includes(':') || p.includes('_') || p.includes('.')));
}

async function coerce(source: unknown): Promise<{
  body: Record<string, unknown> | undefined;
  text: string | undefined;
  www: string | undefined;
}> {
  if (source == null) return { body: undefined, text: undefined, www: undefined };

  // Response-like
  if (typeof source === 'object' && (source as ResponseLike).headers !== undefined) {
    const r = source as ResponseLike;
    const www = readHeader(r.headers, 'WWW-Authenticate');
    let body: Record<string, unknown> | undefined;
    let text: string | undefined;
    try {
      if (typeof r.json === 'function') {
        const parsed = await r.json();
        if (parsed && typeof parsed === 'object') body = parsed as Record<string, unknown>;
      }
    } catch {
      /* ignore */
    }
    if (!body && typeof r.text === 'function') {
      try {
        text = await r.text();
        if (text) {
          try {
            const parsed = JSON.parse(text);
            if (parsed && typeof parsed === 'object') body = parsed as Record<string, unknown>;
          } catch {
            /* keep as text */
          }
        }
      } catch {
        /* ignore */
      }
    }
    return { body, text, www };
  }

  // Error → use .message
  if (source instanceof Error) {
    return { body: undefined, text: source.message, www: undefined };
  }

  // String
  if (typeof source === 'string') {
    try {
      const parsed = JSON.parse(source);
      if (parsed && typeof parsed === 'object') {
        return { body: parsed as Record<string, unknown>, text: source, www: undefined };
      }
    } catch {
      /* not JSON */
    }
    return { body: undefined, text: source, www: undefined };
  }

  // Already a parsed object
  if (typeof source === 'object') {
    const obj = source as Record<string, unknown>;
    const www =
      (typeof obj.www_authenticate === 'string' && obj.www_authenticate) ||
      (typeof obj['WWW-Authenticate'] === 'string' && (obj['WWW-Authenticate'] as string)) ||
      undefined;
    return { body: obj, text: undefined, www };
  }

  return { body: undefined, text: undefined, www: undefined };
}

/** Parse whatever the MCP transport handed you into a typed
 *  `AuthSecAccessError`, or `null` if it doesn't look like an AuthSec denial. */
export async function parseMcpError(source: unknown): Promise<AuthSecAccessError | null> {
  const { body, text, www } = await coerce(source);
  const wwwFields = parseWwwAuthenticate(www);

  // 1) Structured 403 body from runtime/server.ts
  if (body && body.error === 'insufficient_scope') {
    return new InsufficientScopeError({
      description: (body.error_description as string | undefined) ?? '',
      rawBody: body,
      wwwAuthenticate: www,
      tool: body.tool as string | undefined,
      requiredScopes: (body.required_scopes as string[] | undefined) ?? [],
      grantedScopes: (body.granted_scopes as string[] | undefined) ?? [],
    });
  }

  // 2) Structured 401 body
  if (body && (body.error === 'invalid_token' || body.error === 'missing_token')) {
    const reason = (body.reason as AuthSecReason | undefined) ?? 'invalid_token';
    const description = (body.error_description as string | undefined) ?? '';
    if (reason === 'client_registration_revoked') {
      return new ClientRegistrationRevokedError({ description, rawBody: body, wwwAuthenticate: www });
    }
    if (reason === 'token_revoked') {
      return new TokenRevokedError({ description, rawBody: body, wwwAuthenticate: www });
    }
    return new AuthRequiredError({ description, rawBody: body, wwwAuthenticate: www, reason });
  }

  // 3) Rich WWW-Authenticate header without a structured body
  if (wwwFields.error === 'insufficient_scope') {
    return new InsufficientScopeError({
      description: wwwFields.error_description ?? '',
      wwwAuthenticate: www,
      requiredScopes: (wwwFields.scope ?? '').split(/\s+/).filter(Boolean),
    });
  }

  // 4) Plain-text fallback — string classifier + best-effort field recovery
  const textSource =
    text ??
    (body
      ? String(body.error_description ?? body.error ?? '')
      : '');
  if (!textSource) return null;
  const cls = classifyFromText(textSource);
  if (!cls) return null;

  if (cls === InsufficientScopeError) {
    const toolMatch = /[Tt]ool ['"]?([^'"]+?)['"]?[\s,]+(?:requires|needs)/.exec(textSource);
    const scopeMatch = /(?:requires? scope:?|requires?|needs)[\s:]*([^\.]+)/i.exec(textSource);
    const grantedMatch = /(?:has|granted)[\s:]*([^\.]+)/i.exec(textSource);
    return new InsufficientScopeError({
      description: textSource.trim(),
      tool: toolMatch ? toolMatch[1].trim() : undefined,
      requiredScopes: scopeMatch ? splitScopes(scopeMatch[1]) : [],
      grantedScopes: grantedMatch ? splitScopes(grantedMatch[1]) : [],
    });
  }
  if (cls === AuthRequiredError) {
    return new AuthRequiredError({ description: textSource.trim(), reason: 'invalid_token' });
  }
  return new (cls as new (init: AuthSecAccessErrorInit) => AuthSecAccessError)({
    description: textSource.trim(),
  });
}
