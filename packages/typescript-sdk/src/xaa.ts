/**
 * Cross-App Access (XAA) client helpers — TypeScript port of the Go SDK's
 * xaa.go. Implements the two legs of the IETF
 * draft-ietf-oauth-identity-assertion-authz-grant flow:
 *
 *   1. requestIdJag()       — Token Exchange at the IdP (RFC 8693).
 *   2. exchangeForAccessToken() — jwt-bearer grant at the Resource AS (RFC 7523).
 *   3. crossAppAccess()     — convenience wrapper that chains both.
 *
 * The functions are intentionally thin — no caching, no automatic refresh.
 * Callers manage token lifecycle themselves. The point is to make the wire
 * format hard to get wrong, not to hide it.
 */

// Standard grant + token type URNs.
export const GRANT_TYPE_TOKEN_EXCHANGE =
  'urn:ietf:params:oauth:grant-type:token-exchange';
export const GRANT_TYPE_JWT_BEARER =
  'urn:ietf:params:oauth:grant-type:jwt-bearer';
export const TOKEN_TYPE_ID_JAG =
  'urn:ietf:params:oauth:token-type:id-jag';
export const TOKEN_TYPE_ID_TOKEN =
  'urn:ietf:params:oauth:token-type:id_token';
export const TOKEN_TYPE_REFRESH_TOKEN =
  'urn:ietf:params:oauth:token-type:refresh_token';

/** Input to {@link requestIdJag}. Mirrors the Token Exchange form fields. */
export interface RequestIdJagInput {
  /**
   * IdP AS's `/idjag/token` endpoint. For AuthSec today:
   * `https://<authsec>/authsec/oauth/v2/idjag/token`.
   */
  idpTokenEndpoint: string;

  /** Requesting client's credentials (xaa_client_apps row for AuthSec). */
  clientId: string;
  clientSecret: string;

  /** The user's id_token (or refresh token) — their identity assertion. */
  subjectToken: string;

  /** Defaults to TOKEN_TYPE_ID_TOKEN if omitted. */
  subjectTokenType?: string;

  /**
   * Resource AS issuer URI the ID-JAG will be redeemed at. Required.
   * For AuthSec where IdP and Resource AS share a host, this is the AuthSec
   * issuer (e.g. `https://prod.api.authsec.ai`).
   */
  audience: string;

  /**
   * RFC 8707 target resource URI — the specific MCP the access token will be
   * valid for. Required by AuthSec because XAA policy keys on
   * resource_server_id.
   */
  resource: string;

  /** Desired scope set. Empty = whatever the IdP's policy allows. */
  scopes?: string[];

  /**
   * Optional fetch implementation override. Defaults to globalThis.fetch.
   * Useful for injecting timeouts / retries / Node 18- shims.
   */
  fetch?: typeof fetch;
}

/** IdP response per RFC 8693 §2.2.1. */
export interface IdJagResponse {
  access_token: string;
  issued_token_type: string;
  /** "N_A" for ID-JAGs per the spec — they're not bearer access tokens. */
  token_type: string;
  expires_in: number;
  scope?: string;
}

/**
 * Typed OAuth error per RFC 6749 §5.2. Use `instanceof OAuthError` (or
 * `err.code === 'invalid_grant'` etc.) to branch on the error code.
 */
export class OAuthError extends Error {
  readonly httpStatus: number;
  readonly code: string;
  readonly description?: string;
  readonly uri?: string;

  constructor(httpStatus: number, body: unknown) {
    const obj = (body && typeof body === 'object' ? body : {}) as Record<string, unknown>;
    const code = typeof obj.error === 'string' ? obj.error : `http_${httpStatus}`;
    const description = typeof obj.error_description === 'string' ? obj.error_description : undefined;
    super(description ? `oauth ${code}: ${description}` : `oauth ${code}`);
    this.name = 'OAuthError';
    this.httpStatus = httpStatus;
    this.code = code;
    this.description = description;
    this.uri = typeof obj.error_uri === 'string' ? obj.error_uri : undefined;
  }
}

/**
 * Exchange a user's identity assertion at the IdP for an ID-JAG.
 *
 * @example
 * ```ts
 * const idjag = await requestIdJag({
 *   idpTokenEndpoint: 'https://prod.api.authsec.ai/authsec/oauth/v2/idjag/token',
 *   clientId: 'my-agent',
 *   clientSecret: process.env.AGENT_SECRET!,
 *   subjectToken: userIdToken,
 *   audience: 'https://prod.api.authsec.ai',
 *   resource: 'https://my-mcp.example.com/mcp',
 *   scopes: ['orders:read'],
 * });
 * ```
 */
export async function requestIdJag(
  input: RequestIdJagInput,
): Promise<IdJagResponse> {
  validateRequestIdJagInput(input);
  const body = new URLSearchParams();
  body.set('grant_type', GRANT_TYPE_TOKEN_EXCHANGE);
  body.set('requested_token_type', TOKEN_TYPE_ID_JAG);
  body.set('subject_token', input.subjectToken);
  body.set('subject_token_type', input.subjectTokenType ?? TOKEN_TYPE_ID_TOKEN);
  body.set('audience', input.audience);
  body.set('resource', input.resource);
  if (input.scopes && input.scopes.length > 0) {
    body.set('scope', input.scopes.join(' '));
  }

  const f = input.fetch ?? fetch;
  const resp = await f(input.idpTokenEndpoint, {
    method: 'POST',
    body,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
      'Authorization':
        'Basic ' + btoa(`${input.clientId}:${input.clientSecret}`),
    },
  });
  const text = await resp.text();
  if (!resp.ok) {
    throw new OAuthError(resp.status, safeJSON(text));
  }
  const parsed = safeJSON(text) as IdJagResponse;
  if (!parsed?.access_token) {
    throw new Error('idjag exchange: empty access_token in response');
  }
  return parsed;
}

/** Input to {@link exchangeForAccessToken}. */
export interface ExchangeForAccessTokenInput {
  /**
   * Resource AS's `/token` endpoint. For AuthSec the same host as the IdP:
   * `https://<authsec>/authsec/oauth/v2/token`.
   */
  resourceAsTokenEndpoint: string;

  /** The ID-JAG returned from {@link requestIdJag}. */
  idJag: string;

  /** Optional narrowing of the ID-JAG's scope set. */
  scopes?: string[];

  /**
   * Optional client auth at the Resource AS. The ID-JAG already carries a
   * client_id claim, so most Resource AS deployments don't require this.
   */
  clientId?: string;
  clientSecret?: string;

  fetch?: typeof fetch;
}

/** Standard OAuth 2.0 access token response (RFC 6749 §5.1). */
export interface AccessTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
  refresh_token?: string;
}

/** Redeem an ID-JAG at the Resource AS for a usable access token. */
export async function exchangeForAccessToken(
  input: ExchangeForAccessTokenInput,
): Promise<AccessTokenResponse> {
  if (!input.resourceAsTokenEndpoint?.trim()) {
    throw new Error('resourceAsTokenEndpoint required');
  }
  if (!input.idJag?.trim()) {
    throw new Error('idJag required');
  }

  const body = new URLSearchParams();
  body.set('grant_type', GRANT_TYPE_JWT_BEARER);
  body.set('assertion', input.idJag);
  if (input.scopes && input.scopes.length > 0) {
    body.set('scope', input.scopes.join(' '));
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json',
  };
  if (input.clientId) {
    headers['Authorization'] =
      'Basic ' + btoa(`${input.clientId}:${input.clientSecret ?? ''}`);
  }

  const f = input.fetch ?? fetch;
  const resp = await f(input.resourceAsTokenEndpoint, {
    method: 'POST',
    body,
    headers,
  });
  const text = await resp.text();
  if (!resp.ok) {
    throw new OAuthError(resp.status, safeJSON(text));
  }
  const parsed = safeJSON(text) as AccessTokenResponse;
  if (!parsed?.access_token) {
    throw new Error('jwt-bearer exchange: empty access_token in response');
  }
  return parsed;
}

/** Input to {@link crossAppAccess} — both endpoints + everything in one call. */
export interface CrossAppAccessInput {
  idpTokenEndpoint: string;
  resourceAsTokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  subjectToken: string;
  subjectTokenType?: string;
  audience: string;
  resource: string;
  scopes?: string[];
  fetch?: typeof fetch;
}

/**
 * Run the full two-leg XAA flow: IdP → ID-JAG → Resource AS → access token.
 * Use the granular {@link requestIdJag} / {@link exchangeForAccessToken} when
 * you want to inspect or cache the ID-JAG between calls.
 */
export async function crossAppAccess(
  input: CrossAppAccessInput,
): Promise<AccessTokenResponse> {
  const idjag = await requestIdJag({
    idpTokenEndpoint: input.idpTokenEndpoint,
    clientId: input.clientId,
    clientSecret: input.clientSecret,
    subjectToken: input.subjectToken,
    subjectTokenType: input.subjectTokenType,
    audience: input.audience,
    resource: input.resource,
    scopes: input.scopes,
    fetch: input.fetch,
  });
  return exchangeForAccessToken({
    resourceAsTokenEndpoint: input.resourceAsTokenEndpoint,
    idJag: idjag.access_token,
    scopes: input.scopes,
    fetch: input.fetch,
  });
}

// ── helpers ─────────────────────────────────────────────────────────────────

function validateRequestIdJagInput(in_: RequestIdJagInput): void {
  if (!in_.idpTokenEndpoint?.trim()) throw new Error('idpTokenEndpoint required');
  if (!in_.clientId?.trim()) throw new Error('clientId required');
  if (!in_.subjectToken?.trim()) throw new Error('subjectToken required');
  if (!in_.audience?.trim()) throw new Error('audience required');
  if (!in_.resource?.trim()) throw new Error('resource required');
}

function safeJSON(text: string): unknown {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
