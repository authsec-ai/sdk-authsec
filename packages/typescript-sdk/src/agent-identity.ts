/**
 * AgentIdentity — flow-selection + token acquisition for agent-to-MCP-server access.
 *
 * Implements §10 of the Agent Identity spec:
 *   1. Discover Protected Resource Metadata (RFC 9728)
 *   2. Discover AS metadata (RFC 8414)
 *   3. Decide direct vs XAA (based on preferredMode + requester-bootstrap)
 *   4. Run the chosen path and return a short-lived access token, or throw
 *      a typed PendingApproval when access is still being reviewed.
 *
 * Usage (service-to-service M2M, API credential):
 *
 *   const identity = new AgentIdentity({
 *     issuer: 'https://auth.example.com',
 *     clientId: 'my-service-client-id',
 *     clientSecret: 'sk-...',
 *   });
 *   const token = await identity.accessFor('https://payments.example.com/mcp');
 *   // → pass token as Bearer in every MCP tool call.
 *
 * Usage (XAA cross-app, user-delegated):
 *
 *   const identity = new AgentIdentity({
 *     issuer: 'https://auth.example.com',
 *     clientId: 'my-agent-client-id',
 *     idpIssuer: 'https://idp.enterprise.com',
 *     preferredMode: 'auto',
 *   });
 *   const token = await identity.accessFor('https://payments.example.com/mcp', {
 *     userSession: { subject_token: '...' },
 *     requestedScopes: ['tickets.read'],
 *   });
 */

// ── Error taxonomy (§9) ────────────────────────────────────────────────────────

export class AuthSecIdentityError extends Error {
  readonly code: string;
  readonly httpStatus?: number;

  constructor(code: string, message: string, httpStatus?: number) {
    super(message);
    this.name = 'AuthSecIdentityError';
    this.code = code;
    this.httpStatus = httpStatus;
  }
}

/** Access was requested and is awaiting admin approval. Poll statusUrl. */
export class PendingApprovalError extends AuthSecIdentityError {
  readonly requestId: string;
  readonly statusUrl: string;

  constructor(requestId: string, statusUrl: string) {
    super('access_pending', 'Access requested — waiting for an admin.', 202);
    this.name = 'PendingApprovalError';
    this.requestId = requestId;
    this.statusUrl = statusUrl;
  }
}

/** An admin declined the access request. */
export class ApprovalDeniedError extends AuthSecIdentityError {
  constructor() {
    super('approval_denied', 'An admin declined this access.', 403);
    this.name = 'ApprovalDeniedError';
  }
}

/** The agent connection was revoked. */
export class ConnectionRevokedError extends AuthSecIdentityError {
  constructor() {
    super('connection_revoked', 'Access was revoked.', 401);
    this.name = 'ConnectionRevokedError';
  }
}

/** The issuer is not trusted by the AuthSec instance. */
export class TrustedIssuerMissingError extends AuthSecIdentityError {
  constructor() {
    super('trusted_issuer_missing', "This issuer isn't trusted here.", 403);
    this.name = 'TrustedIssuerMissingError';
  }
}

/** Subject mapping from external identity to local user failed. */
export class SubjectMappingFailedError extends AuthSecIdentityError {
  constructor() {
    super('subject_mapping_failed', "Couldn't map your identity.", 403);
    this.name = 'SubjectMappingFailedError';
  }
}

/** The MCP server URI is not registered. */
export class ResourceNotRegisteredError extends AuthSecIdentityError {
  constructor(resource: string) {
    super('resource_not_registered', `Unknown MCP server: ${resource}`, 404);
    this.name = 'ResourceNotRegisteredError';
  }
}

/** The client credential is invalid. */
export class CredentialInvalidError extends AuthSecIdentityError {
  constructor(detail?: string) {
    super('credential_invalid', detail ?? 'Invalid client credential.', 401);
    this.name = 'CredentialInvalidError';
  }
}

/** The workload has not yet attested via SPIFFE. */
export class WorkloadNotAttestedError extends AuthSecIdentityError {
  constructor() {
    super('workload_not_attested', "Workload hasn't attested yet.", 403);
    this.name = 'WorkloadNotAttestedError';
  }
}

// ── Types ─────────────────────────────────────────────────────────────────────

export type PreferredMode = 'auto' | 'direct-only' | 'xaa-allowed';

export interface AgentIdentityConfig {
  /** AuthSec AS issuer URL (e.g. https://auth.example.com) */
  issuer: string;
  /** OAuth client_id for this agent */
  clientId: string;
  /** Client secret (client_secret_basic). Mutually exclusive with privateKey. */
  clientSecret?: string;
  /** JWKS private key for private_key_jwt. Mutually exclusive with clientSecret. */
  privateKey?: { key: unknown; kid: string };
  /** Enterprise IdP issuer for XAA subject tokens. Required for XAA paths. */
  idpIssuer?: string;
  /** Flow preference. Default: 'auto' */
  preferredMode?: PreferredMode;
  /** Override the token endpoint (discovered by default). */
  tokenEndpoint?: string;
  /** HTTP fetch implementation (default: globalThis.fetch). */
  fetch?: typeof fetch;
}

export interface AccessForOptions {
  /** OIDC subject token from the enterprise IdP (required for XAA user-delegated path). */
  userSession?: { subject_token: string; subject_token_type?: string };
  /** Scopes to request. Defaults to the role scopes negotiated at bootstrap. */
  requestedScopes?: string[];
  /** Additional parameters forwarded to the token endpoint. */
  extra?: Record<string, string>;
}

// ── PRM / AS metadata shapes (RFC 9728 / RFC 8414) ───────────────────────────

interface PRMResponse {
  resource: string;
  authorization_servers: string[];
  bearer_methods_supported?: string[];
  scopes_supported?: string[];
  resource_signing_alg_values_supported?: string[];
}

interface ASMetadata {
  issuer: string;
  token_endpoint: string;
  grant_types_supported?: string[];
  identity_chaining_requested_token_types_supported?: string[];
  token_exchange_supported?: boolean;
}

interface BootstrapTarget {
  resource_server_id: string;
  resource: string;
  workspace_id: string;
  relationship: 'same_workspace' | 'cross_workspace';
  recommended_flow: 'direct' | 'id_jag';
  registration_status: 'approved' | 'pending_approval' | 'revoked' | 'none';
  access_status: 'granted' | 'pending' | 'denied' | 'none';
  scopes_supported?: string[];
  prm?: Record<string, unknown>;
}

interface BootstrapPending {
  request_id: string;
  resource_server_id: string;
  status: string;
  expires_at?: string;
}

interface BootstrapResponse {
  client: { client_id: string; client_kind: string; home_workspace_id: string };
  issuer: string;
  as_metadata_url: string;
  metadata_version: string;
  targets: BootstrapTarget[];
  pending: BootstrapPending[];
}

// ── Main class ────────────────────────────────────────────────────────────────

export class AgentIdentity {
  private readonly cfg: Required<Pick<AgentIdentityConfig, 'issuer' | 'clientId' | 'preferredMode'>> & AgentIdentityConfig;
  private readonly _fetch: typeof fetch;

  // In-memory token cache: resource → { token, expiresAt }
  private readonly _cache = new Map<string, { token: string; expiresAt: number }>();

  constructor(config: AgentIdentityConfig) {
    if (!config.issuer) throw new Error('AgentIdentity: issuer is required');
    if (!config.clientId) throw new Error('AgentIdentity: clientId is required');
    this.cfg = { preferredMode: 'auto', ...config };
    this._fetch = config.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /**
   * Obtain a short-lived access token for `resource`.
   *
   * Returns the token string on success.
   * Throws PendingApprovalError when access is requested but not yet approved.
   * Throws other AuthSecIdentityError subclasses for terminal failures.
   */
  async accessFor(resource: string, options: AccessForOptions = {}): Promise<string> {
    const cached = this._cache.get(resource);
    if (cached && cached.expiresAt > Date.now() + 30_000) {
      return cached.token;
    }

    const token = await this._acquireToken(resource, options);
    return token;
  }

  /** Clear cached tokens (e.g. after receiving a 401 to force re-mint). */
  clearCache(resource?: string): void {
    if (resource) {
      this._cache.delete(resource);
    } else {
      this._cache.clear();
    }
  }

  // ── Internal flow selection (§10) ──────────────────────────────────────────

  private async _acquireToken(resource: string, options: AccessForOptions): Promise<string> {
    const prm = await this._discoverPRM(resource);
    const asUrl = prm.authorization_servers?.[0];
    if (!asUrl) throw new ResourceNotRegisteredError(resource);

    const as = await this._discoverAS(asUrl);
    const tokenEndpoint = this.cfg.tokenEndpoint ?? as.token_endpoint;

    const mode = this.cfg.preferredMode;

    // direct-only: skip bootstrap entirely
    if (mode === 'direct-only') {
      return this._direct(resource, tokenEndpoint, options);
    }

    // No XAA support on AS, or no IdP configured, or no user session → direct.
    // XAA is supported when grant_types_supported includes BOTH token-exchange
    // (to mint ID-JAG) AND jwt-bearer (to redeem it), AND the AS advertises the
    // ID-JAG token type — without it the token-exchange step can't produce an
    // ID-JAG, so XAA would fail later.
    const grantTypes = as.grant_types_supported ?? [];
    const idJagTokenTypes = as.identity_chaining_requested_token_types_supported ?? [];
    const asSupportsXaa =
      grantTypes.includes('urn:ietf:params:oauth:grant-type:token-exchange') &&
      grantTypes.includes('urn:ietf:params:oauth:grant-type:jwt-bearer') &&
      idJagTokenTypes.includes('urn:ietf:params:oauth:token-type:id-jag');
    if (!asSupportsXaa || !this.cfg.idpIssuer || !options.userSession) {
      return this._direct(resource, tokenEndpoint, options);
    }

    // requester-bootstrap to decide path
    let bootstrap: BootstrapResponse;
    try {
      bootstrap = await this._requesterBootstrap(resource, tokenEndpoint, options);
    } catch (err) {
      return this._handleBootstrapUnavailable(resource, prm, as, tokenEndpoint, options, err);
    }

    // Find the target matching this resource. No match → safe default (direct).
    const target = (bootstrap.targets ?? []).find(t => t.resource === resource);
    if (!target) {
      return this._direct(resource, tokenEndpoint, options);
    }

    const base = tokenEndpoint.replace(/\/token$/, '');

    // A pending access request for this target → surface PendingApprovalError.
    const pending = (bootstrap.pending ?? []).find(
      p => p.resource_server_id === target.resource_server_id && p.status === 'pending',
    );
    if (pending) {
      throw new PendingApprovalError(pending.request_id, `${base}/access-requests/${pending.request_id}`);
    }
    if (target.access_status === 'denied') {
      throw new ApprovalDeniedError();
    }

    // A user session means the agent is acting ON BEHALF OF a user — that is
    // delegation, so the conformant choice is the XAA / ID-JAG path regardless
    // of the workspace relationship. The XAA boundary is client ≠ resource
    // server, NOT workspace equality (the old same-domain gate was removed), so
    // a same-workspace target is still valid XAA. This holds for both 'auto' and
    // 'xaa-allowed'; 'direct-only' already returned above. Only fall through to
    // the direct (M2M client_credentials) path when there is no user session to
    // delegate — i.e. the agent is acting as itself.
    if (options.userSession?.subject_token) {
      return this._xaa(resource, as, tokenEndpoint, options);
    }

    // Flow decision from the matched target.
    if (target.recommended_flow === 'id_jag') {
      return this._xaa(resource, as, tokenEndpoint, options);
    }
    if (target.recommended_flow === 'direct') {
      return this._direct(resource, tokenEndpoint, options);
    }
    if (target.relationship === 'cross_workspace') {
      return this._xaa(resource, as, tokenEndpoint, options);
    }
    if (target.relationship === 'same_workspace') {
      return this._direct(resource, tokenEndpoint, options);
    }

    return this._direct(resource, tokenEndpoint, options);
  }

  // ── Direct path (M2M client_credentials or plain user token) ──────────────

  private async _direct(resource: string, tokenEndpoint: string, options: AccessForOptions): Promise<string> {
    const body: Record<string, string> = {
      grant_type: 'client_credentials',
      resource,
    };
    if (options.requestedScopes?.length) {
      body['scope'] = options.requestedScopes.join(' ');
    }
    Object.assign(body, options.extra ?? {});

    const resp = await this._tokenRequest(tokenEndpoint, body);
    const token = resp['access_token'] as string;
    const expiresIn = (resp['expires_in'] as number) ?? 3600;
    this._cache.set(resource, { token, expiresAt: Date.now() + expiresIn * 1000 });
    return token;
  }

  // ── XAA path (subject token → token-exchange → ID-JAG → jwt-bearer) ───────

  private async _xaa(
    resource: string,
    as: ASMetadata,
    tokenEndpoint: string,
    options: AccessForOptions,
  ): Promise<string> {
    if (!options.userSession?.subject_token) {
      throw new AuthSecIdentityError(
        'xaa_requires_user_session',
        'XAA path requires a user session (subject_token).',
      );
    }

    // Step 6c: token-exchange → ID-JAG
    const idJag = await this._tokenExchange(tokenEndpoint, options.userSession.subject_token, resource, options);

    // Step 6d: jwt-bearer redemption → access token
    const body: Record<string, string> = {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: idJag,
      resource,
    };
    if (options.requestedScopes?.length) {
      body['scope'] = options.requestedScopes.join(' ');
    }
    Object.assign(body, options.extra ?? {});

    let respBody: Record<string, unknown>;
    try {
      respBody = await this._tokenRequest(tokenEndpoint, body);
    } catch (err) {
      if (err instanceof AuthSecIdentityError) throw err;
      throw err;
    }

    // access_pending (202 surfaced as a 200 with pending status, or 403 with code)
    if (respBody['error'] === 'access_pending' || respBody['status'] === 'pending') {
      const reqId = (respBody['request_id'] as string) ?? '';
      const statusUrl =
        (respBody['status_url'] as string) ??
        `${tokenEndpoint.replace(/\/token$/, '')}/access-requests/${reqId}`;
      throw new PendingApprovalError(reqId, statusUrl);
    }

    const token = respBody['access_token'] as string;
    const expiresIn = (respBody['expires_in'] as number) ?? 3600;
    this._cache.set(resource, { token, expiresAt: Date.now() + expiresIn * 1000 });
    return token;
  }

  // ── token-exchange → ID-JAG ────────────────────────────────────────────────

  private async _tokenExchange(
    tokenEndpoint: string,
    subjectToken: string,
    resource: string,
    options: AccessForOptions,
  ): Promise<string> {
    const body: Record<string, string> = {
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: subjectToken,
      subject_token_type:
        options.userSession?.subject_token_type ??
        'urn:ietf:params:oauth:token-type:id_token',
      requested_token_type: 'urn:ietf:params:oauth:token-type:id-jag',
      audience: this.cfg.issuer,
      resource,
    };
    if (options.requestedScopes?.length) {
      body['scope'] = options.requestedScopes.join(' ');
    }

    const resp = await this._tokenRequest(tokenEndpoint, body);
    const idJag = resp['access_token'] as string;
    if (!idJag) {
      throw new AuthSecIdentityError('token_exchange_failed', 'Token exchange did not return an ID-JAG.');
    }
    return idJag;
  }

  // ── requester-bootstrap ────────────────────────────────────────────────────

  private async _requesterBootstrap(
    resource: string,
    tokenEndpoint: string,
    options: AccessForOptions,
  ): Promise<BootstrapResponse> {
    // Bootstrap endpoint is on the same base as the token endpoint
    const base = tokenEndpoint.replace(/\/token$/, '');
    const bootstrapUrl = `${base}/requester-bootstrap`;

    const body: Record<string, string> = {
      client_id: this.cfg.clientId,
      resource,
    };
    if (options.requestedScopes?.length) {
      body['scope'] = options.requestedScopes.join(' ');
    }
    const authBodyParams = await this._authBodyParams(tokenEndpoint);
    const fullBody = { ...body, ...authBodyParams };

    const resp = await this._fetch(bootstrapUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...this._authHeaders(),
      },
      body: new URLSearchParams(fullBody).toString(),
    });

    if (!resp.ok) {
      const json = (await resp.json().catch(() => ({}))) as Record<string, unknown>;
      this._throwFromErrorBody(json, resp.status);
    }
    return resp.json() as Promise<BootstrapResponse>;
  }

  // ── handleBootstrapUnavailable (§10) ──────────────────────────────────────

  private _handleBootstrapUnavailable(
    resource: string,
    prm: PRMResponse,
    as: ASMetadata,
    tokenEndpoint: string,
    options: AccessForOptions,
    originalError: unknown,
  ): Promise<string> {
    const mode = this.cfg.preferredMode;

    if (
      originalError instanceof CredentialInvalidError ||
      (originalError instanceof AuthSecIdentityError &&
        ['invalid_client', 'credential_invalid'].includes(originalError.code))
    ) {
      throw originalError;
    }

    if (mode === 'xaa-allowed') {
      // If relationship is unknown and preferredMode=xaa-allowed, fail with typed error
      const reason =
        originalError instanceof Error && originalError.message
          ? ` Original error: ${originalError.message}`
          : '';
      throw new AuthSecIdentityError(
        'bootstrap_unavailable',
        `requester-bootstrap is unavailable and preferredMode=xaa-allowed prevents silent fallback.${reason}`,
        originalError instanceof AuthSecIdentityError ? originalError.httpStatus : 503,
      );
    }

    // mode=auto: fall back to direct only if AS metadata proves direct is supported
    const directSupported =
      prm.bearer_methods_supported?.includes('header') !== false &&
      (as.grant_types_supported?.includes('client_credentials') ?? true);

    if (!directSupported) {
      throw new AuthSecIdentityError(
        'bootstrap_unavailable',
        'requester-bootstrap is unavailable and direct auth is not proven supported.',
        503,
      );
    }

    return this._direct(resource, tokenEndpoint, options);
  }

  // ── PRM discovery (RFC 9728) ───────────────────────────────────────────────

  private async _discoverPRM(resource: string): Promise<PRMResponse> {
    const url = new URL(resource);
    const normalizedPath = url.pathname.replace(/\/+$/, '');
    const candidates = [
      ...(normalizedPath && normalizedPath !== '/'
        ? [`${url.origin}/.well-known/oauth-protected-resource${normalizedPath}`]
        : []),
      `${url.origin}/.well-known/oauth-protected-resource`,
    ];

    for (const prmUrl of [...new Set(candidates)]) {
      const resp = await this._fetch(prmUrl, { headers: { Accept: 'application/json' } });
      if (resp.ok) {
        return resp.json() as Promise<PRMResponse>;
      }
    }

    throw new ResourceNotRegisteredError(resource);
  }

  // ── AS metadata discovery (RFC 8414) ──────────────────────────────────────

  private async _discoverAS(asUrl: string): Promise<ASMetadata> {
    const metaUrl = `${asUrl.replace(/\/$/, '')}/.well-known/oauth-authorization-server`;
    const resp = await this._fetch(metaUrl, { headers: { Accept: 'application/json' } });
    if (!resp.ok) {
      throw new AuthSecIdentityError(
        'as_discovery_failed',
        `AS metadata discovery failed for ${asUrl} (${resp.status})`,
        resp.status,
      );
    }
    return resp.json() as Promise<ASMetadata>;
  }

  // ── Token request helper ───────────────────────────────────────────────────

  private async _authBodyParams(tokenEndpoint: string): Promise<Record<string, string>> {
    if (!this.cfg.privateKey) return {};
    const { key, kid } = this.cfg.privateKey;

    const now = Math.floor(Date.now() / 1000);
    const jti = Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    const header = { alg: 'RS256', typ: 'JWT', kid };
    const payload = {
      iss: this.cfg.clientId,
      sub: this.cfg.clientId,
      aud: tokenEndpoint,
      jti,
      iat: now,
      exp: now + 300,
    };

    const encode = (obj: unknown) =>
      btoa(JSON.stringify(obj))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');

    const signingInput = `${encode(header)}.${encode(payload)}`;
    const data = new TextEncoder().encode(signingInput);
    const sig = await (globalThis.crypto as { subtle: { sign: (...args: unknown[]) => Promise<ArrayBuffer> } }).subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      key,
      data,
    );

    const b64Sig = btoa(String.fromCharCode(...new Uint8Array(sig)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const assertion = `${signingInput}.${b64Sig}`;

    return {
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion,
    };
  }

  private async _tokenRequest(
    tokenEndpoint: string,
    body: Record<string, string>,
  ): Promise<Record<string, unknown>> {
    const authBodyParams = await this._authBodyParams(tokenEndpoint);
    const fullBody = { ...body, ...authBodyParams };
    const resp = await this._fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...this._authHeaders(),
      },
      body: new URLSearchParams(fullBody).toString(),
    });

    const json = (await resp.json().catch(() => ({}))) as Record<string, unknown>;

    if (!resp.ok) {
      this._throwFromErrorBody(json, resp.status);
    }

    return json;
  }

  private _throwFromErrorBody(body: Record<string, unknown>, status: number): never {
    const code = (body['error'] as string) ?? 'server_error';
    const msg = (body['error_description'] as string) ?? 'Token request failed.';

    switch (code) {
      case 'access_pending':
        throw new PendingApprovalError(
          body['request_id'] as string,
          body['status_url'] as string,
        );
      case 'approval_denied':
        throw new ApprovalDeniedError();
      case 'connection_revoked':
        throw new ConnectionRevokedError();
      case 'trusted_issuer_missing':
        throw new TrustedIssuerMissingError();
      case 'subject_mapping_failed':
        throw new SubjectMappingFailedError();
      case 'resource_not_registered':
        throw new ResourceNotRegisteredError('');
      case 'invalid_client':
      case 'credential_invalid':
        throw new CredentialInvalidError(msg);
      case 'workload_not_attested':
        throw new WorkloadNotAttestedError();
      default:
        throw new AuthSecIdentityError(code, msg, status);
    }
  }

  // ── Client auth headers ───────────────────────────────────────────────────

  private _authHeaders(): Record<string, string> {
    if (this.cfg.clientSecret) {
      const encoded = btoa(`${this.cfg.clientId}:${this.cfg.clientSecret}`);
      return { Authorization: `Basic ${encoded}` };
    }
    // private_key_jwt: the assertion is added to the POST body by the caller;
    // no Authorization header here.
    return {};
  }
}

export interface PollOptions {
  /** How often to poll in ms. Default: 2000 */
  intervalMs?: number;
  /** Max attempts before giving up. Default: 150 (~5 minutes at 2s interval) */
  maxAttempts?: number;
  /** Custom fetch implementation. Default: globalThis.fetch */
  fetch?: typeof fetch;
  /** AbortSignal to cancel polling. */
  signal?: AbortSignal;
}

/**
 * Poll `statusUrl` until the access request is approved, then call
 * `identity.clearCache(resource)` and retry `accessFor`.
 *
 * Usage:
 *   try {
 *     token = await identity.accessFor(resource);
 *   } catch (err) {
 *     if (err instanceof PendingApprovalError) {
 *       token = await pollUntilApproved(identity, resource, err.statusUrl);
 *     } else throw err;
 *   }
 */
export async function pollUntilApproved(
  identity: AgentIdentity,
  resource: string,
  statusUrl: string,
  options: PollOptions & { accessForOptions?: AccessForOptions } = {},
): Promise<string> {
  const {
    intervalMs = 2000,
    maxAttempts = 150,
    fetch: fetchImpl = globalThis.fetch.bind(globalThis),
    signal,
    accessForOptions = {},
  } = options;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    if (signal?.aborted) {
      throw new AuthSecIdentityError('poll_aborted', 'Polling was aborted.', 0);
    }

    // Wait before polling (skip on first attempt only if status might already be approved)
    if (attempt > 0) {
      await new Promise<void>((resolve, reject) => {
        const t = setTimeout(resolve, intervalMs);
        signal?.addEventListener('abort', () => { clearTimeout(t); reject(new AuthSecIdentityError('poll_aborted', 'Polling was aborted.', 0)); }, { once: true });
      });
    }

    const resp = await fetchImpl(statusUrl, { signal, headers: { Accept: 'application/json' } });
    if (!resp.ok) continue; // transient HTTP errors — keep polling

    const body = (await resp.json().catch(() => ({}))) as Record<string, unknown>;
    const status = body['status'] as string | undefined;

    if (status === 'approved') {
      identity.clearCache(resource);
      return identity.accessFor(resource, accessForOptions);
    }
    if (status === 'denied') {
      throw new ApprovalDeniedError();
    }
    if (status === 'revoked') {
      throw new ConnectionRevokedError();
    }
    // status=pending → keep polling
  }

  throw new AuthSecIdentityError(
    'poll_timeout',
    `pollUntilApproved: timed out after ${maxAttempts} attempts (${maxAttempts * (options.intervalMs ?? 2000) / 1000}s).`,
    408,
  );
}
