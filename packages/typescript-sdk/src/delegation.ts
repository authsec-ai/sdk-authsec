import { Buffer } from 'node:buffer';

type DelegationBody =
  | string
  | Buffer
  | Uint8Array
  | ArrayBuffer
  | URLSearchParams
  | null;

export interface DelegationClientOptions {
  clientId: string;
  userflowUrl: string;
  autoRefresh?: boolean;
  refreshBufferSeconds?: number;
  timeoutMs?: number;
}

export interface DelegationTokenInfo {
  token?: string;
  spiffe_id?: string;
  permissions?: string[];
  audience?: string;
  expires_at?: string;
  ttl_seconds?: number;
  client_id?: string;
  tenant_id?: string;
  status?: string;
  [key: string]: any;
}

export interface DelegationRequestOptions
  extends Omit<RequestInit, 'method' | 'headers' | 'body' | 'signal'> {
  headers?: Record<string, string>;
  jsonBody?: unknown;
  body?: DelegationBody;
}

export class DelegationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DelegationError';
  }
}

export class DelegationTokenExpired extends DelegationError {
  constructor(message: string) {
    super(message);
    this.name = 'DelegationTokenExpired';
  }
}

export class DelegationTokenNotFound extends DelegationError {
  constructor(message: string) {
    super(message);
    this.name = 'DelegationTokenNotFound';
  }
}

export class DelegationHTTPResponse {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly body: Uint8Array;
  readonly url: string;

  constructor(
    status: number,
    headers: Record<string, string>,
    body: Uint8Array,
    url: string
  ) {
    this.status = status;
    this.headers = headers;
    this.body = body;
    this.url = url;
  }

  get ok(): boolean {
    return this.status >= 200 && this.status < 300;
  }

  text(encoding: BufferEncoding = 'utf-8'): string {
    return Buffer.from(this.body).toString(encoding);
  }

  json<T = any>(): T | null {
    if (this.body.length === 0) {
      return null;
    }
    return JSON.parse(this.text()) as T;
  }
}

export class DelegationClient {
  readonly clientId: string;
  readonly userflowUrl: string;
  readonly autoRefresh: boolean;
  readonly refreshBufferSeconds: number;
  readonly timeoutMs: number;

  private tokenValue: string | null = null;
  private tokenInfo: DelegationTokenInfo | null = null;
  private permissionList: string[] = [];
  private expiresAtMs = 0;

  constructor(options: DelegationClientOptions) {
    const clientId = options.clientId?.trim();
    const userflowUrl = options.userflowUrl?.trim().replace(/\/+$/, '');

    if (!clientId) {
      throw new DelegationError('clientId must be a non-empty string');
    }
    if (!userflowUrl) {
      throw new DelegationError('userflowUrl must be a non-empty string');
    }

    this.clientId = clientId;
    this.userflowUrl = userflowUrl;
    this.autoRefresh = options.autoRefresh ?? true;
    this.refreshBufferSeconds = options.refreshBufferSeconds ?? 300;
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  get token(): string | null {
    return this.tokenValue;
  }

  get permissions(): string[] {
    return [...this.permissionList];
  }

  get spiffeId(): string | null {
    return this.tokenInfo?.spiffe_id ?? null;
  }

  get isExpired(): boolean {
    if (!this.expiresAtMs) {
      return true;
    }
    return Date.now() >= this.expiresAtMs;
  }

  get expiresInSeconds(): number {
    if (!this.expiresAtMs) {
      return 0;
    }
    return Math.max(0, Math.floor((this.expiresAtMs - Date.now()) / 1000));
  }

  async pullToken(): Promise<DelegationTokenInfo> {
    const url =
      `${this.userflowUrl}/sdk/delegation-token` +
      `?client_id=${encodeURIComponent(this.clientId)}`;

    let response: Response;
    try {
      response = await fetch(url, {
        method: 'GET',
        headers: {
          'X-Client-ID': this.clientId,
          Accept: 'application/json',
        },
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error: any) {
      throw wrapDelegationError(error, `Network error pulling delegation token from ${url}`);
    }

    const body = await parseJsonBody(response);

    if (response.status === 200) {
      this.tokenValue = typeof body.token === 'string' ? body.token : null;
      this.tokenInfo = body;
      this.permissionList = Array.isArray(body.permissions)
        ? body.permissions.filter((value): value is string => typeof value === 'string')
        : [];
      this.expiresAtMs = resolveExpiryMs(body);
      return body;
    }

    if (response.status === 404) {
      throw new DelegationTokenNotFound(
        errorMessage(body, 'No active delegation token found')
      );
    }

    if (response.status === 410) {
      this.tokenValue = null;
      this.tokenInfo = null;
      this.permissionList = [];
      this.expiresAtMs = 0;
      throw new DelegationTokenExpired(
        errorMessage(body, 'Delegation token has expired')
      );
    }

    throw new DelegationError(
      `HTTP ${response.status}: ${errorMessage(body, 'Unknown error')}`
    );
  }

  async ensureToken(): Promise<string> {
    if (this.needsRefresh()) {
      await this.pullToken();
    }

    if (!this.tokenValue) {
      throw new DelegationError('Delegation token is unavailable after refresh');
    }

    return this.tokenValue;
  }

  hasPermission(permission: string): boolean {
    return this.permissionList.includes(permission);
  }

  hasAnyPermission(...permissions: string[]): boolean {
    return permissions.some((permission) => this.permissionList.includes(permission));
  }

  hasAllPermissions(...permissions: string[]): boolean {
    return permissions.every((permission) => this.permissionList.includes(permission));
  }

  async request(
    method: string,
    url: string,
    options: DelegationRequestOptions = {}
  ): Promise<DelegationHTTPResponse> {
    const token = await this.ensureToken();
    let response = await this.requestOnce(method, url, token, options);

    if (response.status === 401 && this.autoRefresh) {
      await this.pullToken();
      if (!this.tokenValue) {
        throw new DelegationError('Delegation token refresh returned no token');
      }
      response = await this.requestOnce(method, url, this.tokenValue, options);
    }

    return response;
  }

  async requestJson<T = any>(
    method: string,
    url: string,
    options: DelegationRequestOptions = {}
  ): Promise<T | null> {
    const response = await this.request(method, url, options);
    if (response.body.length === 0) {
      return null;
    }

    try {
      return response.json<T>();
    } catch (error: any) {
      throw new DelegationError(
        `Expected JSON response from ${response.url}: ${error?.message ?? error}`
      );
    }
  }

  getAuthHeader(): Record<string, string> {
    if (!this.tokenValue) {
      throw new DelegationError(
        'No token cached. Call pullToken() or ensureToken() first.'
      );
    }
    return { Authorization: `Bearer ${this.tokenValue}` };
  }

  decodeTokenClaims(): Record<string, any> {
    if (!this.tokenValue) {
      return {};
    }

    try {
      const parts = this.tokenValue.split('.');
      if (parts.length < 2) {
        return {};
      }

      const payload = parts[1] ?? '';
      const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4);
      const decoded = Buffer.from(padded, 'base64url').toString('utf-8');
      const claims = JSON.parse(decoded);
      return typeof claims === 'object' && claims !== null ? claims : {};
    } catch {
      return {};
    }
  }

  private needsRefresh(): boolean {
    if (!this.tokenValue || !this.expiresAtMs) {
      return true;
    }

    return Date.now() >= this.expiresAtMs - this.refreshBufferSeconds * 1000;
  }

  private async requestOnce(
    method: string,
    url: string,
    token: string,
    options: DelegationRequestOptions
  ): Promise<DelegationHTTPResponse> {
    const headers = new Headers(options.headers ?? {});
    headers.set('Authorization', `Bearer ${token}`);

    let body: DelegationBody | undefined = options.body;
    if (options.jsonBody !== undefined) {
      headers.set('Content-Type', headers.get('Content-Type') ?? 'application/json');
      body = JSON.stringify(options.jsonBody);
    }

    let response: Response;
    try {
      response = await fetch(url, {
        ...options,
        method,
        headers,
        body,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error: any) {
      throw wrapDelegationError(error, `Network error calling delegated endpoint ${url}`);
    }

    const buffer = new Uint8Array(await response.arrayBuffer());
    return new DelegationHTTPResponse(
      response.status,
      headersToObject(response.headers),
      buffer,
      response.url,
    );
  }
}

function headersToObject(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key] = value;
  });
  return out;
}

async function parseJsonBody(response: Response): Promise<Record<string, any>> {
  const text = await response.text();
  if (!text) {
    return {};
  }

  try {
    const parsed = JSON.parse(text);
    return typeof parsed === 'object' && parsed !== null
      ? (parsed as Record<string, any>)
      : { value: parsed };
  } catch {
    return { error: text };
  }
}

function resolveExpiryMs(tokenInfo: DelegationTokenInfo): number {
  if (typeof tokenInfo.expires_at === 'string') {
    const parsed = Date.parse(tokenInfo.expires_at);
    if (!Number.isNaN(parsed)) {
      return parsed;
    }
  }

  if (typeof tokenInfo.ttl_seconds === 'number') {
    return Date.now() + tokenInfo.ttl_seconds * 1000;
  }

  return 0;
}

function errorMessage(body: Record<string, any>, fallback: string): string {
  const message = body.error ?? body.message ?? fallback;
  return typeof message === 'string' ? message : fallback;
}

function wrapDelegationError(error: unknown, fallback: string): DelegationError {
  if (error instanceof DelegationError) {
    return error;
  }
  if (error instanceof Error && error.message) {
    return new DelegationError(`${fallback}: ${error.message}`);
  }
  return new DelegationError(fallback);
}
