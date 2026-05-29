/**
 * Runtime SDK configuration — TypeScript parity port of python/runtime/config.py
 * and go-sdk/config.go.
 *
 * The Config interface holds everything required to protect an MCP resource
 * server with AuthSec. It supports two orthogonal mode enums:
 *
 *  - PolicyMode      — how the tool→scope policy is sourced and enforced.
 *  - ValidationMode  — how JWT verification and RFC 7662 introspection combine.
 *
 * Field semantics mirror the Python and Go SDKs exactly. See the production
 * AuthSec admin UI ("Application onboarding → Show config") for canonical
 * example values.
 */

/** How the SDK selects and enforces its tool→scope policy source. */
export type PolicyMode =
  | 'unset'
  | 'remote_required'
  | 'remote_with_local_fallback'
  | 'local_only'
  | 'open';

/** How JWT and RFC 7662 introspection are combined for token validation. */
export type ValidationMode =
  | 'unset'
  | 'jwt_only'
  | 'introspection_only'
  | 'jwt_and_introspect'
  | 'jwt_or_introspect';

/**
 * A sync or async function returning a list of manifest tool descriptors.
 * Escape hatch for manifest publishing — bypasses synthetic ``tools/list``.
 */
export type ToolInventoryProvider = () =>
  | ManifestToolInput[]
  | Promise<ManifestToolInput[]>;

/** Loose shape accepted by ToolInventoryProvider / publishManifest. */
export interface ManifestToolInput {
  /** Canonical MCP tool name. */
  name?: string;
  /** Legacy alias accepted from older examples. */
  tool_id?: string;
  title?: string;
  description?: string;
  /** Accept either snake_case (Python) or camelCase (JS) input. */
  input_schema?: Record<string, unknown> | null;
  inputSchema?: Record<string, unknown> | null;
  annotations?: Record<string, unknown> | null;
  suggested_scopes?: string[];
  /** Convenience alias accepted by some helpers. */
  scopes_required?: string[];
}

/** Configuration for protecting an MCP resource server with AuthSec. */
export interface Config {
  issuer: string;
  authorizationServer: string;
  jwksUrl: string;
  introspectionUrl: string;
  introspectionClientId: string;
  introspectionClientSecret: string;
  resourceUri: string;
  resourceName: string;

  /**
   * AuthSec resource server UUID. When set, the SDK fetches the authoritative
   * tool→scope mapping from AuthSec at startup and refreshes it periodically.
   */
  resourceServerId: string;

  /**
   * OAuth scopes this RS advertises in protected-resource metadata. Optional
   * if the RS is already registered in AuthSec.
   */
  supportedScopes: string[];

  /**
   * Optional LOCAL tool→scope mapping for defense-in-depth. Empty list for a
   * tool key marks it explicitly public. Absent key means denied when any
   * policy is active. `null` (or omitted) means "no local map".
   */
  toolScopes: Record<string, string[]> | null;

  /** How long the fetched tool→scope mapping is cached, in seconds. */
  scopeMatrixCacheTtlSeconds: number;

  policyMode: PolicyMode;
  validationMode: ValidationMode;

  /** When true, the SDK pushes its tool inventory to AuthSec at startup. */
  publishManifest: boolean;

  /** SDK author's recommended scope set per tool. Used only for manifest publish. */
  toolScopeSuggestions: Record<string, string[]>;

  /** Escape hatch for manifest publishing — bypass synthetic ``tools/list``. */
  toolInventoryProvider: ToolInventoryProvider | null;

  bearerMethodsSupported: string[];
  requestTimeoutSeconds: number;
}

/** Construct a fresh Config with all defaults. */
export function defaultConfig(): Config {
  return {
    issuer: '',
    authorizationServer: '',
    jwksUrl: '',
    introspectionUrl: '',
    introspectionClientId: '',
    introspectionClientSecret: '',
    resourceUri: '',
    resourceName: '',
    resourceServerId: '',
    supportedScopes: [],
    toolScopes: null,
    scopeMatrixCacheTtlSeconds: 300,
    policyMode: 'unset',
    validationMode: 'unset',
    publishManifest: false,
    toolScopeSuggestions: {},
    toolInventoryProvider: null,
    bearerMethodsSupported: ['header'],
    requestTimeoutSeconds: 10,
  };
}

/** Resolve ``policyMode === 'unset'`` to an inferred default. */
export function effectivePolicyMode(cfg: Config): PolicyMode {
  if (cfg.policyMode !== 'unset') return cfg.policyMode;
  if (cfg.resourceServerId.trim()) return 'remote_required';
  if (cfg.toolScopes !== null) return 'local_only';
  return 'open';
}

/** Resolve ``validationMode === 'unset'`` to an inferred default. */
export function effectiveValidationMode(cfg: Config): ValidationMode {
  if (cfg.validationMode !== 'unset') return cfg.validationMode;
  const hasJwks = !!cfg.jwksUrl.trim();
  const hasIntrospection = !!cfg.introspectionUrl.trim();
  if (hasJwks && hasIntrospection) return 'jwt_and_introspect';
  if (hasJwks) return 'jwt_only';
  return 'introspection_only';
}

/**
 * Validate the config. Throws a verbose Error if unusable. Always run this
 * before constructing a Runtime — production misconfig should fail loudly.
 */
export function validateConfig(cfg: Config): void {
  if (!cfg.issuer.trim()) throw new Error('issuer is required');
  if (!cfg.resourceUri.trim()) throw new Error('resourceUri is required');

  try {
    const parsed = new URL(cfg.resourceUri);
    if (!parsed.protocol || !parsed.host) {
      throw new Error(
        `resourceUri must be an absolute URI with scheme and host (got ${JSON.stringify(cfg.resourceUri)})`,
      );
    }
  } catch (e) {
    if (e instanceof Error && e.message.startsWith('resourceUri must')) throw e;
    throw new Error(
      `resourceUri must be an absolute URI with scheme and host (got ${JSON.stringify(cfg.resourceUri)})`,
    );
  }

  if (!cfg.jwksUrl.trim() && !cfg.introspectionUrl.trim()) {
    throw new Error('at least one of jwksUrl or introspectionUrl is required');
  }

  if (
    cfg.introspectionUrl.trim() &&
    (!cfg.introspectionClientId.trim() || !cfg.introspectionClientSecret.trim())
  ) {
    throw new Error(
      'introspection client credentials are required when introspection is enabled',
    );
  }

  const pm = effectivePolicyMode(cfg);
  if (pm === 'remote_required' || pm === 'remote_with_local_fallback') {
    if (!cfg.resourceServerId.trim()) {
      throw new Error(`${pm} requires resourceServerId`);
    }
    if (!cfg.authorizationServer.trim() && !cfg.issuer.trim()) {
      throw new Error(`${pm} requires authorizationServer`);
    }
    if (!cfg.introspectionClientId.trim() || !cfg.introspectionClientSecret.trim()) {
      throw new Error(
        `${pm} requires introspection credentials (introspectionClientId + introspectionClientSecret)`,
      );
    }
  }
  if (pm === 'remote_with_local_fallback' && cfg.toolScopes === null) {
    throw new Error(
      'PolicyMode.remote_with_local_fallback requires toolScopes (non-null) as the local fallback',
    );
  }

  const vm = effectiveValidationMode(cfg);
  if (vm === 'jwt_only' && !cfg.jwksUrl.trim()) {
    throw new Error(`${vm} requires jwksUrl`);
  }
  if (vm === 'introspection_only') {
    if (!cfg.introspectionUrl.trim()) {
      throw new Error(`${vm} requires introspectionUrl`);
    }
    if (!cfg.introspectionClientId.trim() || !cfg.introspectionClientSecret.trim()) {
      throw new Error(`${vm} requires introspection credentials`);
    }
  }
  if (vm === 'jwt_and_introspect' || vm === 'jwt_or_introspect') {
    if (!cfg.jwksUrl.trim()) throw new Error(`${vm} requires jwksUrl`);
    if (!cfg.introspectionUrl.trim()) throw new Error(`${vm} requires introspectionUrl`);
    if (!cfg.introspectionClientId.trim() || !cfg.introspectionClientSecret.trim()) {
      throw new Error(`${vm} requires introspection credentials`);
    }
  }
}

/** Return a copy of the config with sensible defaults filled in. */
export function normalizeConfig(cfg: Config): Config {
  const out: Config = { ...cfg };
  if (!out.authorizationServer) out.authorizationServer = out.issuer;
  if (!out.resourceName) out.resourceName = 'AuthSec Protected MCP Resource';
  if (!out.bearerMethodsSupported || out.bearerMethodsSupported.length === 0) {
    out.bearerMethodsSupported = ['header'];
  }
  return out;
}

const POLICY_MODES: ReadonlySet<PolicyMode> = new Set<PolicyMode>([
  'unset',
  'remote_required',
  'remote_with_local_fallback',
  'local_only',
  'open',
]);

const VALIDATION_MODES: ReadonlySet<ValidationMode> = new Set<ValidationMode>([
  'unset',
  'jwt_only',
  'introspection_only',
  'jwt_and_introspect',
  'jwt_or_introspect',
]);

function parsePolicyMode(v: string | undefined): PolicyMode {
  if (!v) return 'unset';
  const lowerRaw = v.trim().toLowerCase();
  if (lowerRaw === 'enforce') return 'remote_required';
  if (lowerRaw === 'observe') return 'open';
  const lower = lowerRaw as PolicyMode;
  return POLICY_MODES.has(lower) ? lower : 'unset';
}

function parseValidationMode(v: string | undefined): ValidationMode {
  if (!v) return 'unset';
  const lowerRaw = v.trim().toLowerCase();
  if (lowerRaw === 'auto') return 'unset';
  const lower = lowerRaw as ValidationMode;
  return VALIDATION_MODES.has(lower) ? lower : 'unset';
}

function parseStringList(v: string | undefined): string[] {
  if (!v) return [];
  const trimmed = v.trim();
  if (!trimmed) return [];
  if (trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed)) return parsed.map(String).filter(Boolean);
    } catch {
      // fall through to delimiter parsing
    }
  }
  return trimmed.split(/[\s,]+/).filter(Boolean);
}

function parseStringArrayRecord(v: string | undefined): Record<string, string[]> | null {
  if (!v) return null;
  try {
    const parsed = JSON.parse(v);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    const out: Record<string, string[]> = {};
    for (const [key, value] of Object.entries(parsed)) {
      if (Array.isArray(value)) out[key] = value.map(String).filter(Boolean);
      else if (typeof value === 'string') out[key] = parseStringList(value);
    }
    return out;
  } catch {
    return null;
  }
}

/**
 * Build a Config from environment variables, mirroring the Python `from_env`.
 *
 * Conventional env vars (matching the .env block AuthSec UI emits):
 *
 *   AUTHSEC_ISSUER
 *   AUTHSEC_AUTHORIZATION_SERVER
 *   AUTHSEC_JWKS_URL
 *   AUTHSEC_INTROSPECTION_URL
 *   AUTHSEC_INTROSPECTION_CLIENT_ID
 *   AUTHSEC_INTROSPECTION_CLIENT_SECRET
 *   AUTHSEC_RESOURCE_URI
 *   AUTHSEC_RESOURCE_NAME
 *   AUTHSEC_RESOURCE_SERVER_ID
 *   AUTHSEC_SUPPORTED_SCOPES        (space-separated)
 *   AUTHSEC_POLICY_MODE             ('remote_required', etc.)
 *   AUTHSEC_VALIDATION_MODE         ('jwt_and_introspect', etc.)
 *   AUTHSEC_PUBLISH_MANIFEST        ('true' | 'false')
 */
export function loadConfigFromEnv(
  prefix = 'AUTHSEC_',
  env: NodeJS.ProcessEnv = process.env,
): Config {
  const g = (k: string, dflt = ''): string => env[prefix + k] ?? dflt;
  const first = (...keys: string[]): string => {
    for (const key of keys) {
      const value = g(key);
      if (value) return value;
    }
    return '';
  };
  const cfg = defaultConfig();
  cfg.issuer = g('ISSUER');
  cfg.authorizationServer = g('AUTHORIZATION_SERVER');
  cfg.jwksUrl = first('JWKS_URL', 'JWKS_URI');
  cfg.introspectionUrl = first('INTROSPECTION_URL', 'INTROSPECTION_ENDPOINT');
  cfg.introspectionClientId = first('INTROSPECTION_CLIENT_ID', 'INTROSPECTION_ID');
  cfg.introspectionClientSecret = first(
    'INTROSPECTION_CLIENT_SECRET',
    'INTROSPECTION_SECRET',
  );
  cfg.resourceUri = first('RESOURCE_URI', 'RESOURCE');
  cfg.resourceName = g('RESOURCE_NAME');
  cfg.resourceServerId = g('RESOURCE_SERVER_ID');
  cfg.supportedScopes = parseStringList(g('SUPPORTED_SCOPES'));
  cfg.policyMode = parsePolicyMode(g('POLICY_MODE'));
  cfg.validationMode = parseValidationMode(g('VALIDATION_MODE'));
  const publish = g('PUBLISH_MANIFEST').trim().toLowerCase();
  cfg.publishManifest = publish === '1' || publish === 'true' || publish === 'yes';
  cfg.toolScopeSuggestions = parseStringArrayRecord(g('TOOL_SCOPE_SUGGESTIONS_JSON')) ?? {};
  cfg.toolScopes = parseStringArrayRecord(g('TOOL_SCOPES_JSON'));
  return cfg;
}
