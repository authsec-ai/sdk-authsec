/**
 * RFC 9728 Protected Resource Metadata.
 *
 * TypeScript parity port of python/runtime/metadata.py.
 *
 * Provides the discovery document AI clients use to locate the AuthSec
 * authorization server and learn which scopes the resource server supports.
 */

import type { Config } from './config.js';

export const PROTECTED_RESOURCE_PREFIX = '/.well-known/oauth-protected-resource';

/**
 * Compute the RFC 9728 metadata path for the given resource URI (or
 * already-stripped path).
 *
 * Accepts either a full URI (``https://mcp.example.com/mcp``) or just the
 * path component (``/mcp`` or ``mcp``). Returns:
 *
 *   - ``/.well-known/oauth-protected-resource``           (root resources)
 *   - ``/.well-known/oauth-protected-resource/mcp``       (path-based)
 */
export function buildResourceMetadataPath(protectedPath: string): string {
  let path = protectedPath ?? '';
  // If we got a full URI, extract the path component.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(path)) {
    try {
      path = new URL(path).pathname;
    } catch {
      // fall through and use raw value
    }
  }
  const trimmed = path.trim().replace(/^\/+|\/+$/g, '');
  if (!trimmed) return PROTECTED_RESOURCE_PREFIX;
  return `${PROTECTED_RESOURCE_PREFIX}/${trimmed}`;
}

/** Absolute URL of the metadata document for ``resourceUri``. */
export function buildResourceMetadataUrl(resourceUri: string): string {
  const parsed = new URL(resourceUri);
  return `${parsed.protocol}//${parsed.host}${buildResourceMetadataPath(resourceUri)}`;
}

/**
 * True iff ``requestPath`` is the metadata discovery path for ``resourceUri``.
 * Path-based resources match only their derived alias; root resources match
 * the bare well-known path.
 */
export function isMetadataRequest(resourceUri: string, requestPath: string): boolean {
  const metadataPath = buildResourceMetadataPath(resourceUri);
  return requestPath === metadataPath || requestPath === metadataPath + '/';
}

/**
 * Construct the JSON-able metadata payload (RFC 9728).
 *
 * The ``scopes_supported`` field is sourced in this order:
 *  1. ``authoritativeScopes`` (if non-null) — the live list pulled from
 *     AuthSec via the scope matrix. **This is the canonical source.**
 *     Admin changes a scope in the AuthSec UI → SDK refreshes the matrix
 *     → PRM auto-updates. No code change in the MCP server.
 *  2. ``cfg.supportedScopes`` — local fallback for boot-time PRM requests
 *     before the scope matrix has been fetched, or for ``policyMode=local_only``
 *     deployments that intentionally manage scopes locally.
 *
 * Always pass ``authoritativeScopes`` from the runtime when one is available.
 */
export function buildMetadataPayload(
  cfg: Config,
  authoritativeScopes?: string[] | null,
): Record<string, unknown> {
  const scopes =
    authoritativeScopes && authoritativeScopes.length >= 0
      ? authoritativeScopes
      : cfg.supportedScopes;
  return {
    resource: cfg.resourceUri,
    authorization_servers: [cfg.authorizationServer || cfg.issuer],
    resource_name: cfg.resourceName,
    scopes_supported: [...scopes],
    bearer_methods_supported: [...cfg.bearerMethodsSupported],
  };
}

export interface WwwAuthenticateOptions {
  realm?: string;
  error?: string;
  errorDescription?: string;
  scope?: string;
  resourceMetadataUrl?: string;
}

/**
 * Build the ``WWW-Authenticate`` header value for a 401/403 response. Always
 * includes ``Bearer realm`` and ``resource_metadata`` (RFC 9728). Optionally
 * includes ``error`` and ``error_description`` for insufficient_scope /
 * invalid_token responses.
 *
 * Overloads:
 *  - ``buildWwwAuthenticate(cfg, { error, errorDescription, scope })``
 *  - ``buildWwwAuthenticate(realm, error, errorDescription)`` (Python-shape positional form)
 */
export function buildWwwAuthenticate(
  cfgOrRealm: Config | string,
  errorOrOptions?: string | WwwAuthenticateOptions,
  errorDescription?: string,
): string {
  let realm: string;
  let error: string | undefined;
  let description: string | undefined;
  let scope: string | undefined;
  let metadataUrl: string | undefined;

  if (typeof cfgOrRealm === 'string') {
    realm = cfgOrRealm || 'AuthSec Protected Resource';
    error = typeof errorOrOptions === 'string' ? errorOrOptions : undefined;
    description = errorDescription;
  } else {
    const cfg = cfgOrRealm;
    realm = cfg.resourceName || 'AuthSec Protected Resource';
    if (typeof errorOrOptions === 'object' && errorOrOptions !== null) {
      error = errorOrOptions.error;
      description = errorOrOptions.errorDescription;
      scope = errorOrOptions.scope;
      metadataUrl = errorOrOptions.resourceMetadataUrl;
      if (errorOrOptions.realm) realm = errorOrOptions.realm;
    }
    if (!metadataUrl) {
      try {
        metadataUrl = buildResourceMetadataUrl(cfg.resourceUri);
      } catch {
        metadataUrl = undefined;
      }
    }
  }

  const parts: string[] = [`Bearer realm="${sanitizeHeaderValue(realm)}"`];
  if (metadataUrl) parts.push(`resource_metadata="${sanitizeHeaderValue(metadataUrl)}"`);
  if (error) parts.push(`error="${sanitizeHeaderValue(error)}"`);
  if (description) parts.push(`error_description="${sanitizeHeaderValue(description)}"`);
  if (scope) parts.push(`scope="${sanitizeHeaderValue(scope)}"`);
  return parts.join(', ');
}

/**
 * Sanitize a string for inclusion in an HTTP header field-value (RFC 7230 §3.2.6).
 *
 * Field-value MUST NOT contain CR, LF, or NUL — Node's http module enforces this
 * and throws TypeError [ERR_INVALID_CHAR] when violated. Hydra (and most upstream
 * auth servers) leak control chars AND non-ASCII bytes (localized error strings,
 * smart quotes, RTL marks, U+00A0 non-breaking space, U+200B zero-width space)
 * into error bodies that then end up in our ``error_description``. The previous
 * regex stripped only ``\x00-\x1F`` + ``\x7F`` and let everything ≥ 0x80
 * through — Node rejects those too. The symptom in the wild was a Node
 * ``TypeError: Invalid character in header content`` surfacing as a 500 with
 * HTML body, instead of a clean 401 JSON.
 *
 * Strategy (printable-ASCII-only):
 *  - Replace anything outside 0x20–0x7E with a single space
 *  - Convert embedded double-quotes to apostrophes (cheaper + safer than
 *    backslash-escaping inside a quoted-string — Node's validator has been
 *    known to reject backslash sequences in some versions)
 *  - Strip embedded backslashes for the same reason
 *  - Hard-truncate to 200 chars so the header stays under the 8 KiB server limit
 *    even with several attribute pairs combined
 */
function sanitizeHeaderValue(s: string): string {
  return s
    .replace(/[^\x20-\x7e]/g, ' ')
    .replace(/[\\"]/g, "'")
    .slice(0, 200);
}

/**
 * Return [body, headers] for a 200 OK metadata response.
 *
 * Pass ``authoritativeScopes`` from ``runtime.getAuthoritativeScopes()`` so
 * the PRM advertises the live AuthSec scope list. When omitted (or ``null``),
 * falls back to ``cfg.supportedScopes`` so legacy callers keep working.
 */
export function metadataJsonResponse(
  cfg: Config,
  authoritativeScopes?: string[] | null,
): { body: string; headers: Record<string, string> } {
  const payload = buildMetadataPayload(cfg, authoritativeScopes);
  return {
    body: JSON.stringify(payload),
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=300',
    },
  };
}
