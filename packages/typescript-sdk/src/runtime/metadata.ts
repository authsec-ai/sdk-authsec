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

/** Construct the JSON-able metadata payload. */
export function buildMetadataPayload(cfg: Config): Record<string, unknown> {
  return {
    resource: cfg.resourceUri,
    authorization_servers: [cfg.authorizationServer || cfg.issuer],
    resource_name: cfg.resourceName,
    scopes_supported: [...cfg.supportedScopes],
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

  const parts: string[] = [`Bearer realm="${realm}"`];
  if (metadataUrl) parts.push(`resource_metadata="${metadataUrl}"`);
  if (error) parts.push(`error="${error}"`);
  if (description) {
    const safe = description.replace(/"/g, '\\"');
    parts.push(`error_description="${safe}"`);
  }
  if (scope) parts.push(`scope="${scope}"`);
  return parts.join(', ');
}

/** Return [body, headers] for a 200 OK metadata response. */
export function metadataJsonResponse(cfg: Config): { body: string; headers: Record<string, string> } {
  const payload = buildMetadataPayload(cfg);
  return {
    body: JSON.stringify(payload),
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=300',
    },
  };
}
