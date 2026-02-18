/**
 * Global configuration store for AuthSec SDK
 * Mirrors Python authsec_sdk config
 */

import type { AuthSecConfig } from './types.js';

const _config: AuthSecConfig = {
  clientId: null,
  appName: null,
  authServiceUrl: 'https://dev.api.authsec.dev/sdkmgr/mcp-auth',
  servicesBaseUrl: 'https://dev.api.authsec.dev/sdkmgr/services',
  timeout: 10,
  retries: 3,
  spireSocketPath: null,
  spireEnabled: false,
};

/** In-memory session cache for user info (best-effort, used for oauth_user_info) */
export const sessionUserInfo: Record<string, any> = {};

/**
 * Normalize caller-provided clientId to the runtime form expected by SDK Manager.
 *
 * Accepts:
 * - base UUID (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
 * - base UUID with underscores
 * - already-suffixed IDs (`...-main-client` or `..._main-client`)
 */
export function normalizeRuntimeClientId(clientId: string): string {
  let raw = (clientId ?? '').trim().replace(/^["']|["']$/g, '');
  if (!raw) {
    throw new Error('client_id must be a non-empty string');
  }

  raw = raw.replace('_main-client', '-main-client');

  let base: string;
  if (raw.endsWith('-main-client')) {
    base = raw.slice(0, -'-main-client'.length);
  } else {
    base = raw;
  }

  // Normalize UUID-like underscore format to hyphen format
  if (base.includes('_') && (base.match(/_/g) || []).length === 4) {
    base = base.replace(/_/g, '-');
  }

  return `${base}-main-client`;
}

/**
 * Configure authentication settings for tool protection.
 */
export function configureAuth(
  clientId: string,
  appName: string,
  options?: {
    authServiceUrl?: string;
    servicesBaseUrl?: string;
    timeout?: number;
    retries?: number;
  }
): void {
  if (!clientId || typeof clientId !== 'string') {
    throw new Error('clientId must be a non-empty string');
  }
  if (!appName || typeof appName !== 'string') {
    throw new Error('appName must be a non-empty string');
  }

  _config.clientId = clientId;
  _config.appName = appName;
  _config.timeout = options?.timeout ?? 10;
  _config.retries = options?.retries ?? 3;

  if (options?.authServiceUrl) {
    _config.authServiceUrl = options.authServiceUrl.replace(/\/+$/, '');
  }
  if (options?.servicesBaseUrl) {
    _config.servicesBaseUrl = options.servicesBaseUrl.replace(/\/+$/, '');
  }

  console.log(`Auth configured: ${appName} with client_id: ${clientId.slice(0, 8)}...`);
  console.log(`Auth service URL: ${_config.authServiceUrl}`);
  console.log(`Services URL: ${_config.servicesBaseUrl}`);
}

/** Get current configuration (for debugging). */
export function getConfig(): Record<string, any> {
  const copy = { ..._config };
  if (copy.clientId) {
    copy.clientId = copy.clientId.slice(0, 8) + '...' + copy.clientId.slice(-4);
  }
  return copy;
}

/** Check if authentication is properly configured. */
export function isConfigured(): boolean {
  return !!(getInternalConfig().clientId && getInternalConfig().appName);
}

/** Internal: get mutable config reference */
export function getInternalConfig(): AuthSecConfig {
  return _config;
}
