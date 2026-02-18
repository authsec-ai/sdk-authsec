/**
 * HTTP client helpers for communicating with SDK Manager
 * Mirrors Python _make_auth_request / _make_services_request
 */

import { getInternalConfig } from './config.js';

/**
 * Make HTTP request to SDK Manager auth service.
 */
export async function makeAuthRequest(
  endpoint: string,
  payload?: Record<string, any> | null,
  method: 'GET' | 'POST' = 'POST'
): Promise<Record<string, any>> {
  const config = getInternalConfig();

  if (!config.clientId) {
    throw new Error('Authentication not configured. Call configureAuth() first.');
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Client-ID': config.clientId,
    'X-App-Name': config.appName!,
  };

  const url = `${config.authServiceUrl}/${endpoint}`;

  for (let attempt = 0; attempt < config.retries; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), config.timeout * 1000);

      const fetchOptions: RequestInit = {
        method,
        headers,
        signal: controller.signal,
      };

      if (method === 'POST' && payload) {
        fetchOptions.body = JSON.stringify(payload);
      }

      const response = await fetch(url, fetchOptions);
      clearTimeout(timeoutId);

      return (await response.json()) as Record<string, any>;
    } catch (e: any) {
      if (attempt < config.retries - 1) {
        await sleep(500 * (attempt + 1));
        continue;
      }

      return {
        allowed: false,
        error: 'Connection error',
        message: `Failed to connect to auth service: ${e.message ?? e}`,
      };
    }
  }

  return {
    allowed: false,
    error: 'Max retries exceeded',
    message: 'Could not complete authentication check',
  };
}

/**
 * Make HTTP request to SDK Manager services.
 */
export async function makeServicesRequest(
  endpoint: string,
  payload?: Record<string, any> | null,
  method: 'GET' | 'POST' = 'POST'
): Promise<Record<string, any>> {
  const config = getInternalConfig();

  if (!config.clientId) {
    throw new Error('Authentication not configured. Call configureAuth() first.');
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Client-ID': config.clientId,
    'X-App-Name': config.appName!,
  };

  const url = `${config.servicesBaseUrl}/${endpoint}`;
  const timeoutMs = config.timeout * 2 * 1000; // Services may take longer

  for (let attempt = 0; attempt < config.retries; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      const fetchOptions: RequestInit = {
        method,
        headers,
        signal: controller.signal,
      };

      if (method === 'POST' && payload) {
        fetchOptions.body = JSON.stringify(payload);
      }

      const response = await fetch(url, fetchOptions);
      clearTimeout(timeoutId);

      if (response.status >= 400) {
        const errorText = await response.text();
        return { error: `HTTP ${response.status}: ${errorText}` };
      }

      return (await response.json()) as Record<string, any>;
    } catch (e: any) {
      if (attempt < config.retries - 1) {
        await sleep(500 * (attempt + 1));
        continue;
      }

      return {
        error: 'Connection error',
        message: `Failed to connect to services: ${e.message ?? e}`,
      };
    }
  }

  return {
    error: 'Max retries exceeded',
    message: 'Could not complete services request',
  };
}

/** Test connection to auth service */
export async function testAuthService(): Promise<boolean> {
  try {
    const result = await makeAuthRequest('health', null, 'GET');
    console.log(`Auth service is running: ${JSON.stringify(result)}`);
    return result.status === 'healthy';
  } catch (e: any) {
    console.log(`Failed to connect to auth service: ${e.message ?? e}`);
    return false;
  }
}

/** Test connection to services */
export async function testServices(): Promise<boolean> {
  try {
    const result = await makeServicesRequest('health', null, 'GET');
    console.log(`Services are running: ${JSON.stringify(result)}`);
    return result.status === 'healthy';
  } catch (e: any) {
    console.log(`Failed to connect to services: ${e.message ?? e}`);
    return false;
  }
}

/** Decode JWT payload without verification (for cache/debug only) */
export function decodeJwtUnverified(token: string): Record<string, any> {
  try {
    const parts = token.split('.');
    if (parts.length < 2) return {};
    const payload = parts[1]!;
    // Add padding
    const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4);
    const decoded = Buffer.from(padded, 'base64url').toString('utf-8');
    const data = JSON.parse(decoded);
    return typeof data === 'object' && data !== null ? data : {};
  } catch {
    return {};
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
