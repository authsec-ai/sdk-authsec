/**
 * CIBA SDK - Passwordless Authentication for Voice Clients
 * Mirrors Python CIBAClient class
 *
 * Supports both Admin and End-User (tenant) authentication flows:
 * - Admin flow: email only (original flow)
 * - Tenant flow: email + client_id (multi-client architecture)
 */

import { loadConfigFile, DEFAULT_CIBA_BASE_URL } from './config.js';

export class CIBAClient {
  private baseUrl: string;
  private clientId: string | null;
  private activePolls: Map<string, boolean>;
  private retryCounts: Map<string, number>;

  /**
   * @param options.baseUrl Priority: explicit param → .authsec.json → hardcoded default
   */
  constructor(options?: { clientId?: string; baseUrl?: string }) {
    this.baseUrl = options?.baseUrl
      ?? loadConfigFile().ciba_base_url as string | undefined
      ?? DEFAULT_CIBA_BASE_URL;
    this.clientId = options?.clientId ?? null;
    this.activePolls = new Map();
    this.retryCounts = new Map();
  }

  /**
   * Triggers a CIBA push notification and cancels any existing poll for this user.
   *
   * - If clientId is set: uses tenant endpoint (/tenant/ciba/initiate)
   * - If clientId is null: uses admin endpoint (/ciba/initiate)
   */
  async initiateAppApproval(email: string): Promise<Record<string, any>> {
    this.retryCounts.set(email, 0);
    if (this.activePolls.has(email)) {
      this.activePolls.set(email, true);
    }

    let endpoint: string;
    let payload: Record<string, any>;

    if (this.clientId) {
      endpoint = `${this.baseUrl}/authsec/uflow/auth/tenant/ciba/initiate`;
      payload = {
        client_id: this.clientId,
        email,
        binding_message: 'Authentication requested via Voice SDK',
      };
    } else {
      endpoint = `${this.baseUrl}/authsec/uflow/auth/ciba/initiate`;
      payload = {
        login_hint: email,
        binding_message: 'Authentication requested via Voice SDK',
      };
    }

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    return (await response.json()) as Record<string, any>;
  }

  /**
   * Verifies a TOTP code for authentication.
   *
   * - If clientId is set: uses tenant endpoint (/tenant/totp/login)
   * - If clientId is null: uses admin endpoint (/totp/login)
   */
  async verifyTotp(email: string, code: string): Promise<Record<string, any>> {
    if (!this.retryCounts.has(email)) {
      this.retryCounts.set(email, 0);
    }
    if (this.retryCounts.get(email)! >= 3) {
      return { success: false, error: 'too_many_retries', remaining: 0 };
    }

    let endpoint: string;
    let payload: Record<string, any>;

    if (this.clientId) {
      endpoint = `${this.baseUrl}/authsec/uflow/auth/tenant/totp/login`;
      payload = { client_id: this.clientId, email, totp_code: code };
    } else {
      // Admin flow (fallback to dev.api if base_url is localhost for compatibility)
      if (this.baseUrl.includes('localhost') || this.baseUrl.includes('127.0.0.1')) {
        endpoint = 'https://dev.api.authsec.dev/authsec/uflow/auth/totp/login';
      } else {
        endpoint = `${this.baseUrl}/authsec/uflow/auth/totp/login`;
      }
      payload = { email, totp_code: code };
    }

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(10000),
      });

      const resData = (await response.json()) as Record<string, any>;
      const token = resData.token ?? resData.access_token;

      if (token || resData.success === true) {
        this.retryCounts.set(email, 0);
        return { ...resData, success: true, token, remaining: 3 };
      } else {
        this.retryCounts.set(email, this.retryCounts.get(email)! + 1);
        return {
          success: false,
          error: 'invalid_code',
          remaining: 3 - this.retryCounts.get(email)!,
        };
      }
    } catch (e: any) {
      return {
        success: false,
        error: e.message ?? String(e),
        remaining: 3 - (this.retryCounts.get(email) ?? 0),
      };
    }
  }

  /**
   * Polls for CIBA approval status.
   *
   * - If clientId is set: uses tenant endpoint (/tenant/ciba/token)
   * - If clientId is null: uses admin endpoint (/ciba/token)
   */
  async pollForApproval(
    email: string,
    authReqId: string,
    options?: { interval?: number; timeout?: number }
  ): Promise<Record<string, any>> {
    const interval = (options?.interval ?? 5) * 1000;
    const timeout = (options?.timeout ?? 300) * 1000;

    this.activePolls.set(email, false);

    let endpoint: string;
    let payload: Record<string, any>;

    if (this.clientId) {
      endpoint = `${this.baseUrl}/authsec/uflow/auth/tenant/ciba/token`;
      payload = { client_id: this.clientId, auth_req_id: authReqId };
    } else {
      endpoint = `${this.baseUrl}/authsec/uflow/auth/ciba/token`;
      payload = { auth_req_id: authReqId };
    }

    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      if (this.activePolls.get(email) === true) {
        return { status: 'cancelled' };
      }

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = (await response.json()) as Record<string, any>;
      const token = data.access_token ?? data.token;

      if (token) {
        return { status: 'approved', token };
      }
      if (data.error === 'access_denied' || data.error === 'expired_token') {
        return { status: data.error };
      }

      await new Promise((resolve) => setTimeout(resolve, interval));

      if (timeout <= 2000) {
        break; // Short check for manual check
      }
    }

    return { status: 'timeout' };
  }

  /**
   * Cancels any ongoing poll and resets retry logic for the user.
   */
  cancelApproval(email: string): Record<string, any> {
    this.activePolls.set(email, true);
    this.retryCounts.set(email, 0);
    return { status: 'cancelled' };
  }
}
