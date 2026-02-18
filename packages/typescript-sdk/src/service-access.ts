/**
 * ServiceAccessSDK - access external service credentials via hosted services
 * Mirrors Python ServiceAccessSDK class
 */

import { makeServicesRequest } from './http.js';
import type { ServiceCredentials } from './types.js';

export class ServiceAccessError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ServiceAccessError';
  }
}

export class ServiceAccessSDK {
  private sessionId: string;
  private session: any;
  private timeout: number;

  constructor(
    session: { sessionId: string; [key: string]: any } | { session_id: string; [key: string]: any },
    timeout: number = 30
  ) {
    // Extract session_id from various session object shapes
    if ('sessionId' in session) {
      this.sessionId = session.sessionId;
    } else if ('session_id' in session) {
      this.sessionId = session.session_id;
    } else {
      throw new Error('Session must contain sessionId or session_id');
    }

    this.session = session;
    this.timeout = timeout;
  }

  /** Check service health via hosted service */
  async healthCheck(): Promise<Record<string, any>> {
    return makeServicesRequest('health', null, 'GET');
  }

  /** Get service credentials via hosted service */
  async getServiceCredentials(serviceName: string): Promise<ServiceCredentials> {
    const payload = {
      session_id: this.sessionId,
      service_name: serviceName,
    };

    const result = await makeServicesRequest('credentials', payload);

    if (result.error) {
      throw new ServiceAccessError(result.error);
    }

    return {
      serviceId: result.service_id,
      serviceName: result.service_name,
      serviceType: result.service_type,
      authType: result.auth_type,
      url: result.url,
      credentials: result.credentials,
      metadata: result.metadata ?? {},
      retrievedAt: result.retrieved_at,
    };
  }

  /** Get access token for service */
  async getServiceToken(serviceName: string): Promise<string> {
    const credentials = await this.getServiceCredentials(serviceName);
    const token = credentials.credentials.access_token;
    if (!token) {
      throw new ServiceAccessError(`No access token available for ${serviceName}`);
    }
    return token;
  }

  /** Get JWT payload details via hosted service */
  async getServiceUserDetails(serviceName: string): Promise<Record<string, any>> {
    const payload = {
      session_id: this.sessionId,
      service_name: serviceName,
    };

    return makeServicesRequest('user-details', payload);
  }

  /** Close SDK (no-op in this minimal implementation) */
  async close(): Promise<void> {
    // No-op
  }
}
