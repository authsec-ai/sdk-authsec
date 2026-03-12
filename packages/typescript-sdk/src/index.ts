/**
 * AuthSec SDK for TypeScript/JavaScript
 *
 * Enterprise-grade authentication and authorization library for JS/TS servers.
 * Provides OAuth 2.0, RBAC, SPIFFE workload identity, and CIBA passwordless auth.
 *
 * @example
 * ```ts
 * import {
 *   protectedByAuthSec,
 *   mcpTool,
 *   runMcpServerWithOAuth,
 *   ServiceAccessSDK,
 *   CIBAClient,
 *   DelegationClient,
 * } from '@authsec/sdk';
 *
 * const adminTool = protectedByAuthSec({
 *   toolName: 'admin_dashboard',
 *   roles: ['admin'],
 *   description: 'Access admin dashboard',
 * }, async (args, session) => {
 *   const sdk = new ServiceAccessSDK(session);
 *   const creds = await sdk.getServiceCredentials('my-db');
 *   return [{ type: 'text', text: JSON.stringify(creds) }];
 * });
 *
 * runMcpServerWithOAuth({
 *   tools: [adminTool],
 *   clientId: 'your-client-id',
 *   appName: 'my-app',
 * });
 * ```
 */

// Core Auth & MCP
export { protectedByAuthSec, mcpTool } from './decorators.js';
export { runMcpServerWithOAuth } from './mcp-server.js';
export type { RunMcpServerOptions } from './mcp-server.js';

// Configuration
export { configureAuth, getConfig, isConfigured } from './config.js';

// HTTP / Testing
export { testAuthService, testServices } from './http.js';

// Service Access
export { ServiceAccessSDK, ServiceAccessError } from './service-access.js';

// CIBA Passwordless Auth
export { CIBAClient } from './ciba.js';

// Trust Delegation
export {
  DelegationClient,
  DelegationError,
  DelegationHTTPResponse,
  DelegationTokenExpired,
  DelegationTokenNotFound,
} from './delegation.js';
export type {
  DelegationClientOptions,
  DelegationRequestOptions,
  DelegationTokenInfo,
} from './delegation.js';

// SPIFFE Workload Identity
export { QuickStartSVID } from './spiffe/quick-start-svid.js';
export { WorkloadAPIClient } from './spiffe/workload-api-client.js';
export { WorkloadSVID } from './spiffe/workload-svid.js';

// Types
export type {
  ToolHandler,
  ToolHandlerWithSession,
  ToolDefinition,
  RbacRequirements,
  McpContent,
  UserInfo,
  ServiceCredentials,
  AuthSecConfig,
  McpMessage,
} from './types.js';
export { SimpleSession } from './types.js';

export const VERSION = '4.1.0';
