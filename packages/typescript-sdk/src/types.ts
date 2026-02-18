/**
 * Shared TypeScript types for AuthSec SDK
 */

/** MCP content item returned by tool handlers */
export interface McpContent {
  type: string;
  text: string;
}

/** Async tool handler function (no session) */
export type ToolHandler = (arguments_: Record<string, any>) => Promise<McpContent[]>;

/** Async tool handler function (with session) */
export type ToolHandlerWithSession = (
  arguments_: Record<string, any>,
  session: SimpleSession
) => Promise<McpContent[]>;

/** RBAC requirements for a protected tool */
export interface RbacRequirements {
  roles: string[];
  groups: string[];
  resources: string[];
  scopes: string[];
  permissions: string[];
  requireAll: boolean;
}

/** Tool definition with metadata (returned by decorator functions) */
export interface ToolDefinition {
  /** The wrapped handler function */
  handler: (arguments_: Record<string, any>) => Promise<McpContent[]>;
  /** Tool name */
  name: string;
  /** Tool description */
  description?: string;
  /** MCP-compliant JSON schema for input */
  inputSchema?: Record<string, any>;
  /** Whether this tool is protected by AuthSec */
  isProtected: boolean;
  /** RBAC requirements (only for protected tools) */
  rbacRequirements?: RbacRequirements;
}

/** Session object passed to protected tool handlers */
export class SimpleSession {
  sessionId: string;
  accessToken: string | null;
  tenantId: string | null;
  userId: string | null;
  orgId: string | null;

  constructor(sessionId: string, userInfo: Record<string, any>) {
    this.sessionId = sessionId;
    this.accessToken = userInfo.access_token ?? null;
    this.tenantId = userInfo.tenant_id ?? null;
    this.userId = userInfo.user_id ?? null;
    this.orgId = userInfo.org_id ?? null;
  }
}

/** User info extracted from JWT / auth service */
export interface UserInfo {
  email?: string;
  tenant_id?: string;
  user_id?: string;
  org_id?: string;
  access_token?: string;
  roles?: string[];
  groups?: string[];
  scopes?: string[] | string;
  scope?: string[] | string;
  resources?: string[];
  permissions?: string[];
  [key: string]: any;
}

/** Service credentials returned by ServiceAccessSDK */
export interface ServiceCredentials {
  serviceId: string;
  serviceName: string;
  serviceType: string;
  authType: string;
  url: string;
  credentials: Record<string, any>;
  metadata: Record<string, string>;
  retrievedAt: string;
}

/** SDK configuration */
export interface AuthSecConfig {
  clientId: string | null;
  appName: string | null;
  authServiceUrl: string;
  servicesBaseUrl: string;
  timeout: number;
  retries: number;
  spireSocketPath: string | null;
  spireEnabled: boolean;
}

/** MCP JSON-RPC message */
export interface McpMessage {
  jsonrpc: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, any>;
  result?: any;
  error?: { code: number; message: string };
}
