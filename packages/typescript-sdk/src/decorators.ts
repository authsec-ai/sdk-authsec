/**
 * Tool decorator functions (higher-order functions)
 * Mirrors Python @protected_by_AuthSec and @mcp_tool decorators
 */

import { makeAuthRequest } from './http.js';
import { evaluateRbac } from './rbac.js';
import {
  getCurrentSessionId,
  getInternalConfig,
  sessionUserInfo,
} from './config.js';
import type {
  ToolDefinition,
  ToolHandler,
  ToolHandlerWithSession,
  RbacRequirements,
  McpContent,
  UserInfo,
  SimpleSession,
} from './types.js';
import { SimpleSession as SimpleSessionClass } from './types.js';
import type { Principal } from './runtime/principal.js';

interface ProtectedToolOptions {
  toolName: string;
  roles?: string[];
  groups?: string[];
  resources?: string[];
  scopes?: string[];
  permissions?: string[];
  requireAll?: boolean;
  description?: string;
  inputSchema?: Record<string, any>;
}

/**
 * Protect a tool via SDK Manager auth service API with optional RBAC.
 *
 * The handler receives (arguments, session) where session contains user context.
 *
 * @example
 * ```ts
 * const adminTool = protectedByAuthSec({
 *   toolName: 'admin_dashboard',
 *   roles: ['admin'],
 *   description: 'Access admin dashboard',
 * }, async (args, session) => {
 *   return [{ type: 'text', text: `Hello ${session.userId}` }];
 * });
 * ```
 */
export function protectedByAuthSec(
  options: ProtectedToolOptions,
  handler: ToolHandler | ToolHandlerWithSession
): ToolDefinition {
  const rbacRequirements: RbacRequirements = {
    roles: options.roles ?? [],
    groups: options.groups ?? [],
    resources: options.resources ?? [],
    scopes: options.scopes ?? [],
    permissions: options.permissions ?? [],
    requireAll: options.requireAll ?? false,
  };

  // Determine if handler expects session (by checking function arity)
  const expectsSession = handler.length >= 2;

  const wrappedHandler = async (
    arguments_: Record<string, any>
  ): Promise<McpContent[]> => {
    const runtimePrincipal = principalFromArguments(arguments_);
    if (runtimePrincipal) {
      const userInfo = userInfoFromPrincipal(runtimePrincipal);
      // In runtime mode, exact tool scope enforcement has already happened
      // through AuthSec's authoritative scope matrix. Decorator scopes are
      // retained as manifest suggestions only, while role/group/resource
      // checks remain available for legacy handlers that use them.
      const [rbacOk, rbacReason] = evaluateRbac(userInfo, {
        ...rbacRequirements,
        scopes: [],
      });
      if (!rbacOk) {
        const errorResponse = {
          error: 'Access denied',
          message: `RBAC denied: ${rbacReason}`,
          tool: options.toolName,
        };
        return [{ type: 'text', text: JSON.stringify(errorResponse) }];
      }

      arguments_._user_info = userInfo;
      try {
        if (expectsSession) {
          const session = new SimpleSessionClass('', userInfo);
          return await (handler as ToolHandlerWithSession)(arguments_, session);
        }
        return await (handler as ToolHandler)(arguments_);
      } catch (e: any) {
        return toolExecutionError(options.toolName, e);
      }
    }

    const config = getInternalConfig();
    const sessionId = arguments_.session_id ?? getCurrentSessionId();
    if (sessionId && !arguments_.session_id) {
      arguments_.session_id = sessionId;
    }

    // Single API call to auth service for tool protection
    const payload = {
      session_id: sessionId,
      tool_name: options.toolName,
      client_id: config.clientId,
      app_name: config.appName,
    };

    const protectionResult = await makeAuthRequest('protect-tool', payload);

    // Check if access is allowed
    if (!protectionResult.allowed) {
      const errorResponse = {
        error: protectionResult.error ?? 'Access denied',
        message: protectionResult.message ?? 'Authentication failed',
        tool: options.toolName,
      };
      return [{ type: 'text', text: JSON.stringify(errorResponse) }];
    }

    const resolvedSessionId =
      protectionResult.session_id ?? sessionId;
    const userInfo = protectionResult.user_info ?? {};

    if (resolvedSessionId) {
      sessionUserInfo[String(resolvedSessionId)] = userInfo;
      arguments_.session_id = resolvedSessionId;
    }

    // Enforce RBAC at execution time
    const [rbacOk, rbacReason] = evaluateRbac(userInfo, rbacRequirements);
    if (!rbacOk) {
      const errorResponse = {
        error: 'Access denied',
        message: `RBAC denied: ${rbacReason}`,
        tool: options.toolName,
      };
      return [{ type: 'text', text: JSON.stringify(errorResponse) }];
    }

    // Add user info to arguments for the business function
    arguments_._user_info = userInfo;

    try {
      if (expectsSession) {
        const session = new SimpleSessionClass(
          String(resolvedSessionId ?? ''),
          protectionResult.user_info ?? {}
        );
        return await (handler as ToolHandlerWithSession)(arguments_, session);
      } else {
        return await (handler as ToolHandler)(arguments_);
      }
    } catch (e: any) {
      return toolExecutionError(options.toolName, e);
    }
  };

  return {
    handler: wrappedHandler,
    name: options.toolName,
    description: options.description,
    inputSchema: options.inputSchema,
    isProtected: true,
    rbacRequirements,
  };
}

function principalFromArguments(arguments_: Record<string, any>): Principal | null {
  const raw = arguments_?._authsec_principal;
  if (!raw || typeof raw !== 'object') return null;
  const principal = raw as Partial<Principal>;
  if (typeof principal.subject !== 'string') return null;
  return principal as Principal;
}

function userInfoFromPrincipal(principal: Principal): UserInfo {
  const claims = principal.claims ?? {};
  const workspaceID = stringClaim(claims.workspace_id);
  const userID = stringClaim(claims.user_id) ?? principal.subject;
  return {
    ...claims,
    workspace_id: workspaceID,
    user_id: userID,
    email: stringClaim(claims.email),
    roles: stringArrayClaim(claims.roles),
    groups: stringArrayClaim(claims.groups),
    scope: principal.scopes,
    scopes: principal.scopes,
  };
}

function stringClaim(value: unknown): string | undefined {
  return typeof value === 'string' && value ? value : undefined;
}

function stringArrayClaim(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  if (typeof value === 'string') return value.split(/\s+/).filter(Boolean);
  return [];
}

function toolExecutionError(toolName: string, e: any): McpContent[] {
  return [
    {
      type: 'text',
      text: JSON.stringify({
        error: 'Tool execution failed',
        message: `Internal error in ${toolName}: ${e.message ?? e}`,
        tool: toolName,
      }),
    },
  ];
}

interface McpToolOptions {
  name?: string;
  description?: string;
  inputSchema?: Record<string, any>;
}

/**
 * Define a standard MCP tool (no authentication required).
 *
 * @example
 * ```ts
 * const echoTool = mcpTool({
 *   name: 'echo',
 *   description: 'Echo a message',
 *   inputSchema: {
 *     type: 'object',
 *     properties: { message: { type: 'string' } },
 *     required: ['message'],
 *   },
 * }, async (args) => {
 *   return [{ type: 'text', text: args.message }];
 * });
 * ```
 */
export function mcpTool(
  options: McpToolOptions,
  handler: ToolHandler
): ToolDefinition {
  const toolName = options.name ?? handler.name ?? 'unnamed_tool';

  return {
    handler,
    name: toolName,
    description: options.description,
    inputSchema: options.inputSchema ?? {
      type: 'object',
      properties: {},
      required: [],
    },
    isProtected: false,
  };
}
