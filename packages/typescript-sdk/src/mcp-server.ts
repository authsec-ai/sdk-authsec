/**
 * MCP Server implementation
 * Mirrors Python MCPServer class + run_mcp_server_with_oauth
 */

import express from 'express';
import cors from 'cors';
import { spawn } from 'node:child_process';
import { makeAuthRequest } from './http.js';
import {
  clearCurrentSessionId,
  configureAuth,
  getCurrentSessionId,
  getInternalConfig,
  normalizeRuntimeClientId,
  setCurrentSessionId,
} from './config.js';
import type { ToolDefinition, McpMessage } from './types.js';

class MCPServer {
  private clientId: string;
  private appName: string;
  private userTools: Array<Record<string, any>> = [];
  private unprotectedTools: Array<Record<string, any>> = [];
  private toolHandlers: Map<string, (args: Record<string, any>) => Promise<any>> = new Map();
  public app: express.Express;

  constructor(clientId: string, appName: string) {
    this.clientId = clientId;
    this.appName = appName;

    this.app = express();
    this.app.use(cors());
    this.app.use(express.json({ limit: '10mb' }));

    this.setupRoutes();
  }

  /**
   * Register tools (replaces Python's set_user_module with module introspection).
   * In JS/TS, users pass an array of ToolDefinition objects.
   */
  setTools(tools: ToolDefinition[]): void {
    for (const tool of tools) {
      if (tool.isProtected) {
        // Protected tool — extract metadata and send to SDK Manager
        const toolMetadata: Record<string, any> = {
          name: tool.name,
          rbac: {
            roles: tool.rbacRequirements?.roles ?? [],
            groups: tool.rbacRequirements?.groups ?? [],
            resources: tool.rbacRequirements?.resources ?? [],
            scopes: tool.rbacRequirements?.scopes ?? [],
            permissions: tool.rbacRequirements?.permissions ?? [],
            require_all: tool.rbacRequirements?.requireAll ?? false,
          },
        };

        if (tool.description) {
          toolMetadata.description = tool.description;
        }
        if (tool.inputSchema) {
          toolMetadata.inputSchema = tool.inputSchema;
        }

        this.userTools.push(toolMetadata);
        this.toolHandlers.set(tool.name, tool.handler);
      } else {
        // Unprotected tool — register as standard MCP tool
        const toolSchema: Record<string, any> = {
          name: tool.name,
          description: tool.description ?? `Tool: ${tool.name}`,
          inputSchema: tool.inputSchema ?? {
            type: 'object',
            properties: {},
            required: [],
          },
        };

        this.unprotectedTools.push(toolSchema);
        this.toolHandlers.set(tool.name, tool.handler);
        console.log(
          `Registered unprotected tool: ${tool.name} (standard MCP tool, no auth required)`
        );
      }
    }
  }

  private setupRoutes(): void {
    this.app.get('/', (_req, res) => {
      const config = getInternalConfig();
      res.json({
        name: this.appName,
        version: '1.0.0',
        protocol: 'mcp-with-oauth',
        status: 'running',
        auth_service: config.authServiceUrl,
        services_url: config.servicesBaseUrl,
      });
    });

    this.app.post('/', async (req, res) => {
      try {
        const message = req.body as McpMessage;
        const response = await this.processMcpMessage(message, req);
        res.json(response);
      } catch (e: any) {
        res.json({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32603, message: e.message ?? String(e) },
        });
      }
    });
  }

  private deriveReturnUrl(req: express.Request): string | null {
    const referer = req.headers.referer;
    if (referer) {
      try {
        const parsed = new URL(referer);
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
          return parsed.origin + (parsed.pathname || '/') + parsed.search + parsed.hash;
        }
      } catch {
        // ignore
      }
    }

    const origin = req.headers.origin;
    if (origin) {
      try {
        const parsed = new URL(origin);
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
          return `${parsed.protocol}//${parsed.host}/`;
        }
      } catch {
        // ignore
      }
    }

    return null;
  }

  private normalizeOauthArguments(
    arguments_: Record<string, any>
  ): Record<string, any> {
    if (typeof arguments_ !== 'object' || arguments_ === null) {
      return arguments_;
    }

    const args = { ...arguments_ };

    for (const [key, value] of Object.entries(args)) {
      if (Array.isArray(value)) {
        if (value.length === 1) {
          args[key] = String(value[0]);
        } else {
          args[key] = value.map(String).join(' ');
        }
      }
    }

    return args;
  }

  private shouldOpenBrowser(arguments_: Record<string, any>): boolean {
    const value = arguments_?.open_browser;
    if (typeof value === 'boolean') return value;
    if (typeof value === 'string') {
      return ['1', 'true', 'yes', 'on'].includes(value.trim().toLowerCase());
    }
    return false;
  }

  private openBrowser(url: string): boolean {
    try {
      let command: string;
      let args: string[];

      if (process.platform === 'darwin') {
        command = 'open';
        args = [url];
      } else if (process.platform === 'win32') {
        command = 'cmd';
        args = ['/c', 'start', '', url];
      } else {
        command = 'xdg-open';
        args = [url];
      }

      const child = spawn(command, args, {
        detached: true,
        stdio: 'ignore',
      });
      child.unref();
      return true;
    } catch {
      return false;
    }
  }

  private maybeOpenBrowserFromContent(
    content: Array<Record<string, any>>
  ): boolean {
    for (const item of content) {
      if (typeof item?.text !== 'string') continue;
      try {
        const payload = JSON.parse(item.text);
        if (
          typeof payload === 'object' &&
          payload !== null &&
          typeof payload.authorization_url === 'string' &&
          payload.authorization_url
        ) {
          const opened = this.openBrowser(payload.authorization_url);
          payload.browser_opened = opened;
          item.text = JSON.stringify(payload, null, 2);
          return opened;
        }
      } catch {
        // ignore non-JSON text payloads
      }
    }
    return false;
  }

  private updateCurrentSessionFromOauthContent(
    toolName: string,
    content: Array<Record<string, any>>
  ): void {
    for (const item of content) {
      if (item?.type !== 'text' || typeof item.text !== 'string') continue;
      try {
        const payload = JSON.parse(item.text);
        if (!payload || typeof payload !== 'object' || payload.error) return;

        const sessionId =
          typeof payload.session_id === 'string' ? payload.session_id : null;

        if ((toolName === 'oauth_start' || toolName === 'oauth_authenticate') && sessionId) {
          setCurrentSessionId(sessionId);
          return;
        }

        if (toolName === 'oauth_status') {
          if (payload.status === 'authenticated' && sessionId) {
            setCurrentSessionId(sessionId);
          } else if (
            payload.status === 'expired' ||
            payload.status === 'not_found' ||
            payload.status === 'logged_out'
          ) {
            clearCurrentSessionId(sessionId);
          }
          return;
        }

        if (toolName === 'oauth_logout') {
          clearCurrentSessionId(sessionId);
          return;
        }
      } catch {
        return;
      }
    }
  }

  private async processMcpMessage(
    message: McpMessage,
    req: express.Request
  ): Promise<Record<string, any>> {
    const method = message.method;
    const messageId = message.id;
    const params = message.params ?? {};

    if (method === 'initialize') {
      return {
        jsonrpc: '2.0',
        id: messageId,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: this.appName, version: '1.0.0' },
        },
      };
    }

    if (method === 'tools/list') {
      // Get protected tools from SDK Manager (with OAuth and RBAC)
      let toolsResponse: Record<string, any>;
      const toolsListTimeout = parseInt(
        process.env.AUTHSEC_TOOLS_LIST_TIMEOUT_SECONDS ?? '8',
        10
      );

      try {
        toolsResponse = await Promise.race([
          makeAuthRequest('tools/list', {
            client_id: this.clientId,
            app_name: this.appName,
            session_id: getCurrentSessionId(),
            user_tools: this.userTools,
          }),
          new Promise<Record<string, any>>((_, reject) =>
            setTimeout(
              () => reject(new Error('tools/list timed out')),
              toolsListTimeout * 1000
            )
          ),
        ]);
      } catch {
        toolsResponse = { error: 'tools/list timed out against auth service' };
      }

      // Combine protected tools (from SDK Manager) with unprotected tools (local)
      const remoteTools = Array.isArray(toolsResponse?.tools)
        ? toolsResponse.tools
        : [];
      const allTools = [...remoteTools, ...this.unprotectedTools];

      return {
        jsonrpc: '2.0',
        id: messageId,
        result: { tools: allTools },
      };
    }

    if (method === 'tools/call') {
      const toolName: string = params.name;
      let arguments_ = params.arguments ?? {};
      let content: Array<Record<string, any>>;

      if (toolName.startsWith('oauth_')) {
        // Delegate OAuth tools to hosted service
        arguments_ = this.normalizeOauthArguments(arguments_);
        if (
          toolName === 'oauth_authenticate' &&
          typeof arguments_ === 'object' &&
          arguments_ !== null &&
          typeof arguments_.jwt_token === 'string'
        ) {
          // Backward/forward compatibility across auth service payload variants.
          const token = arguments_.jwt_token;
          if (!arguments_.token) arguments_.token = token;
          if (!arguments_.jwt) arguments_.jwt = token;
          if (!arguments_.access_token) arguments_.access_token = token;
        }
        if (
          toolName === 'oauth_start' &&
          typeof arguments_ === 'object' &&
          !arguments_.return_url
        ) {
          const autoReturnUrl = this.deriveReturnUrl(req);
          if (autoReturnUrl) {
            arguments_.return_url = autoReturnUrl;
          }
        }

        const toolResponse = await makeAuthRequest(
          `tools/call/${toolName}`,
          {
            client_id: this.clientId,
            app_name: this.appName,
            arguments: arguments_,
          }
        );

        if (
          typeof toolResponse === 'object' &&
          Array.isArray(toolResponse.content)
        ) {
          content = toolResponse.content;
          this.updateCurrentSessionFromOauthContent(toolName, content);
          if (
            toolName === 'oauth_start' &&
            typeof arguments_ === 'object' &&
            arguments_ !== null &&
            this.shouldOpenBrowser(arguments_)
          ) {
            this.maybeOpenBrowserFromContent(content);
          }
        } else {
          // Preserve useful upstream diagnostics
          const errorPayload: Record<string, any> = {
            error: 'Tool execution failed',
            tool: toolName,
          };
          if (typeof toolResponse === 'object') {
            if (toolResponse.detail) errorPayload.detail = toolResponse.detail;
            if (toolResponse.error)
              errorPayload.upstream_error = toolResponse.error;
            if (toolResponse.message)
              errorPayload.upstream_message = toolResponse.message;
          }
          content = [{ type: 'text', text: JSON.stringify(errorPayload) }];
        }
      } else if (this.toolHandlers.has(toolName)) {
        if (
          typeof arguments_ === 'object' &&
          arguments_ !== null &&
          !arguments_.session_id &&
          getCurrentSessionId()
        ) {
          arguments_.session_id = getCurrentSessionId();
        }
        // Execute user's tool locally
        content = await this.toolHandlers.get(toolName)!(arguments_);
      } else {
        content = [
          {
            type: 'text',
            text: JSON.stringify({ error: `Unknown tool: ${toolName}` }),
          },
        ];
      }

      return {
        jsonrpc: '2.0',
        id: messageId,
        result: { content },
      };
    }

    return {
      jsonrpc: '2.0',
      id: messageId,
      error: { code: -32601, message: `Method not found: ${method}` },
    };
  }

  private async cleanupSessions(): Promise<void> {
    try {
      const result = await makeAuthRequest('cleanup-sessions', {
        client_id: this.clientId,
        app_name: this.appName,
        reason: 'server_shutdown',
      });
      console.log(`Sessions cleanup: ${result.message ?? 'Completed'}`);
    } catch (e: any) {
      console.log(`Session cleanup failed: ${e.message ?? e}`);
    }
  }

  setupShutdownHandlers(): void {
    const handler = () => {
      console.log('\nReceived shutdown signal, cleaning up sessions...');
      this.cleanupSessions()
        .catch(() => {})
        .finally(() => process.exit(0));
    };

    process.on('SIGINT', handler);
    process.on('SIGTERM', handler);
  }
}

export interface RunMcpServerOptions {
  /** Array of tool definitions created by protectedByAuthSec() and mcpTool() */
  tools: ToolDefinition[];
  /** Your client ID from AuthSec */
  clientId: string;
  /** Application name */
  appName: string;
  /** Server host (default: "0.0.0.0") */
  host?: string;
  /** Server port (default: 3005) */
  port?: number;
  /** Optional path to SPIRE agent socket */
  spireSocketPath?: string;
}

/**
 * Run MCP server using SDK Manager for auth.
 *
 * @example
 * ```ts
 * import { protectedByAuthSec, mcpTool, runMcpServerWithOAuth } from '@authsec/sdk';
 *
 * const myTool = protectedByAuthSec({
 *   toolName: 'my_tool',
 *   roles: ['admin'],
 * }, async (args, session) => {
 *   return [{ type: 'text', text: 'Hello!' }];
 * });
 *
 * runMcpServerWithOAuth({
 *   tools: [myTool],
 *   clientId: 'your-client-id',
 *   appName: 'my-app',
 * });
 * ```
 */
export function runMcpServerWithOAuth(options: RunMcpServerOptions): void {
  const host = options.host ?? '0.0.0.0';
  const port = options.port ?? 3005;

  const authServiceUrl = process.env.AUTHSEC_AUTH_SERVICE_URL;
  const servicesBaseUrl = process.env.AUTHSEC_SERVICES_URL;
  const timeoutSeconds = parseInt(
    process.env.AUTHSEC_TIMEOUT_SECONDS ?? '15',
    10
  );
  const retries = parseInt(process.env.AUTHSEC_RETRIES ?? '2', 10);

  const runtimeClientId = normalizeRuntimeClientId(options.clientId);

  configureAuth(runtimeClientId, options.appName, {
    authServiceUrl: authServiceUrl ?? undefined,
    servicesBaseUrl: servicesBaseUrl ?? undefined,
    timeout: timeoutSeconds,
    retries,
  });

  // Store SPIRE socket path in global config if provided
  const config = getInternalConfig();
  if (options.spireSocketPath) {
    config.spireSocketPath = options.spireSocketPath;
    config.spireEnabled = true;
  } else {
    config.spireEnabled = false;
  }

  const server = new MCPServer(runtimeClientId, options.appName);
  server.setTools(options.tools);
  server.setupShutdownHandlers();

  console.log(`Starting ${options.appName} MCP Server on ${host}:${port}`);
  console.log(`Authentication via: ${config.authServiceUrl}`);
  console.log(`Services via: ${config.servicesBaseUrl}`);

  if (config.spireEnabled) {
    console.log('SPIRE Workload Identity: ENABLED');
    console.log(`  Agent socket: ${config.spireSocketPath}`);
  } else {
    console.log('SPIRE Workload Identity: DISABLED');
  }

  console.log(
    `MCP Inspector: npx @modelcontextprotocol/inspector http://${host}:${port}`
  );

  server.app.listen(port, host, () => {
    console.log(`Server listening on ${host}:${port}`);
  });
}
