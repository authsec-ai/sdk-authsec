/**
 * @authsec/sdk client-side helpers (agent side).
 *
 * Import from `@authsec/sdk/client` to get typed exceptions and the
 * `parseMcpError` helper for translating raw 401/403 responses (or wrapped
 * Errors from transports like @modelcontextprotocol/sdk and
 * langchain-mcp-adapters) into actionable class instances.
 *
 * **Tool-error middleware** — use {@link authsecToolErrorHandler} to convert
 * tool-call errors into actionable strings for the LLM:
 *
 * ```ts
 * import { authsecToolErrorHandler } from '@authsec/sdk/client';
 *
 * // Wrap each tool call
 * const result = await callTool(name, args).catch(authsecToolErrorHandler);
 * ```
 *
 * **Bearer-token separation:** AuthSec bearer tokens authenticate the *agent*
 * to the AuthSec authorization layer.  If the MCP server requires a separate
 * upstream credential (e.g. a GitHub PAT), that credential must travel as a
 * server-owned env var (`UPSTREAM_API_TOKEN`) — never in the same
 * `Authorization` header.  The SDK never mixes the two layers.
 */
export {
  AuthRequiredError,
  AuthSecAccessError,
  ClientRegistrationRevokedError,
  InsufficientScopeError,
  TokenRevokedError,
  parseMcpError,
} from './errors.js';
export type { AuthSecReason, AuthSecAccessErrorInit, InsufficientScopeInit, AuthRequiredInit } from './errors.js';
export { authsecToolErrorHandler } from './tool-error-handler.js';
