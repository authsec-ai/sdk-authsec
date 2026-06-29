/**
 * @authsec/sdk client-side helpers (agent side).
 *
 * Import from `@authsec/sdk/client` to get typed exceptions and the
 * `parseMcpError` helper for translating raw 401/403 responses (or wrapped
 * Errors from transports like @modelcontextprotocol/sdk and
 * langchain-mcp-adapters) into actionable Python-style class instances.
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
