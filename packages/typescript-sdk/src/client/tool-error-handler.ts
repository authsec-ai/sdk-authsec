/**
 * Tool-error middleware for AuthSec-protected MCP tool calls.
 *
 * Converts any tool-call error into an actionable, LLM-readable string.
 * AuthSec 401/403 denials are parsed into human-readable messages; other
 * errors are stringified so the LLM can still respond instead of the
 * agent loop crashing.
 *
 * Usage with any agent framework:
 *
 * ```ts
 * import { authsecToolErrorHandler } from '@authsec/sdk/client';
 *
 * // As a .catch() handler
 * const result = await callTool(name, args).catch(authsecToolErrorHandler);
 *
 * // Or in a try/catch
 * try {
 *   return await callTool(name, args);
 * } catch (e) {
 *   return authsecToolErrorHandler(e);
 * }
 * ```
 */

import { parseMcpError } from './errors.js';

/**
 * Convert any tool-call error into an actionable LLM-readable string.
 *
 * Tries to parse the error as an AuthSec access error first; falls back to
 * a generic representation so the LLM can still respond.
 */
export async function authsecToolErrorHandler(error: unknown): Promise<string> {
  const accessErr = await parseMcpError(error);
  if (accessErr !== null) {
    return accessErr.formatForUser();
  }
  // Non-AuthSec tool error — return as plain text so the LLM can respond.
  if (error instanceof Error) {
    return `Tool call failed: ${error.message}`;
  }
  return `Tool call failed: ${String(error)}`;
}
