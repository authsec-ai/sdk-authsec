/**
 * Tool→scope policy primitives.
 *
 * TypeScript parity port of python/runtime/policy.py.
 *
 * The authoritative tool→scope mapping lives in AuthSec's Scope Matrix UI.
 * When ``resourceServerId`` is set in Config, the SDK fetches this mapping
 * from AuthSec at startup and refreshes it periodically. Developers do not
 * need to maintain tool→scope mappings in code.
 *
 * A ToolScopeMap can also be set directly via ``Config.toolScopes`` as a
 * local defense-in-depth fallback.
 */

/**
 * The mapping shape returned from the scope matrix endpoint, including the
 * structured form with ``policy_complete`` and ``tools``.
 *
 * The keys of ``tools`` are tool ids; the value lists the OAuth scopes
 * required (empty array == public).
 */
export interface ToolScopeMap {
  policy_complete: boolean;
  tools: Record<string, { required_any: string[] }>;
}

/** Three-state outcome of `lookupTool`. */
export type ToolPolicyOutcome = 'absent' | 'public' | 'scoped';

/**
 * Result of resolving a tool against the policy. ``denied`` is set with a
 * short reason string when the policy says the tool must be denied (e.g. it
 * was absent from a non-OPEN policy, or the policy was incomplete).
 */
export interface ToolPolicyResult {
  outcome: ToolPolicyOutcome;
  required_any: string[];
  denied?: string;
}

/**
 * Look up a tool in the policy map. Returns a typed result with the required
 * scopes (empty for ABSENT / PUBLIC). Callers must combine this with the
 * effective policy mode to decide whether to allow an absent tool.
 */
export function lookupTool(
  matrix: ToolScopeMap | null | undefined,
  toolId: string,
): ToolPolicyResult {
  if (!matrix) {
    return { outcome: 'absent', required_any: [] };
  }
  if (!matrix.policy_complete) {
    return {
      outcome: 'absent',
      required_any: [],
      denied: 'policy_incomplete',
    };
  }
  const name = (toolId ?? '').trim();
  const entry = matrix.tools[name];
  if (!entry) {
    return { outcome: 'absent', required_any: [] };
  }
  const required = entry.required_any ?? [];
  if (required.length === 0) {
    return { outcome: 'public', required_any: [] };
  }
  return { outcome: 'scoped', required_any: [...required] };
}

/** True iff any of ``granted`` is in ``required``; empty required is OK. */
export function hasAnyRequired(required: string[], granted: Set<string> | string[]): boolean {
  if (!required || required.length === 0) return true;
  const gset = granted instanceof Set ? granted : new Set(granted);
  for (const r of required) {
    if (gset.has(r)) return true;
  }
  return false;
}

/**
 * Build a ToolScopeMap from the simpler ``Record<string, string[]>`` shape
 * that Config.toolScopes uses. Empty array → public.
 */
export function toolScopeMapFromRecord(
  record: Record<string, string[]> | null | undefined,
): ToolScopeMap | null {
  if (!record) return null;
  const tools: Record<string, { required_any: string[] }> = {};
  for (const [name, scopes] of Object.entries(record)) {
    tools[name] = { required_any: [...(scopes ?? [])] };
  }
  return { policy_complete: true, tools };
}
