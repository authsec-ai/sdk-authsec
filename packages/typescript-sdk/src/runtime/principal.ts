/**
 * Principal — the authenticated subject extracted from a validated token.
 *
 * TypeScript parity port of python/runtime/principal.py.
 */

export interface Principal {
  /** The token's ``sub`` claim — the user or service-account identifier. */
  subject: string;

  /** The token's ``iss`` claim — the authorization server. */
  issuer: string;

  /** The token's ``aud`` claim, normalized to an array. */
  audience: string[];

  /** OAuth scopes carried by the token. */
  scopes: string[];

  /** Raw claim map for downstream consumers that need extra attributes. */
  claims: Record<string, unknown>;

  /**
   * False indicates introspection returned ``active=false`` — the token is
   * revoked / suspended / expired even if the JWT signature was valid.
   */
  active: boolean;
}

/** Build a Principal with defaults filled in. */
export function newPrincipal(partial: Partial<Principal> = {}): Principal {
  return {
    subject: '',
    issuer: '',
    audience: [],
    scopes: [],
    claims: {},
    active: true,
    ...partial,
  };
}

/**
 * True if the principal holds at least one of ``required``. An empty
 * ``required`` list always returns true (no requirement).
 */
export function hasAnyScope(principal: Principal, required: string[]): boolean {
  if (!required || required.length === 0) return true;
  const granted = new Set(principal.scopes);
  for (const scope of required) {
    if (granted.has(scope)) return true;
  }
  return false;
}
