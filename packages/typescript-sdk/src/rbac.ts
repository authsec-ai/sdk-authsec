/**
 * RBAC evaluation logic
 * Mirrors Python _evaluate_rbac and _normalize_claim_list
 */

import type { RbacRequirements, UserInfo } from './types.js';

/**
 * Normalize a claim value to a Set of strings.
 */
function normalizeClaimList(value: any): Set<string> {
  if (value == null) return new Set();
  if (typeof value === 'string') return new Set([value]);
  if (Array.isArray(value)) {
    return new Set(
      value
        .filter((v) => v != null && String(v) !== '')
        .map((v) => String(v))
    );
  }
  return new Set();
}

/**
 * Evaluate RBAC requirements against user info.
 *
 * @returns [allowed, reason] - allowed is true if access is granted, reason explains denial
 */
export function evaluateRbac(
  userInfo: UserInfo,
  requirements: RbacRequirements
): [boolean, string] {
  const rolesReq = new Set(requirements.roles ?? []);
  const groupsReq = new Set(requirements.groups ?? []);
  const resourcesReq = new Set(requirements.resources ?? []);
  const scopesReq = new Set(requirements.scopes ?? []);
  const permsReq = new Set(requirements.permissions ?? []);
  const requireAll = requirements.requireAll ?? false;

  // Normalize user claims
  const userRoles = normalizeClaimList(userInfo.roles);
  const userGroups = normalizeClaimList(userInfo.groups);

  // Scopes from both 'scopes' and 'scope' claims
  const rawScopes = union(
    normalizeClaimList(userInfo.scopes),
    normalizeClaimList(userInfo.scope)
  );

  // Resources: direct claim + extracted from "resource:action" scopes
  const userResources = normalizeClaimList(userInfo.resources);
  for (const s of rawScopes) {
    if (s.includes(':')) {
      userResources.add(s.split(':')[0]!);
    }
  }

  // Scopes: non-resource scopes + action part of "resource:action"
  const userScopes = new Set<string>();
  for (const s of rawScopes) {
    if (s.includes(':')) {
      userScopes.add(s.split(':')[1]!);
    } else {
      userScopes.add(s);
    }
  }

  // Permissions: direct claim + "resource:action" scopes
  const userPerms = normalizeClaimList(userInfo.permissions);
  for (const s of rawScopes) {
    if (s.includes(':')) {
      userPerms.add(s);
    }
  }

  // Build checks map
  const checks: Record<string, boolean> = {};

  if (rolesReq.size > 0) {
    checks['roles'] = hasIntersection(userRoles, rolesReq);
  }
  if (groupsReq.size > 0) {
    checks['groups'] = hasIntersection(userGroups, groupsReq);
  }
  if (resourcesReq.size > 0) {
    checks['resources'] = hasIntersection(userResources, resourcesReq);
  }
  if (scopesReq.size > 0) {
    checks['scopes'] = hasIntersection(userScopes, scopesReq);
  }
  if (permsReq.size > 0) {
    if (userPerms.size > 0) {
      checks['permissions'] = hasIntersection(userPerms, permsReq);
    } else {
      // Fallback: check if user has matching resource + action combo
      let allowed = false;
      for (const perm of permsReq) {
        if (perm.includes(':')) {
          const [res, act] = perm.split(':');
          if (userResources.has(res!) && userScopes.has(act!)) {
            allowed = true;
            break;
          }
        }
      }
      checks['permissions'] = allowed;
    }
  }

  // No RBAC requirements -> allow
  if (Object.keys(checks).length === 0) {
    return [true, ''];
  }

  if (requireAll) {
    const missing = Object.entries(checks)
      .filter(([_, ok]) => !ok)
      .map(([k]) => k);
    if (missing.length > 0) {
      return [false, `missing required ${missing.join(', ')}`];
    }
    return [true, ''];
  }

  // OR logic across categories
  if (Object.values(checks).some((v) => v)) {
    return [true, ''];
  }
  return [false, 'no RBAC requirement satisfied'];
}

function hasIntersection(a: Set<string>, b: Set<string>): boolean {
  for (const item of a) {
    if (b.has(item)) return true;
  }
  return false;
}

function union(a: Set<string>, b: Set<string>): Set<string> {
  const result = new Set(a);
  for (const item of b) {
    result.add(item);
  }
  return result;
}
