/**
 * Express middleware for protecting an MCP route with AuthSec.
 *
 * TypeScript parity port of python/runtime/server.py's ``mount_mcp`` ASGI
 * middleware. Same lifecycle:
 *
 *  - On mount: validate config, build the Runtime, publish the manifest if
 *    ``tools`` provided, register the protected-resource-metadata GET handler
 *    at ``/.well-known/oauth-protected-resource{protected_path}``.
 *  - Per request on ``options.path`` (default ``/mcp``): extract bearer
 *    token from Authorization header, call ``runtime.authorize``, on allow
 *    attach ``req.locals.principal``, on deny respond with the structured
 *    body and ``WWW-Authenticate`` header.
 *  - Tool id extraction: read the JSON-RPC ``method`` / ``params.name`` from
 *    the request body. Same logic as Python ``server.py``.
 *
 * The Express types are imported through a structural shape so the package
 * can ship without forcing a hard dependency on @types/express at build time
 * (express remains an optional peer dependency).
 */

import type { Config, ManifestToolInput } from './config.js';
import { buildResourceMetadataPath, metadataJsonResponse } from './metadata.js';
import type { Principal } from './principal.js';
import { Runtime } from './runtime.js';

// Structural Express types — kept loose so we don't hard-depend on @types/express.
export interface ExpressLikeRequest {
  method: string;
  path?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  locals?: Record<string, unknown> & { principal?: Principal };
  // Express attaches its own locals on `res`, but the python parity puts the
  // principal on `req.locals` — we honor both.
}

export interface ExpressLikeResponse {
  status(code: number): ExpressLikeResponse;
  setHeader(name: string, value: string): ExpressLikeResponse | void;
  json(payload: unknown): ExpressLikeResponse | void;
  send(payload?: unknown): ExpressLikeResponse | void;
}

export type ExpressLikeNext = (err?: unknown) => void;

export type ExpressLikeHandler = (
  req: ExpressLikeRequest,
  res: ExpressLikeResponse,
  next: ExpressLikeNext,
) => unknown | Promise<unknown>;

export interface ExpressLikeApp {
  get(path: string, handler: ExpressLikeHandler): unknown;
  use(path: string, handler: ExpressLikeHandler): unknown;
  use(handler: ExpressLikeHandler): unknown;
}

export interface MountMcpOptions {
  config: Config;
  tools?: ManifestToolInput[];
  /** URL prefix to protect (default ``"/mcp"``). */
  path?: string;
}

/**
 * Mount an AuthSec-protected MCP route on an Express app.
 *
 * Returns the constructed Runtime so the caller can hook into it for tests
 * or further customisation.
 */
export async function mountMCP(
  app: ExpressLikeApp,
  options: MountMcpOptions,
): Promise<Runtime> {
  const cfg = options.config;
  const path = options.path ?? '/mcp';
  const runtime = await Runtime.create(cfg);

  // Best-effort manifest publish from explicit tools list, if supplied.
  // (Runtime.startup already triggered the manifest if cfg.publishManifest
  // is true and no toolInventoryProvider was wired; here we additionally
  // honor the explicit ``tools`` mount option.)
  if (options.tools && options.tools.length > 0 && cfg.publishManifest) {
    // Re-trigger with the explicit tools list. publishManifestSafe doesn't
    // throw, so it's safe to await here without blocking startup semantics.
    const { publishManifestSafe } = await import('./manifest.js');
    void publishManifestSafe(cfg, options.tools);
  }

  // ── Metadata route (RFC 9728) ────────────────────────────────────
  // PRM is served from the runtime's scope-matrix cache so admin-side scope
  // changes in AuthSec auto-propagate without redeploy. Falls back to
  // cfg.supportedScopes only when the cache hasn't populated (boot race) or
  // when policyMode=local_only.
  const metadataPath = buildResourceMetadataPath(cfg.resourceUri);
  app.get(metadataPath, async (_req, res) => {
    const authoritative = await runtime.getAuthoritativeScopes();
    const { body, headers } = metadataJsonResponse(runtime.cfg, authoritative);
    for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
    res.status(200).send(body);
  });

  // ── Protected MCP route ──────────────────────────────────────────
  const protectedHandler: ExpressLikeHandler = async (req, res, next) => {
    const authHeader = headerString(req.headers['authorization']);
    const token = extractBearer(authHeader);

    const result = await runtime.authorize(token, '');
    if (!result.allowed) {
      res.setHeader('WWW-Authenticate', result.denial.wwwAuthenticate);
      const body: Record<string, unknown> = {
        error:
          result.denial.code === 'scope_insufficient'
            ? 'insufficient_scope'
            : result.denial.code,
        error_description: result.denial.description,
      };
      if (result.denial.requiredScopes) body.required_scopes = result.denial.requiredScopes;
      if (result.denial.tool) body.tool = result.denial.tool;
      res.status(result.denial.status).json(body);
      return;
    }

    for (const toolId of extractToolIdsFromBody(req.body)) {
      const toolResult = await runtime.authorizePrincipal(result.principal, toolId);
      if (!toolResult.allowed) {
        res.setHeader('WWW-Authenticate', toolResult.denial.wwwAuthenticate);
        const body: Record<string, unknown> = {
          error:
            toolResult.denial.code === 'scope_insufficient'
              ? 'insufficient_scope'
              : toolResult.denial.code,
          error_description: toolResult.denial.description,
        };
        if (toolResult.denial.requiredScopes) body.required_scopes = toolResult.denial.requiredScopes;
        if (toolResult.denial.tool) body.tool = toolResult.denial.tool;
        res.status(toolResult.denial.status).json(body);
        return;
      }
    }

    // Attach principal for downstream handlers.
    req.locals = req.locals ?? {};
    req.locals.principal = result.principal;

    if (isToolsListRequest(req.body)) {
      wrapToolsListResponse(runtime, result.principal, res);
    }

    next();
  };

  app.use(path, protectedHandler);

  return runtime;
}

// ── Helpers ──────────────────────────────────────────────────────────

function headerString(v: string | string[] | undefined): string {
  if (!v) return '';
  if (Array.isArray(v)) return v[0] ?? '';
  return v;
}

function extractBearer(authorizationHeader: string): string {
  if (!authorizationHeader) return '';
  const parts = authorizationHeader.split(/\s+/, 2);
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') return '';
  return parts[1].trim();
}

/**
 * Extract a tool id from a JSON-RPC request body. Returns the empty string
 * for non tools/call requests. Mirrors Python ``server.py``.
 */
export function extractToolIdFromBody(body: unknown): string {
  return extractToolIdsFromBody(body)[0] ?? '';
}

/**
 * Extract tool ids from a JSON-RPC request body. Handles single requests and
 * batches; non tools/call requests are ignored.
 */
export function extractToolIdsFromBody(body: unknown): string[] {
  if (!body || typeof body !== 'object') return [];
  if (Array.isArray(body)) {
    return body.flatMap((item) => extractToolIdsFromBody(item));
  }
  const obj = body as Record<string, unknown>;
  if (obj.method !== 'tools/call') return [];
  const params = (obj.params as Record<string, unknown> | undefined) ?? {};
  const name = params.name;
  return typeof name === 'string' ? [name] : [];
}

function isToolsListRequest(body: unknown): boolean {
  if (!body || typeof body !== 'object') return false;
  if (Array.isArray(body)) return body.some(isToolsListRequest);
  return (body as Record<string, unknown>).method === 'tools/list';
}

function wrapToolsListResponse(
  runtime: Runtime,
  principal: Principal,
  res: ExpressLikeResponse,
): void {
  const raw = res as unknown as {
    json: (payload: unknown) => unknown;
    send: (payload?: unknown) => unknown;
    status: (code: number) => unknown;
    setHeader: (name: string, value: string) => unknown;
  };
  const originalJson = raw.json.bind(raw);
  const originalSend = raw.send.bind(raw);

  raw.json = (payload: unknown) => {
    void filterToolsListPayload(runtime, principal, payload)
      .then((filtered) => originalJson(filtered))
      .catch((err) => writeFilterError(raw, originalJson, err));
    return res;
  };

  raw.send = (payload?: unknown) => {
    if (typeof payload !== 'string' && !Buffer.isBuffer(payload)) {
      return originalSend(payload);
    }
    const text = Buffer.isBuffer(payload) ? payload.toString('utf8') : payload;
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return originalSend(payload);
    }
    void filterToolsListPayload(runtime, principal, parsed)
      .then((filtered) => originalSend(JSON.stringify(filtered)))
      .catch((err) => writeFilterError(raw, originalJson, err));
    return res;
  };
}

async function filterToolsListPayload(
  runtime: Runtime,
  principal: Principal,
  payload: unknown,
): Promise<unknown> {
  if (Array.isArray(payload)) {
    return Promise.all(payload.map((item) => filterToolsListPayload(runtime, principal, item)));
  }
  if (!payload || typeof payload !== 'object') return payload;
  const obj = payload as Record<string, unknown>;
  const result = obj.result;
  if (!result || typeof result !== 'object') return payload;
  const resultObj = result as Record<string, unknown>;
  if (!Array.isArray(resultObj.tools)) return payload;

  const filtered: unknown[] = [];
  for (const tool of resultObj.tools) {
    if (!tool || typeof tool !== 'object') continue;
    const name = (tool as Record<string, unknown>).name;
    if (typeof name !== 'string' || !name) continue;
    const decision = await runtime.authorizePrincipal(principal, name);
    if (!decision.allowed) {
      if (decision.denial.code === 'policy_unavailable') {
        throw decision.denial;
      }
      continue;
    }
    filtered.push(tool);
  }
  return {
    ...obj,
    result: {
      ...resultObj,
      tools: filtered,
    },
  };
}

function writeFilterError(
  res: {
    json: (payload: unknown) => unknown;
    status: (code: number) => unknown;
    setHeader: (name: string, value: string) => unknown;
  },
  originalJson: (payload: unknown) => unknown,
  err: unknown,
): void {
  const denial =
    err && typeof err === 'object' && 'code' in err
      ? (err as { code?: string; status?: number; description?: string; wwwAuthenticate?: string })
      : null;
  if (denial?.wwwAuthenticate) {
    res.setHeader('WWW-Authenticate', denial.wwwAuthenticate);
  }
  res.status(denial?.status ?? 503);
  originalJson({
    error: denial?.code ?? 'policy_unavailable',
    error_description: denial?.description ?? 'tool policy unavailable',
  });
}
