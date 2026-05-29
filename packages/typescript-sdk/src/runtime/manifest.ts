/**
 * publishManifest — best-effort one-way push of the tool inventory to AuthSec.
 *
 * TypeScript parity port of python/runtime/manifest.py and go-sdk's
 * manifest_publisher.go.
 *
 * Endpoint: ``PUT {authorizationServer}/authsec/resource-servers/{id}/sdk-manifest``.
 *
 * Failure never blocks startup — the runtime SDK works the same whether the
 * publish succeeded or not. Manifest sync is purely admin-facing inventory data.
 */

import type { Config, ManifestToolInput } from './config.js';

const MANIFEST_PUBLISH_TIMEOUT_MS = 30_000;

/** Canonical manifest tool entry. */
export interface ManifestTool {
  name: string;
  title?: string;
  description?: string;
  input_schema?: Record<string, unknown> | null;
  annotations?: Record<string, unknown> | null;
  suggested_scopes?: string[];
}

function normalizeTool(t: ManifestToolInput | ManifestTool): ManifestTool {
  const inputSchema =
    (t as ManifestToolInput).input_schema ??
    (t as ManifestToolInput).inputSchema ??
    null;
  const suggested =
    (t as ManifestToolInput).suggested_scopes ??
    (t as ManifestToolInput).scopes_required ??
    [];
  const out: ManifestTool = {
    name: (t as ManifestToolInput).name ?? (t as ManifestToolInput).tool_id ?? '',
  };
  if (t.title) out.title = t.title;
  if (t.description) out.description = t.description;
  if (inputSchema !== null && inputSchema !== undefined) out.input_schema = inputSchema;
  if (t.annotations !== null && t.annotations !== undefined) out.annotations = t.annotations;
  if (suggested && suggested.length > 0) out.suggested_scopes = [...suggested];
  return out;
}

function toJson(t: ManifestTool): Record<string, unknown> {
  const out: Record<string, unknown> = { name: t.name };
  if (t.title) out.title = t.title;
  if (t.description) out.description = t.description;
  if (t.input_schema !== null && t.input_schema !== undefined) out.input_schema = t.input_schema;
  if (t.annotations !== null && t.annotations !== undefined) out.annotations = t.annotations;
  if (t.suggested_scopes && t.suggested_scopes.length > 0) {
    out.suggested_scopes = [...t.suggested_scopes];
  }
  return out;
}

function buildPayload(
  tools: ManifestTool[],
  suggestions: Record<string, string[]>,
): Record<string, unknown> {
  const outTools = tools.map((t) => {
    const entry: ManifestTool = { ...t };
    if (!entry.suggested_scopes || entry.suggested_scopes.length === 0) {
      const sugg = suggestions[entry.name];
      if (sugg && sugg.length > 0) entry.suggested_scopes = [...sugg];
    }
    return toJson(entry);
  });
  return { tools: outTools };
}

/**
 * Enumerate tools and PUT the manifest to AuthSec.
 *
 * The ``tools`` argument is the explicit inventory; pass either an array of
 * ``ManifestTool`` shapes or use ``cfg.toolInventoryProvider`` (which takes
 * precedence). Either source is sufficient — synthetic MCP handshake-based
 * enumeration is not implemented in the TypeScript port.
 *
 * Throws on configuration / transport failure. Most callers should use
 * ``publishManifestSafe`` which logs-and-ignores at boot.
 */
export async function publishManifest(
  cfg: Config,
  tools: Array<ManifestToolInput | ManifestTool> = [],
): Promise<void> {
  if (!cfg.resourceServerId) {
    throw new Error('publishManifest requires resourceServerId');
  }
  if (!cfg.introspectionClientId || !cfg.introspectionClientSecret) {
    throw new Error('publishManifest requires introspection client credentials');
  }
  const base = (cfg.authorizationServer || cfg.issuer).replace(/\/+$/, '');
  if (!base) {
    throw new Error('publishManifest requires authorizationServer or issuer');
  }
  const endpoint = `${base}/authsec/resource-servers/${cfg.resourceServerId}/sdk-manifest`;

  let inventory: ManifestTool[];
  if (cfg.toolInventoryProvider) {
    const raw = await cfg.toolInventoryProvider();
    inventory = raw.map(normalizeTool);
  } else {
    inventory = tools.map(normalizeTool);
  }

  const payload = buildPayload(inventory, cfg.toolScopeSuggestions);

  const credentials = Buffer.from(
    `${cfg.introspectionClientId}:${cfg.introspectionClientSecret}`,
  ).toString('base64');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), MANIFEST_PUBLISH_TIMEOUT_MS);
  let resp: Response;
  try {
    resp = await fetch(endpoint, {
      method: 'PUT',
      headers: {
        Authorization: `Basic ${credentials}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
  if (resp.status < 200 || resp.status >= 300) {
    const body = await resp.text().catch(() => '');
    throw new Error(`manifest publish returned HTTP ${resp.status}: ${body.slice(0, 512)}`);
  }
}

/**
 * Like ``publishManifest`` but logs-and-ignores all failures. Designed for
 * boot-time use where manifest publish must never block startup.
 */
export async function publishManifestSafe(
  cfg: Config,
  tools: Array<ManifestToolInput | ManifestTool> = [],
  logger: { info?: (msg: string) => void; warn?: (msg: string) => void } = console,
): Promise<void> {
  try {
    await publishManifest(cfg, tools);
    logger.info?.(
      `authsec manifest published for resource_server_id=${cfg.resourceServerId}`,
    );
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    logger.warn?.(`authsec manifest publish failed (non-fatal): ${msg}`);
  }
}
