/**
 * AuthSec runtime SDK — barrel re-export.
 *
 * Mirrors the Python `authsec_sdk.runtime` and Go `authsec` packages. Use
 * `Runtime.create(cfg)` or `mountMCP(app, { config })` to protect an MCP
 * resource server.
 */

export {
  defaultConfig,
  effectivePolicyMode,
  effectiveValidationMode,
  loadConfigFromEnv,
  normalizeConfig,
  validateConfig,
  type Config,
  type ManifestToolInput,
  type PolicyMode,
  type ToolInventoryProvider,
  type ValidationMode,
} from './config.js';

export {
  hasAnyScope,
  newPrincipal,
  type Principal,
} from './principal.js';

export {
  hasAnyRequired,
  lookupTool,
  toolScopeMapFromRecord,
  type ToolPolicyOutcome,
  type ToolPolicyResult,
  type ToolScopeMap,
} from './policy.js';

export {
  PROTECTED_RESOURCE_PREFIX,
  buildMetadataPayload,
  buildResourceMetadataPath,
  buildResourceMetadataUrl,
  buildWwwAuthenticate,
  isMetadataRequest,
  metadataJsonResponse,
  type WwwAuthenticateOptions,
} from './metadata.js';

export {
  HybridValidator,
  ValidationError,
  newValidator,
  type ValidationErrorCode,
} from './validator.js';

export {
  PolicyIncompleteError,
  ScopeMatrixClient,
  type CacheStatus,
} from './scopeMatrix.js';

export {
  publishManifest,
  publishManifestSafe,
  type ManifestTool,
} from './manifest.js';

export {
  Runtime,
  type AuthorizeDenial,
  type AuthorizeResult,
  type DenialCode,
} from './runtime.js';

export {
  extractToolIdFromBody,
  mountMCP,
  type ExpressLikeApp,
  type ExpressLikeHandler,
  type ExpressLikeNext,
  type ExpressLikeRequest,
  type ExpressLikeResponse,
  type MountMcpOptions,
} from './server.js';
