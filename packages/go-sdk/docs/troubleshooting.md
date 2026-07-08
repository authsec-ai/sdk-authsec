# Troubleshooting

A consolidated map of symptom → cause → fix, grouped by where the problem
shows up. Guide-specific tables live in each guide; this page is the
single lookup.

- [Server startup](#server-startup)
- [Protection-check / dashboard](#protection-check--dashboard)
- [Token validation](#token-validation)
- [Scopes & authorization](#scopes--authorization)
- [Manifest publishing](#manifest-publishing)
- [Agent-side token acquisition (M2M)](#agent-side-token-acquisition-m2m)
- [ID-JAG delegation](#id-jag-delegation)
- [SPIFFE / SPIRE](#spiffe--spire)

---

## Server startup

| Symptom | Cause | Fix |
|---|---|---|
| `MountMCP` / `NewRuntime` returns an error | `Config.Validate` failed | Read the message; ensure `Issuer`, absolute `ResourceURI`, and a validation path (JWKS or introspection) are set. See [required fields](configuration.md#what-configvalidate-requires). |
| Startup fails fetching policy | `PolicyModeRemoteRequired` and the RS is still in onboarding | Set `PublishManifest=true` (starts deny-all, refreshes in background), or use `PolicyModeRemoteWithLocalFallback` with non-nil `ToolScopes` during setup. |
| `panic` on `NewAgentIdentity` | Empty `Issuer`/`ClientID`, or both `Auth` and `ClientSecret` set | Provide the required fields; set exactly one credential. |

## Protection-check / dashboard

| Symptom | Cause | Fix |
|---|---|---|
| Protection check: `Default access policy` failing | No role is marked default | Access tab → role ⋮ → Make default role → grant scopes → Save grants. |
| Every tool call denied, policy state `needs_setup` / `policy_complete=false` | Vocabulary exists but tools aren't mapped, or no default access | Map tools to scopes, set a default role, then Launch. |
| A tool stays `denied` after launch | "No label assigned" — unmapped tools fail closed | Tools tab → open the tool → Map an access label. |
| Metadata path returns `404` | Wrong PRM path for a path-based resource | Use `BuildResourceMetadataPath(cfg.ResourceURI)`; `.../mcp` serves PRM at `/.well-known/oauth-protected-resource/mcp`. |

## Token validation

| Symptom | Cause | Fix |
|---|---|---|
| `401` even with a fresh, valid token | `ResourceURI` doesn't exactly match the URL agents call, so the audience check fails | Make `ResourceURI` byte-identical to the called URL (scheme/host/path). Re-check after an ngrok URL change. |
| Revoked token still works briefly | `ValidationModeJWTOnly` — revocation is bounded by token lifetime | Use `ValidationModeJWTAndIntrospect`. |
| A tampered/expired JWT is accepted | `ValidationModeJWTOrIntrospect` let introspection pass a bad signature | Use `ValidationModeJWTAndIntrospect` (signature is mandatory there). |

## Scopes & authorization

| Symptom | Cause | Fix |
|---|---|---|
| `tools/list` returns nothing for a user | RS not `ready`, no role binding, or requested scope doesn't intersect user scopes | Effective scopes = `requested ∩ scopes_supported ∩ user_effective`. Fix whichever set is empty. |
| Scope changes not taking effect | Within the scope-matrix cache window | Wait ~30s (default `ScopeMatrixTTL`); confirm the server can reach the AS. |
| Write tool callable with a read-only token | Tool mapped to a read scope, or `PolicyModeOpen` | Re-map the tool; don't run `PolicyModeOpen` in production. |
| `insufficient_scope` where you expected success | Token lacks the tool's required scope | Request the right scopes; confirm the mapping in the Tools tab. |

## Manifest publishing

| Symptom | Cause | Fix |
|---|---|---|
| Dashboard shows zero tools | `PublishManifest=false`, empty `ToolInventoryProvider`, synthetic enumeration can't reach your inner handler, or wrong introspection creds (`PUT /sdk-manifest` → 401) | Enable `PublishManifest`; check boot logs for `manifest publish failed`; use `ToolInventoryProvider` for custom routing; verify introspection ID/secret. |
| Anonymous scan returns success but zero tools | Expected — a correctly protected server returns `401` to anonymous `tools/list` | Use SDK manifest publishing (or an authenticated scan). |
| Tools appear but activation is blocked | Unmapped tools, missing scopes, or default role grants nothing | Map every non-public tool; grant the default role at least one scope. |

## Agent-side token acquisition (M2M)

| Error | Cause | Fix |
|---|---|---|
| `invalid_client: invalid client secret` | Typo'd/rotated secret (64 hex chars) | Copy-paste from the dashboard; never retype. |
| `access_denied: client not authorized for this resource server` | Valid credential, no access assignment | Grant the service account a role for the target application. |
| `JWKS resolution failed: parse JWKS: invalid character '<'` | JWKS URI returns HTML | Point it at raw JSON; for gists use the `raw` URL. |
| Signature verification fails (private-key JWT) | `kid` mismatch or wrong key | Make `NewPrivateKeyJwtAuth(..., kid)` match the JWKS `kid`. |
| `*ResourceNotRegisteredError` | The MCP URL is unknown to AuthSec | Register the resource server; check the URL. |

## ID-JAG delegation

| Symptom | Cause | Fix |
|---|---|---|
| Stuck "waiting for approval" forever | Requested scopes don't exist on the target server | Use scopes from the server's PRM `scopes_supported`. |
| `redirect_uri mismatch` at login | Registered redirect URI/port differs | Match it; `BrowserLoginOptions.Port` defaults to `8126`. |
| Browser doesn't open | Headless/remote session | Override `BrowserLoginOptions.OpenBrowser`; or log in elsewhere and pass the `id_token`. |
| Token works then suddenly 401s | Connection revoked / token expired | `agent.ClearCache(resource)` + retry once; if `*ConnectionRevokedError`, re-request. |

## SPIFFE / SPIRE

| Error (`*SpiffeTokenExchangeError.Code`) | Meaning | Fix |
|---|---|---|
| `jwks_unconfigured` | Trust-domain JWKS not registered in AuthSec | Register the trust domain's JWKS. |
| `spiffe_id_not_registered` | The SPIFFE ID isn't a registered workload client | Register the exact `spiffe://…` ID. |
| `audience_mismatch` | SVID minted with the wrong audience | Audience must be the token endpoint (`<issuer>/oauth/token`). `SpiffeWorkloadIdentity` handles this automatically. |
| `trust_domain_mismatch` | SVID's trust domain differs from the registration | Align trust domains. |
| `no_scopes_granted` | Workload has no access assignment | Grant the workload client a role/scopes. |
| `client_id_missing` | `ClientID` not sent/registered | Set `SpiffeConfig.ClientID`. |
| `*SpiffeSvidFetchError` | SPIRE agent socket missing, or workload not attested | Check `AgentSocketPath` and the SPIRE registration entry; for testing use `SvidOverride`. |
| `… token is expired` | JWT-SVIDs live ~5 min | Use `SpiffeWorkloadIdentity` (auto-renews) or mint right before use. |

---

[← Docs home](README.md)
