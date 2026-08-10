package authsec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// ErrPolicyUnavailable is returned by AuthorizeTool when the policy backend
// (scope matrix cache) cannot be reached and no valid fallback exists.
// Callers should return HTTP 503, not 403, for this error.
type ErrPolicyUnavailable struct {
	Cause error
}

func (e ErrPolicyUnavailable) Error() string {
	return fmt.Sprintf("policy unavailable: %v", e.Cause)
}

func (e ErrPolicyUnavailable) Unwrap() error {
	return e.Cause
}

// ErrInsufficientScope is returned by AuthorizeTool when the token's scopes
// are insufficient for the requested tool, or the tool is not in the policy map.
// RequiredScopes carries the already-resolved scopes — callers must NOT re-fetch policy.
// GrantedScopes carries the scopes the principal does have, so the response
// can read "you have [a,b], you need [c]" instead of just "you need [c]".
type ErrInsufficientScope struct {
	ToolName       string
	RequiredScopes []string
	GrantedScopes  []string
}

func (e ErrInsufficientScope) Error() string {
	req := joinScopesOrUnknown(e.RequiredScopes)
	if len(e.GrantedScopes) > 0 {
		return fmt.Sprintf(
			"Tool %q requires scope: %s. Your token has: %s. Ask an AuthSec admin to grant the missing scope, or use a tool that fits your current scopes.",
			e.ToolName, req, strings.Join(e.GrantedScopes, ", "),
		)
	}
	return fmt.Sprintf(
		"Tool %q requires scope: %s. Your token does not include this scope. Ask an AuthSec admin to grant it, or use a tool that fits your current scopes.",
		e.ToolName, req,
	)
}

func joinScopesOrUnknown(s []string) string {
	if len(s) == 0 {
		return "(unknown)"
	}
	return strings.Join(s, ", ")
}

// Runtime is the core enforcement engine.
type Runtime struct {
	cfg         Config
	validator   Validator
	scopeMatrix *ScopeMatrixClient // nil if no remote policy needed
	policyMode  PolicyMode
	publishOnce sync.Once // guards idempotent manifest publish in Wrap
}

// NewRuntime constructs and validates a Runtime. For PolicyModeRemoteRequired,
// the initial scope matrix fetch must succeed or startup fails.
func NewRuntime(cfg Config) (*Runtime, error) {
	n := cfg.normalized()
	if err := n.Validate(); err != nil {
		return nil, err
	}
	validator, err := NewHybridValidator(n)
	if err != nil {
		return nil, err
	}

	rt := &Runtime{
		cfg:        n,
		validator:  validator,
		policyMode: n.effectivePolicyMode(),
	}

	if rt.policyMode == PolicyModeOpen || rt.policyMode == PolicyModeLocalOnly {
		return rt, nil
	}

	// Remote modes: set up scope matrix client.
	client := NewScopeMatrixClient(n)
	if client == nil {
		if rt.policyMode == PolicyModeRemoteRequired {
			return nil, fmt.Errorf("PolicyModeRemoteRequired: could not create scope matrix client (check ResourceServerID and credentials)")
		}
		// RemoteWithLocalFallback: proceed without remote client; Validate() already
		// confirmed ToolScopes is non-nil so local fallback is available.
		return rt, nil
	}
	rt.scopeMatrix = client

	fetchErr := client.FetchAndCache(context.Background())
	if fetchErr != nil {
		// When PublishManifest=true, a brand-new RS may not have a ready policy yet.
		// Non-fatal: runtime starts in deny-all; background refresh loop will flip it
		// when state=ready arrives. This lets NewRuntime succeed before the admin has
		// activated the RS in the wizard.
		if rt.cfg.PublishManifest {
			n.Logger.Warn("initial scope matrix fetch failed; starting in deny-all mode (PublishManifest=true — policy will refresh when RS is activated)",
				"error", fetchErr,
				"resource_server_id", n.ResourceServerID,
			)
			return rt, nil
		}
		if rt.policyMode == PolicyModeRemoteRequired {
			return nil, fmt.Errorf("PolicyModeRemoteRequired: initial scope matrix fetch failed: %w", fetchErr)
		}
		// RemoteWithLocalFallback: warn and continue with local fallback.
		n.Logger.Warn("initial scope matrix fetch failed, using local fallback",
			"error", fetchErr,
			"resource_server_id", n.ResourceServerID,
		)
	}

	return rt, nil
}

// WrapMCPHTTP wraps an existing MCP HTTP handler with AuthSec enforcement.
// The caller is responsible for also mounting ProtectedResourceHandler at
// BuildResourceMetadataPath(cfg.ResourceURI). Use MountMCP to do both at once.
//
// If cfg.PublishManifest is true, this also kicks off a background manifest
// publish using `next` (the un-wrapped handler) for synthetic tools/list.
// Failure is logged via cfg.Logger and never propagated to the caller —
// manifest publish is one-way push for admin visibility, not enforcement.
func WrapMCPHTTP(next http.Handler, cfg Config) (http.Handler, error) {
	rt, err := NewRuntime(cfg)
	if err != nil {
		return nil, err
	}
	rt.maybePublishManifest(next)
	return rt.Wrap(next), nil
}

// AuthMiddleware returns a standard Go middleware that validates bearer tokens
// and injects the authenticated principal into the request context.
func AuthMiddleware(cfg Config) (func(http.Handler) http.Handler, error) {
	rt, err := NewRuntime(cfg)
	if err != nil {
		return nil, err
	}
	return rt.AuthMiddleware(), nil
}

// MountMCP registers both the protected-resource metadata endpoint and the
// MCP handler on the given mux. This is the preferred installation API because
// it prevents accidentally exposing the MCP handler without the metadata route.
//
// The metadata path is derived from cfg.ResourceURI following RFC 9728:
//   - Root resources: /.well-known/oauth-protected-resource
//   - Path-based resources: /.well-known/oauth-protected-resource/<path>
//
// Limitation: MountMCP is safe when each resource on the mux has a distinct
// URI path component. For multi-host routing, use a host-aware router and
// wire ProtectedResourceHandler manually.
func MountMCP(mux *http.ServeMux, pattern string, handler http.Handler, cfg Config) error {
	rt, err := NewRuntime(cfg)
	if err != nil {
		return err
	}
	rt.maybePublishManifest(handler)
	mux.Handle(BuildResourceMetadataPath(cfg.ResourceURI), rt.ProtectedResourceHandler())
	mux.Handle(pattern, rt.Wrap(handler))
	return nil
}

// maybePublishManifest kicks off PublishManifest in a goroutine when
// cfg.PublishManifest is true. Guarded by publishOnce so it runs at most once
// per Runtime instance regardless of how many times Wrap is called. Errors are
// logged via cfg.Logger and never returned — manifest publish must never block startup.
//
// `inner` is the un-wrapped MCP handler. The synthetic tools/list call goes
// through it directly so we don't have to construct a privileged token.
func (rt *Runtime) maybePublishManifest(inner http.Handler) {
	if !rt.cfg.PublishManifest {
		return
	}
	if rt.cfg.ResourceServerID == "" {
		rt.cfg.Logger.Warn("PublishManifest is true but ResourceServerID is empty; skipping manifest publish")
		return
	}
	rt.publishOnce.Do(func() {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), manifestPublishTimeout)
			defer cancel()
			if err := PublishManifest(ctx, rt.cfg, inner); err != nil {
				rt.cfg.Logger.Warn("manifest publish failed",
					"error", err,
					"resource_server_id", rt.cfg.ResourceServerID,
				)
				return
			}
			rt.cfg.Logger.Info("manifest publish succeeded",
				"resource_server_id", rt.cfg.ResourceServerID,
			)
		}()
	})
}

// GetAuthoritativeScopes returns the authoritative scopes_supported list for
// this RS, fetched from AuthSec via the scope matrix (TTL-cached, refreshed
// in the background). The PRM handler uses this so admin-side scope edits in
// the AuthSec UI propagate to MCP clients within one refresh cycle (≤5 min)
// — **no code change in the MCP server**.
//
// Returns nil when:
//   - the runtime has no scope matrix client (PolicyModeOpen / PolicyModeLocalOnly),
//   - the cache has never been populated, or
//   - the cache exceeded maxStaleAge with the last refresh in error.
//
// Callers (PRM handler) should fall back to cfg.SupportedScopes when this
// returns nil so the server still serves a metadata document.
func (rt *Runtime) GetAuthoritativeScopes(ctx context.Context) []string {
	if rt.scopeMatrix == nil {
		return nil
	}
	return rt.scopeMatrix.GetScopesSupported(ctx)
}

// ProtectedResourceHandler returns the metadata handler for this runtime.
// PRM is served from the runtime's scope-matrix cache when available so
// admin-side scope changes in AuthSec auto-propagate without a redeploy.
func (rt *Runtime) ProtectedResourceHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authoritative := rt.GetAuthoritativeScopes(r.Context())
		writeMetadata(w, rt.cfg, authoritative)
	})
}

// AuthMiddleware returns a middleware that validates bearer tokens.
func (rt *Runtime) AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := parseBearerToken(r)
			if err != nil {
				if err == errMissingAuthorization {
					rt.writeUnauthorized(w)
					return
				}
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			principal, err := rt.validator.Validate(r.Context(), token)
			if err != nil {
				rt.writeUnauthorized(w)
				return
			}

			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
		})
	}
}

// toolScopeMap returns the effective tool→scope mapping for the current request.
func (rt *Runtime) toolScopeMap(ctx context.Context) (ToolScopeMap, error) {
	switch rt.policyMode {
	case PolicyModeOpen:
		return nil, nil
	case PolicyModeLocalOnly:
		return rt.cfg.ToolScopes, nil
	case PolicyModeRemoteRequired:
		if rt.scopeMatrix == nil {
			return nil, fmt.Errorf("scope matrix client not available")
		}
		m, err := rt.scopeMatrix.GetCached(ctx)
		if err != nil {
			return nil, fmt.Errorf("scope matrix unavailable: %w", err)
		}
		return m, nil
	case PolicyModeRemoteWithLocalFallback:
		if rt.scopeMatrix != nil {
			m, err := rt.scopeMatrix.GetCached(ctx)
			if err == nil && m != nil {
				return m, nil
			}
		}
		// Fall back to local ToolScopes. Validate() ensures ToolScopes != nil for this mode.
		if rt.cfg.ToolScopes != nil {
			return rt.cfg.ToolScopes, nil
		}
		return nil, fmt.Errorf("remote policy unavailable and no local fallback configured")
	default:
		return rt.cfg.ToolScopes, nil
	}
}

// AuthorizeTool checks whether the principal may call a tool.
// Returns ErrPolicyUnavailable if the policy backend cannot be reached.
// Returns ErrInsufficientScope if the token lacks the required scope or the tool is absent from policy.
func (rt *Runtime) AuthorizeTool(ctx context.Context, principal *Principal, toolName string) error {
	if principal == nil {
		return ErrInsufficientScope{ToolName: toolName}
	}

	m, err := rt.toolScopeMap(ctx)
	if err != nil {
		return ErrPolicyUnavailable{Cause: err}
	}

	// PolicyModeOpen: nil map, allow all.
	if m == nil {
		return nil
	}

	granted := principal.Scopes
	result, required := m.LookupTool(toolName)
	switch result {
	case ToolPolicyAbsent:
		// Tool not in policy map → deny by default when a policy exists.
		return ErrInsufficientScope{
			ToolName:       toolName,
			RequiredScopes: []string{fmt.Sprintf("<no scope mapping for tool %q>", toolName)},
			GrantedScopes:  granted,
		}
	case ToolPolicyPublic:
		return nil
	case ToolPolicyScoped:
		if !principal.HasAnyScope(required) {
			return ErrInsufficientScope{
				ToolName:       toolName,
				RequiredScopes: required,
				GrantedScopes:  granted,
			}
		}
		return nil
	default:
		return nil
	}
}

// Wrap wraps the given handler with full MCP enforcement: auth, tool authorization,
// tools/list filtering, batch handling, and fail-closed parse behavior.
//
// The body is read and classified BEFORE the auth decision so the SDK can
// mirror the Python/TS runtime's MCP-client-aware behavior:
//   - MCP handshake requests (initialize / notifications/initialized / ping)
//     pass through when a token is present but invalid, so a session survives a
//     mid-session token expiry.
//   - tools/call and generic JSON-RPC auth denials are returned in-band as
//     JSON-RPC responses (HTTP 200) when a token is present and the body is
//     JSON-RPC; otherwise a standard HTTP 401/403 challenge is returned.
//
// Requests with no token, non-JSON-RPC bodies, and 503 (policy unavailable)
// keep the classic HTTP-status behavior. The standalone AuthMiddleware is
// unchanged — this parity behavior lives only in the MCP-aware Wrap path.
func (rt *Runtime) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isMetadataRequest(rt.cfg.ResourceURI, r.URL.Path) {
			rt.ProtectedResourceHandler().ServeHTTP(w, r)
			return
		}

		// Parse the bearer token. A malformed header (present, but not a valid
		// Bearer value) preserves the historical 400 behavior; a missing header
		// yields an empty token that flows into the denial path below.
		token, tokErr := parseBearerToken(r)
		if tokErr != nil && tokErr != errMissingAuthorization {
			http.Error(w, tokErr.Error(), http.StatusBadRequest)
			return
		}

		// Read the body once; it is needed for both the denial and the
		// authenticated paths.
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, "Bad Request: failed to read request body", http.StatusBadRequest)
			return
		}

		// Validate the token (if any). A nil principal means the request is
		// unauthenticated or the token is invalid/expired/wrong-audience.
		var principal *Principal
		var validErr error
		if token != "" {
			principal, validErr = rt.validator.Validate(r.Context(), token)
		}

		if principal == nil {
			rt.handleAuthDenial(w, r, next, token, body, validErr)
			return
		}

		// ── Authenticated path ───────────────────────────────────────────────
		r = r.WithContext(WithPrincipal(r.Context(), principal))

		result := parseMCPEnvelopesStrict(r.Method, body)
		// Fail-closed: non-empty body that couldn't be parsed → 400.
		if result.parseErr != nil {
			http.Error(w, "Bad Request: "+result.parseErr.Error(), http.StatusBadRequest)
			return
		}
		// Non-POST or empty body: pass through without tool enforcement.
		if result.isEmpty {
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
			return
		}

		// Restore body for downstream handlers.
		r.Body = io.NopCloser(bytes.NewReader(body))

		if !result.isBatch {
			rt.handleSingleMCPRequest(w, r, next, principal, result.envelopes[0])
			return
		}
		rt.handleBatchMCPRequest(w, r, next, principal, result.envelopes)
	})
}

// handleAuthDenial handles a request whose token is missing or invalid. It
// mirrors the initial-denial branch of Python's _protected:
//   - handshake pass-through (token present + JSON-RPC + all-handshake body),
//   - in-band JSON-RPC / tools/call errors (token present + JSON-RPC),
//   - standard HTTP 401 challenge otherwise (no token, or non-JSON-RPC body).
func (rt *Runtime) handleAuthDenial(
	w http.ResponseWriter,
	r *http.Request,
	next http.Handler,
	token string,
	body []byte,
	validErr error,
) {
	description := "missing bearer token"
	if token != "" {
		if validErr != nil {
			description = validErr.Error()
		} else {
			description = "invalid bearer token"
		}
	}
	reason := classifyAuthReason(description)
	code := "invalid_token"
	if strings.Contains(strings.ToLower(description), "audience") {
		code = "invalid_audience"
	}

	envelopes, isBatch, isJSONRPC := parseMCPEnvelopesTolerant(r.Method, body)
	tokenPresent := token != ""

	// Handshake pass-through: let the session-setup handshake reach the handler
	// so an MCP session survives a mid-session token expiry.
	if tokenPresent && isJSONRPC && isHandshakeEnvelopes(envelopes) {
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
		return
	}

	// In-band JSON-RPC error (only when a token was presented).
	if tokenPresent && isJSONRPC {
		d := inbandDenial{
			status:      http.StatusUnauthorized,
			code:        code,
			description: description,
			reason:      reason,
		}
		if isToolsCallEnvelopes(envelopes) {
			writeInbandToolAuthError(w, envelopes, isBatch, d)
			return
		}
		writeInbandJSONRPCError(w, envelopes, isBatch, d)
		return
	}

	// Standard HTTP challenge (no token, or non-JSON-RPC caller).
	rt.writeUnauthorizedReason(w, description, reason)
}

func (rt *Runtime) handleSingleMCPRequest(
	w http.ResponseWriter,
	r *http.Request,
	next http.Handler,
	principal *Principal,
	req *mcpEnvelope,
) {
	switch req.Method {
	case "tools/call":
		if err := rt.AuthorizeTool(r.Context(), principal, req.Params.Name); err != nil {
			rt.dispatchToolDenial(w, err, []*mcpEnvelope{req}, false, envelopesAreJSONRPC([]*mcpEnvelope{req}))
			return
		}
		next.ServeHTTP(w, r)
	case "tools/list":
		rec := newResponseRecorder()
		next.ServeHTTP(rec, r)
		rt.writeFilteredToolResponse(w, r.Context(), rec, principal)
	default:
		next.ServeHTTP(w, r)
	}
}

func (rt *Runtime) handleBatchMCPRequest(
	w http.ResponseWriter,
	r *http.Request,
	next http.Handler,
	principal *Principal,
	envelopes []*mcpEnvelope,
) {
	isJSONRPC := envelopesAreJSONRPC(envelopes)

	// Pre-flight: check authorization for all tools/call in the batch.
	for _, env := range envelopes {
		if env.Method != "tools/call" {
			continue
		}
		if err := rt.AuthorizeTool(r.Context(), principal, env.Params.Name); err != nil {
			// Whole batch fails. In-band (200) for scope denials on JSON-RPC
			// clients; HTTP 503 for policy-unavailable (mirrors Python).
			rt.dispatchToolDenial(w, err, envelopes, true, isJSONRPC)
			return
		}
	}

	// If any envelope is tools/list, intercept the response for filtering.
	needsListFilter := false
	for _, env := range envelopes {
		if env.Method == "tools/list" {
			needsListFilter = true
			break
		}
	}

	if needsListFilter {
		rec := newResponseRecorder()
		next.ServeHTTP(rec, r)
		rt.writeFilteredBatchResponse(w, r.Context(), rec, principal, envelopes)
		return
	}

	next.ServeHTTP(w, r)
}

// dispatchToolDenial routes a tools/call authorization failure.
//
//   - ErrPolicyUnavailable → HTTP 503 always (not an OAuth failure; 503 is
//     outside the in-band set, matching Python's status ∈ {401,403} gate).
//   - ErrInsufficientScope → in-band tools/call error (HTTP 200) when the caller
//     is a JSON-RPC MCP client; otherwise the classic HTTP 403 challenge.
//
// envelopes carries the request(s) so the in-band response echoes the correct
// JSON-RPC id(s); for a batch, every item is rendered as an error result.
func (rt *Runtime) dispatchToolDenial(
	w http.ResponseWriter,
	err error,
	envelopes []*mcpEnvelope,
	isBatch bool,
	isJSONRPC bool,
) {
	var policyErr ErrPolicyUnavailable
	var scopeErr ErrInsufficientScope
	if errors.As(err, &policyErr) {
		rt.writePolicyUnavailable(w)
		return
	}
	if errors.As(err, &scopeErr) {
		if isJSONRPC {
			writeInbandToolAuthError(w, envelopes, isBatch, inbandDenial{
				status:         http.StatusForbidden,
				code:           "insufficient_scope",
				description:    scopeErr.Error(),
				tool:           scopeErr.ToolName,
				requiredScopes: scopeErr.RequiredScopes,
				grantedScopes:  scopeErr.GrantedScopes,
			})
			return
		}
		rt.writeInsufficientScope(w, scopeErr)
		return
	}
	// Unexpected error type: fail closed as 503.
	rt.writePolicyUnavailable(w)
}

func (rt *Runtime) writeUnauthorized(w http.ResponseWriter) {
	rt.writeUnauthorizedReason(w, "invalid bearer token", "invalid_token")
}

// writeUnauthorizedReason writes a 401 with a structured JSON body plus the
// classic WWW-Authenticate challenge. The body's `reason` field is a stable,
// machine-parseable subcode (token_revoked, client_registration_revoked,
// token_expired, audience_mismatch, no_token, invalid_token) that the client
// SDKs use to fork between "re-auth" and "ask admin to re-approve".
func (rt *Runtime) writeUnauthorizedReason(w http.ResponseWriter, description, reason string) {
	if reason == "" {
		reason = classifyAuthReason(description)
	}
	if description == "" {
		description = "Unauthorized"
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer realm=%q, error="invalid_token", resource_metadata=%q, error_description=%q`,
		rt.cfg.ResourceName,
		BuildResourceMetadataURL(rt.cfg.ResourceURI),
		description,
	))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	body := map[string]any{
		"error":             "invalid_token",
		"error_description": description,
		"reason":            reason,
	}
	_ = json.NewEncoder(w).Encode(body)
}

// classifyAuthReason maps a free-text 401 description to a stable subcode.
func classifyAuthReason(description string) string {
	m := strings.ToLower(description)
	switch {
	case strings.Contains(m, "revoked") && (strings.Contains(m, "registration") || strings.Contains(m, "client")):
		return "client_registration_revoked"
	case strings.Contains(m, "revoked"):
		return "token_revoked"
	case strings.Contains(m, "expired") || strings.Contains(m, "expir"):
		return "token_expired"
	case strings.Contains(m, "audience"):
		return "audience_mismatch"
	case strings.Contains(m, "missing") || strings.Contains(m, "bearer"):
		return "no_token"
	default:
		return "invalid_token"
	}
}

// writeInsufficientScope writes a 403 using already-resolved scope data.
// Body includes both a human-readable error_description (used by transports
// that flatten the response) AND structured fields (tool, required_scopes,
// granted_scopes) so client SDKs can fork on type without scraping strings.
func (rt *Runtime) writeInsufficientScope(w http.ResponseWriter, e ErrInsufficientScope) {
	scopeStr := strings.Join(e.RequiredScopes, " ")
	if scopeStr == "" {
		scopeStr = "(unknown)"
	}
	description := e.Error()
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer realm=%q, error="insufficient_scope", scope=%q, resource_metadata=%q, error_description=%q`,
		rt.cfg.ResourceName,
		scopeStr,
		BuildResourceMetadataURL(rt.cfg.ResourceURI),
		description,
	))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	body := map[string]any{
		"error":             "insufficient_scope",
		"error_description": description,
		"tool":              e.ToolName,
		"required_scopes":   e.RequiredScopes,
		"granted_scopes":    e.GrantedScopes,
	}
	_ = json.NewEncoder(w).Encode(body)
}

// writePolicyUnavailable writes a 503. This is NOT an OAuth authorization failure
// so no WWW-Authenticate header is set.
func (rt *Runtime) writePolicyUnavailable(w http.ResponseWriter) {
	http.Error(w, "Service Unavailable: policy backend unavailable", http.StatusServiceUnavailable)
}

func (rt *Runtime) writeFilteredToolResponse(
	w http.ResponseWriter,
	ctx context.Context,
	rec *responseRecorder,
	principal *Principal,
) {
	body := rec.body.Bytes()
	if rec.statusCode == 0 {
		rec.statusCode = http.StatusOK
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		filteredBody, filtered, filterErr := rt.filterSSEToolResponse(ctx, body, principal)
		if filterErr != nil {
			var policyErr ErrPolicyUnavailable
			if errors.As(filterErr, &policyErr) {
				rt.writePolicyUnavailable(w)
				return
			}
			rec.WriteTo(w)
			return
		}
		if filtered {
			for key, values := range rec.header {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			w.Header().Del("Content-Length")
			w.WriteHeader(rec.statusCode)
			_, _ = w.Write(filteredBody)
			return
		}
		rec.WriteTo(w)
		return
	}

	if err := rt.filterToolPayload(ctx, payload, principal); err != nil {
		var policyErr ErrPolicyUnavailable
		if errors.As(err, &policyErr) {
			rt.writePolicyUnavailable(w)
			return
		}
		rec.WriteTo(w)
		return
	}
	out, err := json.Marshal(payload)
	if err != nil {
		rec.WriteTo(w)
		return
	}

	for key, values := range rec.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.Header().Del("Content-Length")
	w.WriteHeader(rec.statusCode)
	_, _ = w.Write(out)
}

func (rt *Runtime) filterToolPayload(ctx context.Context, payload map[string]any, principal *Principal) error {
	result, ok := payload["result"].(map[string]any)
	if !ok {
		return nil
	}

	rawTools, ok := result["tools"].([]any)
	if !ok {
		return nil
	}

	filtered := make([]any, 0, len(rawTools))
	for _, rawTool := range rawTools {
		toolMap, ok := rawTool.(map[string]any)
		if !ok {
			continue
		}
		name, _ := toolMap["name"].(string)
		err := rt.AuthorizeTool(ctx, principal, name)
		if err != nil {
			var policyErr ErrPolicyUnavailable
			if errors.As(err, &policyErr) {
				return policyErr
			}
			// ErrInsufficientScope: silently exclude from list.
			continue
		}
		filtered = append(filtered, rawTool)
	}

	result["tools"] = filtered
	return nil
}

func (rt *Runtime) filterSSEToolResponse(ctx context.Context, body []byte, principal *Principal) ([]byte, bool, error) {
	text := string(body)
	if !strings.Contains(text, "data:") {
		return nil, false, nil
	}

	blocks := strings.Split(text, "\n\n")
	changed := false
	for i, block := range blocks {
		if strings.TrimSpace(block) == "" {
			continue
		}
		lines := strings.Split(block, "\n")
		dataParts := make([]string, 0)
		dataLineStart := -1
		dataLineEnd := -1
		for idx, line := range lines {
			if strings.HasPrefix(line, "data:") {
				if dataLineStart == -1 {
					dataLineStart = idx
				}
				dataLineEnd = idx
				dataParts = append(dataParts, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}
		if len(dataParts) == 0 {
			continue
		}

		var payload map[string]any
		if err := json.Unmarshal([]byte(strings.Join(dataParts, "\n")), &payload); err != nil {
			continue
		}
		if err := rt.filterToolPayload(ctx, payload, principal); err != nil {
			return nil, false, err
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, false, err
		}

		nextLines := make([]string, 0, len(lines)-(dataLineEnd-dataLineStart)+1)
		nextLines = append(nextLines, lines[:dataLineStart]...)
		nextLines = append(nextLines, "data: "+string(encoded))
		if dataLineEnd+1 < len(lines) {
			nextLines = append(nextLines, lines[dataLineEnd+1:]...)
		}
		blocks[i] = strings.Join(nextLines, "\n")
		changed = true
	}
	if !changed {
		return nil, false, nil
	}
	return []byte(strings.Join(blocks, "\n\n")), true, nil
}

func (rt *Runtime) writeFilteredBatchResponse(
	w http.ResponseWriter,
	ctx context.Context,
	rec *responseRecorder,
	principal *Principal,
	envelopes []*mcpEnvelope,
) {
	body := rec.body.Bytes()
	if rec.statusCode == 0 {
		rec.statusCode = http.StatusOK
	}

	// Build request-ID → method map for correlation.
	idToMethod := make(map[string]string, len(envelopes))
	for _, env := range envelopes {
		if env.ID != nil {
			idToMethod[string(env.ID)] = env.Method
		}
	}

	// Decode each response item as json.RawMessage to avoid normalising IDs.
	// Then selectively re-parse only tools/list items for filtering.
	var rawItems []json.RawMessage
	if err := json.Unmarshal(body, &rawItems); err != nil {
		// Not a batch response — fall through to single filtering.
		rt.writeFilteredToolResponse(w, ctx, rec, principal)
		return
	}

	// Helper struct for ID extraction only.
	type idHolder struct {
		ID json.RawMessage `json:"id"`
	}

	out := make([]json.RawMessage, 0, len(rawItems))
	for _, rawItem := range rawItems {
		var holder idHolder
		if err := json.Unmarshal(rawItem, &holder); err != nil {
			out = append(out, rawItem)
			continue
		}

		method := idToMethod[string(holder.ID)]
		if method != "tools/list" {
			out = append(out, rawItem)
			continue
		}

		// This is a tools/list response: filter its tools array.
		var item map[string]any
		if err := json.Unmarshal(rawItem, &item); err != nil {
			out = append(out, rawItem)
			continue
		}
		resultMap, ok := item["result"].(map[string]any)
		if !ok {
			out = append(out, rawItem)
			continue
		}
		rawTools, ok := resultMap["tools"].([]any)
		if !ok {
			out = append(out, rawItem)
			continue
		}

		filtered := make([]any, 0, len(rawTools))
		for _, rawTool := range rawTools {
			toolMap, ok := rawTool.(map[string]any)
			if !ok {
				continue
			}
			name, _ := toolMap["name"].(string)
			err := rt.AuthorizeTool(ctx, principal, name)
			if err != nil {
				var policyErr ErrPolicyUnavailable
				if errors.As(err, &policyErr) {
					rt.writePolicyUnavailable(w)
					return
				}
				continue
			}
			filtered = append(filtered, rawTool)
		}
		resultMap["tools"] = filtered

		reencoded, err := json.Marshal(item)
		if err != nil {
			out = append(out, rawItem)
			continue
		}
		out = append(out, json.RawMessage(reencoded))
	}

	finalOut, err := json.Marshal(out)
	if err != nil {
		rec.WriteTo(w)
		return
	}

	for key, values := range rec.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.Header().Del("Content-Length")
	w.WriteHeader(rec.statusCode)
	_, _ = w.Write(finalOut)
}

// mcpEnvelope is a parsed JSON-RPC envelope.
type mcpEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"` // number, string, or null — preserved as-is
	Method  string          `json:"method"`
	Params  struct {
		Name string `json:"name"`
	} `json:"params"`
}

// mcpParseResult is the outcome of parsing an MCP request body.
type mcpParseResult struct {
	envelopes []*mcpEnvelope
	isBatch   bool
	parseErr  error // non-nil = fail closed with 400
	isEmpty   bool
}

// parseMCPEnvelopesStrict parses an already-read request body, handling both
// single JSON-RPC objects and batch arrays. A non-empty body that cannot be
// parsed as valid JSON-RPC sets parseErr (fail-closed: 400 Bad Request). This
// is the authenticated-path parser; the denial path uses the tolerant variant
// in mcp_inband.go.
func parseMCPEnvelopesStrict(method string, body []byte) mcpParseResult {
	if method != http.MethodPost {
		return mcpParseResult{isEmpty: true}
	}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return mcpParseResult{isEmpty: true}
	}

	if trimmed[0] == '[' {
		// JSON-RPC batch request.
		var batch []mcpEnvelope
		if err := json.Unmarshal(body, &batch); err != nil {
			return mcpParseResult{parseErr: fmt.Errorf("invalid JSON-RPC batch: %w", err)}
		}
		envelopes := make([]*mcpEnvelope, len(batch))
		for i := range batch {
			envelopes[i] = &batch[i]
		}
		return mcpParseResult{envelopes: envelopes, isBatch: true}
	}

	// Single JSON-RPC object.
	var req mcpEnvelope
	if err := json.Unmarshal(body, &req); err != nil {
		return mcpParseResult{parseErr: fmt.Errorf("invalid JSON-RPC request: %w", err)}
	}
	return mcpParseResult{envelopes: []*mcpEnvelope{&req}}
}

var errMissingAuthorization = fmt.Errorf("missing required Authorization header")

func parseBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errMissingAuthorization
	}
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
		return authHeader[7:], nil
	}
	if strings.Contains(authHeader, " ") {
		return "", fmt.Errorf("badly formatted Authorization header")
	}
	return authHeader, nil
}

type responseRecorder struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{header: make(http.Header)}
}

func (r *responseRecorder) Header() http.Header { return r.header }

func (r *responseRecorder) Write(data []byte) (int, error) {
	if r.statusCode == 0 {
		r.statusCode = http.StatusOK
	}
	return r.body.Write(data)
}

func (r *responseRecorder) WriteHeader(statusCode int) { r.statusCode = statusCode }

func (r *responseRecorder) WriteTo(w http.ResponseWriter) {
	for key, values := range r.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(r.statusCode)
	_, _ = w.Write(r.body.Bytes())
}

func WithValidator(ctx context.Context, validator Validator) context.Context {
	return context.WithValue(ctx, validatorCtxKey{}, validator)
}

type validatorCtxKey struct{}
