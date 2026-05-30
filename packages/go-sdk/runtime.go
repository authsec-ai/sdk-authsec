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
type ErrInsufficientScope struct {
	ToolName       string
	RequiredScopes []string
}

func (e ErrInsufficientScope) Error() string {
	if len(e.RequiredScopes) == 0 {
		return fmt.Sprintf("tool %q is not permitted (not listed in policy or insufficient scope)", e.ToolName)
	}
	return fmt.Sprintf("insufficient scope for tool %q: requires one of %v", e.ToolName, e.RequiredScopes)
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

	result, required := m.LookupTool(toolName)
	switch result {
	case ToolPolicyAbsent:
		// Tool not in policy map → deny by default when a policy exists.
		return ErrInsufficientScope{ToolName: toolName, RequiredScopes: nil}
	case ToolPolicyPublic:
		return nil
	case ToolPolicyScoped:
		if !principal.HasAnyScope(required) {
			return ErrInsufficientScope{ToolName: toolName, RequiredScopes: required}
		}
		return nil
	default:
		return nil
	}
}

// Wrap wraps the given handler with full MCP enforcement: auth, tool authorization,
// tools/list filtering, batch handling, and fail-closed parse behavior.
func (rt *Runtime) Wrap(next http.Handler) http.Handler {
	auth := rt.AuthMiddleware()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isMetadataRequest(rt.cfg.ResourceURI, r.URL.Path) {
			rt.ProtectedResourceHandler().ServeHTTP(w, r)
			return
		}

		auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, result := parseMCPRequestBody(r)

			// Fail-closed: non-empty body that couldn't be parsed → 400.
			if result.parseErr != nil {
				http.Error(w, "Bad Request: "+result.parseErr.Error(), http.StatusBadRequest)
				return
			}

			// Non-POST or empty body: pass through without tool enforcement.
			if result.isEmpty {
				next.ServeHTTP(w, r)
				return
			}

			// Restore body for downstream handlers.
			r.Body = io.NopCloser(bytes.NewReader(body))

			principal, _ := PrincipalFromContext(r.Context())

			if !result.isBatch {
				rt.handleSingleMCPRequest(w, r, next, principal, result.envelopes[0])
				return
			}
			rt.handleBatchMCPRequest(w, r, next, principal, result.envelopes)
		})).ServeHTTP(w, r)
	})
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
			rt.dispatchAuthError(w, err)
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
	// Pre-flight: check authorization for all tools/call in the batch.
	for _, env := range envelopes {
		if env.Method != "tools/call" {
			continue
		}
		if err := rt.AuthorizeTool(r.Context(), principal, env.Params.Name); err != nil {
			rt.dispatchAuthError(w, err) // 503 or 403, whole batch fails
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

// dispatchAuthError routes ErrPolicyUnavailable to 503 and ErrInsufficientScope to 403.
func (rt *Runtime) dispatchAuthError(w http.ResponseWriter, err error) {
	var policyErr ErrPolicyUnavailable
	var scopeErr ErrInsufficientScope
	if errors.As(err, &policyErr) {
		rt.writePolicyUnavailable(w)
	} else if errors.As(err, &scopeErr) {
		rt.writeInsufficientScope(w, scopeErr)
	} else if err != nil {
		// Unexpected error type: fail closed as 503.
		rt.writePolicyUnavailable(w)
	}
}

func (rt *Runtime) writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q`, BuildResourceMetadataURL(rt.cfg.ResourceURI)))
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// writeInsufficientScope writes a 403 using already-resolved scope data.
// Never consults toolScopeMap again.
func (rt *Runtime) writeInsufficientScope(w http.ResponseWriter, e ErrInsufficientScope) {
	scopeStr := strings.Join(e.RequiredScopes, " ")
	if scopeStr == "" {
		scopeStr = "(unknown)"
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer error="insufficient_scope", scope=%q, resource_metadata=%q, error_description=%q`,
		scopeStr,
		BuildResourceMetadataURL(rt.cfg.ResourceURI),
		"Additional scopes required or tool is not permitted: "+e.ToolName,
	))
	http.Error(w, "Forbidden: insufficient scopes", http.StatusForbidden)
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

// parseMCPRequestBody reads and parses the request body, handling both single
// JSON-RPC objects and batch arrays. A non-empty body that cannot be parsed
// as valid JSON-RPC sets parseErr (fail-closed: 400 Bad Request).
func parseMCPRequestBody(r *http.Request) ([]byte, mcpParseResult) {
	if r.Method != http.MethodPost {
		return nil, mcpParseResult{isEmpty: true}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, mcpParseResult{parseErr: fmt.Errorf("failed to read request body: %w", err)}
	}

	if len(bytes.TrimSpace(body)) == 0 {
		return body, mcpParseResult{isEmpty: true}
	}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		// JSON-RPC batch request.
		var batch []mcpEnvelope
		if err := json.Unmarshal(body, &batch); err != nil {
			return body, mcpParseResult{parseErr: fmt.Errorf("invalid JSON-RPC batch: %w", err)}
		}
		envelopes := make([]*mcpEnvelope, len(batch))
		for i := range batch {
			envelopes[i] = &batch[i]
		}
		return body, mcpParseResult{envelopes: envelopes, isBatch: true}
	}

	// Single JSON-RPC object.
	var req mcpEnvelope
	if err := json.Unmarshal(body, &req); err != nil {
		return body, mcpParseResult{parseErr: fmt.Errorf("invalid JSON-RPC request: %w", err)}
	}
	return body, mcpParseResult{envelopes: []*mcpEnvelope{&req}}
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
