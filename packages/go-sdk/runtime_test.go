package authsec

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestWrapMCPHTTP_ProtectedResourceMetadata(t *testing.T) {
	cfg, _, cleanup := testConfig(t)
	defer cleanup()

	handler, err := WrapMCPHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, BuildResourceMetadataPath(cfg.ResourceURI), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), cfg.AuthorizationServer) {
		t.Fatalf("expected authorization server in metadata body")
	}
}

func TestWrapMCPHTTP_UnauthorizedChallenge(t *testing.T) {
	cfg, _, cleanup := testConfig(t)
	defer cleanup()

	handler, err := WrapMCPHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "resource_metadata=") {
		t.Fatalf("expected resource metadata challenge, got %q", got)
	}
}

func TestWrapMCPHTTP_FiltersToolsList(t *testing.T) {
	cfg, token, cleanup := testConfig(t)
	defer cleanup()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"list_issues"},{"name":"create_issue"}]}}`))
	})

	handler, err := WrapMCPHTTP(next, cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "list_issues") {
		t.Fatalf("expected read tool to remain visible")
	}
	if strings.Contains(rec.Body.String(), "create_issue") {
		t.Fatalf("expected write tool to be filtered out")
	}
}

func TestWrapMCPHTTP_FiltersSSEToolsList(t *testing.T) {
	cfg, token, cleanup := testConfig(t)
	defer cleanup()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: message\n"))
		_, _ = w.Write([]byte(`data: {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"list_issues"},{"name":"create_issue"}]}}`))
		_, _ = w.Write([]byte("\n\n"))
	})

	handler, err := WrapMCPHTTP(next, cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "list_issues") {
		t.Fatalf("expected read tool to remain visible")
	}
	if strings.Contains(rec.Body.String(), "create_issue") {
		t.Fatalf("expected write tool to be filtered out")
	}
	if !strings.Contains(rec.Body.String(), "event: message") {
		t.Fatalf("expected SSE event framing to be preserved")
	}
}

// A JSON-RPC MCP client (token present) that hits an insufficient-scope
// tools/call now gets an IN-BAND JSON-RPC result (HTTP 200, isError=true) so
// the client surfaces a structured error — parity with the Python/TS SDKs.
// Non-JSON-RPC callers still get HTTP 403 (see TestWrapMCPHTTP_NonJSONRPCToolCall_HTTP403).
func TestWrapMCPHTTP_BlocksUnauthorizedToolCall(t *testing.T) {
	cfg, token, cleanup := testConfig(t)
	defer cleanup()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not be reached for an unauthorized tool call")
	})

	handler, err := WrapMCPHTTP(next, cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"create_issue"}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 in-band, got %d", rec.Code)
	}
	meta := decodeInbandToolError(t, rec.Body.Bytes())
	if meta["error"] != "insufficient_scope" {
		t.Fatalf("expected error=insufficient_scope, got %v", meta["error"])
	}
	if meta["tool"] != "create_issue" {
		t.Fatalf("expected tool=create_issue, got %v", meta["tool"])
	}
	if !inbandScopesContain(meta["required_scopes"], "issues:write") {
		t.Fatalf("expected required_scopes to include issues:write, got %v", meta["required_scopes"])
	}
	if !inbandScopesContain(meta["granted_scopes"], "issues:read") {
		t.Fatalf("expected granted_scopes to include issues:read, got %v", meta["granted_scopes"])
	}
}

func TestWrapMCPHTTP_NoToolScopes_AllowsAll(t *testing.T) {
	cfg, token, cleanup := testConfig(t)
	defer cleanup()
	// Clear tool scopes — should allow all tools
	cfg.ToolScopes = nil

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"list_issues"},{"name":"create_issue"}]}}`))
	})

	handler, err := WrapMCPHTTP(next, cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	// tools/list should return ALL tools when no mapping is configured
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "list_issues") {
		t.Fatalf("expected list_issues to remain visible")
	}
	if !strings.Contains(rec.Body.String(), "create_issue") {
		t.Fatalf("expected create_issue to remain visible (no filtering)")
	}

	// tools/call should also allow any tool
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_issue"}}`))
	req2.Header.Set("Authorization", "Bearer "+token)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 when no tool scopes configured, got %d", rec2.Code)
	}
}

func TestWrapMCPHTTP_RemoteScopeMatrix(t *testing.T) {
	// Mock scope matrix endpoint
	scopeMatrixServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "rs-1" || pass != "secret-1" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tools": map[string][]string{
				"list_issues":  {"issues:read"},
				"create_issue": {"issues:write"},
			},
			"fetched_at":  "2026-04-16T00:00:00Z",
			"ttl_seconds": 300,
		})
	}))
	defer scopeMatrixServer.Close()

	cfg, token, cleanup := testConfigWithScopeMatrix(t, scopeMatrixServer.URL)
	defer cleanup()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"list_issues"},{"name":"create_issue"}]}}`))
	})

	handler, err := WrapMCPHTTP(next, cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	// Token has scope "issues:read" — should filter out create_issue
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "list_issues") {
		t.Fatalf("expected read tool to remain visible")
	}
	if strings.Contains(rec.Body.String(), "create_issue") {
		t.Fatalf("expected write tool to be filtered out via remote scope matrix")
	}
}

func TestBuildManifestPayload_PreservesProviderSuggestedScopes(t *testing.T) {
	payload := buildManifestPayload([]rawTool{{
		Name:            "list_issues",
		Description:     "List issues",
		SuggestedScopes: []string{"issues:read"},
	}}, map[string][]string{
		"list_issues": {"issues:write"},
	})

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	if !strings.Contains(string(body), `"suggested_scopes":["issues:read"]`) {
		t.Fatalf("expected provider suggested scopes to win, got %s", string(body))
	}
	if strings.Contains(string(body), "issues:write") {
		t.Fatalf("expected fallback suggestions not to override provider suggestions, got %s", string(body))
	}
}

func TestAuthMiddleware_HydratesPrincipal(t *testing.T) {
	cfg, token, cleanup := testConfig(t)
	defer cleanup()

	rt, err := NewRuntime(cfg)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}

	next := rt.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromContext(r.Context())
		if !ok || principal == nil {
			t.Fatalf("expected principal in context")
		}
		if principal.Subject != "user-123" {
			t.Fatalf("unexpected subject %q", principal.Subject)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
}

// testConfig creates a test config with LOCAL ToolScopes (no remote fetch).
func testConfig(t *testing.T) (Config, string, func()) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "test-kid",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	}))

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if gotUser, gotPass, _ := r.BasicAuth(); gotUser != "rs-1" || gotPass != "secret-1" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active": true,
			"sub":    "user-123",
			"iss":    "https://issuer.example.com",
			"aud":    []string{"https://mcp.example.com/mcp"},
			"scope":  "issues:read",
		})
	}))

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   "https://issuer.example.com",
		"sub":   "user-123",
		"aud":   []string{"https://mcp.example.com/mcp"},
		"scope": "issues:read",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	}).SignedString(key)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	cfg := Config{
		Issuer:                    "https://issuer.example.com",
		AuthorizationServer:       "https://issuer.example.com",
		JWKSURL:                   jwksServer.URL,
		IntrospectionURL:          introspectionServer.URL,
		IntrospectionClientID:     "rs-1",
		IntrospectionClientSecret: "secret-1",
		ResourceURI:               "https://mcp.example.com/mcp",
		ResourceName:              "GitHub MCP Server",
		SupportedScopes:           []string{"issues:read", "issues:write"},
		ToolScopes: ToolScopeMap{
			"list_issues":  {"issues:read"},
			"create_issue": {"issues:write"},
		},
	}

	return cfg, token, func() {
		jwksServer.Close()
		introspectionServer.Close()
	}
}

// testConfigWithScopeMatrix creates a test config that uses remote scope matrix fetch.
func testConfigWithScopeMatrix(t *testing.T, scopeMatrixBaseURL string) (Config, string, func()) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "test-kid",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	}))

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if gotUser, gotPass, _ := r.BasicAuth(); gotUser != "rs-1" || gotPass != "secret-1" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active": true,
			"sub":    "user-123",
			"iss":    "https://issuer.example.com",
			"aud":    []string{"https://mcp.example.com/mcp"},
			"scope":  "issues:read",
		})
	}))

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   "https://issuer.example.com",
		"sub":   "user-123",
		"aud":   []string{"https://mcp.example.com/mcp"},
		"scope": "issues:read",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	}).SignedString(key)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	cfg := Config{
		Issuer:                    "https://issuer.example.com",
		AuthorizationServer:       scopeMatrixBaseURL, // points to mock scope matrix
		JWKSURL:                   jwksServer.URL,
		IntrospectionURL:          introspectionServer.URL,
		IntrospectionClientID:     "rs-1",
		IntrospectionClientSecret: "secret-1",
		ResourceURI:               "https://mcp.example.com/mcp",
		ResourceName:              "GitHub MCP Server",
		ResourceServerID:          "test-rs-id",
		SupportedScopes:           []string{"issues:read", "issues:write"},
	}

	return cfg, token, func() {
		jwksServer.Close()
		introspectionServer.Close()
	}
}

func TestPrincipalFromContext(t *testing.T) {
	ctx := WithPrincipal(context.Background(), &Principal{Subject: "abc"})
	principal, ok := PrincipalFromContext(ctx)
	if !ok || principal.Subject != "abc" {
		t.Fatalf("expected principal in context")
	}
}

// ── NEW TESTS ────────────────────────────────────────────────────────────────

// Test 1: MountMCP registers the correct metadata route(s).
func TestMountMCP_RegistersMetadataRoute(t *testing.T) {
	cfg, _, cleanup := testConfig(t)
	defer cleanup()
	// cfg.ResourceURI = "https://mcp.example.com/mcp" (path-based resource)

	mux := http.NewServeMux()
	mcpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	if err := MountMCP(mux, "/mcp", mcpHandler, cfg); err != nil {
		t.Fatalf("MountMCP() error = %v", err)
	}

	// Path-based resource: alias (/.well-known/oauth-protected-resource/mcp) must return 200.
	aliasPath := BuildResourceMetadataPath(cfg.ResourceURI) // /.well-known/oauth-protected-resource/mcp
	req := httptest.NewRequest(http.MethodGet, aliasPath, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected alias metadata path %s → 200, got %d", aliasPath, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), cfg.AuthorizationServer) {
		t.Fatalf("expected authorization server in metadata body")
	}

	// Bare /.well-known/oauth-protected-resource must return 404 for path-based resources
	// (not registered — this is correct per the alias-only contract).
	req2 := httptest.NewRequest(http.MethodGet, protectedResourcePrefix, nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("expected bare metadata path → 404 for path-based resource, got %d", rec2.Code)
	}

	// MCP route without auth must 401.
	req3 := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 from MCP route without auth, got %d", rec3.Code)
	}

	// Sub-test: root resource — bare path and alias are the same, both should 200.
	t.Run("root resource", func(t *testing.T) {
		rootCfg, _, rootCleanup := testConfigRoot(t)
		defer rootCleanup()

		rootMux := http.NewServeMux()
		if err := MountMCP(rootMux, "/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}), rootCfg); err != nil {
			t.Fatalf("MountMCP() root error = %v", err)
		}

		rootMeta := BuildResourceMetadataPath(rootCfg.ResourceURI) // /.well-known/oauth-protected-resource
		if rootMeta != protectedResourcePrefix {
			t.Fatalf("expected root resource alias == bare path, got %q", rootMeta)
		}
		req := httptest.NewRequest(http.MethodGet, rootMeta, nil)
		rec := httptest.NewRecorder()
		rootMux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected root metadata 200, got %d", rec.Code)
		}
	})
}

// Test 2: Unknown tool is denied when policy exists.
func TestAuthorizeTool_UnknownToolDenied_WhenPolicyExists(t *testing.T) {
	cfg, token, cleanup := testConfig(t)
	defer cleanup()
	// cfg.ToolScopes has list_issues and create_issue only → PolicyModeLocalOnly.
	// "unknown_tool" is not in the map → must be denied.

	handler, err := WrapMCPHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unknown_tool"}}`,
	))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Deny-by-default surfaces in-band (200) for JSON-RPC MCP clients.
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 in-band for unknown tool, got %d", rec.Code)
	}
	meta := decodeInbandToolError(t, rec.Body.Bytes())
	if meta["error"] != "insufficient_scope" {
		t.Fatalf("expected error=insufficient_scope for unknown tool, got %v", meta["error"])
	}
	if meta["tool"] != "unknown_tool" {
		t.Fatalf("expected tool=unknown_tool, got %v", meta["tool"])
	}
}

// Test 3: Batch with one unauthorized call → 403 for entire batch.
func TestWrapMCPHTTP_BatchDeniesUnauthorizedTool(t *testing.T) {
	cfg, token, cleanup := testConfig(t)
	defer cleanup()

	handler, err := WrapMCPHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	// Token has issues:read; create_issue requires issues:write → denied.
	// The whole batch fails; a JSON-RPC client receives an in-band array of
	// error results (HTTP 200), one per request item (parity with Python/TS).
	body := `[
		{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_issues"}},
		{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"create_issue"}}
	]`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 in-band for batch with unauthorized tool, got %d", rec.Code)
	}
	var items []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &items); err != nil {
		t.Fatalf("expected a JSON array of in-band results, got %s (%v)", rec.Body.String(), err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 in-band results (one per batch item), got %d", len(items))
	}
	for i, item := range items {
		result, ok := item["result"].(map[string]any)
		if !ok {
			t.Fatalf("item %d: missing result object: %v", i, item)
		}
		if isErr, _ := result["isError"].(bool); !isErr {
			t.Fatalf("item %d: expected isError=true, got %v", i, result["isError"])
		}
	}
}

// Test 4: Batch where all calls are allowed → 200.
func TestWrapMCPHTTP_BatchAllAllowed(t *testing.T) {
	cfg, token, cleanup := testConfig(t)
	defer cleanup()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler, err := WrapMCPHTTP(next, cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	// Token has issues:read; list_issues requires issues:read → allowed.
	body := `[
		{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_issues"}}
	]`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for allowed batch, got %d", rec.Code)
	}
}

// Test 5: Non-JSON body with valid auth → 400 (fail-closed).
func TestWrapMCPHTTP_ParseMissFailsClosed(t *testing.T) {
	cfg, token, cleanup := testConfig(t)
	defer cleanup()

	handler, err := WrapMCPHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`not valid json at all`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unparseable body, got %d", rec.Code)
	}
}

// Test 6: 50 concurrent GetCached calls after expiry → exactly 1 HTTP fetch.
func TestScopeMatrixClient_CASDedup(t *testing.T) {
	var fetchCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&fetchCount, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tools": map[string][]string{
				"list_issues": {"issues:read"},
			},
		})
	}))
	defer server.Close()

	client := &ScopeMatrixClient{
		endpoint:     server.URL + "/authsec/resource-servers/rs-test/sdk-policy",
		clientID:     "client",
		clientSecret: "secret",
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		ttl:          1 * time.Millisecond,
		maxStaleAge:  defaultMaxStaleAge,
		retryBackoff: defaultRetryBackoff,
	}

	// Seed cache with a successful fetch.
	if err := client.FetchAndCache(context.Background()); err != nil {
		t.Fatalf("initial fetch: %v", err)
	}
	atomic.StoreInt64(&fetchCount, 0) // reset counter

	// Let cache expire.
	time.Sleep(5 * time.Millisecond)

	// Fire 50 concurrent GetCached calls.
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = client.GetCached(context.Background())
		}()
	}
	wg.Wait()

	// Wait for the single background goroutine to finish.
	time.Sleep(200 * time.Millisecond)

	got := atomic.LoadInt64(&fetchCount)
	if got != 1 {
		t.Fatalf("expected exactly 1 HTTP fetch during burst, got %d", got)
	}
}

// Test 7: JWT failure cannot be rescued by introspection in JWTAndIntrospect mode.
func TestValidator_JWTFailureNotRescuedByIntrospection(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey key1: %v", err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey key2: %v", err)
	}

	// JWKS server serves key1's public key.
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "k1",
				"n":   base64.RawURLEncoding.EncodeToString(key1.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key1.E)).Bytes()),
			}},
		})
	}))
	defer jwksServer.Close()

	// Introspection server says token is active (would rescue under old behavior).
	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active": true,
			"sub":    "user-123",
			"iss":    "https://issuer.example.com",
			"aud":    []string{"https://mcp.example.com/mcp"},
			"scope":  "issues:read",
		})
	}))
	defer introspectionServer.Close()

	cfg := Config{
		Issuer:                    "https://issuer.example.com",
		JWKSURL:                   jwksServer.URL,
		IntrospectionURL:          introspectionServer.URL,
		IntrospectionClientID:     "rs-1",
		IntrospectionClientSecret: "secret-1",
		ResourceURI:               "https://mcp.example.com/mcp",
		// ValidationMode defaults to ValidationModeJWTAndIntrospect when both URLs set.
	}

	// Sign the token with key2 — JWKS has key1, so JWT verification must fail.
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"sub": "user-123",
		"aud": []string{"https://mcp.example.com/mcp"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}).SignedString(key2)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	v, err := NewHybridValidator(cfg)
	if err != nil {
		t.Fatalf("NewHybridValidator() error = %v", err)
	}

	_, err = v.Validate(context.Background(), token)
	if err == nil {
		t.Fatal("expected validation to fail: JWT signed with wrong key should not be rescued by introspection in JWTAndIntrospect mode")
	}
}

// Test 8: PolicyModeRemoteRequired fails startup without ResourceServerID.
func TestNewRuntime_PolicyModeRemoteRequired_FailsWithoutResourceServerID(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "kid": "k1",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	}))
	defer jwksServer.Close()

	cfg := Config{
		Issuer:      "https://issuer.example.com",
		JWKSURL:     jwksServer.URL,
		ResourceURI: "https://mcp.example.com/mcp",
		PolicyMode:  PolicyModeRemoteRequired,
		// ResourceServerID intentionally missing.
	}

	_, err = NewRuntime(cfg)
	if err == nil {
		t.Fatal("expected NewRuntime to fail: PolicyModeRemoteRequired requires ResourceServerID")
	}
}

// Test 9: Policy unavailable (degraded cache past maxStaleAge) → 503, not 403.
func TestWrapMCPHTTP_PolicyUnavailable_Returns503(t *testing.T) {
	// Scope matrix server for initial successful fetch.
	scopeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tools": map[string][]string{
				"list_issues":  {"issues:read"},
				"create_issue": {"issues:write"},
			},
		})
	}))
	defer scopeServer.Close()

	// Build a scope matrix client and seed it with a successful fetch.
	client := &ScopeMatrixClient{
		endpoint:     scopeServer.URL + "/authsec/resource-servers/rs-test/sdk-policy",
		clientID:     "client",
		clientSecret: "secret",
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		ttl:          defaultScopeMatrixTTL,
		maxStaleAge:  defaultMaxStaleAge,
		retryBackoff: defaultRetryBackoff,
	}
	if err := client.FetchAndCache(context.Background()); err != nil {
		t.Fatalf("seed fetch: %v", err)
	}

	// Simulate post-start degradation: fetchedAt is older than maxStaleAge,
	// and last refresh errored (e.g. network failure after startup).
	client.mu.Lock()
	client.fetchedAt = time.Now().Add(-(defaultMaxStaleAge + 1*time.Second))
	client.lastErr = errors.New("simulated persistent refresh failure")
	client.lastErrAt = time.Now()
	client.mu.Unlock()

	// Build a valid config and runtime for token validation.
	// Use the original testConfig (ToolScopes-based) for the validator — it passes validation.
	// Then override policyMode on the runtime to RemoteRequired so the scope matrix client is used.
	cfg, token, cleanup := testConfig(t)
	defer cleanup()

	validator, valErr := NewHybridValidator(cfg)
	if valErr != nil {
		t.Fatalf("NewHybridValidator: %v", valErr)
	}

	rt := &Runtime{
		cfg:         cfg.normalized(),
		policyMode:  PolicyModeRemoteRequired,
		scopeMatrix: client,
		validator:   validator,
	}

	handler := rt.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_issues"}}`,
	))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for policy-unavailable (degraded cache), got %d", rec.Code)
	}
}

// testConfigRoot creates a test config for a ROOT resource (no path component in ResourceURI).
// Used for MountMCP root-resource sub-test.
func testConfigRoot(t *testing.T) (Config, string, func()) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "test-kid",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	}))

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active": true,
			"sub":    "user-123",
			"iss":    "https://issuer.example.com",
			"aud":    []string{"https://mcp.example.com"},
			"scope":  "issues:read",
		})
	}))

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   "https://issuer.example.com",
		"sub":   "user-123",
		"aud":   []string{"https://mcp.example.com"},
		"scope": "issues:read",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	}).SignedString(key)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	cfg := Config{
		Issuer:                    "https://issuer.example.com",
		AuthorizationServer:       "https://issuer.example.com",
		JWKSURL:                   jwksServer.URL,
		IntrospectionURL:          introspectionServer.URL,
		IntrospectionClientID:     "rs-1",
		IntrospectionClientSecret: "secret-1",
		ResourceURI:               "https://mcp.example.com", // root: no path
		ResourceName:              "Root MCP Server",
		ToolScopes: ToolScopeMap{
			"list_issues": {"issues:read"},
		},
	}

	return cfg, token, func() {
		jwksServer.Close()
		introspectionServer.Close()
	}
}

// ── Python/TS parity: handshake pass-through + in-band errors + realm/cache ───

// decodeInbandToolError parses an in-band tools/call error result and returns
// the _meta.authsec object, failing the test if the shape is wrong.
func decodeInbandToolError(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode in-band response: %v (body=%s)", err, string(body))
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("missing result object in %s", string(body))
	}
	if isErr, _ := result["isError"].(bool); !isErr {
		t.Fatalf("expected isError=true in %s", string(body))
	}
	meta, ok := result["_meta"].(map[string]any)
	if !ok {
		t.Fatalf("missing _meta in %s", string(body))
	}
	authsec, ok := meta["authsec"].(map[string]any)
	if !ok {
		t.Fatalf("missing _meta.authsec in %s", string(body))
	}
	return authsec
}

func inbandScopesContain(v any, want string) bool {
	arr, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range arr {
		if s, ok := item.(string); ok && s == want {
			return true
		}
	}
	return false
}

// A token-present-but-invalid handshake request (initialize) passes through to
// the wrapped handler so an MCP session survives a mid-session token expiry.
func TestWrapMCPHTTP_HandshakePassThrough_InvalidToken(t *testing.T) {
	cfg, _, cleanup := testConfig(t)
	defer cleanup()

	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2024-11-05"}}`))
	})

	handler, err := WrapMCPHTTP(next, cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	// "expired.invalid.jwt" is JWT-shaped (two dots) but fails verification.
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}`,
	))
	req.Header.Set("Authorization", "Bearer expired.invalid.jwt")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reached {
		t.Fatal("expected handshake to pass through to the handler")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from passed-through handshake, got %d", rec.Code)
	}
}

// With NO token, a handshake request must still be challenged (401) — pass-through
// only applies when a token is present but invalid.
func TestWrapMCPHTTP_HandshakeNoToken_Challenges(t *testing.T) {
	cfg, _, cleanup := testConfig(t)
	defer cleanup()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not be reached without a token")
	})
	handler, err := WrapMCPHTTP(next, cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}`,
	))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated handshake, got %d", rec.Code)
	}
}

// A token-present-but-invalid tools/call returns an in-band error (200) carrying
// the invalid_token code, not an HTTP 401.
func TestWrapMCPHTTP_InvalidToken_InBandToolError(t *testing.T) {
	cfg, _, cleanup := testConfig(t)
	defer cleanup()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not be reached for an invalid token")
	})
	handler, err := WrapMCPHTTP(next, cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_issues"}}`,
	))
	req.Header.Set("Authorization", "Bearer expired.invalid.jwt")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 in-band for invalid token, got %d", rec.Code)
	}
	meta := decodeInbandToolError(t, rec.Body.Bytes())
	if meta["error"] != "invalid_token" {
		t.Fatalf("expected error=invalid_token, got %v", meta["error"])
	}
}

// A token-present-but-invalid non-tools/call JSON-RPC request returns an in-band
// JSON-RPC error object (200) with code -32001.
func TestWrapMCPHTTP_InvalidToken_InBandJSONRPCError(t *testing.T) {
	cfg, _, cleanup := testConfig(t)
	defer cleanup()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not be reached for an invalid token")
	})
	handler, err := WrapMCPHTTP(next, cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":4,"method":"resources/list","params":{}}`,
	))
	req.Header.Set("Authorization", "Bearer expired.invalid.jwt")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 in-band for invalid token, got %d", rec.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	rpcErr, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected a JSON-RPC error object, got %s", rec.Body.String())
	}
	if code, _ := rpcErr["code"].(float64); code != -32001 {
		t.Fatalf("expected code -32001 for a 401 denial, got %v", rpcErr["code"])
	}
}

// A NON-JSON-RPC tools/call (no jsonrpc field) with a valid-but-underscoped
// token still gets the classic HTTP 403 (in-band applies only to JSON-RPC).
func TestWrapMCPHTTP_NonJSONRPCToolCall_HTTP403(t *testing.T) {
	cfg, token, cleanup := testConfig(t)
	defer cleanup()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not be reached for an unauthorized tool call")
	})
	handler, err := WrapMCPHTTP(next, cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	// No "jsonrpc":"2.0" field → not a JSON-RPC caller → HTTP 403 fallback.
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
		`{"id":1,"method":"tools/call","params":{"name":"create_issue"}}`,
	))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-JSON-RPC caller, got %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "insufficient_scope") {
		t.Fatalf("expected insufficient_scope challenge, got %q", got)
	}
}

// The 401 challenge carries realm= (parity with Python/TS) alongside resource_metadata=.
func TestWrapMCPHTTP_Challenge_IncludesRealm(t *testing.T) {
	cfg, _, cleanup := testConfig(t)
	defer cleanup()

	handler, err := WrapMCPHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	got := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(got, `realm="GitHub MCP Server"`) {
		t.Fatalf("expected realm in challenge, got %q", got)
	}
	if !strings.Contains(got, "resource_metadata=") {
		t.Fatalf("expected resource_metadata in challenge, got %q", got)
	}
}

// The PRM metadata response sets Cache-Control (parity with Python/TS).
func TestMetadata_SetsCacheControl(t *testing.T) {
	cfg, _, cleanup := testConfig(t)
	defer cleanup()

	handler, err := WrapMCPHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, BuildResourceMetadataPath(cfg.ResourceURI), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("expected Cache-Control public, max-age=300, got %q", got)
	}
}

func TestFromEnv_ParsesConfig(t *testing.T) {
	t.Setenv("AUTHSEC_ISSUER", "https://issuer.example.com")
	// Exercise the legacy env-var aliases (JWKS_URI, INTROSPECTION_ENDPOINT/ID/
	// SECRET, RESOURCE) alongside the canonical names.
	t.Setenv("AUTHSEC_JWKS_URI", "https://issuer.example.com/oauth/jwks")
	t.Setenv("AUTHSEC_INTROSPECTION_ENDPOINT", "https://issuer.example.com/oauth/introspect")
	t.Setenv("AUTHSEC_INTROSPECTION_ID", "rs-1")
	t.Setenv("AUTHSEC_INTROSPECTION_SECRET", "sec-1")
	t.Setenv("AUTHSEC_RESOURCE", "https://mcp.example.com/mcp")
	t.Setenv("AUTHSEC_RESOURCE_SERVER_ID", "rs-uuid")
	t.Setenv("AUTHSEC_SUPPORTED_SCOPES", "issues:read, issues:write")
	t.Setenv("AUTHSEC_TOOL_SCOPES_JSON", `{"list_issues":["issues:read"],"create_issue":["issues:write"]}`)
	t.Setenv("AUTHSEC_POLICY_MODE", "enforce") // "enforce" alias → RemoteRequired
	t.Setenv("AUTHSEC_VALIDATION_MODE", "jwt_and_introspect")
	t.Setenv("AUTHSEC_PUBLISH_MANIFEST", "true")

	cfg := FromEnv()

	if cfg.JWKSURL != "https://issuer.example.com/oauth/jwks" {
		t.Fatalf("legacy JWKS_URI alias not read: %q", cfg.JWKSURL)
	}
	if cfg.IntrospectionClientID != "rs-1" || cfg.IntrospectionClientSecret != "sec-1" {
		t.Fatalf("legacy introspection aliases not read: %q / (secret redacted)", cfg.IntrospectionClientID)
	}
	if cfg.ResourceURI != "https://mcp.example.com/mcp" {
		t.Fatalf("legacy RESOURCE alias not read: %q", cfg.ResourceURI)
	}
	if len(cfg.SupportedScopes) != 2 || cfg.SupportedScopes[0] != "issues:read" {
		t.Fatalf("supported scopes not parsed: %v", cfg.SupportedScopes)
	}
	if got := cfg.ToolScopes["create_issue"]; len(got) != 1 || got[0] != "issues:write" {
		t.Fatalf("tool scopes not parsed: %v", cfg.ToolScopes)
	}
	if cfg.PolicyMode != PolicyModeRemoteRequired {
		t.Fatalf("expected enforce → PolicyModeRemoteRequired, got %v", cfg.PolicyMode)
	}
	if cfg.ValidationMode != ValidationModeJWTAndIntrospect {
		t.Fatalf("expected jwt_and_introspect, got %v", cfg.ValidationMode)
	}
	if !cfg.PublishManifest {
		t.Fatal("expected PublishManifest=true")
	}

	// The parsed config should validate cleanly (RemoteRequired needs an RS id + creds).
	if err := cfg.Validate(); err != nil {
		t.Fatalf("FromEnv config failed validation: %v", err)
	}
}

// FromEnv leaves ToolScopes nil when unset so policy-mode inference matches the
// contract (nil ToolScopes + no ResourceServerID → OPEN).
func TestFromEnv_NoToolScopes_LeavesNil(t *testing.T) {
	t.Setenv("AUTHSEC_ISSUER", "https://issuer.example.com")
	t.Setenv("AUTHSEC_JWKS_URL", "https://issuer.example.com/oauth/jwks")
	t.Setenv("AUTHSEC_RESOURCE_URI", "https://mcp.example.com/mcp")

	cfg := FromEnv()
	if cfg.ToolScopes != nil {
		t.Fatalf("expected nil ToolScopes when unset, got %v", cfg.ToolScopes)
	}
	if cfg.effectivePolicyMode() != PolicyModeOpen {
		t.Fatalf("expected OPEN when no RS id and no ToolScopes, got %v", cfg.effectivePolicyMode())
	}
}
