package authsec

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestWrapMCPHTTP_BlocksUnauthorizedToolCall(t *testing.T) {
	cfg, token, cleanup := testConfig(t)
	defer cleanup()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler, err := WrapMCPHTTP(next, cfg)
	if err != nil {
		t.Fatalf("WrapMCPHTTP() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_issue"}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "insufficient_scope") {
		t.Fatalf("expected insufficient scope challenge, got %q", got)
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
		Policy: StaticPolicy{
			"list_issues":  {AnyOfScopes: []string{"issues:read"}},
			"create_issue": {AnyOfScopes: []string{"issues:write"}},
		},
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
