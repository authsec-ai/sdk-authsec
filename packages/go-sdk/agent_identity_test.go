package authsec

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// agentAuthCapture records what the stub token endpoint received, so tests can
// assert how the client authenticated.
type agentAuthCapture struct {
	tokenAuthz string
	tokenForm  url.Values
}

// newAgentStub stands up a minimal AuthSec AS + resource server for
// AgentIdentity tests: RFC 9728 PRM, RFC 8414 AS metadata, and a /token
// endpoint whose response is supplied by tokenResp. The resource URL is
// srv.URL + "/mcp".
func newAgentStub(t *testing.T, cap *agentAuthCapture, tokenResp func() (int, string)) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()

	prm := func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              srv.URL + "/mcp",
			"authorization_servers": []string{srv.URL},
		})
	}
	mux.HandleFunc("/.well-known/oauth-protected-resource", prm)
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", prm)

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                srv.URL,
			"token_endpoint":        srv.URL + "/token",
			"grant_types_supported": []string{"client_credentials"},
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		cap.tokenAuthz = r.Header.Get("Authorization")
		cap.tokenForm = r.Form
		code, body := tokenResp()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func okToken() (int, string) {
	return http.StatusOK, `{"access_token":"tok-abc","expires_in":3600}`
}

// Backward-compat: ClientSecret keeps working and sends HTTP Basic; no client_id
// leaks into the body when Basic is present.
func TestAgentIdentity_ClientSecret_DirectFlow(t *testing.T) {
	cap := &agentAuthCapture{}
	stub := newAgentStub(t, cap, okToken)

	ai := NewAgentIdentity(AgentIdentityConfig{
		Issuer:        stub.URL,
		ClientID:      "client-1",
		ClientSecret:  "secret-1",
		PreferredMode: "direct-only",
	})

	tok, err := ai.AccessFor(context.Background(), stub.URL+"/mcp")
	if err != nil {
		t.Fatalf("AccessFor() error = %v", err)
	}
	if tok != "tok-abc" {
		t.Fatalf("expected token tok-abc, got %q", tok)
	}

	wantAuthz := "Basic " + base64.StdEncoding.EncodeToString([]byte("client-1:secret-1"))
	if cap.tokenAuthz != wantAuthz {
		t.Fatalf("expected Basic auth %q, got %q", wantAuthz, cap.tokenAuthz)
	}
	if got := cap.tokenForm.Get("grant_type"); got != "client_credentials" {
		t.Fatalf("expected grant_type client_credentials, got %q", got)
	}
	if got := cap.tokenForm.Get("resource"); got != stub.URL+"/mcp" {
		t.Fatalf("expected resource in body, got %q", got)
	}
	if got := cap.tokenForm.Get("client_id"); got != "" {
		t.Fatalf("did not expect client_id in body when Basic auth is present, got %q", got)
	}
}

// Explicit Auth = NewClientSecretAuth(...) is equivalent to the ClientSecret shorthand.
func TestAgentIdentity_ExplicitClientSecretAuth_Equivalent(t *testing.T) {
	cap := &agentAuthCapture{}
	stub := newAgentStub(t, cap, okToken)

	ai := NewAgentIdentity(AgentIdentityConfig{
		Issuer:        stub.URL,
		ClientID:      "client-1",
		Auth:          NewClientSecretAuth("secret-1"),
		PreferredMode: "direct-only",
	})

	if _, err := ai.AccessFor(context.Background(), stub.URL+"/mcp"); err != nil {
		t.Fatalf("AccessFor() error = %v", err)
	}
	wantAuthz := "Basic " + base64.StdEncoding.EncodeToString([]byte("client-1:secret-1"))
	if cap.tokenAuthz != wantAuthz {
		t.Fatalf("expected Basic auth %q, got %q", wantAuthz, cap.tokenAuthz)
	}
}

// private_key_jwt sends no Basic header; instead it carries a client_assertion
// (audience-bound to the token endpoint) plus an explicit client_id in the body.
func TestAgentIdentity_PrivateKeyJwt_DirectFlow(t *testing.T) {
	cap := &agentAuthCapture{}
	stub := newAgentStub(t, cap, okToken)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	auth, err := NewPrivateKeyJwtAuth(rsaPrivateKeyPEM(t, key), "kid-1")
	if err != nil {
		t.Fatalf("NewPrivateKeyJwtAuth: %v", err)
	}

	ai := NewAgentIdentity(AgentIdentityConfig{
		Issuer:        stub.URL,
		ClientID:      "client-1",
		Auth:          auth,
		PreferredMode: "direct-only",
	})

	tok, err := ai.AccessFor(context.Background(), stub.URL+"/mcp")
	if err != nil {
		t.Fatalf("AccessFor() error = %v", err)
	}
	if tok != "tok-abc" {
		t.Fatalf("expected token tok-abc, got %q", tok)
	}

	if cap.tokenAuthz != "" {
		t.Fatalf("expected no Authorization header for private_key_jwt, got %q", cap.tokenAuthz)
	}
	if got := cap.tokenForm.Get("client_assertion_type"); got != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("unexpected client_assertion_type in body: %q", got)
	}
	assertion := cap.tokenForm.Get("client_assertion")
	if assertion == "" {
		t.Fatal("expected a client_assertion in the body")
	}
	if got := cap.tokenForm.Get("client_id"); got != "client-1" {
		t.Fatalf("expected client_id injected in body for assertion auth, got %q", got)
	}

	parsed, err := jwt.Parse(assertion, func(*jwt.Token) (any, error) { return &key.PublicKey, nil })
	if err != nil || !parsed.Valid {
		t.Fatalf("assertion did not verify: err=%v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["aud"] != stub.URL+"/token" {
		t.Fatalf("expected assertion aud=%s, got %v", stub.URL+"/token", claims["aud"])
	}
}

func TestNewAgentIdentity_PanicsWhenAuthAndClientSecretBothSet(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic when both Auth and ClientSecret are set")
		}
	}()
	NewAgentIdentity(AgentIdentityConfig{
		Issuer:       "https://issuer.example.com",
		ClientID:     "client-1",
		ClientSecret: "secret-1",
		Auth:         NewClientSecretAuth("secret-1"),
	})
}

func TestNewAgentIdentity_PanicsWithoutIssuerOrClientID(t *testing.T) {
	// case 0: missing issuer. case 1: missing client id.
	cases := []AgentIdentityConfig{
		{ClientID: "c"},
		{Issuer: "https://i.example"},
	}
	for i, cfg := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("case %d: expected panic", i)
				}
			}()
			NewAgentIdentity(cfg)
		}()
	}
}
