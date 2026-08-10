package authsec

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestSpiffeWorkloadIdentity_Success(t *testing.T) {
	cap := &agentAuthCapture{}
	stub := newAgentStub(t, cap, okToken)

	w, err := NewSpiffeWorkloadIdentity(SpiffeConfig{
		MCPServerURL: stub.URL + "/mcp",
		ClientID:     "workload-1",
		SpiffeID:     "spiffe://acme.example/ns/default/sa/svc",
		Scopes:       "mcp:read mcp:tools:read",
		SvidOverride: "eyJfakesvid",
	})
	if err != nil {
		t.Fatalf("NewSpiffeWorkloadIdentity: %v", err)
	}

	tok, err := w.AccessFor(context.Background())
	if err != nil {
		t.Fatalf("AccessFor() error = %v", err)
	}
	if tok != "tok-abc" {
		t.Fatalf("expected token tok-abc, got %q", tok)
	}

	if got := cap.tokenForm.Get("grant_type"); got != "client_credentials" {
		t.Fatalf("expected grant_type client_credentials, got %q", got)
	}
	if got := cap.tokenForm.Get("client_assertion_type"); got != "urn:authsec:params:oauth:client-assertion-type:spiffe-svid" {
		t.Fatalf("unexpected client_assertion_type: %q", got)
	}
	if got := cap.tokenForm.Get("client_assertion"); got != "eyJfakesvid" {
		t.Fatalf("expected SVID as client_assertion, got %q", got)
	}
	if got := cap.tokenForm.Get("resource"); got != stub.URL+"/mcp" {
		t.Fatalf("expected resource in body, got %q", got)
	}
	if got := cap.tokenForm.Get("scope"); got != "mcp:read mcp:tools:read" {
		t.Fatalf("expected scope in body, got %q", got)
	}
	if got := cap.tokenForm.Get("client_id"); got != "workload-1" {
		t.Fatalf("expected client_id in body, got %q", got)
	}
}

func TestSpiffeWorkloadIdentity_TokenCache(t *testing.T) {
	var tokenCalls int32
	cap := &agentAuthCapture{}
	stub := newAgentStub(t, cap, func() (int, string) {
		atomic.AddInt32(&tokenCalls, 1)
		return okToken()
	})

	w, err := NewSpiffeWorkloadIdentity(SpiffeConfig{
		MCPServerURL: stub.URL + "/mcp",
		ClientID:     "workload-1",
		SpiffeID:     "spiffe://acme.example/svc",
		Scopes:       "mcp:read",
		SvidOverride: "eyJfakesvid",
	})
	if err != nil {
		t.Fatalf("NewSpiffeWorkloadIdentity: %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, err := w.AccessFor(context.Background()); err != nil {
			t.Fatalf("AccessFor() #%d error = %v", i, err)
		}
	}
	if n := atomic.LoadInt32(&tokenCalls); n != 1 {
		t.Fatalf("expected 1 token exchange (rest served from cache), got %d", n)
	}
}

func TestSpiffeWorkloadIdentity_ErrorMapping(t *testing.T) {
	cap := &agentAuthCapture{}
	stub := newAgentStub(t, cap, func() (int, string) {
		return 403, `{"error":"access_denied","error_description":"No scopes granted for resource"}`
	})

	w, err := NewSpiffeWorkloadIdentity(SpiffeConfig{
		MCPServerURL: stub.URL + "/mcp",
		ClientID:     "workload-1",
		SpiffeID:     "spiffe://acme.example/svc",
		Scopes:       "mcp:read",
		SvidOverride: "eyJfakesvid",
	})
	if err != nil {
		t.Fatalf("NewSpiffeWorkloadIdentity: %v", err)
	}

	_, err = w.AccessFor(context.Background())
	var texc *SpiffeTokenExchangeError
	if !errors.As(err, &texc) {
		t.Fatalf("expected *SpiffeTokenExchangeError, got %T: %v", err, err)
	}
	if texc.Code != "no_scopes_granted" {
		t.Fatalf("expected code no_scopes_granted, got %q", texc.Code)
	}
	if texc.HTTPStatus != 403 {
		t.Fatalf("expected HTTP 403, got %d", texc.HTTPStatus)
	}
}

func TestNewSpiffeWorkloadIdentity_Validation(t *testing.T) {
	base := SpiffeConfig{
		MCPServerURL: "https://mcp.example/mcp",
		ClientID:     "workload-1",
		SpiffeID:     "spiffe://acme.example/svc",
		Scopes:       "mcp:read",
		SvidOverride: "eyJfakesvid",
	}

	mutate := func(f func(*SpiffeConfig)) SpiffeConfig {
		c := base
		f(&c)
		return c
	}

	cases := map[string]SpiffeConfig{
		"missing client id": mutate(func(c *SpiffeConfig) { c.ClientID = "" }),
		"bad spiffe id":     mutate(func(c *SpiffeConfig) { c.SpiffeID = "acme/svc" }),
		"missing scopes":    mutate(func(c *SpiffeConfig) { c.Scopes = "" }),
		"non-https token endpoint": mutate(func(c *SpiffeConfig) {
			c.TokenEndpoint = "http://as.example/token"
		}),
		"no override + missing socket": mutate(func(c *SpiffeConfig) {
			c.SvidOverride = ""
			c.AgentSocketPath = "/nonexistent/authsec-test/agent.sock"
		}),
	}

	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSpiffeWorkloadIdentity(cfg); err == nil {
				t.Fatalf("expected error for %q", name)
			}
		})
	}
}
