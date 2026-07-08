package authsec

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newPollStub serves PRM + AS metadata + /token (for the post-approval
// AccessFor) and a /status endpoint whose body is produced by statusFn.
func newPollStub(t *testing.T, statusFn func() string) *httptest.Server {
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
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"tok-xyz","expires_in":3600}`))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": statusFn()})
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func pollAgent(t *testing.T, issuer string) *AgentIdentity {
	t.Helper()
	return NewAgentIdentity(AgentIdentityConfig{
		Issuer:        issuer,
		ClientID:      "client-1",
		ClientSecret:  "secret-1",
		PreferredMode: "direct-only",
	})
}

func TestPollUntilApproved_ApprovedReturnsToken(t *testing.T) {
	var calls int32
	stub := newPollStub(t, func() string {
		if atomic.AddInt32(&calls, 1) >= 2 {
			return "approved"
		}
		return "pending"
	})

	ai := pollAgent(t, stub.URL)
	tok, err := PollUntilApproved(context.Background(), ai, stub.URL+"/mcp", stub.URL+"/status",
		&PollOptions{Interval: 5 * time.Millisecond, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("PollUntilApproved() error = %v", err)
	}
	if tok != "tok-xyz" {
		t.Fatalf("expected token tok-xyz, got %q", tok)
	}
}

func TestPollUntilApproved_Denied(t *testing.T) {
	stub := newPollStub(t, func() string { return "denied" })
	ai := pollAgent(t, stub.URL)
	_, err := PollUntilApproved(context.Background(), ai, stub.URL+"/mcp", stub.URL+"/status",
		&PollOptions{Interval: 5 * time.Millisecond, Timeout: time.Second})
	var denied *ApprovalDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected *ApprovalDeniedError, got %T: %v", err, err)
	}
}

func TestPollUntilApproved_Revoked(t *testing.T) {
	stub := newPollStub(t, func() string { return "revoked" })
	ai := pollAgent(t, stub.URL)
	_, err := PollUntilApproved(context.Background(), ai, stub.URL+"/mcp", stub.URL+"/status",
		&PollOptions{Interval: 5 * time.Millisecond, Timeout: time.Second})
	var revoked *ConnectionRevokedError
	if !errors.As(err, &revoked) {
		t.Fatalf("expected *ConnectionRevokedError, got %T: %v", err, err)
	}
}

func TestPollUntilApproved_Timeout(t *testing.T) {
	stub := newPollStub(t, func() string { return "pending" })
	ai := pollAgent(t, stub.URL)
	_, err := PollUntilApproved(context.Background(), ai, stub.URL+"/mcp", stub.URL+"/status",
		&PollOptions{Interval: 5 * time.Millisecond, Timeout: 40 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected a timeout error, got %v", err)
	}
}
