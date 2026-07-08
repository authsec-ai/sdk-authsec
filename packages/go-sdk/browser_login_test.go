package authsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// newOIDCStub serves an OIDC discovery document and a /token endpoint that
// returns a fixed id_token.
func newOIDCStub(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id_token":"eyJid","access_token":"at"}`))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// freePort returns a currently-free localhost TCP port.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func TestBrowserLogin_HappyPath(t *testing.T) {
	stub := newOIDCStub(t)
	port := freePort(t)

	// Simulate the browser: parse the state from the auth URL and hit the
	// local callback with a matching code+state.
	open := func(authURL string) error {
		u, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		state := u.Query().Get("state")
		go func() {
			cb := fmt.Sprintf("http://localhost:%d/callback?code=test-code&state=%s", port, url.QueryEscape(state))
			for i := 0; i < 100; i++ {
				resp, err := http.Get(cb)
				if err == nil {
					_ = resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						return
					}
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
		return nil
	}

	idToken, err := BrowserLogin(context.Background(), stub.URL, "public-client", &BrowserLoginOptions{
		Port:        port,
		Timeout:     3 * time.Second,
		OpenBrowser: open,
	})
	if err != nil {
		t.Fatalf("BrowserLogin() error = %v", err)
	}
	if idToken != "eyJid" {
		t.Fatalf("expected id_token eyJid, got %q", idToken)
	}
}

func TestBrowserLogin_Timeout(t *testing.T) {
	stub := newOIDCStub(t)
	port := freePort(t)

	// OpenBrowser never completes the callback → BrowserLogin must time out.
	open := func(string) error { return nil }

	_, err := BrowserLogin(context.Background(), stub.URL, "public-client", &BrowserLoginOptions{
		Port:        port,
		Timeout:     60 * time.Millisecond,
		OpenBrowser: open,
	})
	if err == nil || !strings.Contains(err.Error(), "no login completed") {
		t.Fatalf("expected a timeout error, got %v", err)
	}
}

func TestBrowserLogin_RequiresIssuerAndClientID(t *testing.T) {
	if _, err := BrowserLogin(context.Background(), "", "c", nil); err == nil {
		t.Fatal("expected error for empty issuer")
	}
	if _, err := BrowserLogin(context.Background(), "https://issuer.example", "", nil); err == nil {
		t.Fatal("expected error for empty clientID")
	}
}
