package authsec

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// BrowserLoginOptions configures BrowserLogin. Zero values fall back to
// defaults (Scopes ["openid","email","profile"], Port 8126, Timeout 300s).
type BrowserLoginOptions struct {
	// Resource optionally binds the login to a specific MCP resource (RFC 8707).
	Resource string
	// Scopes to request. Defaults to ["openid", "email", "profile"].
	Scopes []string
	// Port for the local redirect callback. Must match the redirect URI
	// registered for the OAuth client. Default: 8126.
	Port int
	// Timeout for the user to complete the browser login. Default: 300s.
	Timeout time.Duration
	// OpenBrowser opens the authorization URL. When nil a platform default is
	// used. Set it in tests to avoid launching a real browser.
	OpenBrowser func(url string) error
}

// BrowserLogin runs an interactive OAuth PKCE login and returns the id_token,
// ready to pass as WithUserSession(idToken) to AgentIdentity.AccessFor for the
// ID-JAG / XAA flow. It is the Go parity of the Python SDK's browser_login.
//
// It handles OIDC discovery, PKCE pair generation, a one-shot local callback
// server, browser launch, and the authorization-code exchange.
func BrowserLogin(ctx context.Context, issuer, clientID string, opts *BrowserLoginOptions) (string, error) {
	if issuer == "" {
		return "", fmt.Errorf("browser_login: issuer is required")
	}
	if clientID == "" {
		return "", fmt.Errorf("browser_login: clientID is required")
	}

	o := BrowserLoginOptions{}
	if opts != nil {
		o = *opts
	}
	if o.Port == 0 {
		o.Port = 8126
	}
	if o.Timeout == 0 {
		o.Timeout = 300 * time.Second
	}
	scopes := o.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	openBrowser := o.OpenBrowser
	if openBrowser == nil {
		openBrowser = defaultOpenBrowser
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}

	meta, err := fetchOIDCMetadata(ctx, httpClient, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return "", err
	}

	// PKCE pair.
	verifier, err := randomURLSafe(48)
	if err != nil {
		return "", fmt.Errorf("browser_login: %w", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	state, err := randomURLSafe(16)
	if err != nil {
		return "", fmt.Errorf("browser_login: %w", err)
	}
	nonce, err := randomURLSafe(16)
	if err != nil {
		return "", fmt.Errorf("browser_login: %w", err)
	}

	redirectURI := fmt.Sprintf("http://localhost:%d/callback", o.Port)
	authParams := url.Values{}
	authParams.Set("response_type", "code")
	authParams.Set("client_id", clientID)
	authParams.Set("redirect_uri", redirectURI)
	authParams.Set("scope", strings.Join(scopes, " "))
	authParams.Set("state", state)
	authParams.Set("nonce", nonce)
	authParams.Set("code_challenge", challenge)
	authParams.Set("code_challenge_method", "S256")
	if o.Resource != "" {
		authParams.Set("resource", o.Resource)
	}
	authURL := meta.AuthorizationEndpoint + "?" + authParams.Encode()

	// One-shot callback server — shuts down when this function returns.
	codeCh := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := q.Get("code")
		st := q.Get("state")
		switch {
		case code != "" && st == state:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<h2>Login complete — you can close this tab.</h2>"))
			select {
			case codeCh <- code:
			default:
			}
		case code != "":
			// Code present but state mismatch — possible CSRF / stale redirect.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("<h2>Login rejected: state mismatch. Please retry.</h2>"))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})

	ln, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", o.Port))
	if err != nil {
		return "", fmt.Errorf("browser_login: cannot listen on localhost:%d — is the port already in use? %w", o.Port, err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	if err := openBrowser(authURL); err != nil {
		// Non-fatal: the user can open the URL manually.
		fmt.Printf("Open this URL to log in:\n%s\n", authURL)
	}

	var code string
	select {
	case code = <-codeCh:
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(o.Timeout):
		return "", fmt.Errorf("browser_login: no login completed within %s", o.Timeout)
	}

	// Exchange code → tokens.
	tokenBody := url.Values{}
	tokenBody.Set("grant_type", "authorization_code")
	tokenBody.Set("code", code)
	tokenBody.Set("redirect_uri", redirectURI)
	tokenBody.Set("client_id", clientID)
	tokenBody.Set("code_verifier", verifier)
	if o.Resource != "" {
		tokenBody.Set("resource", o.Resource)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.TokenEndpoint, strings.NewReader(tokenBody.Encode()))
	if err != nil {
		return "", fmt.Errorf("browser_login: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("browser_login: token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(raw, &tokens); err != nil {
		return "", fmt.Errorf("browser_login: token endpoint returned non-JSON (HTTP %d)", resp.StatusCode)
	}
	if tokens.IDToken == "" {
		return "", fmt.Errorf("browser_login: token exchange failed — no id_token (HTTP %d): %s", resp.StatusCode, string(raw))
	}
	return tokens.IDToken, nil
}

type oidcMetadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func fetchOIDCMetadata(ctx context.Context, client *http.Client, discoveryURL string) (*oidcMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("browser_login: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("browser_login: OIDC discovery failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("browser_login: OIDC discovery returned HTTP %d from %s", resp.StatusCode, discoveryURL)
	}
	var m oidcMetadata
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("browser_login: OIDC discovery returned non-JSON from %s", discoveryURL)
	}
	if m.AuthorizationEndpoint == "" || m.TokenEndpoint == "" {
		return nil, fmt.Errorf("browser_login: OIDC discovery missing authorization_endpoint/token_endpoint")
	}
	return &m, nil
}

func randomURLSafe(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func defaultOpenBrowser(u string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	case "darwin":
		return exec.Command("open", u).Start()
	default:
		return exec.Command("xdg-open", u).Start()
	}
}
