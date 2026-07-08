package authsec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// SpiffeWorkloadIdentity obtains short-lived Bearer access tokens using
// SPIFFE/SPIRE workload identity, for Kubernetes workloads. It is the Go parity
// of the Python SDK's identity/spiffe.py.
//
// Flow:
//  1. Discover the AuthSec token endpoint from MCPServerURL (RFC 9728 PRM →
//     RFC 8414 AS metadata). This endpoint is also the SVID audience.
//  2. Fetch a JWT-SVID from the local SPIRE agent (spire-agent api fetch jwt).
//  3. Exchange the SVID at the token endpoint for a Bearer access token.
//  4. Cache both (SVID ~4.5 min; token until expires_in-60s).
//
// On an MCP-server 401: call ClearCache() then AccessFor() again (retry once).

// ── Errors ─────────────────────────────────────────────────────────────────

// SpiffeIdentityError is the base error for SpiffeWorkloadIdentity failures.
type SpiffeIdentityError struct {
	Code       string
	Message    string
	HTTPStatus int
}

func (e *SpiffeIdentityError) Error() string {
	if e.HTTPStatus != 0 {
		return fmt.Sprintf("spiffe[%s] (HTTP %d): %s", e.Code, e.HTTPStatus, e.Message)
	}
	return fmt.Sprintf("spiffe[%s]: %s", e.Code, e.Message)
}

// SpiffeSvidFetchError is returned when a JWT-SVID cannot be fetched from the
// SPIRE agent.
type SpiffeSvidFetchError struct{ SpiffeIdentityError }

func newSpiffeSvidFetchError(msg string) *SpiffeSvidFetchError {
	return &SpiffeSvidFetchError{SpiffeIdentityError{Code: "svid_fetch_failed", Message: msg}}
}

func (e *SpiffeSvidFetchError) Error() string { return e.SpiffeIdentityError.Error() }

// SpiffeTokenExchangeError is returned when AuthSec rejects the JWT-SVID during
// token exchange. Its Code carries an actionable subreason.
type SpiffeTokenExchangeError struct{ SpiffeIdentityError }

func newSpiffeTokenExchangeError(code, msg string, status int) *SpiffeTokenExchangeError {
	return &SpiffeTokenExchangeError{SpiffeIdentityError{Code: code, Message: msg, HTTPStatus: status}}
}

func (e *SpiffeTokenExchangeError) Error() string { return e.SpiffeIdentityError.Error() }

// ── Config ─────────────────────────────────────────────────────────────────

// SpiffeConfig holds all settings for SPIFFE/SPIRE workload identity auth.
type SpiffeConfig struct {
	// MCPServerURL is the protected MCP resource URL. The token endpoint is
	// discovered from it, and that endpoint is also the SVID audience.
	MCPServerURL string
	// ClientID is the workload client_id from the AuthSec portal (UUID).
	ClientID string
	// SpiffeID is the exact SPIFFE ID of this workload (spiffe://...).
	SpiffeID string
	// Scopes is a space-separated scope list, e.g. "mcp:read mcp:tools:read".
	Scopes string
	// TokenEndpoint overrides discovery. If empty it is discovered from
	// MCPServerURL. If set it must be https://.
	TokenEndpoint string
	// AgentSocketPath is the SPIRE agent Unix socket. Default:
	// /run/spire/sockets/agent.sock.
	AgentSocketPath string
	// SvidOverride is a pre-minted JWT-SVID; when set the SPIRE agent
	// subprocess is skipped (useful for testing outside a pod).
	SvidOverride string
}

const defaultSpireAgentSocket = "/run/spire/sockets/agent.sock"

// ── Client ─────────────────────────────────────────────────────────────────

// SpiffeWorkloadIdentity acquires Bearer tokens via SPIFFE/SPIRE. Safe for
// concurrent use.
type SpiffeWorkloadIdentity struct {
	cfg        SpiffeConfig
	httpClient *http.Client

	mu                    sync.Mutex
	resolvedTokenEndpoint string
	svid                  string
	svidExpiresAt         time.Time
	token                 string
	tokenExpiresAt        time.Time
}

// NewSpiffeWorkloadIdentity validates the config and returns a client. When no
// SvidOverride is set, the SPIRE agent socket must already exist.
func NewSpiffeWorkloadIdentity(cfg SpiffeConfig) (*SpiffeWorkloadIdentity, error) {
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, fmt.Errorf("SpiffeConfig.ClientID is required")
	}
	if !strings.HasPrefix(cfg.SpiffeID, "spiffe://") {
		return nil, fmt.Errorf("SpiffeConfig.SpiffeID must start with 'spiffe://'")
	}
	if cfg.TokenEndpoint != "" && !strings.HasPrefix(cfg.TokenEndpoint, "https://") {
		return nil, fmt.Errorf("SpiffeConfig.TokenEndpoint must start with 'https://'")
	}
	if strings.TrimSpace(cfg.Scopes) == "" {
		return nil, fmt.Errorf("SpiffeConfig.Scopes is required")
	}
	if cfg.AgentSocketPath == "" {
		cfg.AgentSocketPath = defaultSpireAgentSocket
	}
	if cfg.SvidOverride == "" {
		if _, err := os.Stat(cfg.AgentSocketPath); err != nil {
			return nil, newSpiffeSvidFetchError(fmt.Sprintf(
				"SPIRE agent socket not found at %s. Is the SPIRE agent running and the socket mounted?",
				cfg.AgentSocketPath,
			))
		}
	}
	return &SpiffeWorkloadIdentity{
		cfg:                   cfg,
		httpClient:            &http.Client{Timeout: 30 * time.Second},
		resolvedTokenEndpoint: cfg.TokenEndpoint,
	}, nil
}

// AccessFor returns a valid Bearer access token for the configured MCP server,
// serving from cache when the token has more than 60 seconds remaining.
func (s *SpiffeWorkloadIdentity) AccessFor(ctx context.Context) (string, error) {
	s.mu.Lock()
	if s.token != "" && time.Until(s.tokenExpiresAt) > 60*time.Second {
		t := s.token
		s.mu.Unlock()
		return t, nil
	}
	s.mu.Unlock()
	return s.exchangeForToken(ctx)
}

// ClearCache clears the SVID and token caches (keeps the discovered token
// endpoint). Call after an MCP-server 401, then AccessFor again.
func (s *SpiffeWorkloadIdentity) ClearCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.svid = ""
	s.svidExpiresAt = time.Time{}
	s.token = ""
	s.tokenExpiresAt = time.Time{}
}

// ── Internal ───────────────────────────────────────────────────────────────

func (s *SpiffeWorkloadIdentity) exchangeForToken(ctx context.Context) (string, error) {
	tokenEndpoint, err := s.resolveTokenEndpoint(ctx)
	if err != nil {
		return "", err
	}
	svid, err := s.getSVID(ctx, tokenEndpoint)
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", s.cfg.ClientID)
	form.Set("client_assertion_type", spiffeSvidAssertionType)
	form.Set("client_assertion", svid)
	form.Set("resource", s.cfg.MCPServerURL)
	form.Set("scope", s.cfg.Scopes)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", newSpiffeTokenExchangeError("token_exchange_failed", err.Error(), 0)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", newSpiffeTokenExchangeError("token_exchange_failed", err.Error(), 0)
	}
	defer resp.Body.Close()

	var body map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", s.exchangeError(body, resp.StatusCode, tokenEndpoint)
	}

	token, _ := body["access_token"].(string)
	if token == "" {
		return "", newSpiffeTokenExchangeError("token_exchange_failed", "no access_token in response", resp.StatusCode)
	}
	expiresIn := 3600.0
	if v, ok := body["expires_in"].(float64); ok {
		expiresIn = v
	}

	s.mu.Lock()
	s.token = token
	s.tokenExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	s.mu.Unlock()
	return token, nil
}

func (s *SpiffeWorkloadIdentity) resolveTokenEndpoint(ctx context.Context) (string, error) {
	s.mu.Lock()
	if s.resolvedTokenEndpoint != "" {
		te := s.resolvedTokenEndpoint
		s.mu.Unlock()
		return te, nil
	}
	s.mu.Unlock()

	// RFC 9728 PRM — uses the alias path for path-based resources.
	prmURL := BuildResourceMetadataURL(s.cfg.MCPServerURL)
	prm := struct {
		AuthorizationServers []string `json:"authorization_servers"`
	}{}
	if err := s.getJSON(ctx, prmURL, &prm); err != nil {
		return "", &SpiffeIdentityError{
			Code:    "prm_discovery_failed",
			Message: fmt.Sprintf("protected resource metadata not found at %s: %v. Is the MCP server registered in AuthSec?", prmURL, err),
		}
	}
	if len(prm.AuthorizationServers) == 0 {
		return "", &SpiffeIdentityError{
			Code:    "no_authorization_server",
			Message: fmt.Sprintf("no authorization_servers in PRM for %s. Is the MCP server registered in AuthSec?", s.cfg.MCPServerURL),
		}
	}

	// RFC 8414 AS metadata.
	asURL := strings.TrimRight(prm.AuthorizationServers[0], "/")
	meta := struct {
		TokenEndpoint string `json:"token_endpoint"`
	}{}
	if err := s.getJSON(ctx, asURL+"/.well-known/oauth-authorization-server", &meta); err != nil {
		return "", &SpiffeIdentityError{
			Code:    "as_discovery_failed",
			Message: fmt.Sprintf("AS metadata discovery failed for %s: %v", asURL, err),
		}
	}
	if meta.TokenEndpoint == "" {
		return "", &SpiffeIdentityError{
			Code:    "token_endpoint_missing",
			Message: fmt.Sprintf("token_endpoint not found in AS metadata for %s", asURL),
		}
	}

	s.mu.Lock()
	s.resolvedTokenEndpoint = meta.TokenEndpoint
	s.mu.Unlock()
	return meta.TokenEndpoint, nil
}

func (s *SpiffeWorkloadIdentity) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (s *SpiffeWorkloadIdentity) getSVID(ctx context.Context, tokenEndpoint string) (string, error) {
	if s.cfg.SvidOverride != "" {
		return s.cfg.SvidOverride, nil
	}

	s.mu.Lock()
	if s.svid != "" && time.Until(s.svidExpiresAt) > 30*time.Second {
		sv := s.svid
		s.mu.Unlock()
		return sv, nil
	}
	s.mu.Unlock()

	svid, err := s.fetchSVIDFromAgent(ctx, tokenEndpoint)
	if err != nil {
		return "", err
	}
	// SVID TTL is ~5 min; cache for 4.5 min so we refresh before expiry.
	s.mu.Lock()
	s.svid = svid
	s.svidExpiresAt = time.Now().Add(270 * time.Second)
	s.mu.Unlock()
	return svid, nil
}

func (s *SpiffeWorkloadIdentity) fetchSVIDFromAgent(ctx context.Context, tokenEndpoint string) (string, error) {
	if _, err := os.Stat(s.cfg.AgentSocketPath); err != nil {
		return "", newSpiffeSvidFetchError(fmt.Sprintf(
			"SPIRE agent socket not found at %s. Is the SPIRE agent running and the socket mounted?",
			s.cfg.AgentSocketPath,
		))
	}

	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// audience MUST be the exact token endpoint URL.
	cmd := exec.CommandContext(cctx, "spire-agent", "api", "fetch", "jwt",
		"-audience", tokenEndpoint,
		"-socketPath", s.cfg.AgentSocketPath,
	)
	out, err := cmd.CombinedOutput()
	if cctx.Err() == context.DeadlineExceeded {
		return "", newSpiffeSvidFetchError(
			"SVID fetch failed: spire-agent timed out after 10s. Ensure the SPIRE agent is running and the workload is attested.",
		)
	}
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return "", newSpiffeSvidFetchError(fmt.Sprintf(
			"SVID fetch failed: %s. Ensure the SPIRE agent is running and the workload is attested.", msg,
		))
	}

	svid := parseJWTSVID(string(out))
	if svid == "" {
		return "", newSpiffeSvidFetchError(
			"SVID fetch failed: could not parse JWT from spire-agent output. Ensure the SPIRE agent is running and the workload is attested.",
		)
	}
	return svid, nil
}

// exchangeError maps an AuthSec error response to an actionable typed error.
func (s *SpiffeWorkloadIdentity) exchangeError(body map[string]any, status int, tokenEndpoint string) error {
	descRaw, _ := body["error_description"].(string)
	if descRaw == "" {
		descRaw, _ = body["error"].(string)
	}
	desc := strings.ToLower(descRaw)

	if status == http.StatusUnauthorized {
		switch {
		case strings.Contains(desc, "no usable signing keys found in jwks"):
			issuerBase := tokenEndpoint
			if i := strings.Index(tokenEndpoint, "/oauth"); i >= 0 {
				issuerBase = tokenEndpoint[:i]
			}
			return newSpiffeTokenExchangeError("jwks_unconfigured",
				"AuthSec cannot verify SPIRE JWKS. Check the Workload Identity Provider is configured and OIDC discovery is reachable at "+
					issuerBase+"/.well-known/openid-configuration", status)
		case strings.Contains(desc, "no active service account for spiffe id"):
			return newSpiffeTokenExchangeError("spiffe_id_not_registered",
				fmt.Sprintf("SPIFFE ID %q not registered in AuthSec. Complete the Connect Kubernetes workload wizard in the portal.", s.cfg.SpiffeID), status)
		case strings.Contains(desc, "token aud must include this token endpoint"):
			return newSpiffeTokenExchangeError("audience_mismatch",
				fmt.Sprintf("SVID audience is wrong. Fetch the SVID with audience = %q exactly.", tokenEndpoint), status)
		case strings.Contains(desc, "svid trust domain does not match"):
			return newSpiffeTokenExchangeError("trust_domain_mismatch",
				"Trust domain mismatch. Check the Workload Identity Provider trust domain in the portal.", status)
		}
	}
	if status == http.StatusForbidden && strings.Contains(desc, "no scopes granted") {
		return newSpiffeTokenExchangeError("no_scopes_granted",
			"No scopes granted for this resource. Assign a role with the required scopes to the workload in the AuthSec portal.", status)
	}
	if status == http.StatusBadRequest && strings.Contains(desc, "client_id is required") {
		return newSpiffeTokenExchangeError("client_id_missing",
			"client_id missing. Pass the workload client_id from the AuthSec portal.", status)
	}

	code, _ := body["error"].(string)
	if code == "" {
		code = "token_exchange_failed"
	}
	msg := descRaw
	if msg == "" {
		msg = "Token exchange failed."
	}
	return newSpiffeTokenExchangeError(code, msg, status)
}

// parseJWTSVID extracts the first JWT (eyJ...) from spire-agent CLI output.
func parseJWTSVID(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "eyJ") {
			return line
		}
	}
	return ""
}
