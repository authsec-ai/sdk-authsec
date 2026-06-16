package authsec

// Cross-App Access (XAA) client helpers.
//
// These wrap the IETF draft-ietf-oauth-identity-assertion-authz-grant flow so
// an agent or chained MCP server can:
//
//	1. Exchange a user's id_token at the IdP for an ID-JAG via
//	   POST /authsec/oauth/v2/idjag/token (Token Exchange, RFC 8693).
//	2. Redeem the ID-JAG at the Resource AS for an access token via
//	   POST /authsec/oauth/v2/token (jwt-bearer grant, RFC 7523).
//
// The two functions in this file are thin HTTP wrappers — no hidden state,
// no caching. Callers manage token reuse + refresh themselves. The point is
// to make the spec wire-format hard to get wrong, not to hide it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Grant + token type constants (IETF draft-ietf-oauth-identity-assertion-authz-grant + RFC 8693).
const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	GrantTypeJWTBearer     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	TokenTypeIDJAG         = "urn:ietf:params:oauth:token-type:id-jag"
	TokenTypeIDToken       = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeRefreshToken  = "urn:ietf:params:oauth:token-type:refresh_token"
)

// RequestIDJAGInput is the input for RequestIDJAG. Mirrors the Token Exchange
// form parameters one-to-one so callers reading the IETF draft see the same
// names.
type RequestIDJAGInput struct {
	// IdPTokenEndpoint is the IdP AS's /idjag/token URL. For AuthSec
	// today: https://<authsec>/authsec/oauth/v2/idjag/token.
	IdPTokenEndpoint string

	// ClientID + ClientSecret authenticate the requesting agent at the
	// IdP. Maps to the xaa_client_apps row when AuthSec is the IdP.
	ClientID     string
	ClientSecret string

	// SubjectToken is the user's identity assertion — usually the
	// id_token they got from their original login at the IdP. Refresh
	// tokens are also accepted by the spec but most IdPs prefer id_token
	// here.
	SubjectToken string

	// SubjectTokenType. Defaults to TokenTypeIDToken when empty.
	SubjectTokenType string

	// Audience is the Resource AS issuer the ID-JAG will be redeemed at.
	// REQUIRED. For internal AuthSec deployments this is the AuthSec
	// issuer URL itself (e.g. https://prod.api.authsec.ai) since AuthSec
	// is also the Resource AS.
	Audience string

	// Resource is the RFC 8707 target resource URI — the specific MCP
	// the access token will be valid for. REQUIRED by AuthSec because
	// XAA policy is keyed on resource_server_id.
	Resource string

	// Scopes is the desired scope set. Empty = "give me whatever the
	// IdP policy permits for this (client, resource)".
	Scopes []string

	// HTTPClient lets callers inject timeouts, proxies, retries. nil =
	// a default client with a 10s timeout.
	HTTPClient *http.Client
}

// IDJAGResponse is the IdP's RFC 8693 §2.2.1 reply.
type IDJAGResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"` // "N_A" per spec for ID-JAG
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
}

// OAuthError is the RFC 6749 error response we surface to callers as a typed
// error. errors.As lets callers branch on the error code without parsing
// strings.
type OAuthError struct {
	HTTPStatus       int    `json:"-"`
	Code             string `json:"error"`
	Description      string `json:"error_description,omitempty"`
	URI              string `json:"error_uri,omitempty"`
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("oauth %s: %s", e.Code, e.Description)
	}
	return "oauth " + e.Code
}

// RequestIDJAG performs the Token Exchange at the IdP and returns the ID-JAG.
//
// Typical use:
//
//	idjag, err := authsec.RequestIDJAG(ctx, authsec.RequestIDJAGInput{
//	    IdPTokenEndpoint: "https://prod.api.authsec.ai/authsec/oauth/v2/idjag/token",
//	    ClientID:         "my-agent",
//	    ClientSecret:     os.Getenv("AGENT_SECRET"),
//	    SubjectToken:     userIDToken,
//	    Audience:         "https://prod.api.authsec.ai",
//	    Resource:         "https://my-mcp.example.com/mcp",
//	    Scopes:           []string{"orders:read"},
//	})
func RequestIDJAG(ctx context.Context, in RequestIDJAGInput) (*IDJAGResponse, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("requested_token_type", TokenTypeIDJAG)
	form.Set("subject_token", in.SubjectToken)
	subjType := in.SubjectTokenType
	if subjType == "" {
		subjType = TokenTypeIDToken
	}
	form.Set("subject_token_type", subjType)
	form.Set("audience", in.Audience)
	form.Set("resource", in.Resource)
	if len(in.Scopes) > 0 {
		form.Set("scope", strings.Join(in.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.IdPTokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(in.ClientID, in.ClientSecret)

	resp, err := defaultClient(in.HTTPClient).Do(req)
	if err != nil {
		return nil, fmt.Errorf("idjag exchange: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("idjag exchange: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseOAuthError(resp.StatusCode, body)
	}
	var out IDJAGResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("idjag exchange: decode response: %w", err)
	}
	if out.AccessToken == "" {
		return nil, errors.New("idjag exchange: empty access_token in response")
	}
	return &out, nil
}

func (in RequestIDJAGInput) validate() error {
	switch {
	case strings.TrimSpace(in.IdPTokenEndpoint) == "":
		return errors.New("IdPTokenEndpoint required")
	case strings.TrimSpace(in.ClientID) == "":
		return errors.New("ClientID required")
	case strings.TrimSpace(in.SubjectToken) == "":
		return errors.New("SubjectToken required")
	case strings.TrimSpace(in.Audience) == "":
		return errors.New("Audience required")
	case strings.TrimSpace(in.Resource) == "":
		return errors.New("Resource required")
	}
	return nil
}

// ExchangeForAccessTokenInput drives the second leg — redeeming the ID-JAG at
// the Resource AS for a usable access token.
type ExchangeForAccessTokenInput struct {
	// ResourceASTokenEndpoint is the Resource AS's /token endpoint. For
	// AuthSec this is the same host as the IdP because AuthSec serves
	// both roles in v1: https://<authsec>/authsec/oauth/v2/token.
	ResourceASTokenEndpoint string

	// IDJAG is the assertion received from RequestIDJAG().
	IDJAG string

	// Scopes optionally narrows the access token's scope to a subset of
	// what the ID-JAG carries. Empty = take everything the IDJAG offers.
	Scopes []string

	// ClientID + ClientSecret are OPTIONAL at the Resource AS — the ID-JAG
	// already carries a client_id claim. Supplied here only if your
	// Resource AS requires client authentication on the JWT-bearer grant.
	ClientID     string
	ClientSecret string

	HTTPClient *http.Client
}

// AccessTokenResponse is the standard OAuth token response (RFC 6749 §5.1).
type AccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// ExchangeForAccessToken redeems an ID-JAG for an access token at the Resource
// AS via the RFC 7523 jwt-bearer grant.
func ExchangeForAccessToken(ctx context.Context, in ExchangeForAccessTokenInput) (*AccessTokenResponse, error) {
	switch {
	case strings.TrimSpace(in.ResourceASTokenEndpoint) == "":
		return nil, errors.New("ResourceASTokenEndpoint required")
	case strings.TrimSpace(in.IDJAG) == "":
		return nil, errors.New("IDJAG required")
	}

	form := url.Values{}
	form.Set("grant_type", GrantTypeJWTBearer)
	form.Set("assertion", in.IDJAG)
	if len(in.Scopes) > 0 {
		form.Set("scope", strings.Join(in.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.ResourceASTokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if in.ClientID != "" {
		req.SetBasicAuth(in.ClientID, in.ClientSecret)
	}

	resp, err := defaultClient(in.HTTPClient).Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwt-bearer exchange: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("jwt-bearer exchange: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseOAuthError(resp.StatusCode, body)
	}
	var out AccessTokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("jwt-bearer exchange: decode response: %w", err)
	}
	if out.AccessToken == "" {
		return nil, errors.New("jwt-bearer exchange: empty access_token in response")
	}
	return &out, nil
}

// CrossAppAccess is the convenience wrapper most agents will actually use —
// chains the two steps so the caller doesn't have to wire them. Use the
// granular RequestIDJAG / ExchangeForAccessToken when you need to inspect or
// cache the ID-JAG between calls.
type CrossAppAccessInput struct {
	IdPTokenEndpoint        string
	ResourceASTokenEndpoint string
	ClientID                string
	ClientSecret            string
	SubjectToken            string
	SubjectTokenType        string
	Audience                string
	Resource                string
	Scopes                  []string
	HTTPClient              *http.Client
}

// CrossAppAccess runs the full two-leg flow and returns the final access
// token. Errors propagate from whichever leg fails.
func CrossAppAccess(ctx context.Context, in CrossAppAccessInput) (*AccessTokenResponse, error) {
	idjag, err := RequestIDJAG(ctx, RequestIDJAGInput{
		IdPTokenEndpoint: in.IdPTokenEndpoint,
		ClientID:         in.ClientID,
		ClientSecret:     in.ClientSecret,
		SubjectToken:     in.SubjectToken,
		SubjectTokenType: in.SubjectTokenType,
		Audience:         in.Audience,
		Resource:         in.Resource,
		Scopes:           in.Scopes,
		HTTPClient:       in.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return ExchangeForAccessToken(ctx, ExchangeForAccessTokenInput{
		ResourceASTokenEndpoint: in.ResourceASTokenEndpoint,
		IDJAG:                   idjag.AccessToken,
		Scopes:                  in.Scopes,
		HTTPClient:              in.HTTPClient,
	})
}

// ── helpers ──────────────────────────────────────────────────────────────────

func defaultClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func parseOAuthError(status int, body []byte) error {
	var e OAuthError
	if err := json.Unmarshal(body, &e); err != nil || e.Code == "" {
		// Server returned non-JSON or non-OAuth shape. Wrap raw body.
		return fmt.Errorf("http %d: %s", status, strings.TrimSpace(string(body)))
	}
	e.HTTPStatus = status
	return &e
}
