package authsec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ── Error taxonomy (§9) ──────────────────────────────────────────────────────

// AuthSecIdentityError is the base typed error for all AgentIdentity failures.
type AuthSecIdentityError struct {
	Code       string
	Message    string
	HTTPStatus int
}

func (e *AuthSecIdentityError) Error() string {
	if e.HTTPStatus != 0 {
		return fmt.Sprintf("authsec[%s] (HTTP %d): %s", e.Code, e.HTTPStatus, e.Message)
	}
	return fmt.Sprintf("authsec[%s]: %s", e.Code, e.Message)
}

// PendingApprovalError is returned when access is requested but awaiting admin approval.
// Poll StatusURL to check progress.
type PendingApprovalError struct {
	AuthSecIdentityError
	RequestID string
	StatusURL string
}

func newPendingApprovalError(requestID, statusURL string) *PendingApprovalError {
	return &PendingApprovalError{
		AuthSecIdentityError: AuthSecIdentityError{
			Code:       "access_pending",
			Message:    "Access requested — waiting for an admin.",
			HTTPStatus: 202,
		},
		RequestID: requestID,
		StatusURL: statusURL,
	}
}

func (e *PendingApprovalError) Error() string {
	return fmt.Sprintf("authsec[access_pending] (HTTP 202): Access requested — waiting for an admin. request_id=%s status_url=%s",
		e.RequestID, e.StatusURL)
}

// ApprovalDeniedError is returned when an admin declined the access request.
type ApprovalDeniedError struct{ AuthSecIdentityError }

func newApprovalDeniedError() *ApprovalDeniedError {
	return &ApprovalDeniedError{AuthSecIdentityError{Code: "approval_denied", Message: "An admin declined this access.", HTTPStatus: 403}}
}

func (e *ApprovalDeniedError) Error() string { return e.AuthSecIdentityError.Error() }

// ConnectionRevokedError is returned when the agent connection was revoked.
type ConnectionRevokedError struct{ AuthSecIdentityError }

func newConnectionRevokedError() *ConnectionRevokedError {
	return &ConnectionRevokedError{AuthSecIdentityError{Code: "connection_revoked", Message: "Access was revoked.", HTTPStatus: 401}}
}

func (e *ConnectionRevokedError) Error() string { return e.AuthSecIdentityError.Error() }

// TrustedIssuerMissingError is returned when the issuer is not trusted by the AuthSec instance.
type TrustedIssuerMissingError struct{ AuthSecIdentityError }

func newTrustedIssuerMissingError() *TrustedIssuerMissingError {
	return &TrustedIssuerMissingError{AuthSecIdentityError{Code: "trusted_issuer_missing", Message: "This issuer isn't trusted here.", HTTPStatus: 403}}
}

func (e *TrustedIssuerMissingError) Error() string { return e.AuthSecIdentityError.Error() }

// SubjectMappingFailedError is returned when subject mapping from external identity to local user fails.
type SubjectMappingFailedError struct{ AuthSecIdentityError }

func newSubjectMappingFailedError() *SubjectMappingFailedError {
	return &SubjectMappingFailedError{AuthSecIdentityError{Code: "subject_mapping_failed", Message: "Couldn't map your identity.", HTTPStatus: 403}}
}

func (e *SubjectMappingFailedError) Error() string { return e.AuthSecIdentityError.Error() }

// ResourceNotRegisteredError is returned when the MCP server URI is not registered.
type ResourceNotRegisteredError struct {
	AuthSecIdentityError
	Resource string
}

func newResourceNotRegisteredError(resource string) *ResourceNotRegisteredError {
	msg := "resource_not_registered"
	if resource != "" {
		msg = fmt.Sprintf("Unknown MCP server: %s", resource)
	}
	return &ResourceNotRegisteredError{
		AuthSecIdentityError: AuthSecIdentityError{Code: "resource_not_registered", Message: msg, HTTPStatus: 404},
		Resource:             resource,
	}
}

func (e *ResourceNotRegisteredError) Error() string { return e.AuthSecIdentityError.Error() }

// CredentialInvalidError is returned when the client credential is invalid.
type CredentialInvalidError struct {
	AuthSecIdentityError
	Detail string
}

func newCredentialInvalidError(detail string) *CredentialInvalidError {
	if detail == "" {
		detail = "Invalid client credential."
	}
	return &CredentialInvalidError{
		AuthSecIdentityError: AuthSecIdentityError{Code: "credential_invalid", Message: detail, HTTPStatus: 401},
		Detail:               detail,
	}
}

func (e *CredentialInvalidError) Error() string { return e.AuthSecIdentityError.Error() }

// WorkloadNotAttestedError is returned when the workload has not yet attested via SPIFFE.
type WorkloadNotAttestedError struct{ AuthSecIdentityError }

func newWorkloadNotAttestedError() *WorkloadNotAttestedError {
	return &WorkloadNotAttestedError{AuthSecIdentityError{Code: "workload_not_attested", Message: "Workload hasn't attested yet.", HTTPStatus: 403}}
}

func (e *WorkloadNotAttestedError) Error() string { return e.AuthSecIdentityError.Error() }

// ── Config & options ─────────────────────────────────────────────────────────

// AgentIdentityConfig holds the configuration for an AgentIdentity instance.
type AgentIdentityConfig struct {
	// Issuer is the AuthSec AS issuer URL (e.g. https://auth.example.com).
	Issuer string
	// ClientID is the OAuth client_id for this agent.
	ClientID string
	// ClientSecret is the client secret for client_secret_basic auth.
	// It is shorthand for Auth = NewClientSecretAuth(ClientSecret) and is
	// mutually exclusive with Auth — setting both panics in NewAgentIdentity.
	ClientSecret string
	// Auth is the client-authentication method (client_secret_basic,
	// private_key_jwt, SPIFFE-SVID, …). When nil, it is derived from
	// ClientSecret. Mutually exclusive with ClientSecret.
	Auth ClientAuth
	// IDPIssuer is the enterprise IdP issuer for XAA subject tokens. Required for XAA paths.
	IDPIssuer string
	// PreferredMode controls flow selection: "auto", "direct-only", or "xaa-allowed". Default: "auto".
	PreferredMode string
	// TokenEndpoint overrides the token endpoint (discovered by default).
	TokenEndpoint string
}

// accessForOptions holds options for a single AccessFor call.
type accessForOptions struct {
	userSession     *userSession
	requestedScopes []string
	extra           map[string]string
}

type userSession struct {
	SubjectToken     string
	SubjectTokenType string
}

// AccessForOption is a functional option for AccessFor.
type AccessForOption func(*accessForOptions)

// WithUserSession sets the OIDC subject token from the enterprise IdP (required for XAA user-delegated path).
func WithUserSession(subjectToken string) AccessForOption {
	return func(o *accessForOptions) {
		o.userSession = &userSession{SubjectToken: subjectToken}
	}
}

// WithRequestedScopes sets the scopes to request.
func WithRequestedScopes(scopes ...string) AccessForOption {
	return func(o *accessForOptions) {
		o.requestedScopes = scopes
	}
}

// WithExtra adds an additional key/value parameter forwarded to token endpoint calls.
func WithExtra(key, val string) AccessForOption {
	return func(o *accessForOptions) {
		if o.extra == nil {
			o.extra = make(map[string]string)
		}
		o.extra[key] = val
	}
}

// ── Discovery shapes ─────────────────────────────────────────────────────────

type prmResponse struct {
	Resource                          string   `json:"resource"`
	AuthorizationServers              []string `json:"authorization_servers"`
	BearerMethodsSupported            []string `json:"bearer_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResourceSigningAlgValuesSupported []string `json:"resource_signing_alg_values_supported"`
}

type asMetadata struct {
	Issuer                                       string   `json:"issuer"`
	TokenEndpoint                                string   `json:"token_endpoint"`
	GrantTypesSupported                          []string `json:"grant_types_supported"`
	IdentityChainingRequestedTokenTypesSupported []string `json:"identity_chaining_requested_token_types_supported"`
	TokenExchangeSupported                       bool     `json:"token_exchange_supported"`
}

type bootstrapTarget struct {
	ResourceServerID   string          `json:"resource_server_id"`
	Resource           string          `json:"resource"`
	WorkspaceID        string          `json:"workspace_id"`
	Relationship       string          `json:"relationship"`
	RecommendedFlow    string          `json:"recommended_flow"`
	RegistrationStatus string          `json:"registration_status"`
	AccessStatus       string          `json:"access_status"`
	ScopesSupported    []string        `json:"scopes_supported"`
	PRM                json.RawMessage `json:"prm"`
}

type bootstrapPending struct {
	RequestID        string `json:"request_id"`
	ResourceServerID string `json:"resource_server_id"`
	Status           string `json:"status"`
	ExpiresAt        string `json:"expires_at"`
}

type bootstrapClient struct {
	ClientID        string `json:"client_id"`
	ClientKind      string `json:"client_kind"`
	HomeWorkspaceID string `json:"home_workspace_id"`
}

type bootstrapResponse struct {
	Client          bootstrapClient    `json:"client"`
	Issuer          string             `json:"issuer"`
	ASMetadataURL   string             `json:"as_metadata_url"`
	MetadataVersion string             `json:"metadata_version"`
	Targets         []bootstrapTarget  `json:"targets"`
	Pending         []bootstrapPending `json:"pending"`
}

// ── Token cache ──────────────────────────────────────────────────────────────

type cachedToken struct {
	Token     string
	ExpiresAt time.Time
}

// ── AgentIdentity ─────────────────────────────────────────────────────────────

// AgentIdentity implements flow-selection and token acquisition for agent-to-MCP-server access.
// It implements §10 of the Agent Identity spec.
type AgentIdentity struct {
	cfg        AgentIdentityConfig
	auth       ClientAuth // resolved from cfg.Auth or cfg.ClientSecret; may be nil
	httpClient *http.Client

	cacheMu sync.RWMutex
	cache   map[string]cachedToken
}

// NewAgentIdentity creates a new AgentIdentity from the given config.
// It panics if Issuer or ClientID are empty, or if both Auth and ClientSecret
// are set (they are mutually exclusive — ClientSecret is shorthand for
// Auth = NewClientSecretAuth(ClientSecret)).
func NewAgentIdentity(cfg AgentIdentityConfig) *AgentIdentity {
	if cfg.Issuer == "" {
		panic("AgentIdentity: Issuer is required")
	}
	if cfg.ClientID == "" {
		panic("AgentIdentity: ClientID is required")
	}
	if cfg.Auth != nil && cfg.ClientSecret != "" {
		panic("AgentIdentity: Auth and ClientSecret are mutually exclusive — " +
			"ClientSecret is shorthand for Auth = NewClientSecretAuth(ClientSecret)")
	}
	if cfg.PreferredMode == "" {
		cfg.PreferredMode = "auto"
	}

	auth := cfg.Auth
	if auth == nil && cfg.ClientSecret != "" {
		auth = NewClientSecretAuth(cfg.ClientSecret)
	}

	return &AgentIdentity{
		cfg:        cfg,
		auth:       auth,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		cache:      make(map[string]cachedToken),
	}
}

// AccessFor obtains a short-lived access token for resource.
//
// Returns the token string on success.
// Returns *PendingApprovalError when access is requested but not yet approved.
// Returns other *AuthSecIdentityError subclasses for terminal failures.
func (a *AgentIdentity) AccessFor(ctx context.Context, resource string, opts ...AccessForOption) (string, error) {
	o := &accessForOptions{}
	for _, opt := range opts {
		opt(o)
	}

	// Check cache first (with 30s buffer)
	a.cacheMu.RLock()
	cached, ok := a.cache[resource]
	a.cacheMu.RUnlock()
	if ok && time.Now().Add(30*time.Second).Before(cached.ExpiresAt) {
		return cached.Token, nil
	}

	return a.acquireToken(ctx, resource, o)
}

// ClearCache removes cached tokens. If resource is specified, only that resource's token
// is cleared. If no resource is specified, all cached tokens are cleared.
func (a *AgentIdentity) ClearCache(resource ...string) {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	if len(resource) == 0 {
		a.cache = make(map[string]cachedToken)
		return
	}
	for _, r := range resource {
		delete(a.cache, r)
	}
}

// ── Internal flow selection (§10) ────────────────────────────────────────────

func (a *AgentIdentity) acquireToken(ctx context.Context, resource string, o *accessForOptions) (string, error) {
	prm, err := a.discoverPRM(ctx, resource)
	if err != nil {
		return "", err
	}
	if len(prm.AuthorizationServers) == 0 {
		return "", newResourceNotRegisteredError(resource)
	}
	asUrl := prm.AuthorizationServers[0]

	as, err := a.discoverAS(ctx, asUrl)
	if err != nil {
		return "", err
	}

	tokenEndpoint := a.cfg.TokenEndpoint
	if tokenEndpoint == "" {
		tokenEndpoint = as.TokenEndpoint
	}

	mode := a.cfg.PreferredMode

	// direct-only: skip bootstrap entirely
	if mode == "direct-only" {
		return a.direct(ctx, resource, tokenEndpoint, o)
	}

	// No XAA support on AS, or no IdP configured, or no user session → direct.
	// XAA is supported when grant_types_supported includes BOTH token-exchange
	// (to mint ID-JAG) AND jwt-bearer (to redeem it), AND the AS advertises the
	// ID-JAG token type — without it the token-exchange step can't produce an
	// ID-JAG, so XAA would fail later.
	hasTokenExchange := false
	hasJWTBearer := false
	for _, g := range as.GrantTypesSupported {
		switch g {
		case "urn:ietf:params:oauth:grant-type:token-exchange":
			hasTokenExchange = true
		case "urn:ietf:params:oauth:grant-type:jwt-bearer":
			hasJWTBearer = true
		}
	}
	hasIDJAG := contains(as.IdentityChainingRequestedTokenTypesSupported, "urn:ietf:params:oauth:token-type:id-jag")
	asSupportsXaa := hasTokenExchange && hasJWTBearer && hasIDJAG
	if !asSupportsXaa || a.cfg.IDPIssuer == "" || o.userSession == nil {
		return a.direct(ctx, resource, tokenEndpoint, o)
	}

	// requester-bootstrap to decide path
	bootstrap, err := a.requesterBootstrap(ctx, resource, tokenEndpoint, o)
	if err != nil {
		return a.handleBootstrapUnavailable(ctx, resource, prm, as, tokenEndpoint, o, err)
	}

	// Find the target matching this resource. No match → safe default (direct).
	var target *bootstrapTarget
	for i := range bootstrap.Targets {
		if bootstrap.Targets[i].Resource == resource {
			target = &bootstrap.Targets[i]
			break
		}
	}
	if target == nil {
		return a.direct(ctx, resource, tokenEndpoint, o)
	}

	base := strings.TrimSuffix(tokenEndpoint, "/token")

	// A pending access request for this target → surface PendingApprovalError.
	for _, p := range bootstrap.Pending {
		if p.ResourceServerID == target.ResourceServerID && p.Status == "pending" {
			return "", newPendingApprovalError(p.RequestID, base+"/access-requests/"+p.RequestID)
		}
	}
	if target.AccessStatus == "denied" {
		return "", newApprovalDeniedError()
	}

	// Flow decision from the matched target.
	if target.RecommendedFlow == "id_jag" {
		return a.xaa(ctx, resource, as, tokenEndpoint, o)
	}
	if target.RecommendedFlow == "direct" {
		return a.direct(ctx, resource, tokenEndpoint, o)
	}
	if target.Relationship == "cross_workspace" {
		return a.xaa(ctx, resource, as, tokenEndpoint, o)
	}
	if target.Relationship == "same_workspace" {
		return a.direct(ctx, resource, tokenEndpoint, o)
	}

	return a.direct(ctx, resource, tokenEndpoint, o)
}

// ── Direct path (M2M client_credentials) ─────────────────────────────────────

func (a *AgentIdentity) direct(ctx context.Context, resource, tokenEndpoint string, o *accessForOptions) (string, error) {
	body := url.Values{}
	body.Set("grant_type", "client_credentials")
	body.Set("resource", resource)
	if len(o.requestedScopes) > 0 {
		body.Set("scope", strings.Join(o.requestedScopes, " "))
	}
	for k, v := range o.extra {
		body.Set(k, v)
	}

	resp, err := a.tokenRequest(ctx, tokenEndpoint, body)
	if err != nil {
		return "", err
	}

	token, _ := resp["access_token"].(string)
	expiresIn := int64(3600)
	if v, ok := resp["expires_in"]; ok {
		switch n := v.(type) {
		case float64:
			expiresIn = int64(n)
		case int64:
			expiresIn = n
		}
	}

	a.cacheMu.Lock()
	a.cache[resource] = cachedToken{
		Token:     token,
		ExpiresAt: time.Now().Add(time.Duration(expiresIn) * time.Second),
	}
	a.cacheMu.Unlock()

	return token, nil
}

// ── XAA path (subject token → token-exchange → ID-JAG → jwt-bearer) ─────────

func (a *AgentIdentity) xaa(ctx context.Context, resource string, as *asMetadata, tokenEndpoint string, o *accessForOptions) (string, error) {
	if o.userSession == nil || o.userSession.SubjectToken == "" {
		return "", &AuthSecIdentityError{
			Code:    "xaa_requires_user_session",
			Message: "XAA path requires a user session (subject_token).",
		}
	}

	// Step 6c: token-exchange → ID-JAG
	idJag, err := a.tokenExchange(ctx, tokenEndpoint, o.userSession.SubjectToken, resource, o)
	if err != nil {
		return "", err
	}

	// Step 6d: jwt-bearer redemption → access token
	body := url.Values{}
	body.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	body.Set("assertion", idJag)
	body.Set("resource", resource)
	if len(o.requestedScopes) > 0 {
		body.Set("scope", strings.Join(o.requestedScopes, " "))
	}
	for k, v := range o.extra {
		body.Set(k, v)
	}

	respBody, err := a.tokenRequest(ctx, tokenEndpoint, body)
	if err != nil {
		return "", err
	}

	// access_pending (202 surfaced as a 200 with pending status)
	errCode, _ := respBody["error"].(string)
	status, _ := respBody["status"].(string)
	if errCode == "access_pending" || status == "pending" {
		reqID, _ := respBody["request_id"].(string)
		statusURL, _ := respBody["status_url"].(string)
		if statusURL == "" {
			base := strings.TrimSuffix(tokenEndpoint, "/token")
			statusURL = base + "/access-requests/" + reqID
		}
		return "", newPendingApprovalError(reqID, statusURL)
	}

	token, _ := respBody["access_token"].(string)
	expiresIn := int64(3600)
	if v, ok := respBody["expires_in"]; ok {
		switch n := v.(type) {
		case float64:
			expiresIn = int64(n)
		case int64:
			expiresIn = n
		}
	}

	a.cacheMu.Lock()
	a.cache[resource] = cachedToken{
		Token:     token,
		ExpiresAt: time.Now().Add(time.Duration(expiresIn) * time.Second),
	}
	a.cacheMu.Unlock()

	return token, nil
}

// ── token-exchange → ID-JAG ───────────────────────────────────────────────────

func (a *AgentIdentity) tokenExchange(ctx context.Context, tokenEndpoint, subjectToken, resource string, o *accessForOptions) (string, error) {
	body := url.Values{}
	body.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	body.Set("subject_token", subjectToken)
	body.Set("subject_token_type", "urn:ietf:params:oauth:token-type:id_token")
	body.Set("requested_token_type", "urn:ietf:params:oauth:token-type:id-jag")
	body.Set("resource", resource)
	if len(o.requestedScopes) > 0 {
		body.Set("scope", strings.Join(o.requestedScopes, " "))
	}

	resp, err := a.tokenRequest(ctx, tokenEndpoint, body)
	if err != nil {
		return "", err
	}

	idJag, _ := resp["access_token"].(string)
	if idJag == "" {
		return "", &AuthSecIdentityError{
			Code:    "token_exchange_failed",
			Message: "Token exchange did not return an ID-JAG.",
		}
	}
	return idJag, nil
}

// ── requester-bootstrap ───────────────────────────────────────────────────────

func (a *AgentIdentity) requesterBootstrap(ctx context.Context, resource, tokenEndpoint string, o *accessForOptions) (*bootstrapResponse, error) {
	base := strings.TrimSuffix(tokenEndpoint, "/token")
	bootstrapURL := base + "/requester-bootstrap"

	body := url.Values{}
	body.Set("client_id", a.cfg.ClientID)
	body.Set("resource", resource)
	if len(o.requestedScopes) > 0 {
		body.Set("scope", strings.Join(o.requestedScopes, " "))
	}
	// Assertion-based auth (private_key_jwt / SPIFFE) authenticates via body
	// params; the assertion audience is the token endpoint.
	for k, v := range a.authBodyParams(tokenEndpoint) {
		body.Set(k, v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, bootstrapURL, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, &AuthSecIdentityError{Code: "bootstrap_failed", Message: err.Error()}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range a.authHeaders() {
		req.Header.Set(k, v)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, &AuthSecIdentityError{Code: "bootstrap_failed", Message: err.Error()}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &AuthSecIdentityError{
			Code:       "bootstrap_failed",
			Message:    fmt.Sprintf("requester-bootstrap failed (%d): %s", resp.StatusCode, string(bodyBytes)),
			HTTPStatus: resp.StatusCode,
		}
	}

	var br bootstrapResponse
	if err := json.Unmarshal(bodyBytes, &br); err != nil {
		return nil, &AuthSecIdentityError{Code: "bootstrap_failed", Message: "invalid bootstrap response: " + err.Error()}
	}
	return &br, nil
}

// ── handleBootstrapUnavailable ────────────────────────────────────────────────

func (a *AgentIdentity) handleBootstrapUnavailable(ctx context.Context, resource string, prm *prmResponse, as *asMetadata, tokenEndpoint string, o *accessForOptions, originalErr error) (string, error) {
	mode := a.cfg.PreferredMode

	if mode == "xaa-allowed" {
		return "", &AuthSecIdentityError{
			Code:       "bootstrap_unavailable",
			Message:    "requester-bootstrap is unavailable and preferredMode=xaa-allowed prevents silent fallback.",
			HTTPStatus: 503,
		}
	}

	// mode=auto: fall back to direct only if AS metadata proves direct is supported
	bearerOK := true
	if len(prm.BearerMethodsSupported) > 0 {
		bearerOK = false
		for _, m := range prm.BearerMethodsSupported {
			if m == "header" {
				bearerOK = true
				break
			}
		}
	}
	directGrantOK := true
	if len(as.GrantTypesSupported) > 0 {
		directGrantOK = false
		for _, g := range as.GrantTypesSupported {
			if g == "client_credentials" {
				directGrantOK = true
				break
			}
		}
	}

	if !bearerOK || !directGrantOK {
		return "", &AuthSecIdentityError{
			Code:       "bootstrap_unavailable",
			Message:    "requester-bootstrap is unavailable and direct auth is not proven supported.",
			HTTPStatus: 503,
		}
	}

	return a.direct(ctx, resource, tokenEndpoint, o)
}

// ── PRM discovery (RFC 9728) ──────────────────────────────────────────────────

func (a *AgentIdentity) discoverPRM(ctx context.Context, resource string) (*prmResponse, error) {
	u, err := url.Parse(resource)
	if err != nil {
		return nil, newResourceNotRegisteredError(resource)
	}
	prmURL := u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, prmURL, nil)
	if err != nil {
		return nil, newResourceNotRegisteredError(resource)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, newResourceNotRegisteredError(resource)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, newResourceNotRegisteredError(resource)
	}

	var prm prmResponse
	if err := json.NewDecoder(resp.Body).Decode(&prm); err != nil {
		return nil, newResourceNotRegisteredError(resource)
	}
	return &prm, nil
}

// ── AS metadata discovery (RFC 8414) ─────────────────────────────────────────

func (a *AgentIdentity) discoverAS(ctx context.Context, asUrl string) (*asMetadata, error) {
	metaURL := strings.TrimSuffix(asUrl, "/") + "/.well-known/oauth-authorization-server"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return nil, &AuthSecIdentityError{Code: "as_discovery_failed", Message: fmt.Sprintf("AS metadata discovery failed for %s: %v", asUrl, err)}
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, &AuthSecIdentityError{Code: "as_discovery_failed", Message: fmt.Sprintf("AS metadata discovery failed for %s: %v", asUrl, err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &AuthSecIdentityError{
			Code:       "as_discovery_failed",
			Message:    fmt.Sprintf("AS metadata discovery failed for %s (%d)", asUrl, resp.StatusCode),
			HTTPStatus: resp.StatusCode,
		}
	}

	var meta asMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, &AuthSecIdentityError{Code: "as_discovery_failed", Message: "invalid AS metadata response: " + err.Error()}
	}
	return &meta, nil
}

// ── Token request helper ──────────────────────────────────────────────────────

func (a *AgentIdentity) tokenRequest(ctx context.Context, tokenEndpoint string, body url.Values) (map[string]interface{}, error) {
	// Merge client-auth body params (e.g. client_assertion for private_key_jwt /
	// SPIFFE-SVID). client_secret_basic contributes none.
	for k, v := range a.authBodyParams(tokenEndpoint) {
		body.Set(k, v)
	}

	headers := a.authHeaders()
	// Assertion-based auth carries no Authorization header, so the server needs
	// an explicit client_id in the body (matches the raw protocol + Python SDK).
	if _, hasAuthz := headers["Authorization"]; !hasAuthz && body.Get("client_id") == "" {
		body.Set("client_id", a.cfg.ClientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, &AuthSecIdentityError{Code: "server_error", Message: err.Error()}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, &AuthSecIdentityError{Code: "server_error", Message: err.Error()}
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	bodyBytes, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(bodyBytes, &result)
	if result == nil {
		result = make(map[string]interface{})
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, a.throwFromErrorBody(result, resp.StatusCode)
	}

	return result, nil
}

func (a *AgentIdentity) throwFromErrorBody(body map[string]interface{}, status int) error {
	code, _ := body["error"].(string)
	if code == "" {
		code = "server_error"
	}
	msg, _ := body["error_description"].(string)
	if msg == "" {
		msg = "Token request failed."
	}

	switch code {
	case "access_pending":
		reqID, _ := body["request_id"].(string)
		statusURL, _ := body["status_url"].(string)
		return newPendingApprovalError(reqID, statusURL)
	case "approval_denied":
		return newApprovalDeniedError()
	case "connection_revoked":
		return newConnectionRevokedError()
	case "trusted_issuer_missing":
		return newTrustedIssuerMissingError()
	case "subject_mapping_failed":
		return newSubjectMappingFailedError()
	case "resource_not_registered":
		return newResourceNotRegisteredError("")
	case "invalid_client", "credential_invalid":
		return newCredentialInvalidError(msg)
	case "workload_not_attested":
		return newWorkloadNotAttestedError()
	default:
		return &AuthSecIdentityError{Code: code, Message: msg, HTTPStatus: status}
	}
}

// ── Client auth ───────────────────────────────────────────────────────────────

// authHeaders returns the HTTP headers contributed by the configured ClientAuth
// (e.g. Authorization: Basic for client_secret_basic). Nil when no auth is set.
func (a *AgentIdentity) authHeaders() map[string]string {
	if a.auth == nil {
		return nil
	}
	return a.auth.Headers(a.cfg.ClientID)
}

// authBodyParams returns the POST body params contributed by the configured
// ClientAuth (e.g. client_assertion for private_key_jwt / SPIFFE-SVID). Nil
// when no auth is set. tokenEndpoint is the assertion audience.
func (a *AgentIdentity) authBodyParams(tokenEndpoint string) map[string]string {
	if a.auth == nil {
		return nil
	}
	return a.auth.BodyParams(a.cfg.ClientID, tokenEndpoint)
}
