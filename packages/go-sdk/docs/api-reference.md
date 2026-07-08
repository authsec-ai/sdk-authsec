# API reference

Every public type, constructor, function, and option in the Go SDK.

- Module: `github.com/authsec-ai/sdk-authsec/packages/go-sdk` (package `authsec`)
- Sub-package: `.../go-sdk/client` (package `client`)
- Requires Go ≥ 1.24. One dependency: `github.com/golang-jwt/jwt/v5`.

Sections:

- [Server-side MCP protection](#server-side-mcp-protection)
- [Config & environment](#config--environment)
- [Manifest publishing](#manifest-publishing)
- [Tool policy & scopes](#tool-policy--scopes)
- [Principal & context](#principal--context)
- [Token validation](#token-validation)
- [Agent identity (M2M + ID-JAG)](#agent-identity-m2m--id-jag)
- [M2M credential types](#m2m-credential-types)
- [SPIFFE workload identity](#spiffe-workload-identity)
- [ID-JAG helpers](#id-jag-helpers)
- [Agent-side error types](#agent-side-error-types)
- [`client` sub-package](#client-sub-package)
- [Naming notes](#naming-notes)

---

## Server-side MCP protection

```go
func MountMCP(mux *http.ServeMux, pattern string, handler http.Handler, cfg Config) error
```
The one-call install. Registers the PRM metadata route (at
`BuildResourceMetadataPath(cfg.ResourceURI)`) **and** the wrapped MCP handler
(at `pattern`) on `mux`. Kicks off background manifest publishing when
`cfg.PublishManifest` is true. Returns an error if `cfg.Validate` fails, or (in
`PolicyModeRemoteRequired`) if the initial policy fetch fails.

```go
func WrapMCPHTTP(next http.Handler, cfg Config) (http.Handler, error)
```
Wraps an existing MCP handler with AuthSec enforcement and returns it. You must
mount the metadata route separately (see `ProtectedResourceHandler`).

```go
func AuthMiddleware(cfg Config) (func(http.Handler) http.Handler, error)
```
Returns standard Go middleware that validates bearer tokens and injects the
`*Principal` into the request context. (Authentication only — no per-tool
authorization.)

```go
func ProtectedResourceHandler(cfg Config) (http.Handler, error)
```
Package-level constructor for the PRM metadata handler. (Distinct from the
`Runtime` method of the same name — see [naming notes](#naming-notes).)

```go
func NewRuntime(cfg Config) (*Runtime, error)
```
Constructs and validates a `Runtime` — the core enforcement engine. Use this
for manual wiring.

### `Runtime`

```go
type Runtime struct { /* unexported fields */ }

func (rt *Runtime) Wrap(next http.Handler) http.Handler
func (rt *Runtime) ProtectedResourceHandler() http.Handler
func (rt *Runtime) AuthMiddleware() func(http.Handler) http.Handler
func (rt *Runtime) AuthorizeTool(ctx context.Context, principal *Principal, toolName string) error
func (rt *Runtime) GetAuthoritativeScopes(ctx context.Context) []string
```

- `Wrap` — full MCP enforcement: authentication, tool authorization,
  `tools/list` filtering, batch handling, in-band JSON-RPC denials, fail-closed
  parsing.
- `ProtectedResourceHandler` — the PRM handler (serves from the scope-matrix
  cache when available).
- `AuthMiddleware` — bearer-validating middleware.
- `AuthorizeTool` — checks whether `principal` may call `toolName`; returns
  `ErrPolicyUnavailable` (→ HTTP 503) or `ErrInsufficientScope` (→ 403).
- `GetAuthoritativeScopes` — the live `scopes_supported` from the scope matrix
  (nil for Open/LocalOnly modes, empty cache, or stale-with-error).

### Metadata path helpers

```go
func BuildResourceMetadataPath(resourceURI string) string
func BuildResourceMetadataURL(resourceURI string) string
```
RFC 9728 path / absolute URL. Root resource → `/.well-known/oauth-protected-resource`;
path resource (`.../mcp`) → `/.well-known/oauth-protected-resource/mcp`. Always
use these — never hardcode the bare path for a path-based resource.

### Server-side errors

```go
type ErrPolicyUnavailable struct{ Cause error }        // → HTTP 503; has Unwrap()
type ErrInsufficientScope struct {                     // server-side scope denial
	ToolName       string
	RequiredScopes []string
	GrantedScopes  []string
}
```

---

## Config & environment

```go
func FromEnv(prefix ...string) Config
```
Builds a `Config` from `AUTHSEC_*` env vars (default prefix `AUTHSEC_`).
Parse-only; does not validate. Full variable list in the
[configuration reference](configuration.md#environment-variables-fromenv).

```go
type Config struct {
	Issuer                    string
	AuthorizationServer       string
	JWKSURL                   string
	IntrospectionURL          string
	IntrospectionClientID     string
	IntrospectionClientSecret string
	ResourceURI               string
	ResourceName              string
	ResourceServerID          string
	SupportedScopes           []string
	ToolScopes                ToolScopeMap
	ScopeMatrixTTL            time.Duration
	PolicyMode                PolicyMode
	ValidationMode            ValidationMode
	PublishManifest           bool
	ToolScopeSuggestions      map[string][]string
	ToolInventoryProvider     func() ([]ManifestTool, error)
	BearerMethodsSupported    []string
	HTTPClient                *http.Client
	Logger                    *slog.Logger
	Now                       func() time.Time
}

func (c Config) Validate() error
```
Field types, defaults, and validation rules: see the
[configuration reference](configuration.md#config--server-side).

### Policy & validation mode constants

```go
type PolicyMode int
const (
	PolicyModeUnset PolicyMode = iota
	PolicyModeRemoteRequired
	PolicyModeRemoteWithLocalFallback
	PolicyModeLocalOnly
	PolicyModeOpen
)
func (pm PolicyMode) String() string  // returns the constant name

type ValidationMode int
const (
	ValidationModeUnset ValidationMode = iota
	ValidationModeJWTOnly
	ValidationModeIntrospectionOnly
	ValidationModeJWTAndIntrospect
	ValidationModeJWTOrIntrospect
)
func (vm ValidationMode) String() string
```

---

## Manifest publishing

```go
type ManifestTool struct {
	Name            string          `json:"name"`
	Title           string          `json:"title,omitempty"`
	Description     string          `json:"description,omitempty"`
	InputSchema     json.RawMessage `json:"input_schema,omitempty"`
	Annotations     json.RawMessage `json:"annotations,omitempty"`
	SuggestedScopes []string        `json:"suggested_scopes,omitempty"`
}

func PublishManifest(ctx context.Context, cfg Config, innerHandler http.Handler) error
```
`PublishManifest` enumerates tools (via `cfg.ToolInventoryProvider`, else a
synthetic `tools/list` against `innerHandler`) and `PUT`s them to
`{AuthorizationServer}/authsec/resource-servers/{ResourceServerID}/sdk-manifest`
(HTTP Basic with the introspection credentials). Best-effort; `MountMCP` /
`WrapMCPHTTP` call it automatically when `cfg.PublishManifest` is true.

---

## Tool policy & scopes

```go
type ToolScopeMap map[string][]string

func (m ToolScopeMap) LookupTool(toolName string) (ToolPolicyResult, []string)
func (m ToolScopeMap) HasAnyRequired(toolName string, granted map[string]struct{}) bool
func (m ToolScopeMap) RequiredScopes(toolName string) []string  // deprecated; prefer LookupTool

type ToolPolicyResult int
const (
	ToolPolicyAbsent ToolPolicyResult = iota // unknown tool → deny (non-Open)
	ToolPolicyPublic                         // empty-slice entry → public
	ToolPolicyScoped                         // requires the listed scopes
)
```

### Scope-matrix client (advanced)

```go
type ScopeMatrixClient struct { /* unexported */ }
func NewScopeMatrixClient(cfg Config) *ScopeMatrixClient  // nil if creds/ID missing

func (c *ScopeMatrixClient) FetchAndCache(ctx context.Context) error
func (c *ScopeMatrixClient) GetScopesSupported(ctx context.Context) []string
func (c *ScopeMatrixClient) GetCached(ctx context.Context) (ToolScopeMap, error)
func (c *ScopeMatrixClient) CacheStatus() CacheStatus

type CacheStatus struct {
	HasData        bool
	FetchedAt      time.Time
	StaleAge       time.Duration
	LastErr        error
	LastErrAt      time.Time
	PolicyState    string
	PolicyComplete bool
	Generation     int64
}

type ErrPolicyIncomplete struct{ State, Reason string } // RS not ready → treat as deny-all
```
Defaults: cache TTL 30s, max stale age 2m, retry backoff 10s. Most users never
touch this directly — `Runtime` manages it.

---

## Principal & context

```go
type Principal struct {
	Subject  string
	Issuer   string
	Audience []string
	Scopes   []string
	Claims   map[string]any
	Active   bool
}
func (p *Principal) HasAnyScope(required []string) bool // empty required → true

func WithPrincipal(ctx context.Context, principal *Principal) context.Context
func PrincipalFromContext(ctx context.Context) (*Principal, bool)
```

---

## Token validation

```go
type Validator interface {
	Validate(ctx context.Context, token string) (*Principal, error)
}

type HybridValidator struct { /* unexported */ }
func NewHybridValidator(cfg Config) (*HybridValidator, error)
func (v *HybridValidator) Validate(ctx context.Context, token string) (*Principal, error)

func WithValidator(ctx context.Context, validator Validator) context.Context
```
`HybridValidator` dispatches per `cfg.ValidationMode`. JWT verification is
RSA-only; JWKS is fetched from `cfg.JWKSURL` and cached by `kid`; introspection
posts to `cfg.IntrospectionURL` with HTTP Basic. The audience must include
`cfg.ResourceURI`.

---

## Agent identity (M2M + ID-JAG)

```go
type AgentIdentityConfig struct {
	Issuer        string       // required (empty panics)
	ClientID      string       // required (empty panics)
	ClientSecret  string       // shorthand for Auth: NewClientSecretAuth(...)
	Auth          ClientAuth   // credential; mutually exclusive with ClientSecret
	IDPIssuer     string       // enterprise IdP issuer (ID-JAG)
	PreferredMode string       // "auto" (default) | "direct-only" | "xaa-allowed"
	TokenEndpoint string       // overrides discovery
}

type AgentIdentity struct { /* unexported */ }
func NewAgentIdentity(cfg AgentIdentityConfig) *AgentIdentity
// panics on empty Issuer/ClientID, or if both Auth and ClientSecret are set

func (a *AgentIdentity) AccessFor(ctx context.Context, resource string, opts ...AccessForOption) (string, error)
func (a *AgentIdentity) ClearCache(resource ...string)  // all, or the named resource(s)
```

### `AccessFor` options

```go
type AccessForOption func(*accessForOptions)

func WithRequestedScopes(scopes ...string) AccessForOption
func WithUserSession(subjectToken string) AccessForOption   // ID-JAG / XAA delegation
func WithExtra(key, val string) AccessForOption             // extra token-endpoint param
```
`AccessFor` returns the cached token while it has >~30s of life left; otherwise
it mints a new one. Returns `*PendingApprovalError` when awaiting approval, or
another [agent-side error type](#agent-side-error-types) on failure.

---

## M2M credential types

```go
type ClientAuth interface {
	Headers(clientID string) map[string]string
	BodyParams(clientID, tokenEndpoint string) map[string]string
}

// A — client_secret_basic
func NewClientSecretAuth(secret string) *ClientSecretAuth   // panics if secret == ""

// B — private_key_jwt (RFC 7523): RS256, 5-min, single-use jti, aud = token endpoint
func NewPrivateKeyJwtAuth(privateKey, kid string) (*PrivateKeyJwtAuth, error)
// privateKey = PEM content or a file path; returns an error (no panic) on empty/parse failure

// C — a pre-held SPIFFE JWT-SVID sent as client_assertion
func NewSpiffeSvidAuth(svid string) *SpiffeSvidAuth         // panics if svid == ""
```
All three implement `ClientAuth` and have a `String()` that never leaks secret
material. Pass any of them as `AgentIdentityConfig.Auth`.

---

## SPIFFE workload identity

```go
type SpiffeConfig struct {
	MCPServerURL    string // token endpoint discovered from this
	ClientID        string // required
	SpiffeID        string // must start with "spiffe://"
	Scopes          string // required; SPACE-SEPARATED string (not []string)
	TokenEndpoint   string // overrides discovery; must be https:// if set
	AgentSocketPath string // default /run/spire/sockets/agent.sock
	SvidOverride    string // pre-minted JWT-SVID; skips the SPIRE subprocess
}

type SpiffeWorkloadIdentity struct { /* unexported */ }
func NewSpiffeWorkloadIdentity(cfg SpiffeConfig) (*SpiffeWorkloadIdentity, error)

func (s *SpiffeWorkloadIdentity) AccessFor(ctx context.Context) (string, error) // no resource/opts
func (s *SpiffeWorkloadIdentity) ClearCache()
```

### SPIFFE errors

```go
type SpiffeIdentityError struct {          // base
	Code       string
	Message    string
	HTTPStatus int
}
type SpiffeSvidFetchError struct{ SpiffeIdentityError }     // SVID fetch from SPIRE failed
type SpiffeTokenExchangeError struct{ SpiffeIdentityError } // AuthSec rejected the SVID
```
`SpiffeTokenExchangeError.Code` carries an actionable subreason:
`jwks_unconfigured`, `spiffe_id_not_registered`, `audience_mismatch`,
`trust_domain_mismatch`, `no_scopes_granted`, `client_id_missing`, or
`token_exchange_failed`.

---

## ID-JAG helpers

```go
type BrowserLoginOptions struct {
	Resource    string                  // RFC 8707 resource binding
	Scopes      []string                // default ["openid","email","profile"]
	Port        int                     // default 8126 (loopback callback)
	Timeout     time.Duration           // default 300s
	OpenBrowser func(url string) error  // default: per-OS launcher
}
func BrowserLogin(ctx context.Context, issuer, clientID string, opts *BrowserLoginOptions) (string, error)
// PKCE (S256) login; returns the id_token. Errors if issuer or clientID is empty.

type PollOptions struct {
	Interval time.Duration // default 3s
	Timeout  time.Duration // default 300s
}
func PollUntilApproved(
	ctx context.Context, ai *AgentIdentity, resource, statusURL string,
	opts *PollOptions, o ...AccessForOption,
) (string, error)
// polls statusURL → on approval clears cache and calls AccessFor (forwarding o)
```

---

## Agent-side error types

All embed `AuthSecIdentityError` and are returned as pointers; match with
`errors.As`.

```go
type AuthSecIdentityError struct {           // base
	Code       string
	Message    string
	HTTPStatus int
}

type PendingApprovalError struct {           // code "access_pending", HTTP 202
	AuthSecIdentityError
	RequestID string
	StatusURL string
}
type ApprovalDeniedError      struct{ AuthSecIdentityError } // "approval_denied", 403
type ConnectionRevokedError   struct{ AuthSecIdentityError } // "connection_revoked", 401
type TrustedIssuerMissingError struct{ AuthSecIdentityError }
type SubjectMappingFailedError struct{ AuthSecIdentityError }
type ResourceNotRegisteredError struct {
	AuthSecIdentityError
	Resource string
}
type CredentialInvalidError struct {
	AuthSecIdentityError
	Detail string
}
type WorkloadNotAttestedError struct{ AuthSecIdentityError }
```

---

## `client` sub-package

Import `github.com/authsec-ai/sdk-authsec/packages/go-sdk/client` — typed
errors for reading the 401/403 responses a **protected server** returns to a
**calling agent**.

```go
func ParseMCPError(source any) AccessError
// source: *http.Response | map[string]any | []byte | string | error; nil if not an AuthSec error

type AccessError interface {
	error
	FormatForUser() string    // actionable, human-readable message
	Description() string
	WWWAuthenticate() string
}

type ErrInsufficientScope struct {   // token valid but missing scope
	Tool           string
	RequiredScopes []string
	GrantedScopes  []string
}
type ErrTokenRevoked              struct{ /* … */ } // token revoked; clear cache + re-auth
type ErrClientRegistrationRevoked struct{ /* … */ } // client registration revoked; admin re-approve
type ErrAuthRequired struct {                        // expired/missing/invalid token
	Reason string // "no_token" | "invalid_token" | "token_expired" | "audience_mismatch"
}
```
Each concrete type is returned as a pointer and satisfies `AccessError`
(so `FormatForUser()`, `Description()`, `WWWAuthenticate()` are available on
all of them).

---

## Naming notes

Two names appear in more than one place — pick by package and shape:

- **`ProtectedResourceHandler`** — a package-level function
  `authsec.ProtectedResourceHandler(cfg Config) (http.Handler, error)` **and**
  a method `(*Runtime).ProtectedResourceHandler() http.Handler`. Same job
  (serve PRM); use whichever fits your wiring.
- **`ErrInsufficientScope`** — the server-side value type
  `authsec.ErrInsufficientScope` (`ToolName`/`RequiredScopes`/`GrantedScopes`)
  is distinct from the client-side pointer type `client.ErrInsufficientScope`
  (`Tool`/`RequiredScopes`/`GrantedScopes` + `FormatForUser()`).

`AccessFor` and `ClearCache` also exist on **both** `AgentIdentity` and
`SpiffeWorkloadIdentity`, with different signatures — `AgentIdentity.AccessFor`
takes a `resource` + options; `SpiffeWorkloadIdentity.AccessFor` takes only a
context.

---

[← Docs home](README.md)
