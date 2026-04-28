package authsec

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PolicyMode controls how the SDK selects and enforces its tool→scope policy source.
type PolicyMode int

const (
	// PolicyModeUnset is the zero value; resolved to a contextual default at runtime.
	PolicyModeUnset PolicyMode = iota

	// PolicyModeRemoteRequired — SDK fails startup if ResourceServerID, AuthorizationServer,
	// or introspection credentials are not set, or if the initial remote fetch fails.
	PolicyModeRemoteRequired

	// PolicyModeRemoteWithLocalFallback — try remote first; fall back to ToolScopes
	// on fetch failure. Requires both a valid remote configuration AND non-nil ToolScopes.
	PolicyModeRemoteWithLocalFallback

	// PolicyModeLocalOnly — use Config.ToolScopes only; ignore ResourceServerID.
	PolicyModeLocalOnly

	// PolicyModeOpen — no tool-level policy; all tools are allowed for any valid token.
	PolicyModeOpen
)

// ValidationMode controls how JWT and introspection are combined.
type ValidationMode int

const (
	// ValidationModeUnset is the zero value; resolved to a contextual default at runtime.
	ValidationModeUnset ValidationMode = iota

	// ValidationModeJWTOnly — only local JWT verification; requires JWKSURL.
	ValidationModeJWTOnly

	// ValidationModeIntrospectionOnly — only introspection; requires IntrospectionURL + credentials.
	ValidationModeIntrospectionOnly

	// ValidationModeJWTAndIntrospect — strict combined mode. For JWT-shaped tokens, JWT
	// must pass local verification first; introspection failure is terminal too. For opaque
	// tokens, introspection is used directly. Requires both JWKSURL and IntrospectionURL.
	ValidationModeJWTAndIntrospect

	// ValidationModeJWTOrIntrospect — either path may succeed independently (prior behavior,
	// preserved for gradual migration). Requires both JWKSURL and IntrospectionURL.
	ValidationModeJWTOrIntrospect
)

// Config holds the AuthSec SDK configuration for protecting an MCP resource server.
type Config struct {
	Issuer                    string
	AuthorizationServer       string
	JWKSURL                   string
	IntrospectionURL          string
	IntrospectionClientID     string
	IntrospectionClientSecret string
	ResourceURI               string
	ResourceName              string

	// ResourceServerID is the AuthSec resource server UUID.
	// When set, the SDK fetches the authoritative tool→scope mapping from
	// AuthSec at startup and refreshes it periodically. This is the recommended
	// configuration — the Scope Matrix UI in AuthSec is the source of truth for
	// which scopes each MCP tool requires.
	ResourceServerID string

	// SupportedScopes lists the OAuth scopes this resource server advertises.
	// Optional if the resource server is already registered in AuthSec — AuthSec
	// maintains the authoritative scope registry via auto-discovery and the
	// Scope Matrix UI. When provided here, these scopes are included in the
	// protected-resource metadata response.
	SupportedScopes []string

	// ToolScopes is an optional LOCAL tool→scope mapping for defense-in-depth.
	// When set, this is used as a fallback if the AuthSec scope matrix is
	// unreachable. When nil and ResourceServerID is set, the SDK fetches the
	// mapping from AuthSec. When both are nil, no tool-level filtering is
	// applied (all tools are allowed for any valid token).
	//
	// A tool with an explicit empty slice entry (e.g. ToolScopeMap{"tool": {}})
	// is treated as explicitly public — allowed for any valid token.
	// A tool absent from the map is denied when any policy exists.
	ToolScopes ToolScopeMap

	// ScopeMatrixTTL controls how long the fetched tool→scope mapping is cached.
	// Default: 5 minutes. Only relevant when ResourceServerID is set.
	ScopeMatrixTTL time.Duration

	// PolicyMode explicitly controls which policy source is used.
	// When unset, defaults are inferred from ResourceServerID and ToolScopes.
	PolicyMode PolicyMode

	// ValidationMode explicitly controls JWT/introspection combination.
	// When unset, defaults are inferred from JWKSURL and IntrospectionURL.
	ValidationMode ValidationMode

	// PublishManifest controls whether the SDK pushes its tool inventory to
	// AuthSec at startup. When true, NewRuntime issues a synthetic tools/list
	// against the wrapped MCP handler, packages the response (including MCP
	// annotations like readOnlyHint and destructiveHint) plus any
	// ToolScopeSuggestions into a manifest, and PUTs it to
	// /authsec/resource-servers/<ResourceServerID>/sdk-manifest using the
	// IntrospectionClient credentials.
	//
	// Failure is logged-and-ignored — manifest publish is never allowed to
	// block startup. The runtime SDK remains fully functional whether the
	// publish succeeded or not; manifest sync is purely a one-way push so
	// AuthSec's admin UI can show the tool inventory and suggested scopes.
	//
	// Recommended setting for production: true. ResourceServerID and the
	// introspection credentials must also be set.
	PublishManifest bool

	// ToolScopeSuggestions is an optional map from tool name to the SDK author's
	// recommended scope set. Used only when publishing the manifest — these
	// values populate suggested_scopes on each tool entry. Admins can override
	// per-tool in the AuthSec UI; admin overrides are preserved across SDK
	// restarts and manifest republishes.
	//
	// Distinct from ToolScopes: ToolScopes is enforced locally by the runtime
	// SDK; ToolScopeSuggestions is admin-facing metadata only and has no
	// runtime enforcement effect.
	ToolScopeSuggestions map[string][]string

	// ToolInventoryProvider is an optional escape hatch for manifest publishing.
	// When set, PublishManifest skips synthetic tools/list enumeration entirely
	// and uses this function's output as the tool inventory instead.
	//
	// Use this when the MCP handler requires custom auth even on initialize, uses
	// a non-HTTP transport, or otherwise doesn't fit the synthetic enumeration path.
	ToolInventoryProvider func() ([]ManifestTool, error)

	BearerMethodsSupported []string
	HTTPClient             *http.Client
	Logger                 *slog.Logger
	Now                    func() time.Time
}

// effectivePolicyMode resolves PolicyModeUnset to an inferred default.
func (c Config) effectivePolicyMode() PolicyMode {
	if c.PolicyMode != PolicyModeUnset {
		return c.PolicyMode
	}
	if strings.TrimSpace(c.ResourceServerID) != "" {
		return PolicyModeRemoteRequired
	}
	if c.ToolScopes != nil {
		return PolicyModeLocalOnly
	}
	return PolicyModeOpen
}

// effectiveValidationMode resolves ValidationModeUnset to an inferred default.
func (c Config) effectiveValidationMode() ValidationMode {
	if c.ValidationMode != ValidationModeUnset {
		return c.ValidationMode
	}
	hasJWKS := strings.TrimSpace(c.JWKSURL) != ""
	hasIntrospection := strings.TrimSpace(c.IntrospectionURL) != ""
	switch {
	case hasJWKS && hasIntrospection:
		return ValidationModeJWTAndIntrospect
	case hasJWKS:
		return ValidationModeJWTOnly
	default:
		return ValidationModeIntrospectionOnly
	}
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Issuer) == "" {
		return fmt.Errorf("issuer is required")
	}
	if strings.TrimSpace(c.ResourceURI) == "" {
		return fmt.Errorf("resource URI is required")
	}
	// ResourceURI must be an absolute URI with a scheme and host; the SDK derives
	// metadata paths, WWW-Authenticate targets, and audience checks from it.
	if u, err := url.Parse(c.ResourceURI); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("resource URI must be an absolute URI with scheme and host (got %q)", c.ResourceURI)
	}
	if strings.TrimSpace(c.JWKSURL) == "" && strings.TrimSpace(c.IntrospectionURL) == "" {
		return fmt.Errorf("at least one of JWKSURL or IntrospectionURL is required")
	}
	if strings.TrimSpace(c.IntrospectionURL) != "" {
		if strings.TrimSpace(c.IntrospectionClientID) == "" || strings.TrimSpace(c.IntrospectionClientSecret) == "" {
			return fmt.Errorf("introspection client credentials are required when introspection is enabled")
		}
	}

	// Policy-mode constraints.
	pm := c.effectivePolicyMode()
	if pm == PolicyModeRemoteRequired || pm == PolicyModeRemoteWithLocalFallback {
		if strings.TrimSpace(c.ResourceServerID) == "" {
			return fmt.Errorf("%v requires ResourceServerID", pm)
		}
		if strings.TrimSpace(c.AuthorizationServer) == "" && strings.TrimSpace(c.Issuer) == "" {
			return fmt.Errorf("%v requires AuthorizationServer", pm)
		}
		if strings.TrimSpace(c.IntrospectionClientID) == "" || strings.TrimSpace(c.IntrospectionClientSecret) == "" {
			return fmt.Errorf("%v requires introspection credentials (IntrospectionClientID and IntrospectionClientSecret)", pm)
		}
	}
	if pm == PolicyModeRemoteWithLocalFallback && c.ToolScopes == nil {
		return fmt.Errorf("PolicyModeRemoteWithLocalFallback requires non-nil ToolScopes (local fallback must exist)")
	}

	// Validation-mode constraints — checked against the effective mode so inferred
	// modes are also validated against available backends.
	vm := c.effectiveValidationMode()
	switch vm {
	case ValidationModeJWTOnly:
		if strings.TrimSpace(c.JWKSURL) == "" {
			return fmt.Errorf("ValidationModeJWTOnly requires JWKSURL")
		}
	case ValidationModeIntrospectionOnly:
		if strings.TrimSpace(c.IntrospectionURL) == "" {
			return fmt.Errorf("ValidationModeIntrospectionOnly requires IntrospectionURL")
		}
		if strings.TrimSpace(c.IntrospectionClientID) == "" || strings.TrimSpace(c.IntrospectionClientSecret) == "" {
			return fmt.Errorf("ValidationModeIntrospectionOnly requires introspection credentials")
		}
	case ValidationModeJWTAndIntrospect, ValidationModeJWTOrIntrospect:
		if strings.TrimSpace(c.JWKSURL) == "" {
			return fmt.Errorf("%v requires JWKSURL", vm)
		}
		if strings.TrimSpace(c.IntrospectionURL) == "" {
			return fmt.Errorf("%v requires IntrospectionURL", vm)
		}
		if strings.TrimSpace(c.IntrospectionClientID) == "" || strings.TrimSpace(c.IntrospectionClientSecret) == "" {
			return fmt.Errorf("%v requires introspection credentials", vm)
		}
	}

	return nil
}

func (c Config) normalized() Config {
	n := c
	if n.AuthorizationServer == "" {
		n.AuthorizationServer = n.Issuer
	}
	if n.ResourceName == "" {
		n.ResourceName = "AuthSec Protected MCP Resource"
	}
	if len(n.BearerMethodsSupported) == 0 {
		n.BearerMethodsSupported = []string{"header"}
	}
	if n.HTTPClient == nil {
		n.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if n.Logger == nil {
		n.Logger = slog.Default()
	}
	if n.Now == nil {
		n.Now = time.Now
	}
	return n
}

func (pm PolicyMode) String() string {
	switch pm {
	case PolicyModeRemoteRequired:
		return "PolicyModeRemoteRequired"
	case PolicyModeRemoteWithLocalFallback:
		return "PolicyModeRemoteWithLocalFallback"
	case PolicyModeLocalOnly:
		return "PolicyModeLocalOnly"
	case PolicyModeOpen:
		return "PolicyModeOpen"
	default:
		return "PolicyModeUnset"
	}
}

func (vm ValidationMode) String() string {
	switch vm {
	case ValidationModeJWTOnly:
		return "ValidationModeJWTOnly"
	case ValidationModeIntrospectionOnly:
		return "ValidationModeIntrospectionOnly"
	case ValidationModeJWTAndIntrospect:
		return "ValidationModeJWTAndIntrospect"
	case ValidationModeJWTOrIntrospect:
		return "ValidationModeJWTOrIntrospect"
	default:
		return "ValidationModeUnset"
	}
}
