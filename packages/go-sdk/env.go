package authsec

import (
	"encoding/json"
	"os"
	"strings"
)

// FromEnv builds a Config from environment variables. It is the Go parity of
// the Python SDK's from_env(): it only reads and parses — it does not validate.
// Call NewRuntime (or Config.Validate) afterwards to fail loudly on a bad config.
//
// The default variable prefix is "AUTHSEC_". Pass a single prefix argument to
// override it. Recognized variables (shown without the prefix), with the legacy
// aliases the AuthSec dashboard has emitted over time:
//
//	ISSUER
//	AUTHORIZATION_SERVER
//	JWKS_URL                  (or JWKS_URI)
//	INTROSPECTION_URL         (or INTROSPECTION_ENDPOINT)
//	INTROSPECTION_CLIENT_ID   (or INTROSPECTION_ID)
//	INTROSPECTION_CLIENT_SECRET (or INTROSPECTION_SECRET)
//	RESOURCE_URI              (or RESOURCE)
//	RESOURCE_NAME
//	RESOURCE_SERVER_ID
//	SUPPORTED_SCOPES              (space/comma-separated, or a JSON array)
//	TOOL_SCOPES_JSON             (JSON object: {"tool": ["scope", ...]})
//	TOOL_SCOPE_SUGGESTIONS_JSON  (JSON object: {"tool": ["scope", ...]})
//	POLICY_MODE                  ("remote_required", "enforce", "observe", ...)
//	VALIDATION_MODE              ("jwt_and_introspect", "auto", ...)
//	PUBLISH_MANIFEST             ("1" | "true" | "yes")
func FromEnv(prefix ...string) Config {
	p := "AUTHSEC_"
	if len(prefix) > 0 && prefix[0] != "" {
		p = prefix[0]
	}

	g := func(key string) string { return os.Getenv(p + key) }
	first := func(keys ...string) string {
		for _, key := range keys {
			if v := g(key); v != "" {
				return v
			}
		}
		return ""
	}

	cfg := Config{
		Issuer:                    g("ISSUER"),
		AuthorizationServer:       g("AUTHORIZATION_SERVER"),
		JWKSURL:                   first("JWKS_URL", "JWKS_URI"),
		IntrospectionURL:          first("INTROSPECTION_URL", "INTROSPECTION_ENDPOINT"),
		IntrospectionClientID:     first("INTROSPECTION_CLIENT_ID", "INTROSPECTION_ID"),
		IntrospectionClientSecret: first("INTROSPECTION_CLIENT_SECRET", "INTROSPECTION_SECRET"),
		ResourceURI:               first("RESOURCE_URI", "RESOURCE"),
		ResourceName:              g("RESOURCE_NAME"),
		ResourceServerID:          g("RESOURCE_SERVER_ID"),
		SupportedScopes:           parseEnvStringList(g("SUPPORTED_SCOPES")),
		ToolScopeSuggestions:      parseEnvStringListMap(g("TOOL_SCOPE_SUGGESTIONS_JSON")),
		PolicyMode:                parseEnvPolicyMode(g("POLICY_MODE")),
		ValidationMode:            parseEnvValidationMode(g("VALIDATION_MODE")),
		PublishManifest:           isEnvTrue(g("PUBLISH_MANIFEST")),
	}

	// tool_scopes must stay nil when unset so PolicyMode inference matches the
	// Go/Python contract (nil ToolScopes → OPEN when no ResourceServerID).
	if ts := parseEnvStringListMap(g("TOOL_SCOPES_JSON")); len(ts) > 0 {
		cfg.ToolScopes = ToolScopeMap(ts)
	}

	return cfg
}

// isEnvTrue matches Python's {"1","true","yes"} truthiness (case-insensitive).
func isEnvTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

// parseEnvStringList accepts a JSON array (e.g. ["a","b"]) or a
// comma/space-separated list. Empty input yields nil.
func parseEnvStringList(value string) []string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var parsed []any
		if err := json.Unmarshal([]byte(trimmed), &parsed); err == nil {
			out := make([]string, 0, len(parsed))
			for _, item := range parsed {
				if s, ok := item.(string); ok && s != "" {
					out = append(out, s)
				}
			}
			if len(out) > 0 {
				return out
			}
			return nil
		}
	}
	// Treat commas as spaces, then split on whitespace.
	fields := strings.Fields(strings.ReplaceAll(trimmed, ",", " "))
	if len(fields) == 0 {
		return nil
	}
	return fields
}

// parseEnvStringListMap parses a JSON object mapping tool names to scope lists.
// A scope value may itself be a JSON array or a space/comma-separated string.
// Invalid or empty input yields nil.
func parseEnvStringListMap(value string) map[string][]string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal([]byte(value), &parsed); err != nil {
		return nil
	}
	out := make(map[string][]string, len(parsed))
	for key, raw := range parsed {
		var list []string
		if err := json.Unmarshal(raw, &list); err == nil {
			out[key] = list
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			out[key] = parseEnvStringList(s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseEnvPolicyMode maps env strings to PolicyMode, including the "enforce"
// and "observe" aliases the dashboard emits. Unknown values → PolicyModeUnset.
func parseEnvPolicyMode(value string) PolicyMode {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return PolicyModeUnset
	case "remote_required", "enforce":
		return PolicyModeRemoteRequired
	case "remote_with_local_fallback":
		return PolicyModeRemoteWithLocalFallback
	case "local_only":
		return PolicyModeLocalOnly
	case "open", "observe":
		return PolicyModeOpen
	default:
		return PolicyModeUnset
	}
}

// parseEnvValidationMode maps env strings to ValidationMode. "auto" and unknown
// values → ValidationModeUnset (resolved contextually at runtime).
func parseEnvValidationMode(value string) ValidationMode {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "jwt_only":
		return ValidationModeJWTOnly
	case "introspection_only":
		return ValidationModeIntrospectionOnly
	case "jwt_and_introspect":
		return ValidationModeJWTAndIntrospect
	case "jwt_or_introspect":
		return ValidationModeJWTOrIntrospect
	default:
		return ValidationModeUnset
	}
}
