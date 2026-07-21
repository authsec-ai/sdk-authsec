// Package client provides typed, actionable error helpers for code calling
// an AuthSec-protected MCP server (the agent side).
//
// The server-side runtime ("github.com/authsec/sdk-go") returns structured
// 401/403 responses:
//
//	403: {error:"insufficient_scope", error_description, tool,
//	      required_scopes, granted_scopes}
//	401: {error:"invalid_token", error_description, reason}
//
// On the agent side, transports often flatten those into an opaque error
// string. This package lets you call ParseMCPError on whatever you have
// (*http.Response, []byte body, plain string, error) and get back one of
// the typed errors below — or nil if the input doesn't look like an
// AuthSec denial. Use errors.As to fork:
//
//	access := client.ParseMCPError(resp)
//	switch e := access.(type) {
//	case *client.ErrInsufficientScope:
//	    fmt.Println(e.FormatForUser())
//	case *client.ErrTokenRevoked, *client.ErrClientRegistrationRevoked:
//	    reAuth()
//	case *client.ErrAuthRequired:
//	    reAuth()
//	}
//
// Tool-error middleware:
//
//	msg := client.ToolErrorHandler(err)
//	// msg is always a non-empty, LLM-readable string
//
// Bearer-token separation: AuthSec bearer tokens authenticate the agent
// to the AuthSec authorization layer.  If the MCP server requires a
// separate upstream credential (e.g. a GitHub PAT), that credential must
// travel as a server-owned env var (UPSTREAM_API_TOKEN) — never in the
// same Authorization header.  The SDK never mixes the two layers.
package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// ─── Typed errors ────────────────────────────────────────────────────────

// AccessError is implemented by every typed AuthSec access denial.
// Embed it in concrete types to inherit the description / WWW-Authenticate
// passthrough. Use errors.As on this interface as well as the concrete types.
type AccessError interface {
	error
	FormatForUser() string
	Description() string
	WWWAuthenticate() string
	rawBody() map[string]any
}

type base struct {
	Desc string
	WWW  string
	Raw  map[string]any
}

func (b base) Error() string             { return b.Desc }
func (b base) Description() string       { return b.Desc }
func (b base) WWWAuthenticate() string   { return b.WWW }
func (b base) rawBody() map[string]any   { return b.Raw }

// ErrInsufficientScope — token valid, but missing a scope the tool needs.
type ErrInsufficientScope struct {
	base
	Tool           string
	RequiredScopes []string
	GrantedScopes  []string
}

func (e *ErrInsufficientScope) FormatForUser() string {
	req := "(unknown)"
	if len(e.RequiredScopes) > 0 {
		req = strings.Join(e.RequiredScopes, ", ")
	}
	tool := ""
	if e.Tool != "" {
		tool = " '" + e.Tool + "'"
	}
	if len(e.GrantedScopes) > 0 {
		return fmt.Sprintf(
			"Insufficient scope: tool%s requires %s. Your token has: %s. Ask an AuthSec admin to grant the missing scope, or use a tool that fits your current scopes.",
			tool, req, strings.Join(e.GrantedScopes, ", "),
		)
	}
	return fmt.Sprintf(
		"Insufficient scope: tool%s requires %s. Your token does not include this scope. Ask an AuthSec admin to grant the missing scope, or use a tool that fits your current scopes.",
		tool, req,
	)
}

// ErrTokenRevoked — access token revoked. Clear cache + re-auth.
type ErrTokenRevoked struct{ base }

func (e *ErrTokenRevoked) FormatForUser() string {
	return "Your AuthSec access token has been revoked. Clear your cached tokens and re-run the authentication flow."
}

// ErrClientRegistrationRevoked — the OAuth client registration is revoked.
// Re-auth won't help; admin must re-approve.
type ErrClientRegistrationRevoked struct{ base }

func (e *ErrClientRegistrationRevoked) FormatForUser() string {
	return "Your OAuth client registration has been revoked by an AuthSec admin. " +
		"Re-running the auth flow will not help — ask the admin to approve the client " +
		"in the AuthSec console (Applications → Clients tab)."
}

// ErrAuthRequired — no token, invalid, expired, or audience mismatch.
type ErrAuthRequired struct {
	base
	Reason string // no_token | invalid_token | token_expired | audience_mismatch
}

func (e *ErrAuthRequired) FormatForUser() string {
	switch e.Reason {
	case "no_token":
		return "Authentication required — no bearer token was sent. Run the AuthSec auth flow."
	case "token_expired":
		return "Your AuthSec token has expired. Refresh or re-authenticate."
	case "audience_mismatch":
		return "Your token was issued for a different MCP server. Re-authenticate against the correct resource."
	default:
		return fmt.Sprintf("Authentication failed (%s). Re-run the AuthSec auth flow.", e.Reason)
	}
}

// ─── Parser ──────────────────────────────────────────────────────────────

// ParseMCPError accepts whatever the MCP transport handed back — an
// *http.Response, a parsed map[string]any body, a raw []byte / string body,
// or an error whose Error() carries the message — and returns one of the
// typed errors above. Returns nil for inputs that don't look like AuthSec
// access denials; callers should fall back to the original error.
func ParseMCPError(source any) AccessError {
	body, text, www := coerce(source)
	wwwFields := parseWWWAuthenticate(www)

	// 1) Structured 403 body
	if body != nil {
		if s, _ := body["error"].(string); s == "insufficient_scope" {
			desc, _ := body["error_description"].(string)
			tool, _ := body["tool"].(string)
			return &ErrInsufficientScope{
				base:           base{Desc: desc, WWW: www, Raw: body},
				Tool:           tool,
				RequiredScopes: asStrings(body["required_scopes"]),
				GrantedScopes:  asStrings(body["granted_scopes"]),
			}
		}
		if s, _ := body["error"].(string); s == "invalid_token" || s == "missing_token" {
			reason, _ := body["reason"].(string)
			if reason == "" {
				reason = "invalid_token"
			}
			desc, _ := body["error_description"].(string)
			b := base{Desc: desc, WWW: www, Raw: body}
			switch reason {
			case "client_registration_revoked":
				return &ErrClientRegistrationRevoked{base: b}
			case "token_revoked":
				return &ErrTokenRevoked{base: b}
			default:
				return &ErrAuthRequired{base: b, Reason: reason}
			}
		}
	}

	// 2) Rich WWW-Authenticate, no structured body
	if wwwFields["error"] == "insufficient_scope" {
		return &ErrInsufficientScope{
			base:           base{Desc: wwwFields["error_description"], WWW: www},
			RequiredScopes: splitNonEmpty(wwwFields["scope"], " "),
		}
	}

	// 3) Plain-text classifier
	probe := text
	if probe == "" && body != nil {
		if s, _ := body["error_description"].(string); s != "" {
			probe = s
		} else if s, _ := body["error"].(string); s != "" {
			probe = s
		}
	}
	if probe == "" {
		return nil
	}
	switch classifyFromText(probe) {
	case "insufficient_scope":
		tool, req, granted := recoverScopeFields(probe)
		return &ErrInsufficientScope{
			base:           base{Desc: probe, WWW: www},
			Tool:           tool,
			RequiredScopes: req,
			GrantedScopes:  granted,
		}
	case "client_registration_revoked":
		return &ErrClientRegistrationRevoked{base: base{Desc: probe, WWW: www}}
	case "token_revoked":
		return &ErrTokenRevoked{base: base{Desc: probe, WWW: www}}
	case "auth_required":
		return &ErrAuthRequired{base: base{Desc: probe, WWW: www}, Reason: "invalid_token"}
	}
	return nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────

func coerce(source any) (body map[string]any, text, www string) {
	switch v := source.(type) {
	case nil:
		return nil, "", ""
	case *http.Response:
		if v == nil {
			return nil, "", ""
		}
		www = v.Header.Get("WWW-Authenticate")
		if v.Body == nil {
			return nil, "", www
		}
		raw, err := io.ReadAll(v.Body)
		_ = v.Body.Close()
		if err != nil {
			return nil, "", www
		}
		text = string(raw)
		var parsed map[string]any
		if json.Unmarshal(raw, &parsed) == nil {
			body = parsed
		}
		return body, text, www
	case map[string]any:
		if s, ok := v["WWW-Authenticate"].(string); ok {
			www = s
		} else if s, ok := v["www_authenticate"].(string); ok {
			www = s
		}
		return v, "", www
	case []byte:
		text = string(v)
		var parsed map[string]any
		if json.Unmarshal(v, &parsed) == nil {
			body = parsed
		}
		return body, text, ""
	case string:
		text = v
		var parsed map[string]any
		if json.Unmarshal([]byte(v), &parsed) == nil {
			body = parsed
		}
		return body, text, ""
	case error:
		return nil, v.Error(), ""
	default:
		return nil, fmt.Sprint(v), ""
	}
}

var wwwAuthKV = regexp.MustCompile(`(\w+)=("([^"]*)"|([^,]+))`)

func parseWWWAuthenticate(header string) map[string]string {
	out := map[string]string{}
	if header == "" {
		return out
	}
	tail := header
	if strings.HasPrefix(strings.ToLower(header), "bearer ") {
		tail = strings.TrimSpace(header[len("Bearer "):])
	}
	for _, m := range wwwAuthKV.FindAllStringSubmatch(tail, -1) {
		key := strings.ToLower(m[1])
		val := m[3]
		if val == "" {
			val = strings.TrimSpace(m[4])
		}
		out[key] = val
	}
	return out
}

func asStrings(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, e := range s {
			if str, ok := e.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}

func splitNonEmpty(s, sep string) []string {
	if s == "" {
		return nil
	}
	out := make([]string, 0, 4)
	for _, p := range strings.Split(s, sep) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func classifyFromText(text string) string {
	t := strings.ToLower(text)
	if strings.Contains(t, "insufficient_scope") ||
		strings.Contains(t, "insufficient scope") ||
		strings.Contains(t, "requires scope") ||
		strings.Contains(t, "required scope") ||
		strings.Contains(t, "does not include the required scope") ||
		strings.Contains(t, "lacks required") ||
		strings.Contains(t, "no scope mapping for tool") {
		return "insufficient_scope"
	}
	if strings.Contains(t, "client") && strings.Contains(t, "revoked") {
		return "client_registration_revoked"
	}
	if strings.Contains(t, "registration") && (strings.Contains(t, "revoked") || strings.Contains(t, "pending")) {
		return "client_registration_revoked"
	}
	if strings.Contains(t, "revoked") {
		return "token_revoked"
	}
	if strings.Contains(t, "expired") {
		return "auth_required"
	}
	if strings.Contains(t, "invalid_token") || (strings.Contains(t, "missing") && strings.Contains(t, "bearer")) {
		return "auth_required"
	}
	if strings.Contains(t, "audience") {
		return "auth_required"
	}
	return ""
}

var (
	toolRe    = regexp.MustCompile(`(?i)[Tt]ool ['"]?([^'"]+?)['"]?[\s,]+(?:requires|needs)`)
	scopeRe   = regexp.MustCompile(`(?i)(?:requires? scope:?|requires?|needs)[\s:]*([^\.]+)`)
	grantedRe = regexp.MustCompile(`(?i)(?:has|granted)[\s:]*([^\.]+)`)
	scopeTok  = regexp.MustCompile(`[\s,;]+`)
)

func recoverScopeFields(text string) (tool string, required, granted []string) {
	if m := toolRe.FindStringSubmatch(text); m != nil {
		tool = strings.TrimSpace(m[1])
	}
	if m := scopeRe.FindStringSubmatch(text); m != nil {
		required = filterScopeLooking(scopeTok.Split(strings.TrimSpace(m[1]), -1))
	}
	if m := grantedRe.FindStringSubmatch(text); m != nil {
		granted = filterScopeLooking(scopeTok.Split(strings.TrimSpace(m[1]), -1))
	}
	return
}

func filterScopeLooking(parts []string) []string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		if strings.ContainsAny(p, ":_.") {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ─── Tool-error middleware ──────────────────────────────────────────────

// ToolErrorHandler converts any tool-call error into an actionable,
// LLM-readable string. AuthSec 401/403 denials are parsed into
// human-readable messages; other errors are stringified so the LLM can
// still respond instead of the agent loop crashing.
func ToolErrorHandler(err error) string {
	if err == nil {
		return ""
	}
	access := ParseMCPError(err)
	if access != nil {
		return access.FormatForUser()
	}
	return fmt.Sprintf("Tool call failed: %v", err)
}
