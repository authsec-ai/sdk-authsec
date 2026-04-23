package authsec

import "strings"

// ToolScopeMap maps MCP tool names to their required OAuth scopes.
//
// The authoritative tool→scope mapping lives in AuthSec's Scope Matrix UI.
// When ResourceServerID is set in Config, the SDK fetches this mapping from
// AuthSec at startup and refreshes it periodically. The developer does not
// need to maintain tool→scope mappings in code.
//
// ToolScopeMap can also be set directly via Config.ToolScopes as a local
// defense-in-depth fallback. When set, it is used if the remote fetch fails.
// When both remote and local are nil, no tool-level filtering is applied
// (all tools are allowed for any valid token).
//
// An explicit empty slice entry marks a tool as public (allowed for any valid token):
//
//	ToolScopeMap{"public_tool": {}}
//
// A tool absent from the map is denied when any non-Open policy mode is active.
type ToolScopeMap map[string][]string

// ToolPolicyResult is the three-state outcome of LookupTool.
type ToolPolicyResult int

const (
	// ToolPolicyAbsent means the tool has no entry in the map.
	// When a non-Open policy mode is active, absent tools are denied.
	ToolPolicyAbsent ToolPolicyResult = iota

	// ToolPolicyPublic means the tool has an explicit empty-slice entry.
	// It is allowed for any valid authenticated token, regardless of scopes.
	ToolPolicyPublic

	// ToolPolicyScoped means the tool requires at least one specific scope.
	ToolPolicyScoped
)

// LookupTool returns the policy result and required scopes for a tool.
// Use this instead of RequiredScopes when deny-by-default is needed.
func (m ToolScopeMap) LookupTool(toolName string) (ToolPolicyResult, []string) {
	if m == nil {
		return ToolPolicyAbsent, nil
	}
	name := strings.TrimSpace(toolName)
	scopes, present := m[name]
	if !present {
		return ToolPolicyAbsent, nil
	}
	if len(scopes) == 0 {
		return ToolPolicyPublic, nil
	}
	return ToolPolicyScoped, scopes
}

// RequiredScopes returns the scopes required for a tool.
// Returns nil if the tool has no mapping (tool is allowed for any valid token).
// Deprecated: prefer LookupTool for deny-by-default semantics.
func (m ToolScopeMap) RequiredScopes(toolName string) []string {
	if m == nil {
		return nil
	}
	return m[strings.TrimSpace(toolName)]
}

// HasAnyRequired checks whether a principal with the given granted scopes
// satisfies the scope requirement for the named tool.
func (m ToolScopeMap) HasAnyRequired(toolName string, granted map[string]struct{}) bool {
	required := m.RequiredScopes(toolName)
	if len(required) == 0 {
		return true // no requirement → allowed
	}
	for _, scope := range required {
		if _, ok := granted[scope]; ok {
			return true
		}
	}
	return false
}
