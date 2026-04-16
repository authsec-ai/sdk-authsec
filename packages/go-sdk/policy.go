package authsec

import "strings"

// ToolPolicy determines the scope requirements for each MCP tool.
type ToolPolicy interface {
	RuleFor(toolName string) ToolRule
}

// ToolRule specifies the scope requirements for a single tool.
type ToolRule struct {
	AnyOfScopes []string
}

// StaticPolicy is a local defense-in-depth fallback that maps tool names to
// scope requirements. The authoritative scope→tool mapping lives in AuthSec
// (Scope Matrix UI). StaticPolicy ensures the MCP server enforces minimum
// scope requirements even if AuthSec is unreachable or misconfigured.
type StaticPolicy map[string]ToolRule

func (p StaticPolicy) RuleFor(toolName string) ToolRule {
	if rule, ok := p[toolName]; ok {
		return rule
	}
	return ToolRule{}
}

type allowAllPolicy struct{}

func (allowAllPolicy) RuleFor(string) ToolRule { return ToolRule{} }

func AllowAllPolicy() ToolPolicy { return allowAllPolicy{} }

func OverrideToolPolicy(base ToolPolicy, overrides map[string]ToolRule) ToolPolicy {
	if base == nil {
		base = AllowAllPolicy()
	}
	return overridePolicy{base: base, overrides: overrides}
}

type overridePolicy struct {
	base      ToolPolicy
	overrides map[string]ToolRule
}

func (p overridePolicy) RuleFor(toolName string) ToolRule {
	if rule, ok := p.overrides[toolName]; ok {
		return rule
	}
	return p.base.RuleFor(toolName)
}

func RequiredScopesForTool(policy ToolPolicy, toolName string) []string {
	if policy == nil {
		return nil
	}
	rule := policy.RuleFor(strings.TrimSpace(toolName))
	return append([]string(nil), rule.AnyOfScopes...)
}
