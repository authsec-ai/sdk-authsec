package client

import (
	"errors"
	"testing"
)

func TestParseStructured403(t *testing.T) {
	body := map[string]any{
		"error":             "insufficient_scope",
		"error_description": "Tool 'slugify' requires scope: demo_server:admin.",
		"tool":              "slugify",
		"required_scopes":   []any{"demo_server:admin"},
		"granted_scopes":    []any{"demo_server:read", "demo_server:write"},
	}
	got := ParseMCPError(body)
	var scope *ErrInsufficientScope
	if !errors.As(got, &scope) {
		t.Fatalf("want *ErrInsufficientScope, got %T (%v)", got, got)
	}
	if scope.Tool != "slugify" {
		t.Errorf("tool = %q, want slugify", scope.Tool)
	}
	if len(scope.RequiredScopes) != 1 || scope.RequiredScopes[0] != "demo_server:admin" {
		t.Errorf("required = %v", scope.RequiredScopes)
	}
	if len(scope.GrantedScopes) != 2 {
		t.Errorf("granted = %v", scope.GrantedScopes)
	}
	if msg := scope.FormatForUser(); msg == "" {
		t.Errorf("empty formatted message")
	}
}

func TestParseStructured401Revoked(t *testing.T) {
	got := ParseMCPError(map[string]any{
		"error":             "invalid_token",
		"error_description": "client registration revoked",
		"reason":            "client_registration_revoked",
	})
	var revoked *ErrClientRegistrationRevoked
	if !errors.As(got, &revoked) {
		t.Fatalf("want *ErrClientRegistrationRevoked, got %T", got)
	}
}

func TestParsePlainStringScope(t *testing.T) {
	got := ParseMCPError("Tool 'slugify' requires scope: demo_server:admin. Your token has: demo_server:read.")
	var scope *ErrInsufficientScope
	if !errors.As(got, &scope) {
		t.Fatalf("want *ErrInsufficientScope, got %T", got)
	}
	if scope.Tool != "slugify" {
		t.Errorf("tool = %q", scope.Tool)
	}
}

func TestParseLegacyOpaqueMessage(t *testing.T) {
	got := ParseMCPError("Unauthorized to perform this action. The token does not include the required scope.")
	var scope *ErrInsufficientScope
	if !errors.As(got, &scope) {
		t.Fatalf("want *ErrInsufficientScope, got %T (%v)", got, got)
	}
}

func TestParseUnrelatedReturnsNil(t *testing.T) {
	if got := ParseMCPError("some completely unrelated error"); got != nil {
		t.Errorf("expected nil for unrelated, got %T (%v)", got, got)
	}
}

func TestParseErrorInput(t *testing.T) {
	src := errors.New("Tool 'slugify' requires scope: demo_server:admin.")
	got := ParseMCPError(src)
	var scope *ErrInsufficientScope
	if !errors.As(got, &scope) {
		t.Fatalf("want *ErrInsufficientScope, got %T", got)
	}
}
