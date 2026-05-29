"""Unit tests for authsec_sdk.runtime (Python parity port of Go SDK).

These tests do not hit any backend — they exercise the in-process logic of
Config validation, lookup_tool, Principal helpers, and metadata construction.
A separate integration suite (TBD) exercises the full HTTP flow against a
running AuthSec instance.
"""

from __future__ import annotations

import pytest

from authsec_sdk.runtime import (
    Config,
    PolicyMode,
    Principal,
    ValidationMode,
    build_resource_metadata_path,
    build_resource_metadata_url,
    build_www_authenticate,
    has_any_required,
    is_metadata_request,
    lookup_tool,
    required_scopes,
    ToolPolicyResult,
)


def _valid_cfg(**overrides) -> Config:
    base = dict(
        issuer="https://dev.api.authsec.dev",
        authorization_server="https://dev.api.authsec.dev",
        jwks_url="https://dev.api.authsec.dev/oauth/jwks",
        introspection_url="https://dev.api.authsec.dev/oauth/introspect",
        introspection_client_id="abc",
        introspection_client_secret="shh",
        resource_uri="https://mcp.example.com/mcp",
        resource_name="Example MCP",
        resource_server_id="525da3b4-4206-4070-ad68-90cc3a6de43b",
        policy_mode=PolicyMode.REMOTE_REQUIRED,
        validation_mode=ValidationMode.JWT_AND_INTROSPECT,
        publish_manifest=True,
    )
    base.update(overrides)
    return Config(**base)


# ─────────────────────────────────────────────────────────────────────
# Config validation
# ─────────────────────────────────────────────────────────────────────


class TestConfigValidation:
    def test_happy_path(self):
        cfg = _valid_cfg()
        cfg.validate()  # no exception
        assert cfg.effective_policy_mode() == PolicyMode.REMOTE_REQUIRED
        assert cfg.effective_validation_mode() == ValidationMode.JWT_AND_INTROSPECT

    def test_missing_issuer_rejected(self):
        with pytest.raises(ValueError, match="issuer is required"):
            _valid_cfg(issuer="").validate()

    def test_resource_uri_must_be_absolute(self):
        with pytest.raises(ValueError, match="absolute URI"):
            _valid_cfg(resource_uri="not-a-uri").validate()

    def test_remote_required_without_rsid_rejected(self):
        with pytest.raises(ValueError, match="resource_server_id"):
            _valid_cfg(resource_server_id="").validate()

    def test_remote_required_without_introspection_creds_rejected(self):
        # The "introspection enabled" check fires first (more specific) since
        # introspection_url is set in the valid config; we accept either message.
        with pytest.raises(ValueError, match="introspection.*credentials"):
            _valid_cfg(introspection_client_id="").validate()

    def test_remote_with_local_fallback_needs_tool_scopes(self):
        with pytest.raises(ValueError, match="tool_scopes"):
            _valid_cfg(
                policy_mode=PolicyMode.REMOTE_WITH_LOCAL_FALLBACK,
                tool_scopes=None,
            ).validate()

    def test_jwt_only_needs_jwks_url(self):
        with pytest.raises(ValueError, match="jwt_only requires jwks_url"):
            _valid_cfg(
                jwks_url="",
                validation_mode=ValidationMode.JWT_ONLY,
                # also have to drop the REMOTE_REQUIRED constraint
                policy_mode=PolicyMode.OPEN,
                resource_server_id="",
            ).validate()

    def test_inference_open_when_no_rs_no_scopes(self):
        cfg = Config(
            issuer="https://x",
            jwks_url="https://x/j",
            resource_uri="https://x/m",
        )
        assert cfg.effective_policy_mode() == PolicyMode.OPEN
        assert cfg.effective_validation_mode() == ValidationMode.JWT_ONLY


# ─────────────────────────────────────────────────────────────────────
# lookup_tool semantics
# ─────────────────────────────────────────────────────────────────────


class TestLookupTool:
    def test_absent_when_map_none(self):
        result, scopes = lookup_tool(None, "foo")
        assert result == ToolPolicyResult.ABSENT
        assert scopes == []

    def test_absent_when_not_in_map(self):
        result, scopes = lookup_tool({"other": ["read"]}, "foo")
        assert result == ToolPolicyResult.ABSENT
        assert scopes == []

    def test_public_when_empty_list(self):
        result, scopes = lookup_tool({"foo": []}, "foo")
        assert result == ToolPolicyResult.PUBLIC
        assert scopes == []

    def test_scoped(self):
        result, scopes = lookup_tool({"foo": ["read", "write"]}, "foo")
        assert result == ToolPolicyResult.SCOPED
        assert scopes == ["read", "write"]

    def test_required_scopes_helper(self):
        assert required_scopes({"foo": ["a"]}, "foo") == ["a"]
        assert required_scopes(None, "foo") == []
        assert required_scopes({}, "foo") == []

    def test_has_any_required(self):
        assert has_any_required({"foo": ["read"]}, "foo", {"read"})
        assert not has_any_required({"foo": ["read"]}, "foo", {"write"})
        assert has_any_required({"foo": []}, "foo", set())  # public — always allowed


# ─────────────────────────────────────────────────────────────────────
# Principal
# ─────────────────────────────────────────────────────────────────────


class TestPrincipal:
    def test_has_any_scope(self):
        p = Principal(subject="u1", scopes=["read", "write"])
        assert p.has_any_scope(["delete", "read"])
        assert not p.has_any_scope(["admin"])

    def test_empty_required_always_true(self):
        p = Principal(subject="u1", scopes=[])
        assert p.has_any_scope([])


# ─────────────────────────────────────────────────────────────────────
# RFC 9728 metadata helpers
# ─────────────────────────────────────────────────────────────────────


class TestMetadataPaths:
    def test_root_resource(self):
        assert (
            build_resource_metadata_path("https://x.com")
            == "/.well-known/oauth-protected-resource"
        )

    def test_path_based_resource(self):
        assert (
            build_resource_metadata_path("https://x.com/mcp")
            == "/.well-known/oauth-protected-resource/mcp"
        )

    def test_nested_path(self):
        assert (
            build_resource_metadata_path("https://x.com/v1/mcp")
            == "/.well-known/oauth-protected-resource/v1/mcp"
        )

    def test_full_url(self):
        assert (
            build_resource_metadata_url("https://x.com/mcp")
            == "https://x.com/.well-known/oauth-protected-resource/mcp"
        )

    def test_is_metadata_request_path_based(self):
        assert is_metadata_request("https://x.com/mcp", "/.well-known/oauth-protected-resource/mcp")
        assert not is_metadata_request("https://x.com/mcp", "/.well-known/oauth-protected-resource")

    def test_is_metadata_request_root(self):
        assert is_metadata_request("https://x.com", "/.well-known/oauth-protected-resource")

    def test_www_authenticate_minimal(self):
        cfg = _valid_cfg()
        header = build_www_authenticate(cfg)
        assert 'Bearer realm="Example MCP"' in header
        assert 'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"' in header

    def test_www_authenticate_with_error(self):
        cfg = _valid_cfg()
        header = build_www_authenticate(
            cfg, error="insufficient_scope", error_description='needs "read"', scope="read"
        )
        assert 'error="insufficient_scope"' in header
        assert 'scope="read"' in header
        # quotes in error_description must be escaped
        assert 'error_description="needs \\"read\\""' in header
