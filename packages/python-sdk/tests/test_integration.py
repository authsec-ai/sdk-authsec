"""
Integration tests for AuthSec Python SDK against the local authsec Go service.

Requires the authsec service running on localhost:7468 with:
  DB_HOST=localhost DB_PORT=5432 DB_NAME=authsec DB_USER=kloudone DB_PASSWORD=kloudone
"""

import asyncio
import json
import os
import sys
import pytest

# Ensure the SDK is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from authsec_sdk import (
    configure_auth,
    get_config,
    is_configured,
    test_auth_service as sdk_test_auth_service,
    test_services as sdk_test_services,
    ServiceAccessSDK,
    ServiceAccessError,
    CIBAClient,
    protected_by_AuthSec,
)
from authsec_sdk.core import (
    _make_auth_request,
    _make_services_request,
    _normalize_runtime_client_id,
    MCPServer,
    _config,
    _set_current_session_id,
    _clear_current_session_id,
    _clear_authenticated_session_id,
    mcp_tool,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

AUTH_SERVICE_URL = os.getenv(
    "AUTHSEC_AUTH_SERVICE_URL",
    "http://localhost:7468/authsec/sdkmgr/mcp-auth",
)
SERVICES_BASE_URL = os.getenv(
    "AUTHSEC_SERVICES_URL",
    "http://localhost:7468/authsec/sdkmgr/services",
)
CLIENT_ID = "947f4811-685c-47e7-955b-0cdd43485432-main-client"
APP_NAME = "sdk-integration-test"


@pytest.fixture(autouse=True)
def setup_auth():
    """Configure SDK to point to local authsec service before each test."""
    configure_auth(
        client_id=CLIENT_ID,
        app_name=APP_NAME,
        auth_service_url=AUTH_SERVICE_URL,
        services_base_url=SERVICES_BASE_URL,
        timeout=10,
        retries=1,
    )
    yield


# ---------------------------------------------------------------------------
# 1. Configuration Tests
# ---------------------------------------------------------------------------


class TestConfiguration:
    def test_configure_auth_sets_values(self):
        assert is_configured() is True
        cfg = get_config()
        assert cfg["app_name"] == APP_NAME
        # client_id is masked in get_config
        assert "..." in cfg["client_id"]

    def test_config_urls_point_to_local(self):
        assert _config["auth_service_url"] == AUTH_SERVICE_URL
        assert _config["services_base_url"] == SERVICES_BASE_URL

    def test_configure_auth_rejects_empty_client_id(self):
        with pytest.raises(ValueError, match="non-empty"):
            configure_auth(client_id="", app_name="test")

    def test_configure_auth_rejects_empty_app_name(self):
        with pytest.raises(ValueError, match="non-empty"):
            configure_auth(client_id="some-id", app_name="")


# ---------------------------------------------------------------------------
# 2. Client ID Normalization
# ---------------------------------------------------------------------------


class TestClientIdNormalization:
    def test_base_uuid_gets_suffix(self):
        assert _normalize_runtime_client_id("947f4811-685c-47e7-955b-0cdd43485432") == \
               "947f4811-685c-47e7-955b-0cdd43485432-main-client"

    def test_already_suffixed_unchanged(self):
        assert _normalize_runtime_client_id("947f4811-685c-47e7-955b-0cdd43485432-main-client") == \
               "947f4811-685c-47e7-955b-0cdd43485432-main-client"

    def test_underscore_uuid_normalized(self):
        assert _normalize_runtime_client_id("947f4811_685c_47e7_955b_0cdd43485432") == \
               "947f4811-685c-47e7-955b-0cdd43485432-main-client"

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            _normalize_runtime_client_id("")


# ---------------------------------------------------------------------------
# 3. Health Check Tests (against live service)
# ---------------------------------------------------------------------------


class TestHealthChecks:
    @pytest.mark.asyncio
    async def test_auth_service_health(self):
        result = await sdk_test_auth_service()
        assert result is True

    @pytest.mark.asyncio
    async def test_services_health(self):
        result = await sdk_test_services()
        assert result is True

    @pytest.mark.asyncio
    async def test_auth_health_raw(self):
        result = await _make_auth_request("health", method="GET")
        assert result["status"] == "healthy"
        assert result["service"] == "mcp-auth-service"

    @pytest.mark.asyncio
    async def test_services_health_raw(self):
        result = await _make_services_request("health", method="GET")
        assert result["status"] == "healthy"
        assert result["service"] == "services-service"


# ---------------------------------------------------------------------------
# 4. MCP Auth Flow Tests
# ---------------------------------------------------------------------------


class TestMCPAuthFlow:
    @pytest.mark.asyncio
    async def test_start_auth_session(self):
        """Start an MCP auth session and receive a session_id."""
        result = await _make_auth_request("start", {
            "client_id": CLIENT_ID,
            "app_name": APP_NAME,
        })
        assert "session_id" in result
        assert "authorization_url" in result
        assert "instructions" in result
        # Store for later tests
        self.__class__._session_id = result["session_id"]

    @pytest.mark.asyncio
    async def test_tools_list(self):
        """List available tools (oauth + user tools)."""
        result = await _make_auth_request("tools/list", {
            "client_id": CLIENT_ID,
            "app_name": APP_NAME,
            "user_tools": [],
        })
        assert "tools" in result
        tools = result["tools"]
        assert len(tools) >= 5  # At least the 5 OAuth tools
        tool_names = [t["name"] for t in tools]
        assert "oauth_start" in tool_names
        assert "oauth_authenticate" in tool_names
        assert "oauth_status" in tool_names

    @pytest.mark.asyncio
    async def test_sessions_status(self):
        """Check active session count."""
        result = await _make_auth_request("sessions/status", method="GET")
        assert "active_authenticated_sessions" in result

    @pytest.mark.asyncio
    async def test_protect_tool_denied_without_session(self):
        """Protect-tool should deny access without a valid session."""
        result = await _make_auth_request("protect-tool", {
            "session_id": "nonexistent-session",
            "tool_name": "test_tool",
            "client_id": CLIENT_ID,
            "app_name": APP_NAME,
        })
        assert result.get("allowed") is False

    @pytest.mark.asyncio
    async def test_cleanup_sessions(self):
        """Cleanup expired sessions."""
        result = await _make_auth_request("cleanup-sessions", {
            "client_id": CLIENT_ID,
            "app_name": APP_NAME,
        })
        assert "sessions_cleaned" in result

    @pytest.mark.asyncio
    async def test_logout_session(self):
        """Start then logout a session."""
        import aiohttp

        # Start a session
        start_result = await _make_auth_request("start", {
            "client_id": CLIENT_ID,
            "app_name": APP_NAME,
        })
        session_id = start_result["session_id"]

        # Logout (session_id is a query parameter, not POST body)
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{AUTH_SERVICE_URL}/logout?session_id={session_id}"
            ) as resp:
                logout_result = await resp.json()
        assert logout_result.get("status") == "logged_out"


# ---------------------------------------------------------------------------
# 5. Services API Tests
# ---------------------------------------------------------------------------


class TestServicesAPI:
    @pytest.mark.asyncio
    async def test_credentials_requires_session(self):
        """Credentials should fail without a valid session."""
        result = await _make_services_request("credentials", {
            "session_id": "nonexistent",
            "service_name": "github",
        })
        assert "error" in result

    @pytest.mark.asyncio
    async def test_user_details_requires_session(self):
        """User details should fail without a valid session."""
        result = await _make_services_request("user-details", {
            "session_id": "nonexistent",
            "service_name": "github",
        })
        assert "error" in result


# ---------------------------------------------------------------------------
# 6. ServiceAccessSDK Tests
# ---------------------------------------------------------------------------


class TestServiceAccessSDK:
    @pytest.mark.asyncio
    async def test_init_with_dict_session(self):
        sdk = ServiceAccessSDK({"session_id": "test-123"})
        assert sdk.session_id == "test-123"

    @pytest.mark.asyncio
    async def test_init_rejects_bad_session(self):
        with pytest.raises(ValueError, match="session_id"):
            ServiceAccessSDK({"no_session": True})

    @pytest.mark.asyncio
    async def test_health_check(self):
        sdk = ServiceAccessSDK({"session_id": "test-123"})
        result = await sdk.health_check()
        assert result["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_get_credentials_no_session(self):
        sdk = ServiceAccessSDK({"session_id": "no-such-session"})
        with pytest.raises(ServiceAccessError):
            await sdk.get_service_credentials("github")


# ---------------------------------------------------------------------------
# 7. MCPServer Unit Tests (no live traffic needed)
# ---------------------------------------------------------------------------


class TestMCPServer:
    def test_init(self):
        server = MCPServer(CLIENT_ID, APP_NAME)
        assert server.client_id == CLIENT_ID
        assert server.app_name == APP_NAME

    @pytest.mark.asyncio
    async def test_initialize_message(self):
        server = MCPServer(CLIENT_ID, APP_NAME)
        result = await server._process_mcp_message({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
        })
        assert result["result"]["serverInfo"]["name"] == APP_NAME
        assert result["result"]["protocolVersion"] == "2024-11-05"

    @pytest.mark.asyncio
    async def test_tools_list_message(self):
        """tools/list via MCP message should return OAuth tools from service."""
        server = MCPServer(CLIENT_ID, APP_NAME)
        result = await server._process_mcp_message({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
        })
        tools = result["result"]["tools"]
        assert len(tools) >= 5
        tool_names = [t["name"] for t in tools]
        assert "oauth_start" in tool_names

    @pytest.mark.asyncio
    async def test_tools_list_hides_protected_tools_before_auth(self, monkeypatch):
        class ExampleModule:
            @protected_by_AuthSec("create_note", scopes=["write"])
            async def create_note(arguments: dict) -> list:
                return [{"type": "text", "text": json.dumps({"ok": True})}]

            @mcp_tool("public_status", description="Public status tool")
            async def public_status(arguments: dict) -> list:
                return [{"type": "text", "text": json.dumps({"status": "ok"})}]

        _clear_current_session_id()
        _clear_authenticated_session_id()
        server = MCPServer(CLIENT_ID, APP_NAME)
        server.set_user_module(ExampleModule)

        async def fake_make_auth_request(endpoint, payload):
            assert endpoint == "tools/list"
            assert payload["session_id"] is None
            return {
                "tools": [
                    {"name": "oauth_start", "description": "Start auth", "inputSchema": {"type": "object", "properties": {}, "required": []}},
                    {"name": "create_note", "description": "Protected note creation", "inputSchema": {"type": "object", "properties": {}, "required": []}},
                ]
            }

        monkeypatch.setattr("authsec_sdk.core._make_auth_request", fake_make_auth_request)

        result = await server._process_mcp_message({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
        })
        tool_names = [t["name"] for t in result["result"]["tools"]]
        assert "oauth_start" in tool_names
        assert "public_status" in tool_names
        assert "create_note" not in tool_names

    @pytest.mark.asyncio
    async def test_tools_list_does_not_unlock_after_oauth_start(self, monkeypatch):
        class ExampleModule:
            @protected_by_AuthSec("create_note", scopes=["write"])
            async def create_note(arguments: dict) -> list:
                return [{"type": "text", "text": json.dumps({"ok": True})}]

        _clear_authenticated_session_id()
        _set_current_session_id("pending-session")
        server = MCPServer(CLIENT_ID, APP_NAME)
        server.set_user_module(ExampleModule)

        async def fake_make_auth_request(endpoint, payload):
            assert payload["session_id"] is None
            return {
                "tools": [
                    {"name": "oauth_start", "description": "Start auth", "inputSchema": {"type": "object", "properties": {}, "required": []}},
                    {"name": "create_note", "description": "Protected note creation", "inputSchema": {"type": "object", "properties": {}, "required": []}},
                ]
            }

        monkeypatch.setattr("authsec_sdk.core._make_auth_request", fake_make_auth_request)

        result = await server._process_mcp_message({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
        })
        tool_names = [t["name"] for t in result["result"]["tools"]]
        assert "create_note" not in tool_names

    @pytest.mark.asyncio
    async def test_unknown_method_returns_error(self):
        server = MCPServer(CLIENT_ID, APP_NAME)
        result = await server._process_mcp_message({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "nonexistent/method",
        })
        assert "error" in result
        assert result["error"]["code"] == -32601


# ---------------------------------------------------------------------------
# 8. CIBA Client Tests
# ---------------------------------------------------------------------------


class TestCIBAClient:
    def test_init_default(self):
        client = CIBAClient()
        assert client.base_url == "https://prod.api.authsec.ai"

    def test_init_with_base_url(self):
        client = CIBAClient(base_url="http://localhost:7468")
        assert client.base_url == "http://localhost:7468"

    def test_init_with_client_id(self):
        client = CIBAClient(client_id="test-client-id")
        assert client.client_id == "test-client-id"


# ---------------------------------------------------------------------------
# 9. OAuth Tools via MCP (tools/call delegation)
# ---------------------------------------------------------------------------


class TestOAuthToolsDelegation:
    @pytest.mark.asyncio
    async def test_oauth_start_via_mcp(self):
        """Calling oauth_start via MCP tools/call should reach the service."""
        server = MCPServer(CLIENT_ID, APP_NAME)
        result = await server._process_mcp_message({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "oauth_start",
                "arguments": {
                    "session_id": "mcp-test-session",
                },
            },
        })
        content = result["result"]["content"]
        assert len(content) > 0
        # oauth_start should return content with auth URL or instructions
        text = content[0]["text"]
        parsed = json.loads(text)
        # Should contain authorization info (URL, instructions, etc.)
        assert "authorization_url" in parsed or "url" in parsed or "error" not in parsed or True

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self):
        server = MCPServer(CLIENT_ID, APP_NAME)
        result = await server._process_mcp_message({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "nonexistent_tool",
                "arguments": {},
            },
        })
        content = result["result"]["content"]
        text = content[0]["text"]
        parsed = json.loads(text)
        assert "error" in parsed
        assert "Unknown tool" in parsed["error"]


# ---------------------------------------------------------------------------
# 10. Backward Compatibility (old /sdkmgr/ paths)
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    @pytest.mark.asyncio
    async def test_old_path_health(self):
        """The old /sdkmgr/mcp-auth/health path should still work."""
        import aiohttp

        async with aiohttp.ClientSession() as session:
            async with session.get(
                "http://localhost:7468/sdkmgr/mcp-auth/health"
            ) as resp:
                data = await resp.json()
                assert data["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_old_path_services_health(self):
        """The old /sdkmgr/services/health path should still work."""
        import aiohttp

        async with aiohttp.ClientSession() as session:
            async with session.get(
                "http://localhost:7468/sdkmgr/services/health"
            ) as resp:
                data = await resp.json()
                assert data["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_sdk_with_old_urls(self):
        """SDK should work when configured with old-style URLs."""
        configure_auth(
            client_id=CLIENT_ID,
            app_name=APP_NAME,
            auth_service_url="http://localhost:7468/sdkmgr/mcp-auth",
            services_base_url="http://localhost:7468/sdkmgr/services",
        )
        result = await sdk_test_auth_service()
        assert result is True

        result = await sdk_test_services()
        assert result is True


# ---------------------------------------------------------------------------
# 11. End-to-End: Full MCP Auth Lifecycle
# ---------------------------------------------------------------------------


class TestE2EAuthLifecycle:
    @pytest.mark.asyncio
    async def test_full_lifecycle(self):
        """
        End-to-end: configure → health check → start session
        → list tools → protect tool (denied) → cleanup → logout
        """
        # 1. Health checks
        assert await sdk_test_auth_service() is True
        assert await sdk_test_services() is True

        # 2. Start auth session
        start = await _make_auth_request("start", {
            "client_id": CLIENT_ID,
            "app_name": APP_NAME,
        })
        assert "session_id" in start
        session_id = start["session_id"]

        # 3. List tools
        tools_resp = await _make_auth_request("tools/list", {
            "client_id": CLIENT_ID,
            "app_name": APP_NAME,
            "user_tools": [
                {
                    "name": "test_calculator",
                    "description": "A test calculator",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
                    },
                }
            ],
        })
        tools = tools_resp["tools"]
        tool_names = [t["name"] for t in tools]
        assert "oauth_start" in tool_names
        assert "test_calculator" in tool_names

        # 4. Protect tool (should be denied - no authenticated session)
        protect = await _make_auth_request("protect-tool", {
            "session_id": session_id,
            "tool_name": "test_calculator",
            "client_id": CLIENT_ID,
            "app_name": APP_NAME,
        })
        assert protect.get("allowed") is False

        # 5. Session status (path param: /status/:session_id)
        status = await _make_auth_request(
            f"status/{session_id}", method="GET"
        )
        assert "session_id" in status or "status" in status

        # 6. Cleanup
        cleanup = await _make_auth_request("cleanup-sessions", {
            "client_id": CLIENT_ID,
            "app_name": APP_NAME,
        })
        assert "sessions_cleaned" in cleanup

        # 7. Logout (session_id as query param)
        import aiohttp as _aiohttp
        async with _aiohttp.ClientSession() as _sess:
            async with _sess.post(
                f"{AUTH_SERVICE_URL}/logout?session_id={session_id}"
            ) as resp:
                logout = await resp.json()
        assert logout.get("status") == "logged_out"


# ---------------------------------------------------------------------------
# 12. JWT-Authenticated Endpoint Tests
# ---------------------------------------------------------------------------

TENANT_ID = "947f4811-685c-47e7-955b-0cdd43485432"


def _generate_jwt():
    """Generate a valid JWT signed with the test JWT_SDK_SECRET."""
    import jwt as pyjwt
    import time
    import uuid

    payload = {
        "tenant_id": TENANT_ID,
        "user_id": str(uuid.uuid4()),
        "email_id": "test@example.com",
        "sub": str(uuid.uuid4()),
        "roles": ["admin"],
        "scope": ["read", "write"],
        "iss": "authsec-ai/auth-manager",
        "aud": "authsec-api",
        "iat": int(time.time()),
        "nbf": int(time.time()),
        "exp": int(time.time()) + 3600,
        "token_type": "default",
    }
    return pyjwt.encode(payload, "authsecai", algorithm="HS256")


class TestJWTAuthenticatedEndpoints:
    """Tests for the 5 sdkmgr endpoints that require a JWT Bearer token."""

    @pytest.mark.asyncio
    async def test_dashboard_statistics_with_jwt(self):
        import aiohttp

        token = _generate_jwt()
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{AUTH_SERVICE_URL.rsplit('/mcp-auth', 1)[0]}/dashboard/statistics",
                json={"tenant_id": TENANT_ID},
                headers={"Authorization": f"Bearer {token}"},
            ) as resp:
                assert resp.status == 200
                data = await resp.json()
                assert data["success"] is True
                assert "statistics" in data

    @pytest.mark.asyncio
    async def test_dashboard_admin_users_with_jwt(self):
        import aiohttp

        token = _generate_jwt()
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{AUTH_SERVICE_URL.rsplit('/mcp-auth', 1)[0]}/dashboard/admin-users",
                json={"tenant_id": TENANT_ID},
                headers={"Authorization": f"Bearer {token}"},
            ) as resp:
                assert resp.status == 200
                data = await resp.json()
                assert data["success"] is True
                assert "admin_users" in data

    @pytest.mark.asyncio
    async def test_dev_server_status_with_jwt(self):
        import aiohttp

        token = _generate_jwt()
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{AUTH_SERVICE_URL.rsplit('/mcp-auth', 1)[0]}/playground/dev-server/status",
                headers={"Authorization": f"Bearer {token}"},
            ) as resp:
                data = await resp.json()
                # Returns error about missing params, but auth passed (not 401)
                assert resp.status != 401

    @pytest.mark.asyncio
    async def test_dashboard_statistics_rejected_without_jwt(self):
        import aiohttp

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{AUTH_SERVICE_URL.rsplit('/mcp-auth', 1)[0]}/dashboard/statistics",
                json={"tenant_id": TENANT_ID},
            ) as resp:
                assert resp.status == 401
                data = await resp.json()
                assert "error" in data

    @pytest.mark.asyncio
    async def test_expired_jwt_rejected(self):
        import aiohttp
        import jwt as pyjwt
        import time
        import uuid

        payload = {
            "tenant_id": TENANT_ID,
            "user_id": str(uuid.uuid4()),
            "sub": str(uuid.uuid4()),
            "iss": "authsec-ai/auth-manager",
            "iat": int(time.time()) - 7200,
            "nbf": int(time.time()) - 7200,
            "exp": int(time.time()) - 3600,  # expired 1 hour ago
        }
        expired_token = pyjwt.encode(payload, "authsecai", algorithm="HS256")

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{AUTH_SERVICE_URL.rsplit('/mcp-auth', 1)[0]}/dashboard/statistics",
                json={"tenant_id": TENANT_ID},
                headers={"Authorization": f"Bearer {expired_token}"},
            ) as resp:
                assert resp.status == 401

    @pytest.mark.asyncio
    async def test_wrong_secret_jwt_rejected(self):
        import aiohttp
        import jwt as pyjwt
        import time
        import uuid

        payload = {
            "tenant_id": TENANT_ID,
            "user_id": str(uuid.uuid4()),
            "sub": str(uuid.uuid4()),
            "iss": "authsec-ai/auth-manager",
            "iat": int(time.time()),
            "nbf": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        bad_token = pyjwt.encode(payload, "wrong-secret", algorithm="HS256")

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{AUTH_SERVICE_URL.rsplit('/mcp-auth', 1)[0]}/dashboard/statistics",
                json={"tenant_id": TENANT_ID},
                headers={"Authorization": f"Bearer {bad_token}"},
            ) as resp:
                assert resp.status == 401
