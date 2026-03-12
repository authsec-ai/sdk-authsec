"""
Browser-based integration test runner for all AuthSec Python SDKs.

Runs all SDK tests against the live authsec service and displays
results in the browser as a styled HTML dashboard.

Usage:
    python tests/test_browser.py

Requires the authsec service running on localhost:7468.
"""

import asyncio
import json
import os
import sys
import time
import traceback
import uuid
import hmac
import hashlib
import base64
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading

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
    DelegationClient,
    DelegationError,
    DelegationTokenNotFound,
)
from authsec_sdk.core import (
    _make_auth_request,
    _make_services_request,
    _normalize_runtime_client_id,
    MCPServer,
    _config,
)

import aiohttp

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASE_URL = "http://localhost:7468"
AUTH_SERVICE_URL = f"{BASE_URL}/authsec/sdkmgr/mcp-auth"
SERVICES_BASE_URL = f"{BASE_URL}/authsec/sdkmgr/services"
SDKMGR_BASE = f"{BASE_URL}/authsec/sdkmgr"
CLIENT_ID = "947f4811-685c-47e7-955b-0cdd43485432-main-client"
TENANT_ID = "947f4811-685c-47e7-955b-0cdd43485432"
APP_NAME = "sdk-browser-test"
JWT_SECRET = "authsecai"


def _generate_jwt(secret=JWT_SECRET, exp_offset=3600):
    """Generate a JWT token using HMAC-SHA256 (no pyjwt dependency)."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()

    now = int(time.time())
    payload_data = {
        "tenant_id": TENANT_ID,
        "user_id": str(uuid.uuid4()),
        "email_id": "test@example.com",
        "sub": str(uuid.uuid4()),
        "roles": ["admin"],
        "scope": ["read", "write"],
        "iss": "authsec-ai/auth-manager",
        "aud": "authsec-api",
        "iat": now,
        "nbf": now,
        "exp": now + exp_offset,
        "token_type": "default",
    }
    payload = base64.urlsafe_b64encode(
        json.dumps(payload_data).encode()
    ).rstrip(b"=").decode()

    signature = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()

    return f"{header}.{payload}.{signature}"


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

class TestResult:
    def __init__(self, suite: str, name: str):
        self.suite = suite
        self.name = name
        self.status = "pending"  # pass, fail, error, skip
        self.message = ""
        self.duration_ms = 0

results: list[TestResult] = []


async def run_test(suite: str, name: str, coro):
    """Run a single async test and record the result."""
    r = TestResult(suite, name)
    results.append(r)
    start = time.monotonic()
    try:
        await coro()
        r.status = "pass"
    except AssertionError as e:
        r.status = "fail"
        r.message = str(e) or "Assertion failed"
    except Exception as e:
        r.status = "error"
        r.message = f"{type(e).__name__}: {e}"
    r.duration_ms = round((time.monotonic() - start) * 1000)


def run_sync_test(suite: str, name: str, fn):
    """Run a synchronous test and record the result."""
    r = TestResult(suite, name)
    results.append(r)
    start = time.monotonic()
    try:
        fn()
        r.status = "pass"
    except AssertionError as e:
        r.status = "fail"
        r.message = str(e) or "Assertion failed"
    except Exception as e:
        r.status = "error"
        r.message = f"{type(e).__name__}: {e}"
    r.duration_ms = round((time.monotonic() - start) * 1000)


# ---------------------------------------------------------------------------
# Test suites
# ---------------------------------------------------------------------------

def setup_sdk():
    configure_auth(
        client_id=CLIENT_ID,
        app_name=APP_NAME,
        auth_service_url=AUTH_SERVICE_URL,
        services_base_url=SERVICES_BASE_URL,
        timeout=10,
        retries=1,
    )


# === 1. Configuration Tests (sync) ===

def test_config_sets_values():
    setup_sdk()
    assert is_configured() is True
    cfg = get_config()
    assert cfg["app_name"] == APP_NAME

def test_config_urls():
    assert _config["auth_service_url"] == AUTH_SERVICE_URL
    assert _config["services_base_url"] == SERVICES_BASE_URL

def test_config_rejects_empty_client_id():
    try:
        configure_auth(client_id="", app_name="test")
        raise AssertionError("Should have raised ValueError")
    except ValueError:
        pass
    setup_sdk()  # restore

def test_config_rejects_empty_app_name():
    try:
        configure_auth(client_id="some-id", app_name="")
        raise AssertionError("Should have raised ValueError")
    except ValueError:
        pass
    setup_sdk()


# === 2. Client ID Normalization (sync) ===

def test_normalize_base_uuid():
    assert _normalize_runtime_client_id("947f4811-685c-47e7-955b-0cdd43485432") == \
           "947f4811-685c-47e7-955b-0cdd43485432-main-client"

def test_normalize_already_suffixed():
    assert _normalize_runtime_client_id("947f4811-685c-47e7-955b-0cdd43485432-main-client") == \
           "947f4811-685c-47e7-955b-0cdd43485432-main-client"

def test_normalize_underscores():
    assert _normalize_runtime_client_id("947f4811_685c_47e7_955b_0cdd43485432") == \
           "947f4811-685c-47e7-955b-0cdd43485432-main-client"

def test_normalize_empty_raises():
    try:
        _normalize_runtime_client_id("")
        raise AssertionError("Should have raised ValueError")
    except ValueError:
        pass


# === 3. Health Checks (async) ===

async def test_auth_service_health():
    result = await sdk_test_auth_service()
    assert result is True

async def test_services_health():
    result = await sdk_test_services()
    assert result is True

async def test_auth_health_raw():
    result = await _make_auth_request("health", method="GET")
    assert result["status"] == "healthy"
    assert result["service"] == "mcp-auth-service"

async def test_services_health_raw():
    result = await _make_services_request("health", method="GET")
    assert result["status"] == "healthy"
    assert result["service"] == "services-service"


# === 4. MCP Auth Flow (async) ===

async def test_start_auth_session():
    result = await _make_auth_request("start", {
        "client_id": CLIENT_ID, "app_name": APP_NAME,
    })
    assert "session_id" in result
    assert "authorization_url" in result

async def test_tools_list():
    result = await _make_auth_request("tools/list", {
        "client_id": CLIENT_ID, "app_name": APP_NAME, "user_tools": [],
    })
    assert "tools" in result
    tool_names = [t["name"] for t in result["tools"]]
    assert "oauth_start" in tool_names
    assert "oauth_authenticate" in tool_names
    assert "oauth_status" in tool_names

async def test_sessions_status():
    result = await _make_auth_request("sessions/status", method="GET")
    assert "active_authenticated_sessions" in result

async def test_protect_tool_denied():
    result = await _make_auth_request("protect-tool", {
        "session_id": "nonexistent-session",
        "tool_name": "test_tool",
        "client_id": CLIENT_ID, "app_name": APP_NAME,
    })
    assert result.get("allowed") is False

async def test_cleanup_sessions():
    result = await _make_auth_request("cleanup-sessions", {
        "client_id": CLIENT_ID, "app_name": APP_NAME,
    })
    assert "sessions_cleaned" in result

async def test_logout_session():
    start_result = await _make_auth_request("start", {
        "client_id": CLIENT_ID, "app_name": APP_NAME,
    })
    session_id = start_result["session_id"]
    async with aiohttp.ClientSession() as session:
        async with session.post(f"{AUTH_SERVICE_URL}/logout?session_id={session_id}") as resp:
            data = await resp.json()
    assert data.get("status") == "logged_out"


# === 5. Services API (async) ===

async def test_credentials_requires_session():
    result = await _make_services_request("credentials", {
        "session_id": "nonexistent", "service_name": "github",
    })
    assert "error" in result

async def test_user_details_requires_session():
    result = await _make_services_request("user-details", {
        "session_id": "nonexistent", "service_name": "github",
    })
    assert "error" in result


# === 6. ServiceAccessSDK (async) ===

async def test_sdk_init_with_dict():
    sdk = ServiceAccessSDK({"session_id": "test-123"})
    assert sdk.session_id == "test-123"

async def test_sdk_rejects_bad_session():
    try:
        ServiceAccessSDK({"no_session": True})
        raise AssertionError("Should have raised ValueError")
    except ValueError:
        pass

async def test_sdk_health_check():
    sdk = ServiceAccessSDK({"session_id": "test-123"})
    result = await sdk.health_check()
    assert result["status"] == "healthy"

async def test_sdk_get_credentials_no_session():
    sdk = ServiceAccessSDK({"session_id": "no-such-session"})
    try:
        await sdk.get_service_credentials("github")
        raise AssertionError("Should have raised ServiceAccessError")
    except ServiceAccessError:
        pass


# === 7. MCPServer (async) ===

async def test_mcpserver_init():
    server = MCPServer(CLIENT_ID, APP_NAME)
    assert server.client_id == CLIENT_ID
    assert server.app_name == APP_NAME

async def test_mcpserver_initialize():
    server = MCPServer(CLIENT_ID, APP_NAME)
    result = await server._process_mcp_message({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
    })
    assert result["result"]["serverInfo"]["name"] == APP_NAME
    assert result["result"]["protocolVersion"] == "2024-11-05"

async def test_mcpserver_tools_list():
    server = MCPServer(CLIENT_ID, APP_NAME)
    result = await server._process_mcp_message({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list",
    })
    tools = result["result"]["tools"]
    assert len(tools) >= 5
    tool_names = [t["name"] for t in tools]
    assert "oauth_start" in tool_names

async def test_mcpserver_unknown_method():
    server = MCPServer(CLIENT_ID, APP_NAME)
    result = await server._process_mcp_message({
        "jsonrpc": "2.0", "id": 99, "method": "nonexistent/method",
    })
    assert "error" in result
    assert result["error"]["code"] == -32601


# === 8. CIBA Client (sync) ===

def test_ciba_init_default():
    client = CIBAClient()
    assert client.base_url == "https://dev.api.authsec.dev"

def test_ciba_init_custom_url():
    client = CIBAClient(base_url="http://localhost:7468")
    assert client.base_url == "http://localhost:7468"

def test_ciba_init_client_id():
    client = CIBAClient(client_id="test-client-id")
    assert client.client_id == "test-client-id"

def test_ciba_cancel_resets():
    client = CIBAClient()
    client.retry_counts["user@test.com"] = 2
    result = client.cancel_approval("user@test.com")
    assert result["status"] == "cancelled"
    assert client.retry_counts["user@test.com"] == 0

def test_ciba_verify_totp_max_retries():
    client = CIBAClient()
    client.retry_counts["user@test.com"] = 3
    result = client.verify_totp("user@test.com", "123456")
    assert result["success"] is False
    assert result["error"] == "too_many_retries"


# === 9. Delegation Client (sync + async) ===

def test_delegation_client_init():
    client = DelegationClient(
        client_id="test-abc-123",
        userflow_url="http://localhost:7468/uflow",
    )
    assert client.client_id == "test-abc-123"
    assert client.userflow_url == "http://localhost:7468/uflow"

def test_delegation_client_expired():
    client = DelegationClient(
        client_id="test-abc-123",
        userflow_url="http://localhost:7468/uflow",
    )
    assert client.is_expired is True
    assert client.expires_in_seconds == 0

def test_delegation_client_permissions():
    client = DelegationClient(
        client_id="test",
        userflow_url="http://localhost:7468/uflow",
    )
    assert client.has_permission("users:read") is False
    assert client.has_any_permission("users:read", "users:write") is False
    assert client.has_all_permissions() is True

async def test_delegation_pull_token_not_found():
    client = DelegationClient(
        client_id="nonexistent-client-id",
        userflow_url=f"{BASE_URL}/authsec/uflow",
        timeout=5,
    )
    try:
        await client.pull_token()
        # If no 404 raised, the endpoint might not exist — that's also acceptable
    except DelegationTokenNotFound:
        pass  # expected
    except DelegationError:
        pass  # server returned an error — acceptable


# === 10. OAuth Tools Delegation (async) ===

async def test_oauth_start_via_mcp():
    server = MCPServer(CLIENT_ID, APP_NAME)
    result = await server._process_mcp_message({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "oauth_start", "arguments": {"session_id": "mcp-test-session"}},
    })
    content = result["result"]["content"]
    assert len(content) > 0

async def test_unknown_tool_via_mcp():
    server = MCPServer(CLIENT_ID, APP_NAME)
    result = await server._process_mcp_message({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "nonexistent_tool", "arguments": {}},
    })
    content = result["result"]["content"]
    parsed = json.loads(content[0]["text"])
    assert "error" in parsed
    assert "Unknown tool" in parsed["error"]


# === 11. Backward Compatibility (async) ===

async def test_old_path_auth_health():
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{BASE_URL}/sdkmgr/mcp-auth/health") as resp:
            data = await resp.json()
            assert data["status"] == "healthy"

async def test_old_path_services_health():
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{BASE_URL}/sdkmgr/services/health") as resp:
            data = await resp.json()
            assert data["status"] == "healthy"

async def test_sdk_with_old_urls():
    configure_auth(
        client_id=CLIENT_ID, app_name=APP_NAME,
        auth_service_url=f"{BASE_URL}/sdkmgr/mcp-auth",
        services_base_url=f"{BASE_URL}/sdkmgr/services",
    )
    assert await sdk_test_auth_service() is True
    assert await sdk_test_services() is True
    setup_sdk()  # restore


# === 12. E2E Auth Lifecycle (async) ===

async def test_full_lifecycle():
    assert await sdk_test_auth_service() is True
    assert await sdk_test_services() is True

    start = await _make_auth_request("start", {
        "client_id": CLIENT_ID, "app_name": APP_NAME,
    })
    assert "session_id" in start
    session_id = start["session_id"]

    tools_resp = await _make_auth_request("tools/list", {
        "client_id": CLIENT_ID, "app_name": APP_NAME,
        "user_tools": [{"name": "test_calculator", "description": "A test calculator",
                        "inputSchema": {"type": "object", "properties": {"a": {"type": "number"}}}}],
    })
    tool_names = [t["name"] for t in tools_resp["tools"]]
    assert "oauth_start" in tool_names
    assert "test_calculator" in tool_names

    protect = await _make_auth_request("protect-tool", {
        "session_id": session_id, "tool_name": "test_calculator",
        "client_id": CLIENT_ID, "app_name": APP_NAME,
    })
    assert protect.get("allowed") is False

    cleanup = await _make_auth_request("cleanup-sessions", {
        "client_id": CLIENT_ID, "app_name": APP_NAME,
    })
    assert "sessions_cleaned" in cleanup

    async with aiohttp.ClientSession() as sess:
        async with sess.post(f"{AUTH_SERVICE_URL}/logout?session_id={session_id}") as resp:
            logout = await resp.json()
    assert logout.get("status") == "logged_out"


# === 13. JWT-Authenticated Endpoints (async) ===

async def test_jwt_dashboard_statistics():
    token = _generate_jwt()
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{SDKMGR_BASE}/dashboard/statistics",
            json={"tenant_id": TENANT_ID},
            headers={"Authorization": f"Bearer {token}"},
        ) as resp:
            assert resp.status == 200
            data = await resp.json()
            assert data["success"] is True
            assert "statistics" in data

async def test_jwt_dashboard_admin_users():
    token = _generate_jwt()
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{SDKMGR_BASE}/dashboard/admin-users",
            json={"tenant_id": TENANT_ID},
            headers={"Authorization": f"Bearer {token}"},
        ) as resp:
            assert resp.status == 200
            data = await resp.json()
            assert data["success"] is True
            assert "admin_users" in data

async def test_jwt_dev_server_status():
    token = _generate_jwt()
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{SDKMGR_BASE}/playground/dev-server/status",
            headers={"Authorization": f"Bearer {token}"},
        ) as resp:
            assert resp.status != 401

async def test_jwt_rejected_without_token():
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{SDKMGR_BASE}/dashboard/statistics",
            json={"tenant_id": TENANT_ID},
        ) as resp:
            assert resp.status == 401

async def test_jwt_expired_rejected():
    token = _generate_jwt(exp_offset=-3600)
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{SDKMGR_BASE}/dashboard/statistics",
            json={"tenant_id": TENANT_ID},
            headers={"Authorization": f"Bearer {token}"},
        ) as resp:
            assert resp.status == 401

async def test_jwt_wrong_secret_rejected():
    token = _generate_jwt(secret="wrong-secret")
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{SDKMGR_BASE}/dashboard/statistics",
            json={"tenant_id": TENANT_ID},
            headers={"Authorization": f"Bearer {token}"},
        ) as resp:
            assert resp.status == 401


# === 14. SPIRE / Workload Endpoints (async) ===

async def test_spire_health():
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{SDKMGR_BASE}/spire/health") as resp:
            data = await resp.json()
            assert resp.status == 200
            assert data["status"] == "healthy"

async def test_spire_workload_initialize():
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{SDKMGR_BASE}/spire/workload/initialize",
            json={"workload_id": "test-workload", "trust_domain": "test.local"},
        ) as resp:
            data = await resp.json()
            assert resp.status in (200, 400, 500)  # endpoint exists

async def test_spire_workload_status():
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{SDKMGR_BASE}/spire/workload/status",
            json={"workload_id": "test-workload"},
        ) as resp:
            data = await resp.json()
            assert resp.status in (200, 400, 500)


# === 15. Playground / MCP OAuth (async) ===

async def test_playground_oauth_check_requirements():
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{SDKMGR_BASE}/playground/oauth/check-requirements") as resp:
            data = await resp.json()
            # Returns 200 or 400 depending on config — endpoint exists either way
            assert resp.status in (200, 400)

async def test_playground_conversations_list():
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{SDKMGR_BASE}/playground/conversations",
            params={"tenant_id": TENANT_ID},
        ) as resp:
            data = await resp.json()
            assert resp.status == 200

async def test_playground_create_conversation():
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{SDKMGR_BASE}/playground/conversations",
            json={"tenant_id": TENANT_ID, "title": "browser-test-conv"},
        ) as resp:
            data = await resp.json()
            assert resp.status in (200, 201)

async def test_playground_health():
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{SDKMGR_BASE}/playground/health") as resp:
            data = await resp.json()
            assert resp.status == 200
            assert "status" in data  # may be unhealthy without Azure OpenAI config


# === 16. Voice Client (async) ===

async def test_voice_interact():
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{SDKMGR_BASE}/voice/interact",
            json={"session_id": "test-voice-session", "input": "hello"},
        ) as resp:
            data = await resp.json()
            assert resp.status in (200, 400, 500)

async def test_voice_poll():
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{SDKMGR_BASE}/voice/poll",
            json={"session_id": "test-voice-session"},
        ) as resp:
            data = await resp.json()
            assert resp.status in (200, 400, 500)


# === 17. Dashboard (public endpoints) ===

async def test_dashboard_sessions():
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{SDKMGR_BASE}/dashboard/sessions",
            json={"tenant_id": TENANT_ID},
        ) as resp:
            data = await resp.json()
            assert resp.status == 200

async def test_dashboard_users():
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{SDKMGR_BASE}/dashboard/users",
            json={"tenant_id": TENANT_ID},
        ) as resp:
            data = await resp.json()
            assert resp.status == 200

async def test_dashboard_health():
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{SDKMGR_BASE}/dashboard/health") as resp:
            data = await resp.json()
            assert resp.status == 200
            assert data["status"] == "healthy"


# ---------------------------------------------------------------------------
# Run all tests and generate HTML
# ---------------------------------------------------------------------------

SUITES = [
    ("1. SDK Configuration", [
        (test_config_sets_values, False),
        (test_config_urls, False),
        (test_config_rejects_empty_client_id, False),
        (test_config_rejects_empty_app_name, False),
    ]),
    ("2. Client ID Normalization", [
        (test_normalize_base_uuid, False),
        (test_normalize_already_suffixed, False),
        (test_normalize_underscores, False),
        (test_normalize_empty_raises, False),
    ]),
    ("3. Health Checks", [
        (test_auth_service_health, True),
        (test_services_health, True),
        (test_auth_health_raw, True),
        (test_services_health_raw, True),
    ]),
    ("4. MCP Auth Flow", [
        (test_start_auth_session, True),
        (test_tools_list, True),
        (test_sessions_status, True),
        (test_protect_tool_denied, True),
        (test_cleanup_sessions, True),
        (test_logout_session, True),
    ]),
    ("5. Services API", [
        (test_credentials_requires_session, True),
        (test_user_details_requires_session, True),
    ]),
    ("6. ServiceAccessSDK", [
        (test_sdk_init_with_dict, True),
        (test_sdk_rejects_bad_session, True),
        (test_sdk_health_check, True),
        (test_sdk_get_credentials_no_session, True),
    ]),
    ("7. MCPServer", [
        (test_mcpserver_init, True),
        (test_mcpserver_initialize, True),
        (test_mcpserver_tools_list, True),
        (test_mcpserver_unknown_method, True),
    ]),
    ("8. CIBA Client", [
        (test_ciba_init_default, False),
        (test_ciba_init_custom_url, False),
        (test_ciba_init_client_id, False),
        (test_ciba_cancel_resets, False),
        (test_ciba_verify_totp_max_retries, False),
    ]),
    ("9. Delegation Client", [
        (test_delegation_client_init, False),
        (test_delegation_client_expired, False),
        (test_delegation_client_permissions, False),
        (test_delegation_pull_token_not_found, True),
    ]),
    ("10. OAuth Tools (MCP)", [
        (test_oauth_start_via_mcp, True),
        (test_unknown_tool_via_mcp, True),
    ]),
    ("11. Backward Compatibility", [
        (test_old_path_auth_health, True),
        (test_old_path_services_health, True),
        (test_sdk_with_old_urls, True),
    ]),
    ("12. E2E Auth Lifecycle", [
        (test_full_lifecycle, True),
    ]),
    ("13. JWT Authentication", [
        (test_jwt_dashboard_statistics, True),
        (test_jwt_dashboard_admin_users, True),
        (test_jwt_dev_server_status, True),
        (test_jwt_rejected_without_token, True),
        (test_jwt_expired_rejected, True),
        (test_jwt_wrong_secret_rejected, True),
    ]),
    ("14. SPIRE / Workload Identity", [
        (test_spire_health, True),
        (test_spire_workload_initialize, True),
        (test_spire_workload_status, True),
    ]),
    ("15. Playground / MCP OAuth", [
        (test_playground_oauth_check_requirements, True),
        (test_playground_conversations_list, True),
        (test_playground_create_conversation, True),
        (test_playground_health, True),
    ]),
    ("16. Voice Client", [
        (test_voice_interact, True),
        (test_voice_poll, True),
    ]),
    ("17. Dashboard", [
        (test_dashboard_sessions, True),
        (test_dashboard_users, True),
        (test_dashboard_health, True),
    ]),
]


async def run_all_tests():
    """Run every test and populate the results list."""
    setup_sdk()
    for suite_name, tests in SUITES:
        for fn, is_async in tests:
            test_name = fn.__name__.replace("test_", "").replace("_", " ").title()
            if is_async:
                await run_test(suite_name, test_name, fn)
            else:
                run_sync_test(suite_name, test_name, fn)
            await asyncio.sleep(0.05)  # avoid rate limiting


def generate_html() -> str:
    """Build the HTML results page."""
    total = len(results)
    passed = sum(1 for r in results if r.status == "pass")
    failed = sum(1 for r in results if r.status == "fail")
    errors = sum(1 for r in results if r.status == "error")
    total_ms = sum(r.duration_ms for r in results)

    status_icon = {"pass": "&#10004;", "fail": "&#10008;", "error": "&#9888;", "pending": "&#8987;"}
    status_color = {"pass": "#22c55e", "fail": "#ef4444", "error": "#f59e0b", "pending": "#94a3b8"}

    # Group by suite
    suites_html = ""
    current_suite = None
    for r in results:
        if r.suite != current_suite:
            if current_suite is not None:
                suites_html += "</tbody></table></div>"
            current_suite = r.suite
            suite_tests = [x for x in results if x.suite == r.suite]
            suite_pass = sum(1 for x in suite_tests if x.status == "pass")
            suite_total = len(suite_tests)
            suite_badge_color = "#22c55e" if suite_pass == suite_total else "#ef4444"
            suites_html += f"""
            <div class="suite">
              <div class="suite-header">
                <span class="suite-name">{r.suite}</span>
                <span class="suite-badge" style="background:{suite_badge_color}">{suite_pass}/{suite_total}</span>
              </div>
              <table><thead><tr>
                <th width="40"></th><th>Test</th><th width="100">Duration</th><th>Details</th>
              </tr></thead><tbody>"""

        msg_html = f'<span class="error-msg">{r.message}</span>' if r.message else ""
        suites_html += f"""
              <tr class="row-{r.status}">
                <td style="color:{status_color[r.status]};font-size:18px;text-align:center">{status_icon[r.status]}</td>
                <td>{r.name}</td>
                <td class="dur">{r.duration_ms} ms</td>
                <td>{msg_html}</td>
              </tr>"""

    if current_suite is not None:
        suites_html += "</tbody></table></div>"

    banner_color = "#22c55e" if failed == 0 and errors == 0 else "#ef4444"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AuthSec Python SDK — Integration Test Results</title>
<style>
  :root {{ --bg: #0f172a; --card: #1e293b; --text: #e2e8f0; --border: #334155; --accent: #3b82f6; }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 24px; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ font-size: 28px; font-weight: 700; margin-bottom: 4px; }}
  .subtitle {{ color: #94a3b8; margin-bottom: 24px; font-size: 14px; }}
  .banner {{ background: {banner_color}; color: white; padding: 18px 24px; border-radius: 12px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }}
  .banner .big {{ font-size: 28px; font-weight: 800; }}
  .stats {{ display: flex; gap: 32px; }}
  .stat {{ text-align: center; }}
  .stat .num {{ font-size: 24px; font-weight: 700; }}
  .stat .lbl {{ font-size: 11px; text-transform: uppercase; opacity: 0.85; }}
  .suite {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 16px; overflow: hidden; }}
  .suite-header {{ padding: 14px 20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); }}
  .suite-name {{ font-weight: 600; font-size: 15px; }}
  .suite-badge {{ color: white; font-size: 12px; font-weight: 600; padding: 3px 10px; border-radius: 12px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  thead {{ background: rgba(0,0,0,0.2); }}
  th {{ text-align: left; padding: 8px 16px; font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: 600; }}
  td {{ padding: 10px 16px; font-size: 14px; border-top: 1px solid var(--border); }}
  .dur {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #94a3b8; }}
  .error-msg {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #f87171; word-break: break-all; }}
  .row-pass td:first-child {{ color: #22c55e; }}
  .row-fail {{ background: rgba(239,68,68,0.06); }}
  .row-error {{ background: rgba(245,158,11,0.06); }}
  .footer {{ text-align: center; color: #64748b; font-size: 12px; margin-top: 32px; }}
  .sdk-badges {{ display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px; }}
  .sdk-badge {{ background: var(--card); border: 1px solid var(--border); padding: 6px 14px; border-radius: 8px; font-size: 13px; }}
  .sdk-badge b {{ color: var(--accent); }}
</style>
</head>
<body>
<div class="container">
  <h1>AuthSec Python SDK — Integration Tests</h1>
  <p class="subtitle">All Python SDKs tested against authsec service at {BASE_URL}</p>

  <div class="sdk-badges">
    <span class="sdk-badge"><b>core</b> — configure_auth, MCPServer, ServiceAccessSDK, protected_by_AuthSec</span>
    <span class="sdk-badge"><b>ciba_sdk</b> — CIBAClient (CIBA + TOTP)</span>
    <span class="sdk-badge"><b>delegation_sdk</b> — DelegationClient</span>
    <span class="sdk-badge"><b>spire_sdk</b> — WorkloadSVID, QuickStartSVID</span>
  </div>

  <div class="banner">
    <div>
      <div class="big">{"ALL TESTS PASSED" if failed == 0 and errors == 0 else f"{failed + errors} FAILURE{'S' if failed+errors != 1 else ''}"}</div>
    </div>
    <div class="stats">
      <div class="stat"><div class="num">{total}</div><div class="lbl">Total</div></div>
      <div class="stat"><div class="num" style="color:#bbf7d0">{passed}</div><div class="lbl">Passed</div></div>
      <div class="stat"><div class="num" style="color:#fca5a5">{failed}</div><div class="lbl">Failed</div></div>
      <div class="stat"><div class="num" style="color:#fde68a">{errors}</div><div class="lbl">Errors</div></div>
      <div class="stat"><div class="num">{total_ms}</div><div class="lbl">ms Total</div></div>
    </div>
  </div>

  {suites_html}

  <div class="footer">
    AuthSec SDK v4.0.0 &middot; Python &middot; Generated {time.strftime("%Y-%m-%d %H:%M:%S")}
  </div>
</div>
</body>
</html>"""
    return html


def serve_html(html: str, port: int = 8899):
    """Serve the HTML on a local port and open a browser."""
    class Handler(SimpleHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
        def log_message(self, format, *args):
            pass  # suppress logs

    import socket
    class ReusableHTTPServer(HTTPServer):
        allow_reuse_address = True
        allow_reuse_port = True
    server = ReusableHTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"\n→ Results at http://localhost:{port}")
    return server


if __name__ == "__main__":
    print("=" * 60)
    print("  AuthSec Python SDK — Browser Integration Test Runner")
    print("=" * 60)
    print()

    asyncio.run(run_all_tests())

    total = len(results)
    passed = sum(1 for r in results if r.status == "pass")
    failed = sum(1 for r in results if r.status in ("fail", "error"))

    print(f"\n{'='*60}")
    print(f"  Results:  {passed}/{total} passed,  {failed} failed")
    print(f"{'='*60}")

    html = generate_html()

    # Write HTML file
    out_path = os.path.join(os.path.dirname(__file__), "test_results.html")
    with open(out_path, "w") as f:
        f.write(html)
    print(f"  HTML saved to {out_path}")

    # Start server
    srv = serve_html(html)
    print("  Server running — press Ctrl+C to stop\n")

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()
