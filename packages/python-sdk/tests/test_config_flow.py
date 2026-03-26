import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import authsec_sdk.core as core_module  # noqa: E402
from authsec_sdk import CIBAClient, configure_auth, protected_by_AuthSec  # noqa: E402
from authsec_sdk.cli import DEFAULTS, cmd_config_show, cmd_init  # noqa: E402
from authsec_sdk.core import (  # noqa: E402
    _clear_authenticated_session_id,
    _clear_current_session_id,
    _config,
    _load_config_file,
    _set_authenticated_session_id,
    _set_current_session_id,
    _update_current_session_from_oauth_result,
    mcp_tool,
    run_mcp_server_with_oauth,
    MCPServer,
)


def test_cli_defaults_point_to_prod():
    assert DEFAULTS["auth_service_url"] == "https://prod.api.authsec.ai/sdkmgr/mcp-auth"
    assert DEFAULTS["services_base_url"] == "https://prod.api.authsec.ai/sdkmgr/services"
    assert DEFAULTS["ciba_base_url"] == "https://prod.api.authsec.ai"


def test_ciba_client_default_base_url_points_to_prod(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    client = CIBAClient()
    assert client.base_url == "https://prod.api.authsec.ai"


def test_configure_auth_precedence_explicit_over_env_and_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path(".authsec.json").write_text(
        json.dumps(
            {
                "client_id": "file-client",
                "auth_service_url": "https://file.example/sdkmgr/mcp-auth",
                "services_base_url": "https://file.example/sdkmgr/services",
            }
        )
    )
    monkeypatch.setenv("AUTHSEC_AUTH_SERVICE_URL", "https://env.example/sdkmgr/mcp-auth")
    monkeypatch.setenv("AUTHSEC_SERVICES_URL", "https://env.example/sdkmgr/services")

    configure_auth(
        client_id="explicit-client",
        app_name="Team Knowledge Base (Protected)",
        auth_service_url="https://explicit.example/sdkmgr/mcp-auth",
        services_base_url="https://explicit.example/sdkmgr/services",
    )

    assert _config["auth_service_url"] == "https://explicit.example/sdkmgr/mcp-auth"
    assert _config["services_base_url"] == "https://explicit.example/sdkmgr/services"


def test_configure_auth_precedence_env_over_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path(".authsec.json").write_text(
        json.dumps(
            {
                "client_id": "file-client",
                "auth_service_url": "https://file.example/sdkmgr/mcp-auth",
                "services_base_url": "https://file.example/sdkmgr/services",
            }
        )
    )
    monkeypatch.setenv("AUTHSEC_AUTH_SERVICE_URL", "https://env.example/sdkmgr/mcp-auth")
    monkeypatch.setenv("AUTHSEC_SERVICES_URL", "https://env.example/sdkmgr/services")

    configure_auth(client_id="explicit-client", app_name="Env Beats File")

    assert _config["auth_service_url"] == "https://env.example/sdkmgr/mcp-auth"
    assert _config["services_base_url"] == "https://env.example/sdkmgr/services"


def test_configure_auth_precedence_file_over_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path(".authsec.json").write_text(
        json.dumps(
            {
                "client_id": "file-client",
                "auth_service_url": "https://file.example/sdkmgr/mcp-auth",
                "services_base_url": "https://file.example/sdkmgr/services",
            }
        )
    )

    configure_auth(client_id="explicit-client", app_name="File Beats Defaults")

    assert _config["auth_service_url"] == "https://file.example/sdkmgr/mcp-auth"
    assert _config["services_base_url"] == "https://file.example/sdkmgr/services"


def test_cli_init_writes_prod_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    answers = iter(["default", "921c2209-0000-0000-0000-000000000000"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    cmd_init()

    config = _load_config_file()
    assert config["client_id"] == "921c2209-0000-0000-0000-000000000000"
    assert config["auth_service_url"] == "https://prod.api.authsec.ai/sdkmgr/mcp-auth"
    assert config["services_base_url"] == "https://prod.api.authsec.ai/sdkmgr/services"
    assert config["ciba_base_url"] == "https://prod.api.authsec.ai"


def test_cli_config_show_renders_saved_config(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    Path(".authsec.json").write_text(
        json.dumps(
            {
                "client_id": "921c2209-0000-0000-0000-000000000000",
                "auth_service_url": "https://prod.api.authsec.ai/sdkmgr/mcp-auth",
                "services_base_url": "https://prod.api.authsec.ai/sdkmgr/services",
                "ciba_base_url": "https://prod.api.authsec.ai",
            }
        )
    )

    cmd_config_show()
    out = capsys.readouterr().out
    assert "https://prod.api.authsec.ai/sdkmgr/mcp-auth" in out
    assert "https://prod.api.authsec.ai/sdkmgr/services" in out


def test_placeholder_client_id_falls_back_to_saved_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path(".authsec.json").write_text(
        json.dumps(
            {
                "client_id": "921c2209-0000-0000-0000-000000000000",
                "auth_service_url": "https://prod.api.authsec.ai/sdkmgr/mcp-auth",
                "services_base_url": "https://prod.api.authsec.ai/sdkmgr/services",
            }
        )
    )

    captured = {}

    class DummyServer:
        def __init__(self, config):
            self.config = config

        async def serve(self):
            return None

    class DummyModule:
        pass

    def fake_asyncio_run(coro):
        coro.close()

    monkeypatch.setattr("authsec_sdk.core.MCPServer.set_user_module", lambda self, mod: None)
    monkeypatch.setattr("authsec_sdk.core.uvicorn.Config", lambda app, host, port, log_level: {"host": host, "port": port})
    monkeypatch.setattr("authsec_sdk.core.uvicorn.Server", lambda config: DummyServer(config))
    monkeypatch.setattr("authsec_sdk.core.asyncio.run", fake_asyncio_run)

    run_mcp_server_with_oauth(
        DummyModule(),
        client_id="your-client-id-here",
        app_name="Team Knowledge Base (Protected)",
        host="0.0.0.0",
        port=3005,
    )

    assert _config["client_id"].startswith("921c2209")


@pytest.fixture(autouse=True)
def reset_sdk_session_state():
    _clear_current_session_id()
    _clear_authenticated_session_id()
    yield
    _clear_current_session_id()
    _clear_authenticated_session_id()


class ProtectedVisibilityModule:
    @protected_by_AuthSec(
        "create_note",
        scopes=["write"],
        description="Create a protected note.",
        inputSchema={
            "type": "object",
            "properties": {
                "title": {"type": "string"},
            },
            "required": ["title"],
        },
    )
    async def create_note(arguments: dict) -> list:
        return [{"type": "text", "text": json.dumps({"ok": True})}]

    @mcp_tool(
        "health_check",
        description="Public health check.",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    )
    async def health_check(arguments: dict) -> list:
        return [{"type": "text", "text": json.dumps({"status": "ok"})}]


@pytest.mark.asyncio
async def test_tools_list_hides_protected_tools_until_authenticated(monkeypatch):
    server = MCPServer("client-123", "Team Knowledge Base (Protected)")
    server.set_user_module(ProtectedVisibilityModule)

    async def fake_make_auth_request(endpoint, payload):
        assert endpoint == "tools/list"
        return {
            "tools": [
                {"name": "oauth_start", "description": "Start auth", "inputSchema": {"type": "object", "properties": {}, "required": []}},
                {"name": "create_note", "description": "Protected note creation", "inputSchema": {"type": "object", "properties": {}, "required": []}},
            ]
        }

    monkeypatch.setattr("authsec_sdk.core._make_auth_request", fake_make_auth_request)

    result = await server._process_mcp_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    tool_names = [tool["name"] for tool in result["result"]["tools"]]

    assert "oauth_start" in tool_names
    assert "health_check" in tool_names
    assert "create_note" not in tool_names


@pytest.mark.asyncio
async def test_tools_list_stays_hidden_after_oauth_start(monkeypatch):
    server = MCPServer("client-123", "Team Knowledge Base (Protected)")
    server.set_user_module(ProtectedVisibilityModule)
    _set_current_session_id("pending-session")

    async def fake_make_auth_request(endpoint, payload):
        assert payload["session_id"] is None
        return {
            "tools": [
                {"name": "oauth_start", "description": "Start auth", "inputSchema": {"type": "object", "properties": {}, "required": []}},
                {"name": "create_note", "description": "Protected note creation", "inputSchema": {"type": "object", "properties": {}, "required": []}},
            ]
        }

    monkeypatch.setattr("authsec_sdk.core._make_auth_request", fake_make_auth_request)

    result = await server._process_mcp_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tool_names = [tool["name"] for tool in result["result"]["tools"]]

    assert "create_note" not in tool_names


@pytest.mark.asyncio
async def test_tools_list_shows_protected_tools_after_authenticated_session(monkeypatch):
    server = MCPServer("client-123", "Team Knowledge Base (Protected)")
    server.set_user_module(ProtectedVisibilityModule)
    _set_current_session_id("authenticated-session")
    _set_authenticated_session_id("authenticated-session")

    async def fake_make_auth_request(endpoint, payload):
        assert payload["session_id"] == "authenticated-session"
        return {
            "tools": [
                {"name": "oauth_start", "description": "Start auth", "inputSchema": {"type": "object", "properties": {}, "required": []}},
                {"name": "create_note", "description": "Protected note creation", "inputSchema": {"type": "object", "properties": {}, "required": []}},
            ]
        }

    monkeypatch.setattr("authsec_sdk.core._make_auth_request", fake_make_auth_request)

    result = await server._process_mcp_message({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    tool_names = [tool["name"] for tool in result["result"]["tools"]]

    assert "create_note" in tool_names
    assert "health_check" in tool_names


def test_oauth_state_transitions_require_authenticated_state_for_visibility():
    _update_current_session_from_oauth_result(
        "oauth_start",
        [{"type": "text", "text": json.dumps({"session_id": "pending-session"})}],
    )

    assert core_module._current_session_id == "pending-session"
    assert core_module._current_authenticated_session_id is None

    _update_current_session_from_oauth_result(
        "oauth_authenticate",
        [{"type": "text", "text": json.dumps({"session_id": "pending-session", "success": True})}],
    )

    assert core_module._current_authenticated_session_id == "pending-session"

    _update_current_session_from_oauth_result(
        "oauth_logout",
        [{"type": "text", "text": json.dumps({"session_id": "pending-session", "status": "logged_out"})}],
    )

    assert core_module._current_session_id is None
    assert core_module._current_authenticated_session_id is None

    _set_current_session_id("expired-session")
    _set_authenticated_session_id("expired-session")
    _update_current_session_from_oauth_result(
        "oauth_status",
        [{"type": "text", "text": json.dumps({"session_id": "expired-session", "status": "expired"})}],
    )

    assert core_module._current_session_id is None
    assert core_module._current_authenticated_session_id is None
