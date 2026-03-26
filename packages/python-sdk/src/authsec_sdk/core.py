"""
AuthSec Python SDK core module.

Provides MCP server integration, OAuth workflows, and protected tool execution
backed by the hosted AuthSec SDK Manager.
"""

import json
import os
import ssl
import urllib.parse
import aiohttp
import asyncio
import inspect
import sys
import uvicorn
import signal
import webbrowser
from typing import Dict, Optional, List, Callable, Any
from functools import wraps
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dataclasses import dataclass
import logging
import certifi

logger = logging.getLogger(__name__)

def _create_ssl_context() -> ssl.SSLContext:
    """Create an SSL context using certifi's CA bundle."""
    return ssl.create_default_context(cafile=certifi.where())


def _should_verify_ssl(url: str) -> bool:
    parsed = urllib.parse.urlparse(url or "")
    host = (parsed.hostname or "").lower()
    return host not in {"localhost", "127.0.0.1", "::1"}


def _ssl_for_url(url: str):
    return _create_ssl_context() if _should_verify_ssl(url) else False


def _default_config() -> Dict[str, Any]:
    return {
        "client_id": None,
        "app_name": None,
        "auth_service_url": _DEFAULT_AUTH_SERVICE_URL,
        "services_base_url": _DEFAULT_SERVICES_BASE_URL,
        "timeout": 10,
        "retries": 3,
    }


def _normalize_url(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = str(value).strip()
    if not normalized:
        return None
    return normalized.rstrip("/")


def _resolve_config_value(
    explicit_value: Optional[str],
    env_key: str,
    file_cfg: Dict[str, Any],
    file_key: str,
    default_value: str,
) -> str:
    env_value = _normalize_url(os.getenv(env_key))
    file_value = _normalize_url(file_cfg.get(file_key))
    explicit_normalized = _normalize_url(explicit_value)
    return explicit_normalized or env_value or file_value or default_value


def _read_response_payload(response) -> Dict[str, Any]:
    content_type = (response.headers.get("Content-Type") or "").lower()
    try:
        data = awaitable_json = response.json(content_type=None)
    except TypeError:
        awaitable_json = response.json()
    try:
        return asyncio.get_event_loop().run_until_complete(awaitable_json)  # type: ignore[arg-type]
    except RuntimeError:
        # We are already inside an event loop for the async request helpers.
        raise


async def _parse_json_response(response) -> Dict[str, Any]:
    try:
        payload = await response.json(content_type=None)
        return payload if isinstance(payload, dict) else {"data": payload}
    except Exception:
        text = await response.text()
        snippet = text[:500]
        return {
            "error": "Invalid JSON response",
            "status": response.status,
            "content_type": response.headers.get("Content-Type"),
            "body": snippet,
        }

# Default URLs
_DEFAULT_AUTH_SERVICE_URL = "https://prod.api.authsec.ai/sdkmgr/mcp-auth"
_DEFAULT_SERVICES_BASE_URL = "https://prod.api.authsec.ai/sdkmgr/services"
_DEFAULT_CIBA_BASE_URL = "https://prod.api.authsec.ai"

# Global configuration storage
_config = _default_config()


def _load_config_file() -> Dict[str, Any]:
    """
    Read .authsec.json from the current working directory.
    Returns an empty dict when the file is absent or invalid.
    """
    config_path = os.path.join(os.getcwd(), ".authsec.json")
    if not os.path.isfile(config_path):
        return {}
    try:
        with open(config_path) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def load_config() -> Dict[str, Any]:
    """
    Public helper — returns the merged config from .authsec.json (if present).
    Useful for programmatic access to the saved configuration.
    """
    return _load_config_file()


# In-memory session cache for user info (best-effort, used for oauth_user_info)
_session_user_info: Dict[str, Any] = {}
_current_session_id: Optional[str] = None
_current_authenticated_session_id: Optional[str] = None


def _decode_jwt_unverified(token: str) -> Dict[str, Any]:
    # Decode JWT payload without verification (for cache/debug only).
    try:
        parts = token.split('.')
        if len(parts) < 2:
            return {}
        payload_b64 = parts[1]
        # pad base64
        padding = '=' * (-len(payload_b64) % 4)
        payload_bytes = __import__('base64').urlsafe_b64decode(payload_b64 + padding)
        data = json.loads(payload_bytes.decode('utf-8'))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _set_current_session_id(session_id: Optional[str]) -> None:
    global _current_session_id
    if session_id:
        _current_session_id = str(session_id)


def _set_authenticated_session_id(session_id: Optional[str]) -> None:
    global _current_authenticated_session_id
    if session_id:
        _current_authenticated_session_id = str(session_id)


def _clear_current_session_id(session_id: Optional[str] = None) -> None:
    global _current_session_id
    if session_id is None or _current_session_id == str(session_id):
        _current_session_id = None


def _clear_authenticated_session_id(session_id: Optional[str] = None) -> None:
    global _current_authenticated_session_id
    if session_id is None or _current_authenticated_session_id == str(session_id):
        _current_authenticated_session_id = None


def _has_authenticated_session() -> bool:
    return bool(_current_authenticated_session_id)


def _extract_content_payload(content: Any) -> Dict[str, Any]:
    if not isinstance(content, list):
        return {}
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
            try:
                parsed = json.loads(item["text"])
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                continue
    return {}


def _update_current_session_from_oauth_result(tool_name: str, content: Any) -> None:
    payload = _extract_content_payload(content)
    if not payload or payload.get("error"):
        return

    session_id = payload.get("session_id")
    if tool_name == "oauth_start" and session_id:
        _set_current_session_id(session_id)
        _clear_authenticated_session_id(session_id)
        return

    if tool_name == "oauth_authenticate" and session_id:
        _set_current_session_id(session_id)
        _set_authenticated_session_id(session_id)
        return

    if tool_name == "oauth_status":
        status = payload.get("status")
        if status == "authenticated" and session_id:
            _set_current_session_id(session_id)
            _set_authenticated_session_id(session_id)
        elif status in {"expired", "not_found", "logged_out"}:
            _clear_current_session_id(session_id)
            _clear_authenticated_session_id(session_id)
        return

    if tool_name == "oauth_logout":
        _clear_current_session_id(session_id)
        _clear_authenticated_session_id(session_id)

def _normalize_runtime_client_id(client_id: str) -> str:
    """
    Normalize caller-provided client_id to the runtime form expected by SDK Manager.
    Accepts:
    - base UUID (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
    - base UUID with underscores
    - already-suffixed IDs (`...-main-client` or `..._main-client`)
    """
    raw = str(client_id or "").strip().strip('"').strip("'")
    if not raw:
        raise ValueError("client_id must be a non-empty string")

    raw = raw.replace("_main-client", "-main-client")
    if raw.endswith("-main-client"):
        base = raw[: -len("-main-client")]
    else:
        base = raw

    # Normalize UUID-like underscore format to hyphen format.
    if "_" in base and base.count("_") == 4:
        base = base.replace("_", "-")

    return f"{base}-main-client"


def _is_placeholder_client_id(client_id: Optional[str]) -> bool:
    raw = str(client_id or "").strip().lower()
    return raw in {
        "",
        "your-client-id",
        "your-client-id-here",
        "<your-client-id>",
        "replace-me",
    }


@dataclass
class ServiceCredentials:
    service_id: str
    service_name: str
    service_type: str
    auth_type: str
    url: str
    credentials: Dict[str, Any]
    metadata: Dict[str, str]
    retrieved_at: str

def configure_auth(
    client_id: str,
    app_name: str,
    auth_service_url: Optional[str] = None,
    services_base_url: Optional[str] = None,
    timeout: int = 10,
    retries: int = 3
):
    """
    Configure authentication settings for tool protection.

    Priority chain (highest → lowest):
        explicit params → environment variables → .authsec.json → hardcoded defaults
    """
    global _config

    if not client_id or not isinstance(client_id, str):
        raise ValueError("client_id must be a non-empty string")

    if not app_name or not isinstance(app_name, str):
        raise ValueError("app_name must be a non-empty string")

    file_cfg = _load_config_file()

    _config.update(_default_config())
    _config.update({
        "client_id": client_id,
        "app_name": app_name,
        "timeout": timeout,
        "retries": retries,
        "auth_service_url": _resolve_config_value(
            auth_service_url,
            "AUTHSEC_AUTH_SERVICE_URL",
            file_cfg,
            "auth_service_url",
            _DEFAULT_AUTH_SERVICE_URL,
        ),
        "services_base_url": _resolve_config_value(
            services_base_url,
            "AUTHSEC_SERVICES_URL",
            file_cfg,
            "services_base_url",
            _DEFAULT_SERVICES_BASE_URL,
        ),
    })

    print(f"Auth configured: {app_name} with client_id: {client_id[:8]}...")
    print(f"Auth service URL: {_config['auth_service_url']}")
    print(f"Services URL: {_config['services_base_url']}")

async def _make_auth_request(endpoint: str, payload: Dict[str, Any] = None, method: str = "POST") -> Dict[str, Any]: #type: ignore
    """Make HTTP request to SDK Manager auth service."""
    if not _config["client_id"]:
        raise RuntimeError("Authentication not configured. Call configure_auth() first.")

    headers = {
        "Content-Type": "application/json",
        "X-Client-ID": _config["client_id"],
        "X-App-Name": _config["app_name"]
    }

    timeout = aiohttp.ClientTimeout(total=_config["timeout"])
    request_url = f"{_config['auth_service_url']}/{endpoint}"
    ssl_ctx = _ssl_for_url(request_url)

    for attempt in range(_config["retries"]):
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                if method == "GET":
                    async with session.get(
                        request_url,
                        headers=headers,
                        ssl=ssl_ctx
                    ) as response:
                        return await _parse_json_response(response)
                else:
                    async with session.post(
                        request_url,
                        json=payload,
                        headers=headers,
                        ssl=ssl_ctx
                    ) as response:
                        return await _parse_json_response(response)

        except Exception as e:
            if attempt < _config["retries"] - 1:
                await asyncio.sleep(0.5 * (attempt + 1))
                continue

            return {
                "allowed": False,
                "error": "Connection error",
                "message": f"Failed to connect to auth service: {str(e)}"
            }

    return {
        "allowed": False,
        "error": "Max retries exceeded",
        "message": "Could not complete authentication check"
    }

async def _make_services_request(endpoint: str, payload: Dict[str, Any] = None, method: str = "POST") -> Dict[str, Any]: #type: ignore
    """Make HTTP request to SDK Manager services."""
    if not _config["client_id"]:
        raise RuntimeError("Authentication not configured. Call configure_auth() first.")

    headers = {
        "Content-Type": "application/json",
        "X-Client-ID": _config["client_id"],
        "X-App-Name": _config["app_name"]
    }

    timeout = aiohttp.ClientTimeout(total=_config["timeout"] * 2)  # Services may take longer
    request_url = f"{_config['services_base_url']}/{endpoint}"
    ssl_ctx = _ssl_for_url(request_url)

    for attempt in range(_config["retries"]):
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                if method == "GET":
                    async with session.get(
                        request_url,
                        headers=headers,
                        ssl=ssl_ctx
                    ) as response:
                        if response.status >= 400:
                            error_text = await response.text()
                            return {"error": f"HTTP {response.status}: {error_text}"}
                        return await _parse_json_response(response)
                else:
                    async with session.post(
                        request_url,
                        json=payload,
                        headers=headers,
                        ssl=ssl_ctx
                    ) as response:
                        if response.status >= 400:
                            error_text = await response.text()
                            return {"error": f"HTTP {response.status}: {error_text}"}
                        return await _parse_json_response(response)

        except Exception as e:
            if attempt < _config["retries"] - 1:
                await asyncio.sleep(0.5 * (attempt + 1))
                continue

            return {
                "error": "Connection error",
                "message": f"Failed to connect to services: {str(e)}"
            }

    return {
        "error": "Max retries exceeded",
        "message": "Could not complete services request"
    }



def _normalize_claim_list(value):
    if value is None:
        return set()
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(v) for v in value if v is not None and str(v) != ""}
    return set()


def _evaluate_rbac(user_info, requirements):
    roles_req = set(requirements.get("roles") or [])
    groups_req = set(requirements.get("groups") or [])
    resources_req = set(requirements.get("resources") or [])
    scopes_req = set(requirements.get("scopes") or [])
    perms_req = set(requirements.get("permissions") or [])
    require_all = bool(requirements.get("require_all"))

    user_roles = _normalize_claim_list(user_info.get("roles"))
    user_groups = _normalize_claim_list(user_info.get("groups"))

    raw_scopes = _normalize_claim_list(user_info.get("scopes")) | _normalize_claim_list(user_info.get("scope"))

    user_resources = _normalize_claim_list(user_info.get("resources"))
    user_resources |= {s.split(":", 1)[0] for s in raw_scopes if "\:" in s}

    user_scopes = {s for s in raw_scopes if "\:" not in s}
    user_scopes |= {s.split(":", 1)[1] for s in raw_scopes if "\:" in s}

    user_perms = _normalize_claim_list(user_info.get("permissions"))
    user_perms |= {s for s in raw_scopes if "\:" in s}

    checks = {}
    if roles_req:
        checks["roles"] = bool(user_roles & roles_req)
    if groups_req:
        checks["groups"] = bool(user_groups & groups_req)
    if resources_req:
        checks["resources"] = bool(user_resources & resources_req)
    if scopes_req:
        checks["scopes"] = bool(user_scopes & scopes_req)
    if perms_req:
        if user_perms:
            checks["permissions"] = bool(user_perms & perms_req)
        else:
            allowed = False
            for perm in perms_req:
                if ":" in perm:
                    res, act = perm.split(":", 1)
                    if res in user_resources and act in user_scopes:
                        allowed = True
                        break
            checks["permissions"] = allowed

    # No RBAC requirements -> allow
    if not checks:
        return True, ""

    if require_all:
        missing = [k for k, ok in checks.items() if not ok]
        if missing:
            return False, f"missing required {', '.join(missing)}"
        return True, ""

    # OR logic across categories
    if any(checks.values()):
        return True, ""
    return False, "no RBAC requirement satisfied"



def _normalize_oauth_arguments(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # Normalize oauth tool arguments to avoid list-vs-string errors in auth service.
    if not isinstance(arguments, dict):
        return arguments
    args = dict(arguments)

    def _coerce_to_str(value):
        if isinstance(value, list):
            if len(value) == 1:
                return str(value[0])
            return " ".join(str(v) for v in value)
        return value

    for key, value in list(args.items()):
        args[key] = _coerce_to_str(value)

    return args


def _should_open_browser(arguments: Any) -> bool:
    if not isinstance(arguments, dict):
        return False
    value = arguments.get("open_browser")
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def _try_open_browser_from_content(content: Any) -> bool:
    if not isinstance(content, list):
        return False
    for item in content:
        if not isinstance(item, dict):
            continue
        text = item.get("text")
        if not isinstance(text, str):
            continue
        try:
            payload = json.loads(text)
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        authorization_url = payload.get("authorization_url")
        if not isinstance(authorization_url, str) or not authorization_url.strip():
            continue
        try:
            opened = bool(webbrowser.open(authorization_url, new=2))
        except Exception:
            opened = False
        payload["browser_opened"] = opened
        item["text"] = json.dumps(payload, indent=2)
        return opened
    return False

def mcp_tool(
    name: Optional[str] = None,
    description: Optional[str] = None,
    inputSchema: Optional[Dict[str, Any]] = None
):
    """
    Decorator for standard MCP tools (no authentication required).

    This is a lightweight decorator for tools that don't need authentication.
    It allows you to specify the tool's description and inputSchema.

    Args:
        name: Tool name (uses function name if not provided)
        description: Tool description (uses docstring if not provided)
        inputSchema: MCP-compliant input schema (optional)

    Example:
        @mcp_tool(description="Echo a message", inputSchema={
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Message to echo"}
            },
            "required": ["message"]
        })
        async def echo(arguments: dict) -> list:
            return [{"type": "text", "text": arguments.get("message", "")}]
    """
    def decorator(func: Callable) -> Callable:
        # Store metadata on the function
        func._mcp_tool_name = name
        func._mcp_tool_description = description
        func._mcp_tool_inputSchema = inputSchema
        return func
    return decorator


def protected_by_AuthSec(
    tool_name: str,
    roles: Optional[List[str]] = None,
    groups: Optional[List[str]] = None,
    resources: Optional[List[str]] = None,
    scopes: Optional[List[str]] = None,
    permissions: Optional[List[str]] = None,
    require_all: bool = False,
    description: Optional[str] = None,
    inputSchema: Optional[Dict[str, Any]] = None
):
    """
    Decorator to protect tools via SDK Manager auth service API with optional RBAC.

    Args:
        tool_name: Name of the tool to protect
        roles: List of role names that can access this tool (e.g., ["admin", "manager"])
        groups: List of group names that can access this tool
        resources: List of resource names user must have access to
        scopes: List of scope names user must have (e.g., ["read", "write"])
        permissions: List of permission names user must have
        require_all: If True, user must satisfy ALL conditions. If False, ANY condition is sufficient.
        description: Optional description of the tool (uses function docstring if not provided)
        inputSchema: Optional MCP-compliant input schema (JSON Schema format)

    RBAC Validation:
        - If no RBAC parameters are provided, only authentication is required
        - If RBAC parameters are provided, they are validated against tenant_{tenant_id} database
        - RBAC check happens during oauth_authenticate tool execution
        - Only tools that satisfy RBAC conditions are exposed/unprotected

    Examples:
        @protected_by_AuthSec("admin_tool", roles=["admin"])
        @protected_by_AuthSec("calculator", roles=["admin", "user"])
        @protected_by_AuthSec("file_upload", roles=["admin"], scopes=["write"])
        @protected_by_AuthSec("analytics", roles=["manager"], resources=["projects"], scopes=["read"])
        @protected_by_AuthSec("notes_manager", description="Manage notes", inputSchema={...})
    """
    def decorator(func: Callable) -> Callable:
        # Store RBAC requirements as metadata on the function
        func._rbac_requirements = {
            "roles": roles or [],
            "groups": groups or [],
            "resources": resources or [],
            "scopes": scopes or [],
            "permissions": permissions or [],
            "require_all": require_all
        }

        # Store optional description and inputSchema
        func._tool_description = description
        func._tool_inputSchema = inputSchema

        # Check if function expects 'session' parameter
        sig = inspect.signature(func)
        expects_session = 'session' in sig.parameters

        @wraps(func)
        async def wrapper(arguments: dict) -> list:
            # Extract session ID from arguments
            session_id = arguments.get("session_id") or _current_session_id
            if session_id and "session_id" not in arguments:
                arguments["session_id"] = session_id

            # Single API call to auth service for tool protection
            payload = {
                "session_id": session_id,
                "tool_name": tool_name,
                "client_id": _config["client_id"],
                "app_name": _config["app_name"]
            }

            protection_result = await _make_auth_request("protect-tool", payload)

            # Check if access is allowed
            if not protection_result.get("allowed", False):
                error_response = {
                    "error": protection_result.get("error", "Access denied"),
                    "message": protection_result.get("message", "Authentication failed"),
                    "tool": tool_name
                }
                return [{"type": "text", "text": json.dumps(error_response)}]

            resolved_session_id = protection_result.get("session_id") or session_id
            user_info = protection_result.get("user_info", {}) or {}
            if resolved_session_id:
                _session_user_info[str(resolved_session_id)] = user_info
                # Make resolved session_id available to downstream tool logic.
                arguments["session_id"] = resolved_session_id
            print(json.dumps(user_info, indent=2))

            # Enforce RBAC at execution time
            rbac_ok, rbac_reason = _evaluate_rbac(user_info, func._rbac_requirements)
            if not rbac_ok:
                error_response = {
                    "error": "Access denied",
                    "message": f"RBAC denied: {rbac_reason}",
                    "tool": tool_name
                }
                return [{"type": "text", "text": json.dumps(error_response)}]

            # Add user info to arguments for the business function
            arguments["_user_info"] = user_info

            # Create session object if function expects it
            if expects_session:
                # Create a simple session object with required attributes
                class SimpleSession:
                    def __init__(self, session_id: str, user_info: Dict):
                        self.session_id = session_id
                        self.access_token = user_info.get("access_token")
                        self.tenant_id = user_info.get("tenant_id")
                        self.user_id = user_info.get("user_id")
                        self.org_id = user_info.get("org_id")

                session_obj = SimpleSession(str(resolved_session_id or ""), protection_result.get("user_info", {}))

                # Call the original business function with session
                try:
                    result = await func(arguments, session_obj)
                    return result
                except Exception as e:
                    return [{
                        "type": "text",
                        "text": json.dumps({
                            "error": "Tool execution failed",
                            "message": f"Internal error in {tool_name}: {str(e)}",
                            "tool": tool_name
                        })
                    }]
            else:
                # Call the original business function without session
                try:
                    result = await func(arguments)
                    return result
                except Exception as e:
                    return [{
                        "type": "text",
                        "text": json.dumps({
                            "error": "Tool execution failed",
                            "message": f"Internal error in {tool_name}: {str(e)}",
                            "tool": tool_name
                        })
                    }]

        # Copy RBAC requirements to wrapper for introspection
        wrapper._rbac_requirements = func._rbac_requirements
        wrapper._tool_description = func._tool_description
        wrapper._tool_inputSchema = func._tool_inputSchema
        wrapper._authsec_tool_name = tool_name

        return wrapper
    return decorator

# ===========================
# =MCP SERVER IMPLEMENTATION=
# ===========================

class MCPServer:
    """Minimal MCP server that delegates to hosted SDK Manager"""

    def __init__(self, client_id: str, app_name: str):
        self.client_id = client_id
        self.app_name = app_name
        self.user_tools: List[Dict[str, Any]] = []  # Protected tools with RBAC metadata
        self.unprotected_tools: List[Dict[str, Any]] = []  # Unprotected tools (standard MCP)
        self.tool_handlers: Dict[str, Callable] = {}  # All tool handlers (both protected and unprotected)

        self.app = FastAPI(title=app_name, version="1.0.0")
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        self._setup_routes()
        self._setup_shutdown_handlers()

    def _setup_shutdown_handlers(self):
        """Setup handlers to clean up sessions on server shutdown"""
        async def cleanup_sessions():
            """Clean up all active sessions for this client"""
            try:
                cleanup_result = await _make_auth_request(
                    "cleanup-sessions",
                    {
                        "client_id": self.client_id,
                        "app_name": self.app_name,
                        "reason": "server_shutdown"
                    }
                )
                print(f"Sessions cleanup: {cleanup_result.get('message', 'Completed')}")
            except Exception as e:
                print(f"Session cleanup failed: {e}")

        # Handle SIGINT (Ctrl+C) and SIGTERM
        def signal_handler(signum, frame):
            print(f"\nReceived signal {signum}, cleaning up sessions...")
            try:
                # Run cleanup synchronously on shutdown
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(cleanup_sessions())
                loop.close()
            except Exception as e:
                print(f"Cleanup error: {e}")
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    def set_user_module(self, module):
        """
        Discover tools from user module (both protected and unprotected).

        Protected tools (with @protected_by_AuthSec decorator):
        - Sent to SDK Manager with RBAC metadata
        - Require authentication and RBAC validation

        Unprotected tools (without decorator):
        - Registered as standard MCP tools
        - No authentication required
        - Work like normal MCP tools
        """
        for name, obj in inspect.getmembers(module):
            if inspect.iscoroutinefunction(obj) and not name.startswith('_'):
                # Check if this is a protected tool (has @protected_by_AuthSec decorator)
                is_protected = hasattr(obj, '__wrapped__') and hasattr(obj, '_rbac_requirements')

                # Check if this is an unprotected MCP tool (has @mcp_tool decorator)
                is_mcp_tool = hasattr(obj, '_mcp_tool_name') or hasattr(obj, '_mcp_tool_description') or hasattr(obj, '_mcp_tool_inputSchema')

                # IMPORTANT: Only register tools that have a decorator
                # Skip functions without any decorator (helper functions like init_database, log_audit)
                if not (is_protected or is_mcp_tool):
                    continue

                if is_protected:
                    # Protected tool - extract metadata and send to SDK Manager
                    rbac_requirements = getattr(obj, '_rbac_requirements', {
                        "roles": [],
                        "groups": [],
                        "resources": [],
                        "scopes": [],
                        "permissions": [],
                        "require_all": False
                    })

                    # Extract optional description (use decorator param or docstring)
                    description = getattr(obj, '_tool_description', None)
                    if not description and obj.__doc__:
                        # Use first line of docstring as description
                        description = obj.__doc__.strip().split('\n')[0]

                    # Extract optional inputSchema
                    inputSchema = getattr(obj, '_tool_inputSchema', None)

                    # Store tool with its RBAC metadata, description, and inputSchema
                    tool_name = getattr(obj, '_authsec_tool_name', name)

                    tool_metadata = {
                        "name": tool_name,
                        "rbac": rbac_requirements
                    }

                    # Add description if provided
                    if description:
                        tool_metadata["description"] = description

                    # Add inputSchema if provided
                    if inputSchema:
                        tool_metadata["inputSchema"] = inputSchema

                    self.user_tools.append(tool_metadata)
                    self.tool_handlers[tool_name] = obj
                else:
                    # Unprotected tool - register as standard MCP tool (no SDK Manager involvement)
                    self.tool_handlers[name] = obj

                    # Extract metadata from @mcp_tool decorator if present
                    tool_name = getattr(obj, '_mcp_tool_name', None) or name
                    description = getattr(obj, '_mcp_tool_description', None)
                    if not description and obj.__doc__:
                        description = obj.__doc__.strip().split('\n')[0]
                    if not description:
                        description = f"Tool: {tool_name}"

                    inputSchema = getattr(obj, '_mcp_tool_inputSchema', None)
                    if not inputSchema:
                        # Create a minimal default inputSchema
                        inputSchema = {
                            "type": "object",
                            "properties": {},
                            "required": []
                        }

                    tool_schema = {
                        "name": tool_name,
                        "description": description,
                        "inputSchema": inputSchema
                    }

                    self.unprotected_tools.append(tool_schema)
                    logger.info(f"Registered unprotected tool: {tool_name} (standard MCP tool, no auth required)")

    def _setup_routes(self):
        """Setup MCP protocol routes"""

        @self.app.get("/")
        async def root():
            return {
                "name": self.app_name,
                "version": "1.0.0",
                "protocol": "mcp-with-oauth",
                "status": "running",
                "auth_service": _config["auth_service_url"],
                "services_url": _config["services_base_url"]
            }

        @self.app.post("/")
        async def mcp_endpoint(request: Request):
            try:
                body = await request.body()
                message = json.loads(body.decode('utf-8'))
                response = await self._process_mcp_message(message, request)
                return JSONResponse(response)
            except Exception as e:
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": str(e)}
                })

    def _oauth_tools_fallback(self) -> List[Dict[str, Any]]:
        """Local fallback OAuth tools if auth service tools/list is unavailable."""
        return [
            {
                "name": "oauth_start",
                "description": "Start OAuth authentication flow",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "open_browser": {"type": "boolean"},
                        "return_url": {"type": "string"}
                    },
                    "required": []
                },
            },
            {
                "name": "oauth_authenticate",
                "description": "Authenticate with JWT token",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "jwt_token": {"type": "string"},
                        "session_id": {"type": "string"},
                        "expires_in": {"type": "number"},
                    },
                    "required": ["jwt_token", "session_id"],
                },
            },
            {
                "name": "oauth_status",
                "description": "Check authentication status",
                "inputSchema": {
                    "type": "object",
                    "properties": {"session_id": {"type": "string"}},
                    "required": ["session_id"],
                },
            },
            {
                "name": "oauth_logout",
                "description": "Logout and invalidate session",
                "inputSchema": {
                    "type": "object",
                    "properties": {"session_id": {"type": "string"}},
                    "required": ["session_id"],
                },
            },
            {
                "name": "oauth_user_info",
                "description": "Get user information for authenticated session",
                "inputSchema": {
                    "type": "object",
                    "properties": {"session_id": {"type": "string"}},
                    "required": ["session_id"],
                },
            },
        ]

    def _derive_return_url(self, request: Request) -> Optional[str]:
        """
        Best-effort return URL discovery from MCP client request context.
        Priority:
        1) Referer
        2) Origin
        """
        referer = request.headers.get("referer")
        if referer:
            try:
                parsed = urllib.parse.urlparse(referer)
                if parsed.scheme in {"http", "https"} and parsed.netloc:
                    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, parsed.fragment))
            except Exception:
                pass

        origin = request.headers.get("origin")
        if origin:
            try:
                parsed = urllib.parse.urlparse(origin)
                if parsed.scheme in {"http", "https"} and parsed.netloc:
                    return f"{parsed.scheme}://{parsed.netloc}/"
            except Exception:
                pass
        return None

    async def _process_mcp_message(self, message: Dict, request: Optional[Request] = None) -> Dict:
        """Process MCP messages - delegate most logic to hosted service"""
        method = message.get("method")
        message_id = message.get("id")
        params = message.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": message_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": self.app_name, "version": "1.0.0"}
                }
            }

        elif method == "tools/list":
            # Get protected tools from SDK Manager (with OAuth and RBAC), with a hard cap to avoid MCP timeout.
            try:
                tools_response = await asyncio.wait_for(
                    _make_auth_request(
                        "tools/list",
                        {
                            "client_id": self.client_id,
                            "app_name": self.app_name,
                            "session_id": _current_authenticated_session_id,
                            "user_tools": self.user_tools  # Protected tools with RBAC metadata
                        }
                    ),
                    timeout=float(os.getenv("AUTHSEC_TOOLS_LIST_TIMEOUT_SECONDS", "8")),
                )
            except asyncio.TimeoutError:
                tools_response = {
                    "error": "tools/list timed out against auth service"
                }

            # Combine protected tools (from SDK Manager) with unprotected tools (local)
            remote_tools = tools_response.get("tools", []) if isinstance(tools_response, dict) else []
            if not remote_tools:
                # Never return empty tools list just because upstream auth listing failed.
                remote_tools = self._oauth_tools_fallback()
            elif not _has_authenticated_session():
                protected_tool_names = {tool["name"] for tool in self.user_tools if isinstance(tool, dict) and tool.get("name")}
                remote_tools = [
                    tool
                    for tool in remote_tools
                    if not isinstance(tool, dict) or tool.get("name") not in protected_tool_names
                ]

            all_tools = remote_tools + self.unprotected_tools

            return {"jsonrpc": "2.0", "id": message_id, "result": {"tools": all_tools}}

        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})

            # Best-effort local cache for oauth_user_info to avoid upstream split errors
            if tool_name == "oauth_user_info":
                session_id = arguments.get("session_id")
                if session_id and session_id in _session_user_info:
                    content = [{"type": "text", "text": json.dumps(_session_user_info[session_id])}]
                    return {"jsonrpc": "2.0", "id": message_id, "result": {"content": content}}

            # Capture JWT on oauth_authenticate for cache (if provided)
            if tool_name == "oauth_authenticate":
                session_id = arguments.get("session_id")
                token = (arguments.get("token") or arguments.get("jwt") or arguments.get("access_token"))
                if session_id and isinstance(token, str):
                    decoded = _decode_jwt_unverified(token)
                    if decoded:
                        _session_user_info[session_id] = decoded

            if tool_name.startswith("oauth_"):
                # Delegate OAuth tools to hosted service
                arguments = _normalize_oauth_arguments(arguments)
                if tool_name == "oauth_start" and isinstance(arguments, dict) and "return_url" not in arguments and request is not None:
                    auto_return_url = self._derive_return_url(request)
                    if auto_return_url:
                        arguments["return_url"] = auto_return_url
                tool_response = await _make_auth_request(
                    f"tools/call/{tool_name}",
                    {
                        "client_id": self.client_id,
                        "app_name": self.app_name,
                        "arguments": arguments
                    }
                )
                if isinstance(tool_response, dict) and isinstance(tool_response.get("content"), list):
                    content = tool_response["content"]
                    _update_current_session_from_oauth_result(tool_name, content)
                    if tool_name == "oauth_start" and _should_open_browser(arguments):
                        _try_open_browser_from_content(content)
                else:
                    # Preserve useful upstream diagnostics instead of collapsing to a generic error.
                    error_payload = {
                        "error": "Tool execution failed",
                        "tool": tool_name,
                    }
                    if isinstance(tool_response, dict):
                        if "detail" in tool_response:
                            error_payload["detail"] = tool_response.get("detail")
                        if "error" in tool_response:
                            error_payload["upstream_error"] = tool_response.get("error")
                        if "message" in tool_response:
                            error_payload["upstream_message"] = tool_response.get("message")
                    content = [{"type": "text", "text": json.dumps(error_payload)}]
            elif tool_name in self.tool_handlers:
                # Execute user's protected tools locally (they have the @protected_by_AuthSec decorator)
                content = await self.tool_handlers[tool_name](arguments)
            else:
                content = [{"type": "text", "text": json.dumps({"error": f"Unknown tool: {tool_name}"})}]

            return {"jsonrpc": "2.0", "id": message_id, "result": {"content": content}}

        else:
            return {
                "jsonrpc": "2.0",
                "id": message_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"}
            }

def run_mcp_server_with_oauth(
    user_module,
    client_id: str,
    app_name: str,
    host: str = "0.0.0.0",
    port: int = 3005,
    spire_socket_path: Optional[str] = None
):
    """
    Run MCP server using SDK Manager for auth.

    Priority chain for URLs: explicit params → env vars → .authsec.json → defaults

    Args:
        user_module: Module containing MCP tools
        client_id: Your client ID
        app_name: Application name
        host: Server host (default: 0.0.0.0)
        port: Server port (default: 3005)
        spire_socket_path: Optional path to SPIRE agent socket.
                          If provided, SPIRE workload identity will be enabled.
                          If None, SPIRE is disabled (default: None)
    """
    # Priority chain: explicit params → env vars → .authsec.json → internal defaults
    file_cfg = _load_config_file()
    env_client_id = (os.getenv("AUTHSEC_CLIENT_ID") or "").strip()
    file_client_id = str(file_cfg.get("client_id") or "").strip()
    explicit_client_id = "" if _is_placeholder_client_id(client_id) else str(client_id or "").strip()
    resolved_client_id = explicit_client_id or env_client_id or file_client_id
    if not resolved_client_id:
        raise ValueError("client_id must be a non-empty string")

    runtime_client_id = _normalize_runtime_client_id(resolved_client_id)
    timeout_seconds = int(os.getenv("AUTHSEC_TIMEOUT_SECONDS", "15"))
    retries = int(os.getenv("AUTHSEC_RETRIES", "2"))

    configure_auth(
        runtime_client_id,
        app_name,
        timeout=timeout_seconds,
        retries=retries,
    )

    # Store SPIRE socket path in global config if provided
    if spire_socket_path:
        _config["spire_socket_path"] = spire_socket_path
        _config["spire_enabled"] = True
    else:
        _config["spire_enabled"] = False

    async def _run():
        server = MCPServer(runtime_client_id, app_name)
        server.set_user_module(user_module)

        print(f"Starting {app_name} MCP Server on {host}:{port}")
        print(f"Authentication via: {_config['auth_service_url']}")
        print(f"Services via: {_config['services_base_url']}")

        if _config.get("spire_enabled"):
            print(f"SPIRE Workload Identity: ENABLED")
            print(f"  Agent socket: {_config['spire_socket_path']}")
        else:
            print(f"SPIRE Workload Identity: DISABLED")

        print(f"MCP Inspector: npx @modelcontextprotocol/inspector http://{host}:{port}")

        config = uvicorn.Config(server.app, host=host, port=port, log_level="info")
        uvicorn_server = uvicorn.Server(config)
        await uvicorn_server.serve()

    asyncio.run(_run())

# Utility functions
def get_config() -> Dict[str, Any]:
    """Get current configuration (for debugging)."""
    config_copy = _config.copy()
    if config_copy.get("client_id"):
        config_copy["client_id"] = config_copy["client_id"][:8] + "..." + config_copy["client_id"][-4:]
    return config_copy

def is_configured() -> bool:
    """Check if authentication is properly configured."""
    return bool(_config.get("client_id") and _config.get("app_name"))

async def test_auth_service():
    """Test connection to auth service"""
    try:
        result = await _make_auth_request("health", method="GET")
        print(f"Auth service is running: {result}")
        return result.get("status") == "healthy"
    except Exception as e:
        print(f"Failed to connect to auth service: {str(e)}")
        return False

async def test_services():
    """Test connection to services"""
    try:
        result = await _make_services_request("health", method="GET")
        print(f"Services are running: {result}")
        return result.get("status") == "healthy"
    except Exception as e:
        print(f"Failed to connect to services: {str(e)}")
        return False

# ================================
# =Services SERVER IMPLEMENTATION=
# ================================

class ServiceAccessError(Exception):
    """Base exception for service access errors"""
    pass

class ServiceAccessSDK:
    """Minimal SDK that delegates to hosted services"""

    def __init__(self, session, timeout: int = 30):
        """Initialize SDK with session data"""
        # Extract session_id from OAuth session object
        if hasattr(session, 'session_id'):
            self.session_id = session.session_id
        elif isinstance(session, dict) and 'session_id' in session:
            self.session_id = session['session_id']
        else:
            raise ValueError("Session must contain session_id")

        # Store session for metadata
        self.session = session
        self.timeout = timeout

    async def health_check(self) -> Dict[str, Any]:
        """Check service health via hosted service"""
        return await _make_services_request("health", method="GET")

    async def get_service_credentials(self, service_name: str) -> ServiceCredentials:
        """Get service credentials via hosted service"""
        payload = {
            "session_id": self.session_id,
            "service_name": service_name
        }

        result = await _make_services_request("credentials", payload)

        if "error" in result:
            raise ServiceAccessError(result["error"])

        return ServiceCredentials(
            service_id=result['service_id'],
            service_name=result['service_name'],
            service_type=result['service_type'],
            auth_type=result['auth_type'],
            url=result['url'],
            credentials=result['credentials'],
            metadata=result.get('metadata', {}),
            retrieved_at=result['retrieved_at']
        )

    async def get_service_token(self, service_name: str) -> str:
        """Get access token for service"""
        credentials = await self.get_service_credentials(service_name)
        token = credentials.credentials.get('access_token')
        if not token:
            raise ServiceAccessError(f"No access token available for {service_name}")
        return token

    async def get_service_user_details(self, service_name: str) -> Dict[str, Any]:
        """Get JWT payload details via hosted service"""
        payload = {
            "session_id": self.session_id,
            "service_name": service_name
        }

        return await _make_services_request("user-details", payload)

    async def close(self):
        """Close SDK (no-op in this minimal implementation)"""
        pass
