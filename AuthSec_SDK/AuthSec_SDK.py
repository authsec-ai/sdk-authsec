"""
Your Auth Package - AuthSec team provided library
Minimal MCP server implementation that delegates to hosted SDK Manager
"""

import json
import aiohttp
import asyncio
import inspect
import sys
import uvicorn
import signal
from typing import Dict, Optional, List, Callable, Any
from functools import wraps
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

# Global configuration storage
_config = {
    "client_id": None,
    "app_name": None,
    "auth_service_url": "https://dev.api.authsec.dev/sdkmgr/mcp-auth",
    "services_base_url": "https://dev.api.authsec.dev/sdkmgr/services",
    "timeout": 10,
    "retries": 3
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
    """Configure authentication settings for tool protection."""
    global _config

    if not client_id or not isinstance(client_id, str):
        raise ValueError("client_id must be a non-empty string")

    if not app_name or not isinstance(app_name, str):
        raise ValueError("app_name must be a non-empty string")

    _config.update({
        "client_id": client_id,
        "app_name": app_name,
        "timeout": timeout,
        "retries": retries
    })

    if auth_service_url:
        _config["auth_service_url"] = auth_service_url.rstrip('/')

    if services_base_url:
        _config["services_base_url"] = services_base_url.rstrip('/')

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

    for attempt in range(_config["retries"]):
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                if method == "GET":
                    async with session.get(
                        f"{_config['auth_service_url']}/{endpoint}",
                        headers=headers
                    ) as response:
                        return await response.json()
                else:
                    async with session.post(
                        f"{_config['auth_service_url']}/{endpoint}",
                        json=payload,
                        headers=headers
                    ) as response:
                        return await response.json()

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

    for attempt in range(_config["retries"]):
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                if method == "GET":
                    async with session.get(
                        f"{_config['services_base_url']}/{endpoint}",
                        headers=headers
                    ) as response:
                        if response.status >= 400:
                            error_text = await response.text()
                            return {"error": f"HTTP {response.status}: {error_text}"}
                        return await response.json()
                else:
                    async with session.post(
                        f"{_config['services_base_url']}/{endpoint}",
                        json=payload,
                        headers=headers
                    ) as response:
                        if response.status >= 400:
                            error_text = await response.text()
                            return {"error": f"HTTP {response.status}: {error_text}"}
                        return await response.json()

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
            session_id = arguments.get("session_id")

            if not session_id:
                error_response = {
                    "error": "Authentication required",
                    "message": f"Tool '{tool_name}' requires authentication. Please provide session_id.",
                    "tool": tool_name
                }
                return [{"type": "text", "text": json.dumps(error_response)}]

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

            # Add user info to arguments for the business function
            arguments["_user_info"] = protection_result.get("user_info", {})

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

                session_obj = SimpleSession(session_id, protection_result.get("user_info", {}))

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

        # OAuth 2.1 connection tracking
        # Maps client_key (host:port) → connection_info
        self.connection_map: Dict[str, Dict] = {}

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
                    tool_metadata = {
                        "name": name,
                        "rbac": rbac_requirements
                    }

                    # Add description if provided
                    if description:
                        tool_metadata["description"] = description

                    # Add inputSchema if provided
                    if inputSchema:
                        tool_metadata["inputSchema"] = inputSchema

                    self.user_tools.append(tool_metadata)
                    self.tool_handlers[name] = obj
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
        """Setup MCP protocol routes with OAuth 2.1 support"""

        # OAuth 2.1 Protected Resource Metadata (RFC 8414)
        @self.app.get("/.well-known/oauth-protected-resource")
        async def oauth_protected_resource_metadata(request: Request):
            """
            RFC 8414: OAuth 2.0 Protected Resource Metadata
            Tells MCP clients where to find the authorization server
            """
            # Get server URL from request
            server_url = f"{request.url.scheme}://{request.url.netloc}"

            # Get auth server base URL (remove path)
            auth_server_url = _config["auth_service_url"].replace("/sdkmgr/mcp-auth", "")

            return JSONResponse({
                "resource": f"{server_url}/mcp",
                "authorization_servers": [auth_server_url],
                "scopes_supported": ["tools:read", "tools:execute", "tools:admin"],
                "bearer_methods_supported": ["header"],
                "resource_documentation": "https://docs.authsec.dev/mcp-oauth"
            })

        # Return OAuth authorization server metadata directly
        @self.app.get("/.well-known/oauth-authorization-server")
        async def oauth_authorization_server_metadata(request: Request):
            """
            OAuth Authorization Server Metadata (RFC 8414)
            Returns metadata with registration_endpoint pointing to THIS MCP server
            This is CRITICAL: MCP clients expect to register with the MCP server, not the auth server!
            """
            # Get server URL from request
            server_url = f"{request.url.scheme}://{request.url.netloc}"

            # Get auth server base URL
            auth_server_url = _config["auth_service_url"].replace("/sdkmgr/mcp-auth", "")

            return JSONResponse({
                "issuer": auth_server_url,
                "authorization_endpoint": f"{auth_server_url}/oauth2/auth",
                "token_endpoint": f"{auth_server_url}/sdkmgr/mcp-auth/oauth/token",
                "revocation_endpoint": f"{auth_server_url}/sdkmgr/mcp-auth/oauth/revoke",
                "registration_endpoint": f"{server_url}/register",  # CRITICAL: Point to MCP server's /register!

                # MCP requires PKCE (S256)
                "code_challenge_methods_supported": ["S256"],

                # OAuth 2.1 only supports authorization_code grant
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "response_types_supported": ["code"],
                "response_modes_supported": ["query"],

                # Scopes for MCP tools
                "scopes_supported": [
                    "tools:read",
                    "tools:execute",
                    "tools:admin",
                    "openid",
                    "profile",
                    "email"
                ],

                # Token endpoint auth methods
                "token_endpoint_auth_methods_supported": [
                    "none",  # Public clients (MCP clients don't have client secrets)
                    "client_secret_post"
                ],

                # Security features
                "require_pushed_authorization_requests": False,
                "require_request_uri_registration": False,
                "tls_client_certificate_bound_access_tokens": False,

                # Additional metadata
                "service_documentation": "https://docs.authsec.dev/mcp-oauth",
                "ui_locales_supported": ["en-US"]
            })

        # Some clients request OpenID configuration
        @self.app.get("/.well-known/openid-configuration")
        async def openid_configuration_metadata(request: Request):
            """
            OpenID configuration metadata (same as oauth-authorization-server)
            Returns metadata with registration_endpoint pointing to THIS MCP server
            """
            # Reuse the same logic as oauth_authorization_server_metadata
            server_url = f"{request.url.scheme}://{request.url.netloc}"
            auth_server_url = _config["auth_service_url"].replace("/sdkmgr/mcp-auth", "")

            return JSONResponse({
                "issuer": auth_server_url,
                "authorization_endpoint": f"{auth_server_url}/oauth2/auth",
                "token_endpoint": f"{auth_server_url}/sdkmgr/mcp-auth/oauth/token",
                "revocation_endpoint": f"{auth_server_url}/sdkmgr/mcp-auth/oauth/revoke",
                "registration_endpoint": f"{server_url}/register",  # Point to MCP server's /register

                "code_challenge_methods_supported": ["S256"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "response_types_supported": ["code"],
                "response_modes_supported": ["query"],

                "scopes_supported": [
                    "tools:read",
                    "tools:execute",
                    "tools:admin",
                    "openid",
                    "profile",
                    "email"
                ],

                "token_endpoint_auth_methods_supported": [
                    "none",
                    "client_secret_post"
                ],

                "require_pushed_authorization_requests": False,
                "require_request_uri_registration": False,
                "tls_client_certificate_bound_access_tokens": False,

                "service_documentation": "https://docs.authsec.dev/mcp-oauth",
                "ui_locales_supported": ["en-US"]
            })

        # Dynamic Client Registration (RFC 7591) - Not supported
        @self.app.post("/register")
        async def dynamic_client_registration(request: Request):
            """
            Dynamic Client Registration endpoint (RFC 7591)
            Delegates to SDK Manager to register ephemeral OAuth clients
            """
            try:
                # Get registration request from MCP client
                body = await request.body()
                registration_data = json.loads(body.decode('utf-8')) if body else {}

                # Forward to SDK Manager for dynamic client registration
                result = await _make_auth_request(
                    "oauth/register",
                    {
                        "client_id": self.client_id,
                        "app_name": self.app_name,
                        "registration_data": registration_data
                    }
                )

                if result.get("error"):
                    return JSONResponse(
                        status_code=400,
                        content={
                            "error": result.get("error"),
                            "error_description": result.get("error_description", "Dynamic client registration failed")
                        }
                    )

                # Return successful registration response
                return JSONResponse({
                    "client_id": result.get("client_id"),
                    "client_secret": result.get("client_secret", ""),  # May be empty for public clients
                    "client_id_issued_at": result.get("client_id_issued_at"),
                    "client_secret_expires_at": result.get("client_secret_expires_at", 0),
                    "grant_types": result.get("grant_types", ["authorization_code", "refresh_token"]),
                    "response_types": result.get("response_types", ["code"]),
                    "token_endpoint_auth_method": result.get("token_endpoint_auth_method", "none")
                })

            except Exception as e:
                logger.error(f"Dynamic client registration error: {str(e)}")
                return JSONResponse(
                    status_code=500,
                    content={
                        "error": "server_error",
                        "error_description": f"Dynamic client registration failed: {str(e)}"
                    }
                )

        @self.app.get("/")
        async def root():
            return {
                "name": self.app_name,
                "version": "1.0.0",
                "protocol": "mcp-oauth-2.1",
                "status": "running",
                "auth_required": True,
                "auth_method": "OAuth 2.1 with PKCE",
                "auth_metadata": "/.well-known/oauth-protected-resource"
            }

        @self.app.post("/")
        async def mcp_endpoint(request: Request):
            """
            Main MCP endpoint with OAuth 2.1 authentication
            Returns 401 Unauthorized if no valid Bearer token provided
            """
            try:
                # Check for Authorization header
                auth_header = request.headers.get("Authorization")

                if not auth_header or not auth_header.startswith("Bearer "):
                    # No auth token - return 401 with OAuth metadata
                    server_url = f"{request.url.scheme}://{request.url.netloc}"

                    return JSONResponse(
                        status_code=401,
                        headers={
                            "WWW-Authenticate": f'Bearer resource_metadata="{server_url}/.well-known/oauth-protected-resource", scope="tools:read tools:execute"'
                        },
                        content={
                            "error": "unauthorized",
                            "error_description": "Authentication required. Please authenticate using OAuth 2.1"
                        }
                    )

                # Extract access token
                access_token = auth_header.replace("Bearer ", "")

                # Process MCP message with authentication
                body = await request.body()
                message = json.loads(body.decode('utf-8'))

                response = await self._process_authenticated_mcp_message(
                    message,
                    request,
                    access_token
                )

                return JSONResponse(response)

            except Exception as e:
                logger.error(f"MCP endpoint error: {str(e)}")
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": str(e)}
                })

    async def _process_authenticated_mcp_message(
        self,
        message: Dict,
        request: Request,
        access_token: str
    ) -> Dict:
        """
        Process MCP messages after OAuth 2.1 authentication
        Validates token with SDK Manager and executes tools
        """
        method = message.get("method")
        message_id = message.get("id")
        params = message.get("params", {})

        # Track connection by client address
        client_key = f"{request.client.host}:{request.client.port}"

        if method == "initialize":
            # Generate unique connection ID
            connection_id = f"conn_{os.urandom(6).hex()}"

            # Validate token with SDK Manager
            validation_result = await _make_auth_request(
                "oauth/validate-token",
                {
                    "access_token": access_token,
                    "connection_id": connection_id,
                    "client_id": self.client_id,
                    "app_name": self.app_name
                }
            )

            if not validation_result.get("valid"):
                error_desc = validation_result.get("error_description", "Invalid or expired access token")
                raise Exception(f"Authentication failed: {error_desc}")

            # Store connection info
            self.connection_map[client_key] = {
                "connection_id": connection_id,
                "session_id": validation_result.get("session_id"),
                "user_email": validation_result.get("user_email"),
                "user_id": validation_result.get("user_id"),
                "tenant_id": validation_result.get("tenant_id"),
                "accessible_tools": validation_result.get("accessible_tools", []),
                "access_token": access_token
            }

            logger.info(f"✅ Authenticated connection: {connection_id} for user {validation_result.get('user_email')}")

            return {
                "jsonrpc": "2.0",
                "id": message_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": self.app_name,
                        "version": "1.0.0",
                        "authenticated_user": validation_result.get("user_email")
                    }
                }
            }

        # Get connection info
        connection_info = self.connection_map.get(client_key)
        if not connection_info:
            raise Exception("Connection not initialized. Please send 'initialize' request first.")

        if method == "tools/list":
            # Get accessible tools based on RBAC
            accessible_tools = connection_info.get("accessible_tools", [])

            # Filter user tools by RBAC
            filtered_user_tools = [
                tool for tool in self.user_tools
                if tool.get("name") in accessible_tools
            ]

            # Generate tool schemas
            tool_schemas = []
            for tool_meta in filtered_user_tools:
                schema = {
                    "name": tool_meta.get("name"),
                    "description": tool_meta.get("description", ""),
                    "inputSchema": tool_meta.get("inputSchema", {
                        "type": "object",
                        "properties": {},
                        "required": []
                    })
                }
                tool_schemas.append(schema)

            # Add oauth_logout tool
            tool_schemas.append({
                "name": "oauth_logout",
                "description": "Logout and revoke access token",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            })

            # Add unprotected tools (available to everyone)
            tool_schemas.extend(self.unprotected_tools)

            logger.info(f"🔧 Returning {len(tool_schemas)} tools for user {connection_info.get('user_email')}")

            return {
                "jsonrpc": "2.0",
                "id": message_id,
                "result": {"tools": tool_schemas}
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})

            # Inject session and user info into arguments
            arguments["_session_id"] = connection_info.get("session_id")
            arguments["_connection_id"] = connection_info.get("connection_id")
            arguments["_access_token"] = access_token
            arguments["_user_info"] = {
                "user_id": connection_info.get("user_id"),
                "email": connection_info.get("user_email"),
                "tenant_id": connection_info.get("tenant_id")
            }

            if tool_name == "oauth_logout":
                # Logout
                try:
                    await _make_auth_request(
                        "oauth/logout",
                        {
                            "session_id": connection_info.get("session_id"),
                            "connection_id": connection_info.get("connection_id")
                        }
                    )

                    # Remove from connection map
                    if client_key in self.connection_map:
                        del self.connection_map[client_key]

                    content = [{
                        "type": "text",
                        "text": "✅ Successfully logged out. Reconnect to authenticate again."
                    }]
                except Exception as e:
                    content = [{
                        "type": "text",
                        "text": f"⚠️ Logout error: {str(e)}"
                    }]

            elif tool_name in self.tool_handlers:
                # Execute protected tool
                try:
                    content = await self.tool_handlers[tool_name](arguments)
                except Exception as e:
                    logger.error(f"Tool execution error for {tool_name}: {str(e)}")
                    content = [{
                        "type": "text",
                        "text": json.dumps({"error": f"Tool execution failed: {str(e)}"})
                    }]
            else:
                content = [{
                    "type": "text",
                    "text": json.dumps({"error": f"Unknown tool: {tool_name}"})
                }]

            return {
                "jsonrpc": "2.0",
                "id": message_id,
                "result": {"content": content}
            }

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
    Run MCP server using SDK Manager for auth

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
    configure_auth((client_id+"-main-client"), app_name)

    # Store SPIRE socket path in global config if provided
    if spire_socket_path:
        _config["spire_socket_path"] = spire_socket_path
        _config["spire_enabled"] = True
    else:
        _config["spire_enabled"] = False

    async def _run():
        server = MCPServer((client_id+"-main-client"), app_name)
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
