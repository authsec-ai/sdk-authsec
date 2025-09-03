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
import atexit
from typing import Dict, Optional, List, Callable, Any
from functools import wraps
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import logging

logger = logging.getLogger(__name__)

# Global configuration storage
_config = {
    "client_id": None,
    "app_name": None,
    "auth_service_url": "https://dev.api.authsec.dev/sdkmgr/mcp-auth",
    "timeout": 10,
    "retries": 3
}

def configure_auth(
    client_id: str,
    app_name: str,
    auth_service_url: Optional[str] = None,
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
    
    print(f"Auth configured: {app_name} with client_id: {client_id[:8]}...")
    print(f"Auth service URL: {_config['auth_service_url']}")

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

def protected_by_AuthSec(tool_name: str):
    """Decorator to protect tools via SDK Manager auth service API."""
    def decorator(func: Callable) -> Callable:
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
            
            # Call the original business function
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
        
        return wrapper
    return decorator

# ===========================================================================
# MCP SERVER IMPLEMENTATION
# ===========================================================================

class MCPServer:
    """Minimal MCP server that delegates to hosted SDK Manager"""
    
    def __init__(self, client_id: str, app_name: str):
        self.client_id = client_id
        self.app_name = app_name
        self.user_tools: List[str] = []
        self.tool_handlers: Dict[str, Callable] = {}
        
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
        """Discover protected tools from user module"""
        for name, obj in inspect.getmembers(module):
            if (inspect.iscoroutinefunction(obj) and 
                hasattr(obj, '__wrapped__') and 
                not name.startswith('_')):
                
                self.user_tools.append(name)
                self.tool_handlers[name] = obj
    
    def _setup_routes(self):
        """Setup MCP protocol routes"""
        
        @self.app.get("/")
        async def root():
            return {
                "name": self.app_name,
                "version": "1.0.0",
                "protocol": "mcp-with-oauth",
                "status": "running",
                "auth_service": _config["auth_service_url"]
            }
        
        @self.app.post("/")
        async def mcp_endpoint(request: Request):
            try:
                body = await request.body()
                message = json.loads(body.decode('utf-8'))
                response = await self._process_mcp_message(message)
                return JSONResponse(response)
            except Exception as e:
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": str(e)}
                })
    
    async def _process_mcp_message(self, message: Dict) -> Dict:
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
            # Delegate to hosted service
            tools_response = await _make_auth_request(
                "tools/list",
                {
                    "client_id": self.client_id,
                    "app_name": self.app_name,
                    "user_tools": self.user_tools
                }
            )
            return {"jsonrpc": "2.0", "id": message_id, "result": {"tools": tools_response.get("tools", [])}}
        
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            
            if tool_name.startswith("oauth_"):
                # Delegate OAuth tools to hosted service
                tool_response = await _make_auth_request(
                    f"tools/call/{tool_name}",
                    {
                        "client_id": self.client_id,
                        "app_name": self.app_name,
                        "arguments": arguments
                    }
                )
                content = tool_response.get("content", [{"type": "text", "text": json.dumps({"error": "Tool execution failed"})}])
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

def run_mcp_server_with_oauth(user_module, client_id: str, app_name: str, host: str = "0.0.0.0", port: int = 3005):
    """Run MCP server using SDK Manager for auth"""
    configure_auth(client_id, app_name)
    async def _run():
        server = MCPServer(client_id, app_name)
        server.set_user_module(user_module)
        
        print(f"Starting {app_name} MCP Server on {host}:{port}")
        print(f"Authentication via: {_config['auth_service_url']}")
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