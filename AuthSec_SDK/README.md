# Secure Your AI Tools in Minutes with AuthSec SDK

**Add Enterprise-Grade Authentication and Authorization to Your MCP Servers with Just 3 Lines of Code**

*Published: November 7, 2025*

---

## The Problem: Unprotected AI Tools

If you're building MCP servers for AI assistants like Claude, you've probably encountered this critical issue:

**All your tools are exposed to everyone by default.**

Without proper security, anyone who connects to your MCP server can:
- Call `delete_user_account`
- Access `view_financial_reports`
- Trigger `deploy_to_production`
- Read sensitive company data

That's a security nightmare waiting to happen.

## The Solution: AuthSec SDK

AuthSec SDK gives you enterprise-grade security in just 3 lines of code:

```python
from authsec_sdk import protected_by_AuthSec, run_mcp_server_with_oauth

@protected_by_AuthSec("admin_tool", roles=["admin"])
async def admin_tool(arguments: dict) -> list:
    return [{"type": "text", "text": "Welcome to admin panel!"}]

run_mcp_server_with_oauth(client_id="your-client-id", app_name="My Server")
```

That's it. Your tool is now protected by OAuth 2.0 and RBAC.

---

## How It Works: The Complete Flow

### Step 1: Before Authentication - Tools Are Hidden

When your MCP server starts, users only see 5 OAuth tools:
- `oauth_start` - Start authentication
- `oauth_authenticate` - Complete authentication
- `oauth_status` - Check auth status
- `oauth_logout` - Logout
- `oauth_user_info` - Get user info

**All your protected business logic tools are completely hidden.** Users can't even see they exist.

### Step 2: User Starts Authentication

```
User: Call oauth_start
Server: Here's your session_id and authorization URL
```

The user opens the URL in their browser and authenticates with your OAuth provider (Google, GitHub, Custom Logon, etc.).

### Step 3: Complete Authentication with JWT

After authentication, the user receives a JWT token containing:

```json
{
  "email": "john@company.com",
  "tenant_id": "acme-corp",
  "roles": ["admin", "developer"],
  "groups": ["engineering"],
  "scopes": ["read", "write"],
  "resources": ["projects", "analytics"]
}
```

They call `oauth_authenticate` with this token.

### Step 4: RBAC Magic - Validating Permissions

Here's where AuthSec SDK does the heavy lifting. For **each tool** in your server, it:

1. Connects to your tenant database (`tenant_acme-corp`)
2. Validates JWT claims against database:
   - Does `admin` role exist in `roles` table? ✓
   - Does `write` scope exist in `scopes` table? ✓
   - Does `analytics` resource exist in `resources` table? ✓
3. Checks if user satisfies tool requirements
4. Returns list of accessible tools

**Example validation**:

```python
# Tool 1: No RBAC - accessible to all authenticated users
@protected_by_AuthSec("calculator")
async def calculator(...) -> list:
    ...

# Tool 2: Requires admin role
@protected_by_AuthSec("admin_dashboard", roles=["admin"])
async def admin_dashboard(...) -> list:
    ...

# Tool 3: Requires write scope AND analytics resource
@protected_by_AuthSec(
    "view_analytics",
    scopes=["read"],
    resources=["analytics"],
    require_all=True
)
async def view_analytics(...) -> list:
    ...
```

**For our user** (roles=["admin"], scopes=["read", "write"], resources=["analytics"]):
- ✅ `calculator` - Accessible (all authenticated users)
- ✅ `admin_dashboard` - Accessible (has admin role)
- ✅ `view_analytics` - Accessible (has read scope + analytics resource)

### Step 5: Tools Are Now Visible

After authentication, users see only what they can access:

```
Available tools:
├── oauth_start
├── oauth_authenticate
├── oauth_status
├── calculator            # ← Now visible
├── admin_dashboard       # ← Now visible (has admin role)
└── view_analytics        # ← Now visible (has permissions)
```

### Step 6: Tool Execution with User Context

When a user calls a protected tool, user information is automatically injected:

```python
@protected_by_AuthSec("admin_dashboard", roles=["admin"])
async def admin_dashboard(arguments: dict) -> list:
    # User info automatically available
    email = arguments['_user_info']['email']        # "john@company.com"
    roles = arguments['_user_info']['roles']        # ["admin", "developer"]
    tenant = arguments['_user_info']['tenant_id']   # "acme-corp"

    return [{
        "type": "text",
        "text": f"Welcome to admin dashboard, {email}!"
    }]
```

---

## Real-World Use Case: GitHub Integration (External-Service Integration)

Let's build a tool that lists GitHub repositories using credentials stored securely in HashiCorp Vault.

### Setup: Store Credentials in Dashboard

1. Log in to [AuthSec Dashboard](https://app.authsec.dev)
2. Navigate to Services section
3. Add service: "GitHub API Integration"
4. Store credential: `access_token` = `ghp_YOUR_TOKEN`
5. Credentials are encrypted and stored in Vault

### Code: Use Credentials Securely

```python
import aiohttp
from authsec_sdk import protected_by_AuthSec, ServiceAccessSDK

@protected_by_AuthSec("list_my_repos", scopes=["read"])
async def list_my_repos(arguments: dict, session) -> list:
    """List user's GitHub repositories."""

    # Create services SDK
    services_sdk = ServiceAccessSDK(session)

    # Fetch GitHub token from Vault (secure!)
    github_token = await services_sdk.get_service_token("GitHub API Integration")

    # Call GitHub API
    async with aiohttp.ClientSession() as http:
        async with http.get(
            'https://api.github.com/user/repos',
            headers={'Authorization': f'Bearer {github_token}'}
        ) as response:
            repos = await response.json()

    # Format response
    repo_list = "\n".join([
        f"- {repo['full_name']} ({repo['stargazers_count']} ⭐)"
        for repo in repos[:10]
    ])

    return [{
        "type": "text",
        "text": f"Your GitHub Repositories:\n{repo_list}"
    }]
```

**Security benefits**:
- ✅ Token stored in Vault, not in code
- ✅ Only users with `read` scope can access
- ✅ Token never exposed to end users
- ✅ All access logged and auditable
- ✅ Credentials can be rotated from dashboard

---

## Advanced RBAC Patterns

### OR Logic - Any Permission Grants Access

```python
@protected_by_AuthSec(
    "view_reports",
    roles=["admin", "manager", "analyst"],
    require_all=False  # Default: OR logic
)
async def view_reports(arguments: dict) -> list:
    return [{"type": "text", "text": "Business reports"}]
```

**Accessible to**: Users with `admin` **OR** `manager` **OR** `analyst` role

### AND Logic - All Permissions Required

```python
@protected_by_AuthSec(
    "deploy_production",
    roles=["admin", "deployer"],      # User needs admin OR deployer
    scopes=["write"],                 # AND user needs write scope
    resources=["production"],         # AND user needs production resource
    require_all=True                  # All conditions must pass
)
async def deploy_production(arguments: dict) -> list:
    return [{"type": "text", "text": "Deployment initiated"}]
```

**Accessible to**: Users with (`admin` **OR** `deployer`) **AND** `write` **AND** `production` resource

### Group-Based Access

```python
@protected_by_AuthSec(
    "engineering_tools",
    groups=["engineering", "devops"]
)
async def engineering_tools(arguments: dict) -> list:
    return [{"type": "text", "text": "Engineering dashboard"}]
```

**Accessible to**: Users in `engineering` **OR** `devops` group

### Complex Multi-Requirement Tool

```python
@protected_by_AuthSec(
    "sensitive_operations",
    roles=["admin", "superuser"],
    groups=["security-team"],
    scopes=["write", "admin"],
    resources=["production", "sensitive-data"],
    require_all=True
)
async def sensitive_operations(arguments: dict) -> list:
    # Only accessible if ALL conditions are met:
    # - Has admin OR superuser role
    # - In security-team group
    # - Has write OR admin scope
    # - Has access to production AND sensitive-data resources
    return [{"type": "text", "text": "Sensitive operation completed"}]
```

---

## Getting Started in 5 Minutes

### 1. Install the SDK

```bash
pip install git+https://github.com/authsec-ai/sdk-authsec.git
```

### 2. Get Your Client Credentials

1. Sign up at [AuthSec Dashboard](https://app.authsec.dev)
2. Create a new application (MCP)
3. Copy your `client_id`
4. Configure your authentication methods for users
5. Configure RBAC rules (roles, scopes, resources)

### 3. Create Your Secure MCP Server

```python
# server.py
from authsec_sdk import protected_by_AuthSec, run_mcp_server_with_oauth

# Tool 1: Accessible to all authenticated users
@protected_by_AuthSec("hello")
async def hello(arguments: dict) -> list:
    return [{
        "type": "text",
        "text": f"Hello, {arguments['_user_info']['email']}!"
    }]

# Tool 2: Admin only
@protected_by_AuthSec("admin_panel", roles=["admin"])
async def admin_panel(arguments: dict) -> list:
    return [{"type": "text", "text": "Admin panel accessed"}]

# Tool 3: Requires write permission
@protected_by_AuthSec("create_resource", scopes=["write"])
async def create_resource(arguments: dict) -> list:
    name = arguments.get("name", "Unnamed")
    return [{
        "type": "text",
        "text": f"Resource '{name}' created successfully!"
    }]

# Start the server
if __name__ == "__main__":
    run_mcp_server_with_oauth(
        client_id="your-client-id-here",
        app_name="My Secure MCP Server"
    )
```

### 4. Run Your Server

```bash
python server.py
```

### 5. Test It Out

From your MCP Clients (MCP Inspector, VS Code, Claude, Windows, etc.):

```
User: Show me available tools
> Only OAuth tools are visible

User: Call oauth_start
> Returns session_id and authorization URL

User: [Opens URL and authenticates]
> Receives JWT token

User: Call oauth_authenticate with token
> Authentication successful!
> Protected tools now visible

User: Call hello
> "Hello, john@company.com!"

User: Call admin_panel
> "Admin panel accessed" (only if admin role)

User: Call create_resource with name="Project Alpha"
> "Resource 'Project Alpha' created!" (only if write scope)
```

---

## Architecture Overview

```
        ┌─────────────────────────────────┐
        │   AI Assistant (Claude, etc.)   │
        │         MCP Client              │
        └────────────┬────────────────────┘
                     │ JSON-RPC 2.0
                     ▼
        ┌─────────────────────────────────┐
        │   Your MCP Server (server.py)   │
        │     with AuthSec SDK            │
        │                                 │
        │  OAuth Tools (always visible):  │
        │  ├── oauth_start                │
        │  ├── oauth_authenticate         │
        │  └── oauth_status               │
        │                                 │
        │  Protected Tools (after auth):  │
        │  ├── @protected_by_AuthSec      │
        │  │   ("hello")                  │
        │  ├── @protected_by_AuthSec      │
        │  │   ("admin_panel",            │
        │  │    roles=["admin"])          │
        │  └── ...                        │
        └────────────┬────────────────────┘
                     │ HTTPS
                     ▼
        ┌─────────────────────────────────┐
        │  AuthSec SDK Manager Service    │
        │    (Managed by AuthSec)         │
        │                                 │
        │   ├── OAuth flow management     │
        │   ├── JWT validation            │
        │   ├── RBAC checking             │
        │   ├── Session management        │
        │   └── Vault integration         │
        └────────────┬────────────────────┘
                     │
                     ▼
        ┌─────────────────────────────────┐
        │      External Services          │
        │  ├── OAuth Provider             │
        │  ├── HashiCorp Vault            │
        │  └── Tenant Database            │
        └─────────────────────────────────┘
```

### Multi-Tenant Architecture

- **Master Database**: Tenant mappings
- **Tenant Databases**: Each tenant has isolated database (`tenant_{tenant_id}`)
  - RBAC tables (roles, scopes, resources, permissions)
  - Authenticated sessions
  - Service configurations
  - User data

---

## Before vs After AuthSec SDK

### Before: Insecure and Messy

```python
# server.py
async def admin_dashboard(arguments: dict) -> list:
    # ❌ No authentication - anyone can call this!
    # ❌ No authorization - can't restrict by role!
    # ❌ Credentials hardcoded - major security risk!
    github_token = "ghp_hardcoded_token_in_my_code"

    # Call GitHub API...
    return [{"type": "text", "text": "Dashboard"}]
```

**Problems**:
- ❌ No authentication
- ❌ No authorization/RBAC
- ❌ Credentials in source code
- ❌ All tools always visible to everyone
- ❌ No audit trail
- ❌ No multi-tenancy

### After: Secure and Clean

```python
# server.py
from authsec_sdk import protected_by_AuthSec, ServiceAccessSDK

@protected_by_AuthSec("admin_dashboard", roles=["admin"])
async def admin_dashboard(arguments: dict, session) -> list:
    # ✅ Authenticated - only valid users
    # ✅ Authorized - only admins can access
    # ✅ Credentials from Vault - secure!

    services_sdk = ServiceAccessSDK(session)
    github_token = await services_sdk.get_service_token("GitHub API")

    # Call GitHub API...
    return [{"type": "text", "text": "Dashboard"}]
```

**Benefits**:
- ✅ OAuth 2.0 authentication
- ✅ RBAC authorization
- ✅ Link any External-Service PROVIDER
- ✅ Credentials in Vault
- ✅ Tools hidden until authenticated
- ✅ Full audit trail
- ✅ Multi-tenant ready

---

## Key Features

### 🔐 Authentication (AuthN)
- OAuth 2.0 flow with PKCE security
- JWT token validation and management
- Persistent session handling
- Multi-tenant support out of the box

### 🛡️ Authorization (AuthZ)
- Role-Based Access Control (RBAC)
- Dynamic tool filtering (users only see permitted tools)
- Flexible permissions: roles, groups, scopes, resources
- Database-backed validation (not just JWT claims)
- AND/OR logic support

### 🔑 External Service Integration
- HashiCorp Vault integration
- Secure credential storage via UI
- Support for any API (GitHub, AWS, databases, Slack, etc.)
- Automatic credential rotation
- No credentials in code

### ✨ Developer Experience
- Single decorator to protect tools
- Minimal code changes
- Automatic tool hiding/showing
- User context auto-injected
- Zero security expertise required

---

## Frequently Asked Questions

**Q: Do I need to modify my existing tools significantly?**
A: No! Just add the `@protected_by_AuthSec` decorator. Minimal changes required.

**Q: What happens if a user loses their JWT token?**
A: They simply re-authenticate by calling `oauth_start` again. The entire process takes less than 30 seconds.

**Q: Can I use my own OAuth provider?**
A: Absolutely! AuthSec SDK works with any OAuth 2.0 provider (Google, GitHub, Custom Logon, etc.).

**Q: How does RBAC validation actually work?**
A: User roles/scopes from JWT are validated against your tenant database. Access is granted only if they exist in both places.

**Q: Are credentials really secure?**
A: Yes. Credentials are stored in HashiCorp Vault, never in your code. They're fetched on-demand and never exposed to end users.

**Q: What's the performance impact?**
A: Minimal. AuthSec SDK uses connection pooling and caching. Typical validation overhead is <5ms per request.

**Q: Can I test this locally?**
A: Yes! You can run your MCP server locally using AuthSec SDK locally for testing as well.

**Q: What about compliance and audit logs?**
A: All authentication and tool access is logged. Audit logging features are available on the [AuthSec Dashboard](https://app.authsec.dev) 

---

## SPIRE Workload Identity Integration

AuthSec SDK now includes **SPIRE (SPIFFE Runtime Environment)** integration for service-to-service mTLS authentication. This allows your MCP servers to establish secure, zero-trust communication with backend services using cryptographically-verified workload identities.

### What is SPIRE?

SPIRE provides **workload attestation** and issues short-lived **X.509-SVIDs** (SPIFFE Verifiable Identity Documents) that workloads use for mutual TLS (mTLS) authentication. This eliminates the need for long-lived secrets or API keys when services communicate with each other.

**Key benefits**:
- ✅ **Zero-trust security**: Every service has a cryptographically-verifiable identity
- ✅ **No shared secrets**: No API keys or passwords in configuration
- ✅ **Automatic rotation**: Certificates auto-renew every 30 minutes
- ✅ **mTLS by default**: All service-to-service traffic is encrypted and authenticated
- ✅ **Works everywhere**: Kubernetes, Docker, VMs, bare metal

### SPIRE is Optional

SPIRE integration is completely optional. If you don't enable it, your MCP server works exactly as before. SPIRE is only enabled when you provide a `spire_socket_path` parameter.

### How to Enable SPIRE

AuthSec SDK supports **three SPIRE usage modes**:

#### Mode 1: MCP Server Integration (Recommended for Multi-Tenant)

Enable SPIRE by adding `spire_socket_path` parameter when starting your MCP server. SPIRE calls are routed through SDK Manager for multi-tenant isolation.

```python
from authsec_sdk import run_mcp_server_with_oauth

if __name__ == "__main__":
    run_mcp_server_with_oauth(
        client_id="your-client-id-here",
        app_name="My Secure MCP Server",
        spire_socket_path="/run/spire/sockets/agent.sock"  # Enable SPIRE
    )
```

#### Mode 2: Standalone with SDK Manager (Multi-Tenant)

Use SPIRE outside of MCP server context, but still route through SDK Manager for tenant isolation:

```python
from authsec_sdk import QuickStartSVID

# Initialize with client_id (routes through SDK Manager)
svid = await QuickStartSVID.initialize(
    client_id="your-client-id",
    socket_path="/run/spire/sockets/agent.sock"
)

# Use for mTLS
ssl_context = svid.create_ssl_context_for_client()
```

#### Mode 3: Direct gRPC Mode (Single Workload)

Connect directly to SPIRE agent via gRPC without SDK Manager. Best for standalone workloads that don't need multi-tenant isolation:

```python
from authsec_sdk import QuickStartSVID

# Initialize without client_id (direct gRPC to agent)
svid = await QuickStartSVID.initialize(
    socket_path="/run/spire/sockets/agent.sock"
)

# Use for mTLS
ssl_context = svid.create_ssl_context_for_client()
```

**Prerequisites**:
- SPIRE agent must be running on the same host as your workload
- Your workload must be registered in the SPIRE server
- The socket path must match your SPIRE agent configuration

### Using SPIRE in Your Tools

Once SPIRE is enabled, you can use workload identities in your protected tools:

#### Example 1: Optional SPIRE Usage (Graceful Degradation)

```python
from authsec_sdk import protected_by_AuthSec, QuickStartSVID
import httpx

@protected_by_AuthSec("call_backend_service", roles=["admin"])
async def call_backend_service(arguments: dict) -> list:
    """Call backend service with optional mTLS"""

    # Initialize SPIRE (returns None if not enabled)
    svid = await QuickStartSVID.initialize()

    if svid:
        # SPIRE enabled: Use mTLS
        ssl_context = svid.create_ssl_context_for_client()
        async with httpx.AsyncClient(verify=ssl_context) as client:
            response = await client.get("https://backend.authsec.svc:8443/api/data")
    else:
        # SPIRE disabled: Fall back to regular HTTPS
        async with httpx.AsyncClient() as client:
            response = await client.get("https://backend.company.com/api/data")

    data = response.json()
    return [{"type": "text", "text": f"Response: {data}"}]
```

#### Example 2: Required SPIRE Usage

```python
from authsec_sdk import protected_by_AuthSec, QuickStartSVID
import httpx

@protected_by_AuthSec("secure_payment", roles=["admin"])
async def secure_payment(arguments: dict) -> list:
    """Process payment - requires SPIRE mTLS"""

    # Raise error if SPIRE is not enabled
    svid = await QuickStartSVID.initialize(raise_on_disabled=True)

    # Use SPIRE identity for mTLS
    ssl_context = svid.create_ssl_context_for_client()

    async with httpx.AsyncClient(verify=ssl_context) as client:
        response = await client.post(
            "https://payment-service.authsec.svc:8443/process",
            json={
                "user": arguments['_user_info']['email'],
                "amount": arguments.get('amount', 100.00)
            }
        )
        data = response.json()

    return [{"type": "text", "text": f"Payment processed: {data}"}]
```

#### Example 3: Combined MCP Auth + SPIRE + Vault

```python
from authsec_sdk import protected_by_AuthSec, QuickStartSVID, ServiceAccessSDK
import aiohttp
import httpx

@protected_by_AuthSec("github_with_audit", scopes=["read"])
async def github_with_audit(arguments: dict, session) -> list:
    """
    Combines three security layers:
    1. MCP authentication (user must have 'read' scope)
    2. External service credentials (GitHub from Vault)
    3. SPIRE mTLS (for calling internal audit service)
    """
    user_info = arguments['_user_info']

    # Get GitHub credentials from Vault
    services_sdk = ServiceAccessSDK(session)
    github_token = await services_sdk.get_service_token("GitHub API Integration")

    # Call GitHub API with OAuth token
    async with aiohttp.ClientSession() as http_session:
        async with http_session.get(
            'https://api.github.com/user/repos',
            headers={'Authorization': f'Bearer {github_token}'}
        ) as response:
            repos = await response.json()

    # Log to internal audit service with SPIRE mTLS (optional)
    svid = await QuickStartSVID.initialize()
    if svid:
        ssl_context = svid.create_ssl_context_for_client()
        async with httpx.AsyncClient(verify=ssl_context) as client:
            await client.post(
                "https://audit-service.authsec.svc:8443/log",
                json={
                    "user": user_info['email'],
                    "action": "github_repos_accessed",
                    "repo_count": len(repos)
                }
            )

    repo_list = "\n".join([f"- {repo['full_name']}" for repo in repos[:10]])
    return [{"type": "text", "text": f"GitHub Repositories:\n{repo_list}"}]
```

### SPIRE Certificate Details

When SPIRE is initialized, it automatically:

1. **Fetches SVID** from local SPIRE agent via SDK Manager
2. **Writes certificates** to disk (`/tmp/spiffe-certs/` by default)
3. **Creates SSL contexts** for mTLS client and server connections
4. **Auto-renews** certificates every 30 minutes

You can access certificate information:

```python
svid = await QuickStartSVID.initialize()

# SPIFFE ID (workload identity)
print(svid.spiffe_id)  # e.g., "spiffe://example.org/my-service"

# Certificate paths
print(svid.cert_file_path)  # /tmp/spiffe-certs/svid.crt
print(svid.key_file_path)   # /tmp/spiffe-certs/svid.key
print(svid.ca_file_path)    # /tmp/spiffe-certs/ca.crt

# Raw PEM strings
print(svid.certificate)     # X.509 certificate PEM
print(svid.private_key)     # Private key PEM
print(svid.trust_bundle)    # CA bundle PEM
```

### SPIRE for Server-Side mTLS

If you're building a service that accepts mTLS connections, use the server SSL context:

```python
from authsec_sdk import QuickStartSVID
import uvicorn
from fastapi import FastAPI

app = FastAPI()

@app.get("/secure-endpoint")
async def secure_endpoint():
    return {"message": "mTLS connection verified"}

if __name__ == "__main__":
    # Initialize SPIRE
    import asyncio
    svid = asyncio.run(QuickStartSVID.initialize(raise_on_disabled=True))

    # Create server SSL context
    ssl_context = svid.create_ssl_context_for_server()

    # Run server with mTLS
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8443,
        ssl_keyfile=str(svid.key_file_path),
        ssl_certfile=str(svid.cert_file_path),
        ssl_ca_certs=str(svid.ca_file_path),
        ssl_cert_reqs=2  # Require client certificates
    )
```

### SPIRE Configuration Options

You can customize SPIRE behavior with additional parameters:

```python
run_mcp_server_with_oauth(
    client_id="your-client-id",
    app_name="My Server",
    spire_socket_path="/run/spire/sockets/agent.sock",  # Required to enable SPIRE
)
```

### Troubleshooting SPIRE

**Q: My tool crashes when SPIRE is not enabled**
```python
# ❌ Bad: Will crash if SPIRE is disabled
svid = await QuickStartSVID.initialize(raise_on_disabled=True)

# ✅ Good: Returns None if SPIRE is disabled
svid = await QuickStartSVID.initialize()
if svid:
    # Use SPIRE
    pass
else:
    # Fall back to alternative approach
    pass
```

**Q: How do I check if SPIRE is enabled?**
```python
from authsec_sdk import QuickStartSVID

svid = await QuickStartSVID.initialize()
if svid:
    print(f"SPIRE enabled. Identity: {svid.spiffe_id}")
else:
    print("SPIRE disabled")
```

**Q: Agent connection failed**
- Verify SPIRE agent is running: `systemctl status spire-agent`
- Check socket path matches agent config: `/run/spire/sockets/agent.sock`
- Ensure workload is registered in SPIRE server
- Check environment variables (K8s pod labels, Docker labels)

**Q: Certificates not renewing**
- Check logs for renewal errors
- Verify agent connection is stable
- Ensure workload registration hasn't expired

### SPIRE Architecture

```
┌─────────────────────────────────────┐
│   Your MCP Server (server.py)      │
│      with AuthSec SDK               │
│                                     │
│   @protected_by_AuthSec             │
│   async def my_tool():              │
│       svid = await QuickStartSVID   │
│         .initialize()               │
│       ssl_ctx = svid.create_ssl()   │
└──────────┬──────────────────────────┘
           │ HTTPS
           ▼
┌─────────────────────────────────────┐
│   AuthSec SDK Manager Service       │
│                                     │
│   ├── Maps client_id to tenant_id  │
│   ├── Validates tenant access       │
│   └── Proxies to SPIRE agent        │
└──────────┬──────────────────────────┘
           │ gRPC (unix socket)
           ▼
┌─────────────────────────────────────┐
│   SPIRE Agent (local)               │
│                                     │
│   ├── Attests workload identity     │
│   ├── Issues X.509-SVID             │
│   └── Manages certificate rotation  │
└──────────┬──────────────────────────┘
           │ gRPC
           ▼
┌─────────────────────────────────────┐
│   SPIRE Server (central)            │
│                                     │
│   ├── Certificate Authority         │
│   ├── Workload registry             │
│   └── Trust domain management       │
└─────────────────────────────────────┘
```

**Key points**:
- Your SDK code makes REST calls to SDK Manager (not direct gRPC)
- SDK Manager handles client_id → tenant_id mapping (same as MCP auth)
- SDK Manager proxies SVID fetch to local SPIRE agent
- Certificates are written to disk and auto-renewed every 30 minutes
- All complexity is hidden from your application code

### SPIRE + MCP Auth: Complete Zero-Trust Architecture

Combining MCP authentication with SPIRE workload identity gives you end-to-end zero-trust security:

1. **User-to-Service**: MCP OAuth ensures only authenticated users can access tools
2. **RBAC Authorization**: Database-backed role checking controls what users can do
3. **Service-to-Service**: SPIRE mTLS ensures only verified services can communicate
4. **External Services**: Vault integration keeps credentials secure

```python
@protected_by_AuthSec("zero_trust_operation", roles=["admin"])
async def zero_trust_operation(arguments: dict, session) -> list:
    # Layer 1: User authenticated via MCP OAuth ✓
    # Layer 2: User has admin role (RBAC) ✓
    user_email = arguments['_user_info']['email']

    # Layer 3: External service credentials from Vault ✓
    services_sdk = ServiceAccessSDK(session)
    api_key = await services_sdk.get_service_token("Payment API")

    # Layer 4: Service-to-service mTLS via SPIRE ✓
    svid = await QuickStartSVID.initialize()
    ssl_context = svid.create_ssl_context_for_client()

    # Now make secure service call
    async with httpx.AsyncClient(verify=ssl_context) as client:
        response = await client.post(
            "https://payment.authsec.svc:8443/charge",
            headers={"X-API-Key": api_key},
            json={"user": user_email, "amount": 100.00}
        )

    return [{"type": "text", "text": "Zero-trust operation completed"}]
```

**All four security layers working together**:
- ✅ **AuthN**: User authenticated via OAuth
- ✅ **AuthZ**: User authorized via RBAC
- ✅ **Secrets**: API keys from Vault
- ✅ **mTLS**: Service identity via SPIRE

---

## Get Started Today

Secure your MCP server in just 5 minutes:

1. **Sign up**: [app.authsec.dev](https://app.authsec.dev)
2. **Install SDK**: `pip install authsec-sdk`
3. **Add decorator**: `@protected_by_AuthSec("tool_name", roles=["admin"])`
4. **Run server**: `python my_server.py`

That's it. Your tools are now protected by enterprise-grade security.

---

## Resources

- **Blogs**: [docs.authsec.dev](https://authsec.dev/blogs)
- **Dashboard**: [app.authsec.dev](https://app.authsec.dev)
- **GitHub**: [github.com/authsec-ai/sdk-authsec](https://github.com/authsec-ai/sdk-authsec.git)
- **Support**: support@authsec.dev

---

## Conclusion

Building secure AI tools shouldn't be complicated. With AuthSec SDK, you get:

- ✅ OAuth 2.0 authentication in 3 lines of code
- ✅ Flexible RBAC with database validation
- ✅ Secure credential management with Vault
- ✅ Dynamic tool filtering based on permissions
- ✅ Multi-tenant architecture out of the box
- ✅ Zero security expertise required

Stop building security infrastructure from scratch. Start building secure AI tools that your users can trust.

**Try AuthSec SDK today**: [app.authsec.dev](https://app.authsec.dev)

---

**Built with ❤️ by the AuthSec team**

*Have questions? Reach out at support@authsec.dev
