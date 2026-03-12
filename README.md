# Secure Your AI Tools in Minutes with AuthSec SDK

**Add Enterprise-Grade Authentication and Authorization to Your MCP Servers with Just 3 Lines of Code**

*Published: November 7, 2025*

---

## Repository Structure

This repository is organized as a monorepo with professional package boundaries:

- `packages/python-sdk`: Python package (`authsec_sdk`)
- `packages/typescript-sdk`: TypeScript package (`@authsec/sdk`)

### Local Development

Install (consumers):

Python (PyPI):

macOS / Linux:

```bash
python3 -m pip install -U authsec-sdk
```

Windows PowerShell:

```powershell
py -3 -m pip install -U authsec-sdk
```

TypeScript (npm):

```bash
npm install @authsec/sdk
```

From GitHub monorepo (advanced, Python):

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install "git+https://github.com/authsec-ai/sdk-authsec.git@main#subdirectory=packages/python-sdk"
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
py -3 -m pip install --upgrade pip
py -3 -m pip install "git+https://github.com/authsec-ai/sdk-authsec.git@main#subdirectory=packages/python-sdk"
```

See `packages/python-sdk/README.md` for full OS-specific install, run, and troubleshooting steps.

Repo contributor setup:

Python SDK:

```bash
python3 -m pip install -e packages/python-sdk
```

TypeScript SDK:

```bash
cd packages/typescript-sdk
npm install
npm run build
```

Memory MCP wrapper example:

```bash
cd packages/typescript-sdk
AUTHSEC_CLIENT_ID="<your-client-id>" npm run example:memory
```

### Publishing (Python)

```bash
cd packages/python-sdk
python3 -m pip install --upgrade build twine
python3 -m build
python3 -m twine check dist/*
# Optional dry run on TestPyPI:
# python3 -m twine upload --repository testpypi dist/*
# Publish:
python3 -m twine upload dist/*
```

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

if __name__ == "__main__":
    import __main__

    run_mcp_server_with_oauth(
        user_module=__main__,
        client_id="your-client-id",
        app_name="My Server",
    )
```

That's it. Your tool is now protected by OAuth 2.0 and RBAC.

### What AuthSec Does (and Why There’s a Server Wrapper)

AuthSec is the **control plane**:
- Users authenticate through AuthSec (SSO/IdP lives outside your MCP server).
- Users show up in the AuthSec web app, where you assign roles/permissions and conditional access policies.
- AuthSec becomes the source of truth for who can see/call which MCP tools.

The SDK is the **enforcement layer**:
- It provides a minimal MCP server runtime (or wrapper) so your tools run behind an enforcement point.
- OAuth tools (`oauth_*`) and authorization decisions are delegated upstream to AuthSec SDK Manager.
- Protected tool calls are enforced at call time (deny means your handler is not executed). Tool hiding in `tools/list` is a UX improvement, not the security boundary.

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

### Step 4: Authorization (RBAC + Conditional Access)

AuthSec is the source of truth for authorization:

1. After a user logs in, they appear in the AuthSec web app.
2. You assign roles/permissions (and optional conditional access policies) to the user.
3. When a protected tool is called, the SDK asks AuthSec whether the session is allowed to call that tool right now.
4. If denied, the SDK returns an error and your business handler is not executed.

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
python3 -m pip install authsec-sdk
```

If you can’t use PyPI, prefer the macOS one-command bootstrap (or see `packages/python-sdk/README.md` for GitHub/Windows install options).

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
    import __main__

    run_mcp_server_with_oauth(
        user_module=__main__,
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

## Copy-Paste Prompt for Any Coding Assistant (MCP Wrap + RBAC Matrix)

Use the prompt below when onboarding an existing MCP server.  
It instructs the assistant to discover tools, ask requirements, generate an RBAC matrix, implement wrapping, and validate.

```text
You are a senior MCP security integration engineer. Your job is to integrate AuthSec SDK into an existing MCP server so tools are protected with OAuth + RBAC.

Important:
- Assume the developer may know nothing about AuthSec internals.
- Do not mention internal service architecture unless asked.
- Keep instructions implementation-focused.

Phase 0 - Install and verify dependencies first:
1) Detect Python package manager setup in the repo.
2) Install SDK dependency:
   - preferred: pip install authsec-sdk
   - fallback: follow `packages/python-sdk/README.md` (GitHub monorepo install commands)
3) Verify imports compile:
   from authsec_sdk import protected_by_AuthSec, run_mcp_server_with_oauth
4) If install/import fails, stop and show exact fix commands.

Phase 1 - Discover the MCP server:
1) Locate server entrypoint file(s).
2) List all tools in a table:
   tool_name | what_it_does | current_auth_state | risk_level
3) Identify which tools are currently public and which should likely be protected.

Phase 2 - Ask user questions before coding (mandatory):
1) Which tools must stay public?
2) Which tools must require login?
3) Which roles should exist? (example: admin, operator, analyst, viewer)
4) For each tool, which roles are allowed?
5) Any scope/resource constraints? (example: write, billing, project:read)
6) Should tool checks use ANY condition or ALL conditions?
7) Should unauthorized tools be hidden from tool list or visible with RBAC denied on call?
8) Do you want SDK scripts to create roles/permissions/bindings automatically?

If user answers are incomplete, propose defaults and request confirmation.

Phase 3 - Build RBAC artifacts:
Generate and show:
1) Role catalog: role_name | purpose
2) Permission catalog: permission_key(resource:action) | description
3) Tool policy table: tool_name | roles | scopes | resources | permissions | require_all
4) Role-permission matrix (markdown table) with allow/deny cells.

Phase 4 - Implement integration:
1) Add SDK imports:
   from authsec_sdk import protected_by_AuthSec, run_mcp_server_with_oauth
2) Wrap each protected tool:
   @protected_by_AuthSec("tool_name", roles=[...], scopes=[...], permissions=[...], require_all=...)
3) Preserve all business logic; only add auth wrapper and safe auth checks.
4) Make startup env-driven:
   AUTHSEC_CLIENT_ID, AUTHSEC_APP_NAME, AUTHSEC_HOST, AUTHSEC_PORT
   Optional endpoint overrides:
   AUTHSEC_AUTH_SERVICE_URL, AUTHSEC_SERVICES_URL
5) Never hardcode secrets, tokens, or local URLs in committed code.

Phase 5 - Optional bootstrap scripts (if requested):
Generate scripts that use SDK/admin APIs to:
1) create permissions
2) create roles
3) bind roles to users

Phase 6 - Validate end to end:
Run and report:
1) tools/list before login
2) oauth_start -> oauth_authenticate
3) call allowed tool with authorized identity
4) call protected tool with unauthorized identity
5) verify denied call returns explicit RBAC denial

Phase 7 - Deliverables:
Return:
1) changed file list and diffs summary
2) final RBAC matrix
3) `.env.example` template
4) exact run commands for the MCP server
5) test/verification evidence and remaining risks

Output format:
1) short summary
2) Q&A decisions captured
3) RBAC tables
4) code changes
5) run commands
6) validation evidence
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
        │   AuthSec Auth Service          │
        │    (managed by AuthSec)         │
        │                                 │
        │   ├── OAuth flow management     │
        │   ├── JWT validation            │
        │   ├── RBAC + policy decisions   │
        │   ├── Session management        │
        │   └── Vault integration         │
        └────────────┬────────────────────┘
                     │
                     ▼
        ┌─────────────────────────────────┐
        │      External Services          │
        │  ├── Your IdP (Okta/AzureAD)    │
        │  └── Secrets store (optional)   │
        └─────────────────────────────────┘
```

### Multi-Tenant

AuthSec is multi-tenant by design: users, roles/permissions, conditional access policies, sessions, and service integrations are configured per tenant in the AuthSec web app. Your MCP server does not need to run (or manage) a tenant database to use RBAC.

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
- Central policy evaluation in AuthSec (configured in the web app)
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
A: You assign users roles/permissions in the AuthSec web app. On every protected tool call, the SDK asks AuthSec whether the session is allowed to call that tool (and returns user context). Tool hiding in `tools/list` improves UX; allow/deny on `tools/call` is the security boundary.

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

AuthSec SDK now includes a **standalone SPIFFE Workload API client** that connects directly to the SPIRE agent via gRPC. This is the recommended approach for most use cases.

#### Standalone Mode (Recommended)

Connect directly to SPIRE agent via gRPC. Simple, fast, and requires no external services:

```python
from authsec_sdk import QuickStartSVID

# Initialize - connects directly to SPIRE agent via gRPC
svid = await QuickStartSVID.initialize(
    socket_path="/run/spire/sockets/agent.sock"
)

# Access SPIFFE identity
print(f"SPIFFE ID: {svid.spiffe_id}")

# Use for mTLS communication
ssl_context = svid.create_ssl_context_for_client()

# Certificates are automatically written to disk and kept up-to-date
print(f"Certificate: {svid.cert_file_path}")  # /tmp/spiffe-certs/svid.crt
print(f"Private Key: {svid.key_file_path}")   # /tmp/spiffe-certs/svid.key
print(f"CA Bundle: {svid.ca_file_path}")      # /tmp/spiffe-certs/ca.crt
```

**Key Features**:
- ✅ **Direct gRPC connection** to SPIRE agent (no external services required)
- ✅ **Automatic certificate renewal** via streaming gRPC connection
- ✅ **Singleton pattern** - one SVID per application lifecycle
- ✅ **Automatic file management** - certificates written to disk and kept fresh

**Prerequisites**:
- SPIRE agent must be running on the same host as your workload
- Your workload must be registered in the SPIRE server
- The socket path must match your SPIRE agent configuration (default: `/run/spire/sockets/agent.sock`)

### Using SPIRE in Your Tools

Once SPIRE is enabled, you can use workload identities in your protected tools:

#### Example 1: Basic SPIRE Usage for mTLS

```python
from authsec_sdk import QuickStartSVID
import httpx

async def call_backend_service():
    """Call backend service with mTLS"""

    # Initialize SPIRE - connects directly to agent
    svid = await QuickStartSVID.initialize(
        socket_path="/run/spire/sockets/agent.sock"
    )

    # Use SPIRE identity for mTLS
    ssl_context = svid.create_ssl_context_for_client()

    async with httpx.AsyncClient(verify=ssl_context) as client:
        response = await client.get("https://backend.authsec.svc:8443/api/data")

    return response.json()
```

#### Example 2: Using SPIRE with FastAPI Server

```python
from authsec_sdk import QuickStartSVID
from fastapi import FastAPI
import uvicorn

app = FastAPI()

async def main():
    # Initialize SPIRE
    svid = await QuickStartSVID.initialize(
        socket_path="/run/spire/sockets/agent.sock"
    )

    # Start server with mTLS
    ssl_context = svid.create_ssl_context_for_server()

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
    svid = asyncio.run(QuickStartSVID.initialize(
        socket_path="/run/spire/sockets/agent.sock"
    ))

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

You can customize the socket path and certificate directory:

```python
from authsec_sdk import QuickStartSVID

svid = await QuickStartSVID.initialize(
    socket_path="/run/spire/sockets/agent.sock",  # Default socket path
    cert_dir="/tmp/spiffe-certs"                   # Default certificate directory
)
```

### Troubleshooting SPIRE

**Q: Connection to SPIRE agent fails**
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
│   AuthSec Auth Service              │
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
- ✅ Flexible RBAC and conditional access enforced by AuthSec
- ✅ Secure credential management with Vault
- ✅ Dynamic tool filtering based on permissions
- ✅ Multi-tenant architecture out of the box
- ✅ Zero security expertise required

Stop building security infrastructure from scratch. Start building secure AI tools that your users can trust.

**Try AuthSec SDK today**: [app.authsec.dev](https://app.authsec.dev)

---

**Built with ❤️ by the AuthSec team**

*Have questions? Reach out at support@authsec.dev
