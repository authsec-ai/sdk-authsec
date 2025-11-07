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
- **Support**: support@authnull.com

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
