# AuthSec Python SDK — Documentation

Welcome! This is the documentation hub for the **AuthSec Python SDK** — one
package that covers both sides of securing the Model Context Protocol:

- **Protecting** an MCP server with OAuth 2.1 + per-tool RBAC — no auth code
  in your tools.
- **Calling** a protected MCP server as an agent — machine-to-machine or on
  behalf of a signed-in user.

```bash
pip install authsec-sdk
```

Requires Python ≥ 3.10. Fully typed. Backend: [https://mcpauthz.com](https://mcpauthz.com).

---

## The problem AuthSec solves

MCP servers expose tools — and tools are power: query a database, send an
email, call an internal API. The MCP spec says *how* agents call tools, but
out of the box **anyone who can reach your server can call every tool**.

You need to answer three questions on every single request:

1. **Authentication** — who is calling? (which agent, which user behind it?)
2. **Authorization** — is this caller allowed to call *this specific tool*?
3. **Administration** — who decides, and how do rules change without redeploying?

AuthSec answers all three: the SDK enforces OAuth tokens and per-tool scopes
inside your server, and the **AuthSec dashboard** is where admins register
clients, approve access, and assign scopes — changes reach your running
server in ~30 seconds, no redeploy.

---

## The big picture

Every AuthSec setup has three parties:

```
┌─────────────┐    1. get token     ┌──────────────────┐
│    AGENT     │ ──────────────────▶ │     AuthSec      │
│  (caller)    │ ◀────────────────── │   mcpauthz.com   │
│              │    2. Bearer token  │ (auth server +   │
│              │                     │    dashboard)    │
│              │                     └──────────────────┘
│              │                            ▲
│              │    3. call tool with token │ policy sync:
│              │       Authorization:       │ scopes, manifest,
│              ▼       Bearer eyJ...        │ validation
┌─────────────────────────────────────────────────────┐
│              YOUR MCP SERVER (resource server)       │
│   authsec-sdk validates the token + enforces scopes  │
│   per tool before your tool code ever runs           │
└─────────────────────────────────────────────────────┘
```

1. The **agent** proves its identity to AuthSec and receives an access token
   scoped to your server.
2. The agent calls your MCP server with `Authorization: Bearer <token>`.
3. Your server (via this SDK) validates the token and checks, per tool call,
   that the token's scopes cover that tool. Deny by default.

Everything — which agents exist, who approved them, which scopes map to
which tools — is managed in the **AuthSec dashboard**, not in code.

---

## The guides

Read them in this order if you're new; each stands alone if you're not.

### 1. [Protect your MCP server](mcp-protection.md) 🔒

*You have (or are building) an MCP server and want it secured.*

Covers: registering a resource server in the dashboard, `mount_mcp()` with a
runnable FastMCP example, environment variables, how tool manifests publish
to the dashboard, how admins assign scopes per tool, and how enforcement
works (401 challenges, RFC 9728 metadata, fail-closed policy). Step-by-step
dashboard screenshots included.

### 2. [Machine-to-machine auth — three methods](m2m-auth.md) 🤖

*You have a service/agent that calls a protected MCP server with no human
in the loop.*

Covers all three ways a machine proves its identity, from simplest to
strongest:

| Method | Proof | Best for |
|---|---|---|
| Client secret | shared secret (HTTP Basic) | quick starts, simple deployments |
| Private-key JWT | RS256-signed assertion (RFC 7523) — key never leaves your machine | enterprise security postures |
| SPIFFE SVID | platform-attested workload identity (SPIRE) | Kubernetes — **zero stored credentials** |

Includes dashboard setup for each (service accounts, JWKS registration,
access assignment), full code, and a troubleshooting table of real errors.

### 3. [ID-JAG delegation — act on behalf of a user](idjag-delegation.md) 👤

*You're building a copilot/chatbot where the agent must act with a specific
user's permissions, not its own.*

Covers the XAA (Cross-App Access) flow: browser login (PKCE), the ID-JAG
token chain (token-exchange → jwt-bearer), first-time approval in the
dashboard, polling, and the resulting auditable token (`sub` = the user,
`act.client_id` = the agent). Dashboard screenshots for client registration
and access approval included.

---

## Which guide do I need?

```
Are you building the MCP SERVER or the thing that CALLS it?
│
├─ THE SERVER ──────────────────────────▶ Guide 1: MCP protection
│
└─ THE CALLER (agent)
   │
   ├─ Acts for a signed-in USER? ───────▶ Guide 3: ID-JAG delegation
   │
   └─ Acts as ITSELF (no user)?
      │
      ├─ Running in Kubernetes? ────────▶ Guide 2, SPIFFE method
      └─ Anywhere else ─────────────────▶ Guide 2, client secret or
                                           private-key JWT
```

Most real deployments need **two** guides: one team protects the server
(guide 1), another team builds the agent (guide 2 or 3).

---

## Glossary

Terms you'll meet across all guides:

| Term | Meaning |
|---|---|
| **Resource server (RS)** | Your MCP server, as registered in the dashboard |
| **Client** | Anything that requests tokens — an agent, service account, or workload |
| **Service account (SA)** | A dashboard-registered machine identity for M2M auth |
| **Scope** | A permission string (e.g. `test_mcp:tools:read`) that gates tools |
| **PRM** | Protected Resource Metadata (RFC 9728) — a JSON document your server publishes at `/.well-known/oauth-protected-resource/...` telling agents where to get tokens and which scopes exist |
| **Manifest** | The tool inventory your server publishes to the dashboard so admins can assign scopes per tool |
| **ID-JAG** | Identity Assertion JWT Authorization Grant — the token that carries a user's identity from the agent to the auth server in the delegation flow |
| **XAA** | Cross-App Access — the overall "agent acts for a user" flow built on ID-JAG |
| **SPIFFE / SVID** | A workload-identity standard / the short-lived identity document (JWT or X.509) a SPIRE agent issues to a pod — identity without stored secrets |
| **JWKS** | JSON Web Key Set — public keys the server uses to verify signatures |

---

## Reference

- [README.md](../README.md) — condensed all-in-one reference (imports,
  package layout, error tables, CLI)
- [examples/](../examples/) — runnable example servers
- SDK version: **4.7.0**
