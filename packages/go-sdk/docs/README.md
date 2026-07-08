# AuthSec Go SDK — Documentation

Welcome! This is the documentation hub for the **AuthSec Go SDK** — one Go
module that covers both sides of securing the Model Context Protocol:

- **Protecting** an MCP server with OAuth 2.1 + per-tool RBAC — no auth code
  in your tool handlers.
- **Calling** a protected MCP server as an agent — machine-to-machine, or on
  behalf of a signed-in user (ID-JAG delegation).

```bash
go get github.com/authsec-ai/sdk-authsec/packages/go-sdk
```

Requires Go ≥ 1.24. One dependency (`github.com/golang-jwt/jwt/v5`). Backend:
[https://mcpauthz.com](https://mcpauthz.com).

---

## Getting started

### What the Go SDK is

The Go SDK sits at the **boundary** between MCP clients (agents) and your MCP
server, and it gives you two independent toolkits:

| You are building | You import | You get |
|---|---|---|
| An **MCP server** that must be protected | package `authsec` (server APIs) | Token validation + per-tool RBAC + RFC 9728 metadata + manifest publishing, in one `MountMCP` call |
| An **agent** that calls a protected server | package `authsec` (identity APIs) | `AgentIdentity` (M2M + ID-JAG), the three M2M credential types, SPIFFE workload identity, `BrowserLogin`, `PollUntilApproved` |

The SDK never calls your upstream application APIs. Your MCP server keeps its
own upstream credential (a GitHub App token, a database DSN, …); the caller's
Bearer token is an AuthSec access token only. AuthSec owns identity, OAuth,
RBAC, consent, and policy — the SDK enforces those decisions at the edge.

### Installation

```bash
go get github.com/authsec-ai/sdk-authsec/packages/go-sdk
```

### Requirements

- **Go ≥ 1.24** (the module declares `go 1.24.0`).
- One transitive dependency: `github.com/golang-jwt/jwt/v5` (JWT/JWKS
  verification). No CGO, no system libraries.
- A **public URL** for a protected server — agents and AuthSec must reach it.
  For local development, an [ngrok](https://ngrok.com) tunnel works
  (`ngrok http 8000`).
- An AuthSec workspace on [https://mcpauthz.com](https://mcpauthz.com).

### Importing the SDK

Everything lives in the root package `authsec`. Alias it on import:

```go
import authsec "github.com/authsec-ai/sdk-authsec/packages/go-sdk"
```

Typed errors for **parsing the 401/403 responses a protected server returns**
to a calling agent live in a small sub-package:

```go
import "github.com/authsec-ai/sdk-authsec/packages/go-sdk/client"
```

That is the entire public surface: one package for building things, one
sub-package for reading a protected server's error responses.

---

## The problem AuthSec solves

MCP servers expose tools — and tools are power: query a database, send an
email, call an internal API. The MCP spec says *how* agents call tools, but
out of the box **anyone who can reach your server can call every tool.**

You need to answer three questions on every single request:

1. **Authentication** — who is calling? (which agent, which user behind it?)
2. **Authorization** — is this caller allowed to call *this specific tool*?
3. **Administration** — who decides, and how do rules change without a redeploy?

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
│   go-sdk validates the token + enforces scopes       │
│   per tool before your tool handler ever runs        │
└─────────────────────────────────────────────────────┘
```

1. The **agent** proves its identity to AuthSec and receives an access token
   scoped to your server (guides 2 and 3).
2. The agent calls your MCP server with `Authorization: Bearer <token>`.
3. Your server (via this SDK) validates the token and checks, per tool call,
   that the token's scopes cover that tool. Deny by default (guide 1).

Everything — which agents exist, who approved them, which scopes map to
which tools — is managed in the **AuthSec dashboard**, not in code.

---

## The guides

Read them in this order if you're new; each stands alone if you're not.

### 1. [Protect your MCP server](mcp-protection.md) 🔒

*You have (or are building) an MCP server and want it secured.*

Covers: registering a resource server in the dashboard, `MountMCP` and
`WrapMCPHTTP` with a runnable `net/http` example, the `AUTHSEC_*` environment
variables, how tool manifests publish to the dashboard, how admins assign
scopes per tool, and how enforcement works (401 challenges, RFC 9728
metadata, fail-closed policy).

### 2. [Machine-to-machine auth — Agent Identity + three methods](m2m-auth.md) 🤖

*You have a service/agent that calls a protected MCP server with no human in
the loop.*

Covers `AgentIdentity`, `AccessFor`, and all three ways a machine proves its
identity, from simplest to strongest:

| Method | Proof | Best for |
|---|---|---|
| `ClientSecretAuth` | shared secret (HTTP Basic) | quick starts, simple deployments |
| `PrivateKeyJwtAuth` | RS256-signed assertion (RFC 7523) — key never leaves your host | enterprise security postures |
| `SpiffeSvidAuth` / `SpiffeWorkloadIdentity` | platform-attested workload identity (SPIRE) | Kubernetes — **zero stored credentials** |

### 3. [ID-JAG delegation — act on behalf of a user](idjag-delegation.md) 👤

*You're building a copilot/chatbot where the agent must act with a specific
user's permissions, not its own.*

Covers the XAA (Cross-App Access) flow: `BrowserLogin` (PKCE), the ID-JAG
token chain (token-exchange → jwt-bearer), first-time approval in the
dashboard, `PollUntilApproved`, and the resulting auditable token
(`sub` = the user, `act.client_id` = the agent).

### Reference material

- **[Examples](examples.md)** — five complete, runnable Go programs.
- **[Configuration reference](configuration.md)** — every `AUTHSEC_*`
  variable, every `Config` field, defaults, and what's required.
- **[Troubleshooting](troubleshooting.md)** — errors, protection-check
  failures, token/scope/manifest problems, and fixes.
- **[Best practices](best-practices.md)** — security, deployment, and a
  production checklist.
- **[API reference](api-reference.md)** — every public type, constructor,
  function, and option.

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
| **Resource server (RS)** | Your MCP server, as registered in the dashboard (the dashboard calls it an *Application*) |
| **Client** | Anything that requests tokens — an agent, service account, or workload |
| **Service account (SA)** | A dashboard-registered machine identity for M2M auth |
| **Scope** | A permission string (e.g. `test_mcp:tools:read`) that gates tools |
| **PRM** | Protected Resource Metadata (RFC 9728) — a JSON document your server publishes at `/.well-known/oauth-protected-resource/...` telling agents where to get tokens and which scopes exist |
| **Manifest** | The tool inventory your server publishes to the dashboard so admins can assign scopes per tool |
| **ID-JAG** | Identity Assertion JWT Authorization Grant — the token that carries a user's identity from the agent to the auth server in the delegation flow |
| **XAA** | Cross-App Access — the overall "agent acts for a user" flow built on ID-JAG |
| **SPIFFE / SVID** | A workload-identity standard / the short-lived identity document (JWT or X.509) a SPIRE agent issues to a pod — identity without stored secrets |
| **JWKS** | JSON Web Key Set — public keys used to verify signatures |
| **Introspection** | RFC 7662 — asking the auth server, live, whether a token is still valid (catches revocation) |

---

## Reference links

- [../README.md](../README.md) — the condensed all-in-one server-side
  reference (endpoints, wiring, failure modes)
- [../CHANGELOG.md](../CHANGELOG.md) — release history
- [../examples/](../examples/) — the runnable example programs
  (`quickstart`, `firstrun`, `agent-m2m`, `agent-idjag`)

> **A note on the dashboard.** The AuthSec dashboard is the same product
> regardless of which SDK you use, so the click-by-click dashboard walkthrough
> (with screenshots) in the
> [Python SDK guides](../../python-sdk/docs/README.md) applies verbatim to Go
> — only the code differs. These Go guides describe every dashboard step in
> prose so they stand alone.
