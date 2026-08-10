# Guide 3 — ID-JAG delegation: agents acting on behalf of a user

*You'll register an AI agent, wire the SDK, log a user in through the agent,
approve it once in the dashboard — and end with an agent that calls MCP tools
with the **user's** permissions, fully auditable and revocable.*

[← Guide 2: M2M auth](m2m-auth.md) | [Docs home](README.md)

---

## Why ID-JAG exists

An M2M service (guide 2) acts as **itself** — its own identity, its own
permissions. But a copilot or chatbot acts **for a person**: when Alice asks
her assistant to check her tickets, the MCP server should apply *Alice's*
permissions, not the agent's — and the audit log should say *"Alice, via agent
X"*.

The naive solutions are all bad:

| Approach | Problem |
|---|---|
| Give the agent a powerful service account | Every user gets the same (over-broad) access; audit says "the bot did it" |
| Hand the user's own token to the agent | The agent can do *everything* the user can, everywhere, invisibly |
| Screen-scrape / password sharing | Please no |

**ID-JAG** (Identity Assertion JWT Authorization Grant — the emerging
cross-app access standard, also called **XAA**) solves it properly: the user
logs in once, the agent exchanges *proof of that login* for a **scoped,
short-lived token** that carries both identities:

```json
{
  "sub": "alice@example.com",         ← whose authority
  "act": { "client_id": "agent-x" },  ← who is acting
  "scope": "test_mcp:read ...",       ← only what was requested & approved
  "aud": "https://your-mcp/mcp"       ← only this server
}
```

The user consents once, an admin approves once, and either can be revoked at
any time — killing the agent's access without touching the user's own.

## The flow

The SDK does all of this — two helper calls (`BrowserLogin`, then
`AccessFor`) plus a one-time `PollUntilApproved` on first contact:

```
   user                agent (your code)                AuthSec              MCP server
    │                        │                             │                     │
    │  1. BrowserLogin()     │                             │                     │
    │◀───opens browser───────│                             │                     │
    │   logs in + consents   │                             │                     │
    │   to requested scopes  │                             │                     │
    │────────id_token───────▶│                             │                     │
    │                        │  2. token-exchange          │                     │
    │                        │     (id_token → ID-JAG)     │                     │
    │                        │────────────────────────────▶│                     │
    │                        │◀───────ID-JAG───────────────│                     │
    │                        │  3. jwt-bearer              │                     │
    │                        │     (ID-JAG → access token) │                     │
    │                        │────────────────────────────▶│                     │
    │                        │◀──scoped access token───────│                     │
    │                        │  4. tools/call with Bearer token────────────────▶ │
    │                        │◀──────────────────────result──────────────────────│
```

Step 1 happens once per user session; steps 2–3 are invisible (inside
`AccessFor`); the token is cached until near expiry.

---

## Step 1 — Register the agent in the dashboard

Open **Agents** in the sidebar and click **＋ Register agent**. Fill in:

1. **Name** — a human label, e.g. `research-agent`.
2. **Redirect URI** — where the user's browser lands after login. For the
   SDK's `BrowserLogin` keep the loopback default
   (`http://localhost:8126/callback`); for a web app, use your app's own OAuth
   callback URL.

On success the dialog shows the agent's credentials — **copy the secret now,
it won't be shown again.**

```bash
AUTHSEC_ISSUER=https://mcpauthz.com
AUTHSEC_AGENT_CLIENT_ID=64c45f84-...
AUTHSEC_AGENT_CLIENT_SECRET=<the secret you copied>
AUTHSEC_RESOURCE_URI=https://your-mcp-server.example.com/mcp
```

## Step 2 — Log the user in with `BrowserLogin`

```go
func BrowserLogin(
	ctx context.Context, issuer, clientID string, opts *BrowserLoginOptions,
) (string, error)
```

`BrowserLogin` runs an interactive OAuth **PKCE** (S256) login and returns the
user's `id_token`. It performs OIDC discovery at
`{issuer}/.well-known/openid-configuration`, opens the browser, and runs a
one-shot loopback callback server on `localhost:{Port}/callback`.

```go
idToken, err := authsec.BrowserLogin(ctx, issuer, agentClientID, &authsec.BrowserLoginOptions{
	Resource: resource,                             // the MCP resource URI (RFC 8707)
	Scopes:   []string{"openid", "email", "profile"},
})
if err != nil {
	log.Fatalf("browser login: %v", err)
}
```

`BrowserLoginOptions`:

| Field | Type | Default |
|---|---|---|
| `Resource` | `string` | none — set it to bind the login to your MCP resource |
| `Scopes` | `[]string` | `["openid", "email", "profile"]` |
| `Port` | `int` | `8126` (must match the registered redirect URI's port) |
| `Timeout` | `time.Duration` | `300s` |
| `OpenBrowser` | `func(url string) error` | a per-OS default launcher |

> `BrowserLogin` returns an error if `issuer` or `clientID` is empty. In a
> headless/remote session, override `OpenBrowser` to print or forward the URL,
> or run this step where a browser is available and pass the resulting
> `id_token` in. **Web apps** should skip `BrowserLogin` entirely and pass the
> `id_token` from their own OIDC login into `WithUserSession`.

## Step 3 — Exchange for a delegated access token

Build an `AgentIdentity` for the agent (set `IDPIssuer`), then call `AccessFor`
with `WithUserSession(idToken)`:

```go
package main

import (
	"context"
	"errors"
	"log"
	"os"

	authsec "github.com/authsec-ai/sdk-authsec/packages/go-sdk"
)

func main() {
	ctx := context.Background()
	issuer := os.Getenv("AUTHSEC_ISSUER")
	resource := os.Getenv("AUTHSEC_RESOURCE_URI")

	// 1) The user logs in via the browser (PKCE) — returns an id_token.
	idToken, err := authsec.BrowserLogin(ctx, issuer, os.Getenv("AUTHSEC_IDP_CLIENT_ID"),
		&authsec.BrowserLoginOptions{
			Resource: resource,
			Scopes:   []string{"openid", "email", "profile"},
		})
	if err != nil {
		log.Fatalf("browser login: %v", err)
	}

	// 2) The agent's own identity — one instance per process, reuse it.
	agent := authsec.NewAgentIdentity(authsec.AgentIdentityConfig{
		Issuer:        issuer,
		ClientID:      os.Getenv("AUTHSEC_AGENT_CLIENT_ID"),
		Auth:          authsec.NewClientSecretAuth(os.Getenv("AUTHSEC_AGENT_CLIENT_SECRET")),
		IDPIssuer:     os.Getenv("AUTHSEC_IDP_ISSUER"),
		PreferredMode: "auto",
	})

	// 3) Scoped token, delegated from the user.
	opts := []authsec.AccessForOption{
		authsec.WithUserSession(idToken),
		authsec.WithRequestedScopes("test_mcp:read", "test_mcp:tools:read"),
	}
	token, err := agent.AccessFor(ctx, resource, opts...)

	// 4) First contact needs admin approval — poll until approved.
	var pending *authsec.PendingApprovalError
	if errors.As(err, &pending) {
		log.Printf("access pending approval (request %s); polling…", pending.RequestID)
		token, err = authsec.PollUntilApproved(ctx, agent, resource, pending.StatusURL, nil, opts...)
	}
	if err != nil {
		var denied *authsec.ApprovalDeniedError
		if errors.As(err, &denied) {
			log.Fatal("admin declined access")
		}
		log.Fatalf("access_for: %v", err)
	}

	log.Printf("acquired ID-JAG access token (%d chars)", len(token))
	// Claims: sub = the user, act.client_id = this agent (auditable delegation).
}
```

> **Scopes must exist on the target server.** Requesting a scope the server
> doesn't define looks exactly like "waiting for approval forever". Check the
> server's PRM `scopes_supported`. This is the #1 gotcha.

## Step 4 — First run: the user consents

Run your agent. The browser opens to the AuthSec login; the user signs in and
sees a **consent screen listing exactly the scopes the agent is requesting**,
and clicks Allow — **once**. This is the user-side half of the double opt-in.

## Step 5 — First run: the admin approves the connection

Meanwhile the SDK returned a `*PendingApprovalError` and your code is polling —
because the server-side half hasn't happened yet. Open the application's
**Connections** tab:

- **Access requests** — the agent's first call appears here as a pending
  request. Approve it and pick the **role** it gets (e.g. `Readonly`). Your
  polling agent picks up the approval automatically and completes — no restart.
- **Active connections** — every approved connection, showing the authority it
  acts under, its role/scopes, and when it last connected.

### `PollUntilApproved`

```go
func PollUntilApproved(
	ctx context.Context, ai *AgentIdentity, resource, statusURL string,
	opts *PollOptions, o ...AccessForOption,
) (string, error)
```

Polls the access-request `statusURL` until the admin decides, then clears the
resource's cache and calls `AccessFor` (forwarding your `AccessForOption`s), so
you get a token back the moment it's approved.

| `PollOptions` field | Default |
|---|---|
| `Interval` | `3s` |
| `Timeout` | `300s` |

Pass `nil` for the defaults (as in the example). Outcomes:

- **approved** → returns the fresh token.
- **denied** → `*ApprovalDeniedError`.
- **revoked** → `*ConnectionRevokedError`.
- **ctx cancelled** → `ctx.Err()`.
- **timeout reached** → an error containing `"timed out"`.

## Step 6 — Every run after: seamless

Both approvals are one-time. From now on the same user + agent + server combo
goes straight through: login → cached/renewed token → tools. No consent
re-run, no pending request, no admin involvement.

## Revoking an agent

Both sides can kill the delegation at any time:

- **Per server** — the application's Connections tab → ⋮ on the connection →
  revoke. The agent's next call fails with `*ConnectionRevokedError`.
- **Per agent** — the Agents page → ⋮ → revoke.

The user's own access is untouched — you're revoking *the agent's right to act
for them*, not the user.

---

## Error handling reference

| Type | Meaning | What to do |
|---|---|---|
| `*PendingApprovalError` | First contact — admin approval pending. Has `RequestID`, `StatusURL`. | `PollUntilApproved(...)` (shown above) |
| `*ApprovalDeniedError` | Admin declined the request | Inform the user; don't retry |
| `*ConnectionRevokedError` | A previously approved connection was revoked | Re-request access or inform |
| `*TrustedIssuerMissingError` | The IdP isn't trusted by the AuthSec AS | Dashboard: configure the identity provider |
| `*CredentialInvalidError` | Agent's client_id/secret wrong | Re-copy from registration |

Match them with `errors.As` (they're pointer types embedding
`AuthSecIdentityError`).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Stuck "waiting for approval" forever, nothing in Connections | Requested scopes don't exist on the target server | Use scopes from the server's PRM `scopes_supported` |
| Browser doesn't open on `BrowserLogin` | Headless/remote session | Override `BrowserLoginOptions.OpenBrowser` to surface the URL, or log in elsewhere and pass the `id_token` |
| `redirect_uri mismatch` at login | Agent registered with a different redirect URI/port | Match the registration; `BrowserLoginOptions.Port` defaults to `8126` → `http://localhost:8126/callback` |
| Token works, then suddenly 401s | Connection revoked, or token expired mid-session | `agent.ClearCache(resource)` and retry once; if `*ConnectionRevokedError`, re-request |
| Agent missing from the Agents page | It has never successfully connected | Normal — it appears after its first server connection |

---

[← Guide 2: M2M auth](m2m-auth.md) | [Docs home](README.md)
