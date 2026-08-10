# Guide 2 — Agent Identity & machine-to-machine auth

*You'll create a service account, pick a credential type, grant it access to
your MCP server, and acquire tokens from Go code — no human in the loop.*

[← Guide 1: MCP protection](mcp-protection.md) | [Guide 3: ID-JAG →](idjag-delegation.md)

---

## When you need this

A data pipeline, a cron job, a backend service, a Kubernetes workload — any
program that calls a protected MCP server **as itself**, with its own
standing permissions and no user session. (If the caller acts *on behalf of a
logged-in user*, that's [guide 3](idjag-delegation.md).)

All the methods here end at the same place — an AuthSec access token you send
as `Authorization: Bearer <token>`. They differ only in **how the machine
proves its identity**:

| Method | Class | Proof | Secret on the wire? | Best for |
|---|---|---|---|---|
| **A. Client secret** | `ClientSecretAuth` | ID + shared secret (HTTP Basic) | ⚠️ every request | quick starts, simple deployments |
| **B. Private-key JWT** | `PrivateKeyJwtAuth` | RS256-signed assertion (RFC 7523) | ✅ never — key stays local | enterprise security postures |
| **C. SPIFFE SVID** | `SpiffeSvidAuth` / `SpiffeWorkloadIdentity` | platform-attested workload identity (SPIRE) | ✅ no stored credential at all | Kubernetes |

Security ladder: A → B → C goes from "shared password" to "asymmetric keys"
to "the infrastructure itself vouches for the workload".

---

## Agent Identity

`AgentIdentity` is the caller-side workhorse. One instance per process — build
it once and reuse it; it caches tokens internally. It handles **both** plain
M2M (this guide) and user delegation (guide 3) — the difference is only which
credential you give it and whether you pass a user session at call time.

### Construction

```go
agent := authsec.NewAgentIdentity(authsec.AgentIdentityConfig{
	Issuer:   "https://mcpauthz.com",
	ClientID: "<service-account-client-id>",
	Auth:     authsec.NewClientSecretAuth("<client-secret>"),
})
```

`AgentIdentityConfig` fields:

| Field | Type | Purpose |
|---|---|---|
| `Issuer` | `string` | AuthSec issuer. **Required** — empty panics. |
| `ClientID` | `string` | Your client/service-account ID. **Required** — empty panics. |
| `Auth` | `ClientAuth` | The credential (methods A/B/C below). Mutually exclusive with `ClientSecret`. |
| `ClientSecret` | `string` | Shorthand for `Auth: NewClientSecretAuth(secret)`. Setting **both** `Auth` and `ClientSecret` panics. |
| `IDPIssuer` | `string` | Enterprise IdP issuer, for the XAA/ID-JAG path (guide 3). |
| `PreferredMode` | `string` | `"auto"` (default), `"direct-only"`, or `"xaa-allowed"`. |
| `TokenEndpoint` | `string` | Override token-endpoint discovery (rarely needed). |

> **Why `NewAgentIdentity` panics instead of returning an error.** A missing
> `Issuer`/`ClientID`, or configuring two credentials at once, is a
> programming mistake that can't be recovered at runtime — failing loudly at
> construction is safer than shipping a misconfigured agent. Credential
> *values* that can legitimately fail (a bad PEM) surface as errors from the
> constructor that builds them — see `NewPrivateKeyJwtAuth` below.

`PreferredMode` controls the flow decision: leave it on `"auto"`.
`"direct-only"` skips delegation entirely (pure M2M services); `"xaa-allowed"`
hard-errors instead of silently downgrading to M2M when the delegation
bootstrap endpoint is unreachable.

### Acquiring a token — `AccessFor`

```go
func (a *AgentIdentity) AccessFor(
	ctx context.Context, resource string, opts ...AccessForOption,
) (string, error)
```

`AccessFor` returns a short-lived Bearer token for the target `resource`
(your MCP server's resource URI). It caches the token and returns the cached
value while it has more than ~30s of life left, so it's cheap to call on every
request.

Options:

| Option | Effect |
|---|---|
| `WithRequestedScopes(scopes ...string)` | The scopes to request (must exist on the target server). |
| `WithUserSession(subjectToken string)` | Attach a user's OIDC token for the ID-JAG/XAA delegation path (guide 3). Omit for plain M2M. |
| `WithExtra(key, val string)` | Forward an extra key/value to token-endpoint calls (advanced). |

```go
ctx := context.Background()
token, err := agent.AccessFor(ctx, "https://your-mcp-server.example.com/mcp",
	authsec.WithRequestedScopes("test_mcp:read", "test_mcp:tools:read"))
if err != nil {
	log.Fatalf("access_for: %v", err)
}
// use as: Authorization: Bearer <token>
```

On a `401` from the MCP server, clear the cache and retry once:

```go
agent.ClearCache("https://your-mcp-server.example.com/mcp") // or ClearCache() for all
```

> **Scopes must exist on the target server.** Check its PRM document
> (`/.well-known/oauth-protected-resource/mcp`, `scopes_supported`).
> Requesting an unknown scope is indistinguishable from "waiting for
> approval". This is the #1 gotcha.

### The three credential classes are interchangeable

Same `AgentIdentity`, same `AccessFor` — only `Auth` changes:

```go
import authsec "github.com/authsec-ai/sdk-authsec/packages/go-sdk"

// A — client secret
agent := authsec.NewAgentIdentity(authsec.AgentIdentityConfig{
	Issuer: ISSUER, ClientID: CLIENT_ID,
	Auth: authsec.NewClientSecretAuth("sec_..."),
})

// B — private-key JWT (PEM string or a path to a .pem file)
pkAuth, err := authsec.NewPrivateKeyJwtAuth("private_key.pem", "key-1")
if err != nil { log.Fatal(err) }
agent := authsec.NewAgentIdentity(authsec.AgentIdentityConfig{
	Issuer: ISSUER, ClientID: CLIENT_ID, Auth: pkAuth,
})

// C — a SPIFFE JWT-SVID you already hold
agent := authsec.NewAgentIdentity(authsec.AgentIdentityConfig{
	Issuer: ISSUER, ClientID: CLIENT_ID,
	Auth: authsec.NewSpiffeSvidAuth(svid),
})
```

Under the hood, `ClientAuth` is a tiny interface — you rarely implement it,
but it's why the three methods slot in interchangeably:

```go
type ClientAuth interface {
	Headers(clientID string) map[string]string
	BodyParams(clientID, tokenEndpoint string) map[string]string
}
```

---

## Service accounts — the dashboard side

Machines are registered as **Service Accounts** (sidebar → Service Accounts →
**＋ Create service account**). Each holds one credential (client secret,
private-key JWT, or Kubernetes SPIFFE SVID) and is granted access to specific
MCP servers independently of any user session.

Creating a service account gives it an **identity, not permissions**. You
must also grant it a role — see [Grant access](#grant-access--required-for-every-method).

---

## Method A — Client secret

The default. Simplest to set up; the secret travels on every token request
(over TLS).

1. Create the service account, keep **Client secret** selected, and click
   **Create service account**.
2. Copy both `CLIENT_ID` and the generated secret — **the secret is shown
   once** (64 hex chars; copy-paste, don't retype).
3. Grant it access (below).

```go
package main

import (
	"context"
	"log"
	"os"

	authsec "github.com/authsec-ai/sdk-authsec/packages/go-sdk"
)

func main() {
	agent := authsec.NewAgentIdentity(authsec.AgentIdentityConfig{
		Issuer:   os.Getenv("AUTHSEC_ISSUER"),
		ClientID: os.Getenv("SA_CLIENT_ID"),
		Auth:     authsec.NewClientSecretAuth(os.Getenv("SA_CLIENT_SECRET")),
	})

	token, err := agent.AccessFor(context.Background(), os.Getenv("MCP_URL"),
		authsec.WithRequestedScopes("test_mcp:read", "test_mcp:tools:read"))
	if err != nil {
		log.Fatalf("access_for: %v", err)
	}
	log.Printf("token: %s… (Authorization: Bearer)", token[:min(25, len(token))])
}
```

> `NewClientSecretAuth("")` panics — an empty secret is always a
> configuration bug. The `ClientSecret` shorthand
> (`AgentIdentityConfig{ClientSecret: "..."}`) behaves identically on the wire
> (`client_secret_basic`).

---

## Method B — Private-key JWT

No shared secret ever crosses the wire. Your service signs a short-lived JWT
assertion with its **private key**; AuthSec verifies the signature with the
**public key** you publish as a JWKS.

### B1. Generate a keypair

```bash
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

`private_key.pem` stays on the machine that runs your service. Never commit
it, never upload it.

### B2. Publish the public key as a JWKS

AuthSec fetches your public key from a URL in JWKS format:

```json
{
  "keys": [
    { "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "key-1",
      "n": "…from your public key…", "e": "AQAB" }
  ]
}
```

Host the JSON anywhere public that returns **raw JSON**.

> ⚠️ **The JWKS URI must return raw JSON, not an HTML page.** With a GitHub
> gist, use the **raw** URL (`gist.githubusercontent.com/.../raw/...`) — the
> normal `gist.github.com/...` page serves HTML and verification fails with
> `parse JWKS: invalid character '<'`.

### B3. Create the service account with the JWKS URI

In the create dialog pick **Private-key JWT** and paste your JWKS URI. There's
no secret to save — just the `CLIENT_ID`. Your private key is the credential.

### B4. Code

```go
pkAuth, err := authsec.NewPrivateKeyJwtAuth("private_key.pem", "key-1") // PEM path or PEM string
if err != nil {
	log.Fatalf("private_key_jwt: %v", err)
}
agent := authsec.NewAgentIdentity(authsec.AgentIdentityConfig{
	Issuer: ISSUER, ClientID: PK_CLIENT_ID, Auth: pkAuth,
})
token, err := agent.AccessFor(ctx, MCP_URL,
	authsec.WithRequestedScopes("test_mcp:read"))
```

`NewPrivateKeyJwtAuth(privateKey, kid string) (*PrivateKeyJwtAuth, error)`
**returns an error** (it doesn't panic) if the key is empty, the `kid` is
empty, or the PEM fails to parse — so validate it at startup. The `kid` you
pass must match the `kid` in your hosted JWKS. Each `AccessFor` signs a fresh
assertion: RS256, 5-minute lifetime, single-use `jti`, audience-bound to the
token endpoint — so an intercepted assertion is useless.

**Key rotation:** generate a new pair, add it to the JWKS under `kid: "key-2"`,
deploy the new private key with `kid="key-2"`, then remove the old entry. No
dashboard changes, no downtime.

---

## Method C — Kubernetes / SPIFFE

There is **no stored credential at all**. The SPIRE agent on the node attests
your pod and issues it a short-lived (~5 min) JWT-SVID; AuthSec verifies it
against your trust domain.

Prerequisites (once per cluster/workload):

1. SPIRE server + agents running; your workload has a registration entry
   mapping its pod selectors to a `spiffe://your-domain/your-workload` ID.
2. In AuthSec: a workload client registered with that exact SPIFFE ID and the
   trust domain's JWKS.

### `SpiffeWorkloadIdentity` — the recommended path inside a pod

Fetches and renews SVIDs from the local SPIRE agent automatically:

```go
workload, err := authsec.NewSpiffeWorkloadIdentity(authsec.SpiffeConfig{
	MCPServerURL: "https://your-mcp-server.example.com/mcp",
	ClientID:     "YOUR_SPIFFE_CLIENT_ID",       // registered in AuthSec
	SpiffeID:     "spiffe://your-domain/your-workload",
	Scopes:       "test_mcp:read test_mcp:tools:read", // space-separated string
})
if err != nil {
	log.Fatal(err)
}
token, err := workload.AccessFor(ctx)  // JWT-SVID from SPIRE → Bearer token
```

`SpiffeConfig` fields:

| Field | Type | Notes |
|---|---|---|
| `MCPServerURL` | `string` | Protected MCP URL; the token endpoint is auto-discovered from it (PRM → AS metadata). |
| `ClientID` | `string` | Workload client ID (UUID). **Required.** |
| `SpiffeID` | `string` | Exact SPIFFE ID; must start with `spiffe://`. |
| `Scopes` | `string` | **Space-separated** scope string (note: a string, not a `[]string`). **Required.** |
| `TokenEndpoint` | `string` | Overrides discovery; if set, must be `https://`. |
| `AgentSocketPath` | `string` | SPIRE agent Unix socket. Default `/run/spire/sockets/agent.sock`. |
| `SvidOverride` | `string` | A pre-minted JWT-SVID; skips the SPIRE agent subprocess (for testing). |

Key differences from `AgentIdentity`:

- `SpiffeWorkloadIdentity.AccessFor(ctx)` takes **no** `resource`/options —
  the resource and scopes come from `SpiffeConfig`.
- The token endpoint is discovered from `MCPServerURL` using the RFC 9728
  alias path — no URL configuration needed.
- Tokens are cached (served while >60s remain); SVIDs are cached (~4.5 min)
  and re-fetched from the SPIRE agent when stale. `ClearCache()` drops both.

**Testing outside a pod:** set `SvidOverride` to an SVID minted manually (e.g.
`spire-agent api fetch jwt -audience <token-endpoint> ...`). SVIDs are
short-lived (~5 min) — mint fresh ones.

Errors are typed and actionable: `*SpiffeSvidFetchError` (agent socket /
registration problems) and `*SpiffeTokenExchangeError` (exchange rejected —
its `Code` tells you whether it's `jwks_unconfigured`,
`spiffe_id_not_registered`, `audience_mismatch`, `trust_domain_mismatch`,
`no_scopes_granted`, or `client_id_missing`).

### `SpiffeSvidAuth` — the low-level path

If you already hold an SVID (minted elsewhere), use `AgentIdentity` with
`SpiffeSvidAuth`:

```go
agent := authsec.NewAgentIdentity(authsec.AgentIdentityConfig{
	Issuer: ISSUER, ClientID: SPIFFE_CLIENT_ID,
	Auth: authsec.NewSpiffeSvidAuth(svid), // panics if svid == ""
})
```

Two hard-won rules for hand-minted SVIDs:

- **The SVID's audience must be the token endpoint**
  (`https://mcpauthz.com/oauth/token`). An SVID minted with only the issuer as
  audience is rejected with *"token aud must include this token endpoint"*.
- **SVIDs live ~5 minutes** and `SpiffeSvidAuth` does **not** refresh — mint
  immediately before use, or use `SpiffeWorkloadIdentity` (which auto-renews).

---

## When to use each authentication method

| If you are… | Use | Why |
|---|---|---|
| Prototyping, or running a simple internal service | **Client secret** (`ClientSecretAuth`) | One value to manage; fastest to stand up. |
| Subject to an enterprise/secret-averse security posture | **Private-key JWT** (`PrivateKeyJwtAuth`) | The credential (private key) never leaves your host; assertions are single-use and short-lived. |
| Running in Kubernetes with SPIRE | **`SpiffeWorkloadIdentity`** | Zero stored credentials; the platform attests the workload and SVIDs auto-renew. |
| In Kubernetes but minting SVIDs yourself / testing | **`SpiffeSvidAuth`** | Low-level; you control minting but must handle audience + expiry. |

---

## Grant access — required for every method

Creating a service account gives it an identity, **not** permissions. Until
you grant a role, every token request fails with:

```
access_denied: client not authorized for this resource server
```

Assign a role (e.g. `Readonly` with the read scopes) to the service account
for your target application, on the application's **Access** / **Connections**
side. Once granted, the connection appears on the application's **Connections**
tab as an active `(m2m)` connection showing its role and scopes.

---

## Error handling

Agent-side errors are typed and embed a common base
(`AuthSecIdentityError`, with `Code`, `Message`, `HTTPStatus`). Match with
`errors.As`:

```go
import "errors"

token, err := agent.AccessFor(ctx, MCP_URL, authsec.WithRequestedScopes("test_mcp:read"))
if err != nil {
	var credErr *authsec.CredentialInvalidError
	var resErr  *authsec.ResourceNotRegisteredError
	switch {
	case errors.As(err, &credErr):
		log.Fatalf("bad credentials: %s", credErr.Detail)
	case errors.As(err, &resErr):
		log.Fatalf("MCP URL not registered in AuthSec: %s", resErr.Resource)
	default:
		log.Fatalf("access_for: %v", err)
	}
}
```

| Type | Meaning | Action |
|---|---|---|
| `*CredentialInvalidError` | Bad client credentials (has a `Detail` field) | Fix config / re-copy the secret |
| `*ResourceNotRegisteredError` | MCP URL unknown to the AS (has a `Resource` field) | Register the resource server |
| `*TrustedIssuerMissingError` | The IdP isn't trusted by the AS | Configure the IdP in the dashboard |
| `*PendingApprovalError` | Access requested, admin approval pending | Poll (see [guide 3](idjag-delegation.md)) |
| `*ApprovalDeniedError` | Admin declined | Inform the user; don't retry |
| `*ConnectionRevokedError` | Previously granted access was revoked | Re-request / inform |
| `*WorkloadNotAttestedError` | SPIFFE workload not attested | Check the SPIRE registration entry |
| `*AuthSecIdentityError` | Base for all of the above | Catch-all |

For parsing errors the **MCP server** returns to your agent (401/403 bodies,
`WWW-Authenticate`), use the `client` sub-package — see
[the examples](examples.md#6-parsing-a-protected-servers-error-response).

---

## Troubleshooting

Every row here is an error we hit for real while building this SDK:

| Error | Cause | Fix |
|---|---|---|
| `invalid_client: invalid client secret` | Typo'd/rotated secret (they're 64 hex chars) | Copy-paste from the dashboard, never retype |
| `access_denied: client not authorized for this resource server` | Credential is **valid** but no access assignment exists | Grant a role for the target application (section above) |
| `JWKS resolution failed: parse JWKS: invalid character '<'` | JWKS URI returns HTML (gist page URL, 404 page, …) | Point it at raw JSON; for gists use the `raw` URL |
| `invalid_client: token aud must include this token endpoint` | SPIFFE SVID minted with the wrong audience | Mint with `audience = <issuer>/oauth/token`, or use `SpiffeWorkloadIdentity` |
| `invalid_client: … token is expired` | JWT-SVIDs live ~5 min | Mint right before use, or use `SpiffeWorkloadIdentity` (auto-renews) |
| Signature verification fails (private-key JWT) | `kid` mismatch between code and JWKS, or wrong key | Make `NewPrivateKeyJwtAuth(..., kid)` match the JWKS `kid` |
| `panic: both Auth and ClientSecret set` | Configured two credentials at once | Set exactly one of `Auth` or `ClientSecret` |

---

[← Guide 1: MCP protection](mcp-protection.md) | [Guide 3: ID-JAG →](idjag-delegation.md)
