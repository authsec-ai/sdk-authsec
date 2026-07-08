# Examples

Five complete, runnable Go programs — one per scenario — plus a helper for
reading a protected server's error responses. Each is self-contained; copy it,
set the environment variables in the comment header, and `go run .`.

Runnable versions of several of these also live in
[`../examples/`](../examples/) (`quickstart`, `firstrun`, `agent-m2m`,
`agent-idjag`).

- [1. Protecting an MCP server](#1-protecting-an-mcp-server)
- [2. M2M client (client secret)](#2-m2m-client-client-secret)
- [3. Browser login](#3-browser-login)
- [4. SPIFFE workload](#4-spiffe-workload)
- [5. ID-JAG (end-to-end)](#5-id-jag-end-to-end)
- [6. Parsing a protected server's error response](#6-parsing-a-protected-servers-error-response)

All examples import the SDK as:

```go
import authsec "github.com/authsec-ai/sdk-authsec/packages/go-sdk"
```

---

## 1. Protecting an MCP server

A complete server: `MountMCP` in front of a minimal hand-rolled MCP handler
with two tools. Configuration comes from `AUTHSEC_*` env vars (see the
[configuration reference](configuration.md)).

```go
// server.go — go run .
package main

import (
	"encoding/json"
	"log"
	"net/http"

	authsec "github.com/authsec-ai/sdk-authsec/packages/go-sdk"
)

func main() {
	cfg := authsec.FromEnv()

	// Optional: hand-curated manifest with suggested scopes. Omit to let the
	// SDK enumerate your tools automatically at startup.
	cfg.ToolInventoryProvider = func() ([]authsec.ManifestTool, error) {
		return []authsec.ManifestTool{
			{Name: "add_no", Description: "Add two numbers",
				SuggestedScopes: []string{"my_mcp:tools:read"}},
			{Name: "multiply_no", Description: "Multiply two numbers",
				SuggestedScopes: []string{"my_mcp:tools:write"}},
		}, nil
	}

	mux := http.NewServeMux()
	if err := authsec.MountMCP(mux, "/mcp", http.HandlerFunc(mcpHandler), cfg); err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on :8000 — resource_uri=%s", cfg.ResourceURI)
	log.Fatal(http.ListenAndServe(":8000", mux))
}

// mcpHandler is a minimal MCP JSON-RPC handler. Real servers use an MCP
// framework; this shows that the SDK wraps any plain http.Handler.
func mcpHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  struct {
			Name      string             `json:"name"`
			Arguments map[string]float64 `json:"arguments"`
		} `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	w.Header().Set("Content-Type", "application/json")

	reply := func(result any) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": req.ID, "result": result,
		})
	}

	switch req.Method {
	case "tools/list":
		reply(map[string]any{"tools": []map[string]any{
			{"name": "add_no", "description": "Add two numbers"},
			{"name": "multiply_no", "description": "Multiply two numbers"},
		}})
	case "tools/call":
		a, b := req.Params.Arguments["a"], req.Params.Arguments["b"]
		out := a + b
		if req.Params.Name == "multiply_no" {
			out = a * b
		}
		reply(map[string]any{"content": []map[string]any{
			{"type": "text", "text": jsonNumber(out)},
		}})
	default: // initialize, notifications/*, ping, …
		reply(map[string]any{"ok": true})
	}
}

func jsonNumber(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}
```

The SDK enforces authentication and per-tool scopes **before** `mcpHandler`
runs — see [guide 1](mcp-protection.md).

---

## 2. M2M client (client secret)

Acquire a token as a service account and call the protected server.

```go
// m2m.go — go run .
//   export AUTHSEC_ISSUER=https://mcpauthz.com
//   export SA_CLIENT_ID=<service-account-client-id>
//   export SA_CLIENT_SECRET=sec_...
//   export MCP_URL=https://your-mcp-server.example.com/mcp
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
	log.Printf("acquired access token (%d chars) — send as Authorization: Bearer", len(token))
}
```

Swap the credential to change methods (all else identical):

```go
// private-key JWT
pkAuth, err := authsec.NewPrivateKeyJwtAuth("private_key.pem", "key-1")
if err != nil { log.Fatal(err) }
// ... Auth: pkAuth

// pre-held SPIFFE SVID
// ... Auth: authsec.NewSpiffeSvidAuth(os.Getenv("AUTHSEC_SVID"))
```

See [guide 2](m2m-auth.md) for when to use each.

---

## 3. Browser login

Log a user in via PKCE and print the `id_token` (the input to the ID-JAG flow).

```go
// login.go — go run .
//   export AUTHSEC_ISSUER=https://mcpauthz.com
//   export AUTHSEC_IDP_CLIENT_ID=<public-browser-client-id>
//   export AUTHSEC_RESOURCE_URI=https://your-mcp-server.example.com/mcp
package main

import (
	"context"
	"log"
	"os"
	"time"

	authsec "github.com/authsec-ai/sdk-authsec/packages/go-sdk"
)

func main() {
	ctx := context.Background()

	idToken, err := authsec.BrowserLogin(ctx,
		os.Getenv("AUTHSEC_ISSUER"),
		os.Getenv("AUTHSEC_IDP_CLIENT_ID"),
		&authsec.BrowserLoginOptions{
			Resource: os.Getenv("AUTHSEC_RESOURCE_URI"),
			Scopes:   []string{"openid", "email", "profile"},
			Port:     8126, // must match the registered redirect URI's port
			Timeout:  5 * time.Minute,
		})
	if err != nil {
		log.Fatalf("browser login: %v", err)
	}
	log.Printf("id_token acquired (%d chars) — pass to WithUserSession()", len(idToken))
}
```

In a headless environment, set `BrowserLoginOptions.OpenBrowser` to a function
that surfaces the URL instead of opening a browser:

```go
OpenBrowser: func(url string) error { log.Printf("open this URL to log in:\n%s", url); return nil },
```

---

## 4. SPIFFE workload

Inside a Kubernetes pod with a SPIRE agent: fetch a JWT-SVID and exchange it
for a Bearer token, with no stored credential.

```go
// spiffe.go — go run .
//   export AUTHSEC_CLIENT_ID=<spiffe-workload-client-id>
//   export AUTHSEC_SPIFFE_ID=spiffe://your-domain/your-workload
//   export AUTHSEC_RESOURCE_URI=https://your-mcp-server.example.com/mcp
package main

import (
	"context"
	"errors"
	"log"
	"os"

	authsec "github.com/authsec-ai/sdk-authsec/packages/go-sdk"
)

func main() {
	workload, err := authsec.NewSpiffeWorkloadIdentity(authsec.SpiffeConfig{
		MCPServerURL: os.Getenv("AUTHSEC_RESOURCE_URI"),
		ClientID:     os.Getenv("AUTHSEC_CLIENT_ID"),
		SpiffeID:     os.Getenv("AUTHSEC_SPIFFE_ID"),
		Scopes:       "test_mcp:read test_mcp:tools:read", // space-separated string
		// AgentSocketPath defaults to /run/spire/sockets/agent.sock
		// SvidOverride: "<jwt-svid>",  // for testing outside a pod
	})
	if err != nil {
		log.Fatalf("spiffe workload: %v", err)
	}

	token, err := workload.AccessFor(context.Background())
	if err != nil {
		var fetchErr *authsec.SpiffeSvidFetchError
		var xchgErr *authsec.SpiffeTokenExchangeError
		switch {
		case errors.As(err, &fetchErr):
			log.Fatalf("could not fetch SVID from SPIRE agent: %v", fetchErr)
		case errors.As(err, &xchgErr):
			log.Fatalf("token exchange rejected (%s): %v", xchgErr.Code, xchgErr)
		default:
			log.Fatalf("AccessFor: %v", err)
		}
	}
	log.Printf("acquired access token (%d chars) via spiffe-workload", len(token))
}
```

---

## 5. ID-JAG (end-to-end)

Browser login → delegated token → poll on first-time approval. This is the
full copilot flow from [guide 3](idjag-delegation.md).

```go
// idjag.go — go run .
//   export AUTHSEC_ISSUER=https://mcpauthz.com
//   export AUTHSEC_IDP_ISSUER=https://idp.enterprise.com
//   export AUTHSEC_IDP_CLIENT_ID=<public-browser-client-id>
//   export AUTHSEC_AGENT_CLIENT_ID=<agent-client-id>
//   export AUTHSEC_AGENT_CLIENT_SECRET=sec_...
//   export AUTHSEC_RESOURCE_URI=https://your-mcp-server.example.com/mcp
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

	idToken, err := authsec.BrowserLogin(ctx, issuer, os.Getenv("AUTHSEC_IDP_CLIENT_ID"),
		&authsec.BrowserLoginOptions{Resource: resource, Scopes: []string{"openid", "email", "profile"}})
	if err != nil {
		log.Fatalf("browser login: %v", err)
	}

	agent := authsec.NewAgentIdentity(authsec.AgentIdentityConfig{
		Issuer:        issuer,
		ClientID:      os.Getenv("AUTHSEC_AGENT_CLIENT_ID"),
		Auth:          authsec.NewClientSecretAuth(os.Getenv("AUTHSEC_AGENT_CLIENT_SECRET")),
		IDPIssuer:     os.Getenv("AUTHSEC_IDP_ISSUER"),
		PreferredMode: "auto",
	})

	opts := []authsec.AccessForOption{
		authsec.WithUserSession(idToken),
		authsec.WithRequestedScopes("test_mcp:read", "test_mcp:tools:read"),
	}

	token, err := agent.AccessFor(ctx, resource, opts...)

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
}
```

---

## 6. Parsing a protected server's error response

When your agent gets a `401`/`403` from an MCP server, the `client`
sub-package turns it into a typed, human-readable error. Import it separately:

```go
// parse.go
package main

import (
	"log"
	"net/http"

	"github.com/authsec-ai/sdk-authsec/packages/go-sdk/client"
)

func handleMCPResponse(resp *http.Response) {
	// ParseMCPError accepts *http.Response, map[string]any, []byte, string, or error.
	if accErr := client.ParseMCPError(resp); accErr != nil {
		// FormatForUser() returns an actionable message, e.g.
		// "Tool X requires scope Y; your token has Z."
		log.Println(accErr.FormatForUser())

		switch e := accErr.(type) {
		case *client.ErrInsufficientScope:
			log.Printf("tool=%s needs=%v have=%v", e.Tool, e.RequiredScopes, e.GrantedScopes)
		case *client.ErrTokenRevoked:
			log.Println("token revoked — clear cache and re-authenticate")
		case *client.ErrClientRegistrationRevoked:
			log.Println("client registration revoked — an admin must re-approve")
		case *client.ErrAuthRequired:
			log.Printf("auth required (reason=%s)", e.Reason)
		}
		return
	}
	// not an AuthSec error — handle the response normally
}
```

`ParseMCPError` returns `nil` for non-AuthSec inputs, so it's safe to call on
any response.

---

[← Docs home](README.md)
