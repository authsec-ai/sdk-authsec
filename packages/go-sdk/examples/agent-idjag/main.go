// agent-idjag demonstrates the ID-JAG (a.k.a. XAA) delegation flow: a user logs
// in through the agent, and the agent exchanges proof of that login for a
// scoped, short-lived access token that carries BOTH identities (the user's
// authority, the agent acting). If access needs admin approval, it polls until
// approved.
//
//	export AUTHSEC_ISSUER=https://mcpauthz.com
//	export AUTHSEC_IDP_ISSUER=https://idp.enterprise.com
//	export AUTHSEC_IDP_CLIENT_ID=<public-browser-client-id>
//	export AUTHSEC_AGENT_CLIENT_ID=<agent-client-id>
//	export AUTHSEC_AGENT_CLIENT_SECRET=sec_...
//	export AUTHSEC_RESOURCE_URI=https://your-mcp-server.example.com/mcp
//	go run ./examples/agent-idjag
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
	idToken, err := authsec.BrowserLogin(ctx, issuer, os.Getenv("AUTHSEC_IDP_CLIENT_ID"), &authsec.BrowserLoginOptions{
		Resource: resource,
		Scopes:   []string{"openid", "email", "profile"},
	})
	if err != nil {
		log.Fatalf("browser login: %v", err)
	}

	// 2) The agent exchanges the id_token for a scoped access token (ID-JAG / XAA).
	agent := authsec.NewAgentIdentity(authsec.AgentIdentityConfig{
		Issuer:        issuer,
		ClientID:      os.Getenv("AUTHSEC_AGENT_CLIENT_ID"),
		Auth:          authsec.NewClientSecretAuth(os.Getenv("AUTHSEC_AGENT_CLIENT_SECRET")),
		IDPIssuer:     os.Getenv("AUTHSEC_IDP_ISSUER"),
		PreferredMode: "auto",
	})

	opts := []authsec.AccessForOption{
		authsec.WithUserSession(idToken),
		authsec.WithRequestedScopes("mcp:tools:read"),
	}

	token, err := agent.AccessFor(ctx, resource, opts...)

	// 3) If access is pending admin approval, poll until approved.
	var pending *authsec.PendingApprovalError
	if errors.As(err, &pending) {
		log.Printf("access pending approval (request %s); polling…", pending.RequestID)
		token, err = authsec.PollUntilApproved(ctx, agent, resource, pending.StatusURL, nil, opts...)
	}
	if err != nil {
		log.Fatalf("access_for: %v", err)
	}

	log.Printf("acquired ID-JAG access token (%d chars)", len(token))
}
