// agent-m2m demonstrates the three machine-to-machine credential types plus the
// Kubernetes SPIFFE workload path. All four end at the same place — a scoped
// AuthSec access token you pass as a Bearer to an MCP server.
//
// Pick a method with AUTH_METHOD = secret | private-key-jwt | spiffe-svid | spiffe-workload.
//
//	export AUTHSEC_ISSUER=https://mcpauthz.com
//	export AUTHSEC_CLIENT_ID=<service-account-client-id>
//	export AUTHSEC_RESOURCE_URI=https://your-mcp-server.example.com/mcp
//	# then, depending on AUTH_METHOD:
//	export AUTHSEC_CLIENT_SECRET=sec_...                 # secret
//	export AUTHSEC_PRIVATE_KEY_PEM="$(cat key.pem)"      # private-key-jwt (or a path)
//	export AUTHSEC_KEY_ID=key-1                          # private-key-jwt
//	export AUTHSEC_SVID=eyJ...                           # spiffe-svid
//	export AUTHSEC_SPIFFE_ID=spiffe://acme.example/svc   # spiffe-workload
//	go run ./examples/agent-m2m
package main

import (
	"context"
	"log"
	"os"

	authsec "github.com/authsec-ai/sdk-authsec/packages/go-sdk"
)

func main() {
	ctx := context.Background()
	issuer := os.Getenv("AUTHSEC_ISSUER")
	clientID := os.Getenv("AUTHSEC_CLIENT_ID")
	resource := os.Getenv("AUTHSEC_RESOURCE_URI")

	method := os.Getenv("AUTH_METHOD")
	if method == "" {
		method = "secret"
	}

	switch method {
	case "secret":
		agent := authsec.NewAgentIdentity(authsec.AgentIdentityConfig{
			Issuer:   issuer,
			ClientID: clientID,
			Auth:     authsec.NewClientSecretAuth(os.Getenv("AUTHSEC_CLIENT_SECRET")),
		})
		mustAccess(ctx, agent, resource)

	case "private-key-jwt":
		auth, err := authsec.NewPrivateKeyJwtAuth(os.Getenv("AUTHSEC_PRIVATE_KEY_PEM"), os.Getenv("AUTHSEC_KEY_ID"))
		if err != nil {
			log.Fatalf("private_key_jwt: %v", err)
		}
		agent := authsec.NewAgentIdentity(authsec.AgentIdentityConfig{
			Issuer:   issuer,
			ClientID: clientID,
			Auth:     auth,
		})
		mustAccess(ctx, agent, resource)

	case "spiffe-svid":
		agent := authsec.NewAgentIdentity(authsec.AgentIdentityConfig{
			Issuer:   issuer,
			ClientID: clientID,
			Auth:     authsec.NewSpiffeSvidAuth(os.Getenv("AUTHSEC_SVID")),
		})
		mustAccess(ctx, agent, resource)

	case "spiffe-workload":
		// Kubernetes: fetches + renews the JWT-SVID from the local SPIRE agent.
		workload, err := authsec.NewSpiffeWorkloadIdentity(authsec.SpiffeConfig{
			MCPServerURL: resource,
			ClientID:     clientID,
			SpiffeID:     os.Getenv("AUTHSEC_SPIFFE_ID"),
			Scopes:       "mcp:read mcp:tools:read",
		})
		if err != nil {
			log.Fatalf("spiffe workload: %v", err)
		}
		token, err := workload.AccessFor(ctx)
		if err != nil {
			log.Fatalf("AccessFor: %v", err)
		}
		log.Printf("acquired access token (%d chars) via spiffe-workload", len(token))

	default:
		log.Fatalf("unknown AUTH_METHOD %q (want secret | private-key-jwt | spiffe-svid | spiffe-workload)", method)
	}
}

func mustAccess(ctx context.Context, agent *authsec.AgentIdentity, resource string) {
	token, err := agent.AccessFor(ctx, resource, authsec.WithRequestedScopes("mcp:tools:read"))
	if err != nil {
		log.Fatalf("AccessFor: %v", err)
	}
	log.Printf("acquired access token (%d chars)", len(token))
}
