// quickstart is the smallest possible AuthSec-protected MCP server.
//
// This is the "ten lines that protect a server" example referenced from the
// Go SDK docs page. Real values are read from env so the same binary runs
// against any AuthSec backend without recompiling.
//
//	export AUTHSEC_BASE=http://localhost:7468
//	export AUTHSEC_RS_ID=<id from POST /authsec/resource-servers>
//	export AUTHSEC_RS_SECRET=<introspection_secret>
//	export AUTHSEC_RESOURCE_URI=http://localhost:8000/mcp
//	go run ./examples/quickstart
//
// The MCP handler here is a one-line stub that always returns OK on
// tools/list — the point of this example is the SDK wiring, not MCP itself.
// For a runnable demo with actual tools, see ./examples/firstrun.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	authsec "github.com/authsec-ai/sdk-authsec/packages/go-sdk"
)

func main() {
	base := os.Getenv("AUTHSEC_BASE")
	rsID := os.Getenv("AUTHSEC_RS_ID")
	rsSecret := os.Getenv("AUTHSEC_RS_SECRET")
	resourceURI := os.Getenv("AUTHSEC_RESOURCE_URI")

	cfg := authsec.Config{
		Issuer:                    base,
		AuthorizationServer:       base,
		JWKSURL:                   base + "/oauth/jwks",
		IntrospectionURL:          base + "/oauth/introspect",
		ResourceServerID:          rsID,
		IntrospectionClientID:     rsID,
		IntrospectionClientSecret: rsSecret,
		ResourceURI:               resourceURI,
	}

	mux := http.NewServeMux()
	if err := authsec.MountMCP(mux, "/mcp", http.HandlerFunc(mcpStub), cfg); err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on :8000 — resource_uri=%s", resourceURI)
	log.Fatal(http.ListenAndServe(":8000", mux))
}

// mcpStub stands in for a real MCP implementation. Replace with your own.
func mcpStub(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
}
