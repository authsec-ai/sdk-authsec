// firstrun is a minimal, executable demo MCP server protected by AuthSec.
//
// It's deliberately tiny — two tools (echo_read, echo_write), one HTTP route —
// so the entire OAuth + scope-matrix loop can be exercised end-to-end with
// curl. The /sdk/first-run docs page walks through reproducing 401, 403, and
// 200 against this exact binary.
//
// Configuration is read from environment variables that map 1:1 to the fields
// of the POST /authsec/resource-servers response body. Paste those values into
// your shell, run this, and the SDK does the rest.
//
//	export AUTHSEC_AUTHORIZATION_SERVER=http://localhost:7468
//	export AUTHSEC_ISSUER=http://localhost:7468
//	export AUTHSEC_JWKS_URL=http://localhost:7468/oauth/jwks
//	export AUTHSEC_INTROSPECTION_URL=http://localhost:7468/oauth/introspect
//	export AUTHSEC_RESOURCE_SERVER_ID=<id from POST /resource-servers>
//	export AUTHSEC_INTROSPECTION_SECRET=<introspection_secret from same response>
//	export AUTHSEC_RESOURCE_URI=http://localhost:8000/mcp
//	go run ./examples/firstrun
//
// Then in another terminal:
//
//	curl -sS http://localhost:8000/mcp  # → 401 + WWW-Authenticate
//
// See /sdk/first-run in the docs for the full token-acquisition walkthrough.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	authsec "github.com/authsec-ai/sdk-authsec/packages/go-sdk"
)

func main() {
	cfg := authsec.Config{
		// Pulled from POST /authsec/resource-servers response fields:
		//   issuer_url, jwks_uri, introspection_endpoint, id,
		//   introspection_secret, resource_url
		Issuer:                    mustGetenv("AUTHSEC_ISSUER"),
		AuthorizationServer:       mustGetenv("AUTHSEC_AUTHORIZATION_SERVER"),
		JWKSURL:                   mustGetenv("AUTHSEC_JWKS_URL"),
		IntrospectionURL:          mustGetenv("AUTHSEC_INTROSPECTION_URL"),
		ResourceServerID:          mustGetenv("AUTHSEC_RESOURCE_SERVER_ID"),
		IntrospectionClientID:     mustGetenv("AUTHSEC_RESOURCE_SERVER_ID"),
		IntrospectionClientSecret: mustGetenv("AUTHSEC_INTROSPECTION_SECRET"),
		ResourceURI:               mustGetenv("AUTHSEC_RESOURCE_URI"),
		ResourceName:              "firstrun-demo",

		// Local fallback used when AuthSec is unreachable. Required by the
		// RemoteWithLocalFallback policy mode; harmless under RemoteRequired
		// (the SDK still uses the remote matrix as the source of truth).
		ToolScopes: authsec.ToolScopeMap{
			"echo_read":  {"mcp:tools:read"},
			"echo_write": {"mcp:tools:write"},
		},
		PolicyMode: authsec.PolicyModeRemoteWithLocalFallback,

		// One-shot publish so this server's tool inventory appears in the
		// AuthSec admin UI. Best-effort — never blocks startup.
		PublishManifest: true,
		ToolScopeSuggestions: map[string][]string{
			"echo_read":  {"mcp:tools:read"},
			"echo_write": {"mcp:tools:write"},
		},
	}

	mux := http.NewServeMux()

	// MountMCP wires up the protected MCP endpoint AND the RFC 9728
	// /.well-known/oauth-protected-resource metadata route that the 401
	// WWW-Authenticate challenge points at.
	if err := authsec.MountMCP(mux, "/mcp", http.HandlerFunc(mcpHandler), cfg); err != nil {
		log.Fatalf("authsec: %v", err)
	}

	addr := getenvDefault("ADDR", ":8000")
	log.Printf("firstrun MCP server listening on %s — resource_uri=%s", addr, cfg.ResourceURI)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// mcpHandler is the minimal MCP transport. Real MCP servers use a library
// like github.com/modelcontextprotocol/go-sdk; this hand-rolled JSON-RPC is
// just enough to demonstrate how AuthSec wraps any HTTP handler.
func mcpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		JSONRPC string                 `json:"jsonrpc"`
		ID      any                    `json:"id"`
		Method  string                 `json:"method"`
		Params  map[string]any         `json:"params,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	switch req.Method {
	case "initialize":
		writeJSONRPC(w, req.ID, map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo":      map[string]any{"name": "firstrun-demo", "version": "0.0.1"},
			"capabilities":    map[string]any{"tools": map[string]any{}},
		})
	case "tools/list":
		writeJSONRPC(w, req.ID, map[string]any{
			"tools": []map[string]any{
				{
					"name":        "echo_read",
					"description": "Echo back the input string. Read-only.",
					"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}},
				},
				{
					"name":        "echo_write",
					"description": "Pretend to write the input string somewhere.",
					"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}},
				},
			},
		})
	case "tools/call":
		name, _ := req.Params["name"].(string)
		args, _ := req.Params["arguments"].(map[string]any)
		text, _ := args["text"].(string)
		writeJSONRPC(w, req.ID, map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": fmt.Sprintf("[%s] %s", name, text)},
			},
		})
	default:
		writeJSONRPCError(w, req.ID, -32601, "method not found: "+req.Method)
	}
}

func writeJSONRPC(w http.ResponseWriter, id any, result any) {
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func writeJSONRPCError(w http.ResponseWriter, id any, code int, message string) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": message},
	})
}

func mustGetenv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s is required (see file header for the full env list)", key)
	}
	return v
}

func getenvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
