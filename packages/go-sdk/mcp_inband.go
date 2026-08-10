package authsec

import (
	"encoding/json"
	"net/http"
	"strings"
)

// This file ports the MCP-client-aware denial behavior from the Python/TS SDKs
// (runtime/server.py, runtime/server.ts):
//
//   - MCP handshake requests (initialize / notifications/initialized / ping)
//     pass through even when a token is present but invalid, so an MCP session
//     can survive a mid-session token expiry.
//   - tools/call and generic JSON-RPC auth denials are returned IN-BAND as
//     JSON-RPC responses (HTTP 200) so MCP clients receive properly structured
//     errors instead of a raw HTTP status.
//
// Gating mirrors Python's _should_handle_mcp_auth_denial_in_band: in-band only
// applies when a token is present AND the body is a JSON-RPC request. No token,
// non-JSON-RPC bodies, and 503 (policy_unavailable) fall back to HTTP status.

// mcpHandshakeMethods are the MCP session-setup methods that may pass through
// without a valid token (mirrors _MCP_HANDSHAKE_METHODS in server.py).
var mcpHandshakeMethods = map[string]bool{
	"initialize":                true,
	"notifications/initialized": true,
	"ping":                      true,
}

// parseMCPEnvelopesTolerant parses a request body for the denial path. Unlike
// the strict authenticated-path parser it never returns an error — an
// unparseable or non-POST body simply yields isJSONRPC=false, letting the
// caller fall back to a standard HTTP challenge.
//
// isJSONRPC mirrors Python's _is_json_rpc_request: true iff at least one
// envelope carries jsonrpc == "2.0".
func parseMCPEnvelopesTolerant(method string, body []byte) (envelopes []*mcpEnvelope, isBatch bool, isJSONRPC bool) {
	if method != http.MethodPost {
		return nil, false, false
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, false, false
	}
	if trimmed[0] == '[' {
		var batch []mcpEnvelope
		if err := json.Unmarshal(body, &batch); err != nil {
			return nil, false, false
		}
		env := make([]*mcpEnvelope, len(batch))
		rpc := false
		for i := range batch {
			env[i] = &batch[i]
			if batch[i].JSONRPC == "2.0" {
				rpc = true
			}
		}
		return env, true, rpc && len(env) > 0
	}
	var one mcpEnvelope
	if err := json.Unmarshal(body, &one); err != nil {
		return nil, false, false
	}
	return []*mcpEnvelope{&one}, false, one.JSONRPC == "2.0"
}

// isHandshakeEnvelopes reports whether every parsed envelope is an MCP handshake
// method (mirrors _is_mcp_handshake_request: a batch must be non-empty and
// contain only handshake methods).
func isHandshakeEnvelopes(envelopes []*mcpEnvelope) bool {
	if len(envelopes) == 0 {
		return false
	}
	for _, env := range envelopes {
		if !mcpHandshakeMethods[env.Method] {
			return false
		}
	}
	return true
}

// isToolsCallEnvelopes reports whether any envelope is a tools/call request
// (mirrors _is_tools_call_request for single + batch bodies).
func isToolsCallEnvelopes(envelopes []*mcpEnvelope) bool {
	for _, env := range envelopes {
		if env.Method == "tools/call" {
			return true
		}
	}
	return false
}

// envelopesAreJSONRPC reports whether any envelope carries jsonrpc == "2.0"
// (mirrors _is_json_rpc_request for the authenticated path).
func envelopesAreJSONRPC(envelopes []*mcpEnvelope) bool {
	for _, env := range envelopes {
		if env.JSONRPC == "2.0" {
			return true
		}
	}
	return false
}

// validJSONRPCID echoes a JSON-RPC id back only if it is a valid id type
// (number, string, or null); anything else becomes null. Mirrors
// _valid_json_rpc_id in server.py. The raw bytes are preserved so numeric ids
// are not reshaped (e.g. 1 stays 1, not 1.0).
func validJSONRPCID(raw json.RawMessage) json.RawMessage {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return json.RawMessage("null")
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return json.RawMessage("null")
	}
	switch v.(type) {
	case nil, string, float64:
		return raw
	default:
		return json.RawMessage("null")
	}
}

// inbandDenial carries everything the in-band builders need. code is the
// wire-level error code emitted to clients ("invalid_token", "invalid_audience",
// "insufficient_scope", "policy_unavailable").
type inbandDenial struct {
	status         int
	code           string
	description    string
	reason         string // stable subcode for 401s; empty otherwise
	tool           string
	requiredScopes []string
	grantedScopes  []string
}

// toolMeta builds the _meta.authsec object for an in-band tool result
// (mirrors the inline authsec_meta in _mcp_tool_auth_error_for_request).
func (d inbandDenial) toolMeta() map[string]any {
	m := map[string]any{
		"error":             d.code,
		"status":            d.status,
		"error_description": d.description,
	}
	if len(d.requiredScopes) > 0 {
		m["required_scopes"] = d.requiredScopes
	}
	if len(d.grantedScopes) > 0 {
		m["granted_scopes"] = d.grantedScopes
	}
	if d.tool != "" {
		m["tool"] = d.tool
	}
	if d.reason != "" {
		m["reason"] = d.reason
	}
	return m
}

// rpcMeta builds the data.authsec object for an in-band JSON-RPC error
// (mirrors _authsec_denial_meta — no granted_scopes / reason).
func (d inbandDenial) rpcMeta() map[string]any {
	m := map[string]any{
		"error":             d.code,
		"status":            d.status,
		"error_description": d.description,
	}
	if len(d.requiredScopes) > 0 {
		m["required_scopes"] = d.requiredScopes
	}
	if d.tool != "" {
		m["tool"] = d.tool
	}
	return m
}

// friendlyMessage renders a human-readable message for the LLM/agent
// (mirrors _friendly_auth_denial_message).
func (d inbandDenial) friendlyMessage() string {
	if d.status == http.StatusForbidden {
		parts := make([]string, 0, 4)
		if d.tool != "" {
			parts = append(parts, "Tool '"+d.tool+"' cannot be called with this token.")
		} else {
			parts = append(parts, "This action cannot be performed with this token.")
		}
		if len(d.requiredScopes) > 0 {
			parts = append(parts, "Required scope: "+strings.Join(d.requiredScopes, ", ")+".")
		}
		if len(d.grantedScopes) > 0 {
			parts = append(parts, "Your token has: "+strings.Join(d.grantedScopes, ", ")+".")
		} else {
			parts = append(parts, "Your token does not include the required scope.")
		}
		parts = append(parts, "Ask an admin to grant the required scope to your role, or use a different tool.")
		return strings.Join(parts, " ")
	}
	switch d.reason {
	case "token_revoked":
		return "Access has been revoked. The user needs to re-authenticate to get a new token."
	case "client_registration_revoked":
		return "This client's registration has been revoked by an admin. " +
			"Re-authentication will not help — contact the workspace admin."
	}
	return "Token is invalid or expired. The user needs to sign in again."
}

// mcpToolAuthErrorForEnvelope builds one in-band tools/call error result
// (mirrors _mcp_tool_auth_error_for_request): HTTP 200 with isError=true and
// _meta.authsec so MCP clients surface a readable, structured error.
func mcpToolAuthErrorForEnvelope(env *mcpEnvelope, d inbandDenial) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      validJSONRPCID(env.ID),
		"result": map[string]any{
			"content": []map[string]any{{"type": "text", "text": d.friendlyMessage()}},
			"isError": true,
			"_meta":   map[string]any{"authsec": d.toolMeta()},
		},
	}
}

// mcpJSONRPCAuthErrorForEnvelope builds one in-band JSON-RPC error object
// (mirrors _mcp_json_rpc_auth_error_for_request): code -32003 for 403,
// -32001 otherwise.
func mcpJSONRPCAuthErrorForEnvelope(env *mcpEnvelope, d inbandDenial) map[string]any {
	code := -32001
	if d.status == http.StatusForbidden {
		code = -32003
	}
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      validJSONRPCID(env.ID),
		"error": map[string]any{
			"code":    code,
			"message": d.friendlyMessage(),
			"data":    map[string]any{"authsec": d.rpcMeta()},
		},
	}
}

// writeInbandToolAuthError writes a 200 in-band tools/call error. For a batch
// body every item is rendered as an error result (mirrors the list branch of
// _mcp_tool_auth_error_payload).
func writeInbandToolAuthError(w http.ResponseWriter, envelopes []*mcpEnvelope, isBatch bool, d inbandDenial) {
	var payload any
	if isBatch {
		arr := make([]map[string]any, 0, len(envelopes))
		for _, env := range envelopes {
			arr = append(arr, mcpToolAuthErrorForEnvelope(env, d))
		}
		payload = arr
	} else {
		payload = mcpToolAuthErrorForEnvelope(envelopes[0], d)
	}
	writeInbandJSON(w, payload)
}

// writeInbandJSONRPCError writes a 200 in-band JSON-RPC error (mirrors
// _mcp_json_rpc_auth_error_payload).
func writeInbandJSONRPCError(w http.ResponseWriter, envelopes []*mcpEnvelope, isBatch bool, d inbandDenial) {
	var payload any
	if isBatch {
		arr := make([]map[string]any, 0, len(envelopes))
		for _, env := range envelopes {
			arr = append(arr, mcpJSONRPCAuthErrorForEnvelope(env, d))
		}
		payload = arr
	} else {
		payload = mcpJSONRPCAuthErrorForEnvelope(envelopes[0], d)
	}
	writeInbandJSON(w, payload)
}

func writeInbandJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(payload)
}
