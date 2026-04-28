package authsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

// manifestPublishTimeout is the maximum time the SDK will wait for a manifest
// publish to complete before giving up. Set generously — manifest publish is
// best-effort and never blocks startup.
const manifestPublishTimeout = 30 * time.Second

// ManifestTool is one entry in the SDK manifest payload sent to AuthSec.
// Mirrors authsec/controllers/platform/scope_matrix_controller.go:ManifestToolPayload.
type ManifestTool struct {
	Name            string          `json:"name"`
	Title           string          `json:"title,omitempty"`
	Description     string          `json:"description,omitempty"`
	InputSchema     json.RawMessage `json:"input_schema,omitempty"`
	Annotations     json.RawMessage `json:"annotations,omitempty"`
	SuggestedScopes []string        `json:"suggested_scopes,omitempty"`
}

// PublishManifest enumerates the tools served by the given inner MCP handler
// (via a synthetic JSON-RPC tools/list call) and PUTs the result to AuthSec's
// /sdk-manifest endpoint.
//
// When cfg.ToolInventoryProvider is set, synthetic enumeration is skipped entirely
// and the provider's output is used as the tool inventory. Use this for handlers
// that require custom auth on initialize, use non-HTTP transports, or otherwise
// don't fit the synthetic enumeration path.
//
// This is a best-effort, one-way push:
//   - Network failures, non-2xx responses, or empty tool lists do NOT propagate
//     errors that could affect the SDK's startup or runtime behavior.
//   - The runtime SDK functions identically whether this call succeeded or not;
//     the manifest is purely admin-facing inventory data for AuthSec's UI.
//
// The returned error is informational — typical callers log it and continue.
//
// The synthetic tools/list call goes against the inner handler directly (preceded
// by a synthetic initialize + notifications/initialized handshake), NOT through
// the auth-wrapping layer.
func PublishManifest(ctx context.Context, cfg Config, innerHandler http.Handler) error {
	if cfg.ResourceServerID == "" {
		return fmt.Errorf("PublishManifest requires Config.ResourceServerID")
	}
	if cfg.IntrospectionClientID == "" || cfg.IntrospectionClientSecret == "" {
		return fmt.Errorf("PublishManifest requires Config.IntrospectionClientID and Config.IntrospectionClientSecret")
	}

	endpoint, err := manifestEndpoint(cfg)
	if err != nil {
		return err
	}

	var tools []rawTool

	if cfg.ToolInventoryProvider != nil {
		// Escape hatch: use caller-supplied inventory instead of synthetic enumeration.
		manifestTools, err := cfg.ToolInventoryProvider()
		if err != nil {
			return fmt.Errorf("ToolInventoryProvider: %w", err)
		}
		// Convert ManifestTool → rawTool for uniform downstream handling.
		for _, mt := range manifestTools {
			tools = append(tools, rawTool{
				Name:        mt.Name,
				Title:       mt.Title,
				Description: mt.Description,
				InputSchema: mt.InputSchema,
				Annotations: mt.Annotations,
			})
		}
	} else {
		if innerHandler == nil {
			return fmt.Errorf("PublishManifest requires a non-nil MCP handler when ToolInventoryProvider is not set")
		}
		tools, err = enumerateTools(ctx, innerHandler)
		if err != nil {
			return fmt.Errorf("enumerate tools via synthetic tools/list: %w", err)
		}
	}

	manifest := buildManifestPayload(tools, cfg.ToolScopeSuggestions)

	body, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build manifest request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(cfg.IntrospectionClientID, cfg.IntrospectionClientSecret)

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: manifestPublishTimeout}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("publish manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
		return fmt.Errorf("manifest publish returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// manifestEndpoint derives the manifest publish URL from the configured
// authorization server / issuer.
func manifestEndpoint(cfg Config) (string, error) {
	base := strings.TrimRight(cfg.AuthorizationServer, "/")
	if base == "" {
		base = strings.TrimRight(cfg.Issuer, "/")
	}
	if base == "" {
		return "", fmt.Errorf("PublishManifest requires AuthorizationServer or Issuer")
	}
	return fmt.Sprintf("%s/authsec/resource-servers/%s/sdk-manifest", base, cfg.ResourceServerID), nil
}

// rawTool is the JSON shape MCP servers return for each tool from tools/list.
// We carry annotations and inputSchema as RawMessage so they pass through
// untouched — the admin UI consumes them as-is.
type rawTool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
}

type toolsListResponse struct {
	Result struct {
		Tools      []rawTool `json:"tools"`
		NextCursor string    `json:"nextCursor,omitempty"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// enumerateTools issues a synthetic MCP handshake followed by paginated tools/list
// against the inner handler. The handler is invoked via httptest.ResponseRecorder,
// so no real network round-trip is involved. Auth is bypassed because the inner
// handler is the un-wrapped MCP handler.
//
// Handshake: initialize → notifications/initialized → tools/list (paginated).
// Any Mcp-Session-Id header returned from initialize is forwarded on all subsequent calls.
func enumerateTools(ctx context.Context, handler http.Handler) ([]rawTool, error) {
	// ── Step 1: synthetic initialize ────────────────────────────────────────
	sessionID := syntheticInitialize(ctx, handler)

	// ── Step 2: synthetic notifications/initialized (fire-and-forget) ───────
	syntheticInitialized(ctx, handler, sessionID)

	// ── Step 3: paginated tools/list ─────────────────────────────────────────
	var all []rawTool
	cursor := ""
	for i := 0; i < 100; i++ { // safety cap on pagination loops
		params := map[string]interface{}{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		reqBody, err := json.Marshal(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      i + 1,
			"method":  "tools/list",
			"params":  params,
		})
		if err != nil {
			return nil, err
		}

		httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqBody))
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Accept", "application/json")
		if sessionID != "" {
			httpReq.Header.Set("Mcp-Session-Id", sessionID)
		}
		httpReq = httpReq.WithContext(ctx)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httpReq)

		if rec.Code < 200 || rec.Code >= 300 {
			return nil, fmt.Errorf("synthetic tools/list returned HTTP %d", rec.Code)
		}

		var resp toolsListResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			return nil, fmt.Errorf("parse tools/list response: %w", err)
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("tools/list returned JSON-RPC error %d: %s",
				resp.Error.Code, resp.Error.Message)
		}

		all = append(all, resp.Result.Tools...)

		if resp.Result.NextCursor == "" {
			break
		}
		cursor = resp.Result.NextCursor
	}

	return all, nil
}

// syntheticInitialize sends a synthetic JSON-RPC initialize to the handler and
// returns any Mcp-Session-Id header value for use in subsequent calls.
// Non-fatal: if initialize fails, enumeration continues without a session ID —
// some servers are permissive about this.
func syntheticInitialize(ctx context.Context, handler http.Handler) string {
	initBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      0,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "authsec-manifest-publisher",
				"version": "1.0",
			},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(initBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	return rec.Header().Get("Mcp-Session-Id")
}

// syntheticInitialized sends the notifications/initialized notification.
// Non-fatal: ignore errors since this is a fire-and-forget notification.
func syntheticInitialized(ctx context.Context, handler http.Handler, sessionID string) {
	notifBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
		"params":  map[string]interface{}{},
	})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(notifBody))
	req.Header.Set("Content-Type", "application/json")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	_ = rec // result ignored — notifications have no response
}

// buildManifestPayload converts enumerated tools + the developer's optional
// scope suggestions map into the request body shape AuthSec expects.
func buildManifestPayload(tools []rawTool, suggestions map[string][]string) map[string]interface{} {
	out := make([]ManifestTool, 0, len(tools))
	for _, t := range tools {
		entry := ManifestTool{
			Name:        t.Name,
			Title:       t.Title,
			Description: t.Description,
			InputSchema: t.InputSchema,
			Annotations: t.Annotations,
		}
		if scopes, ok := suggestions[t.Name]; ok {
			// Defensive copy so concurrent map mutation in the caller can't
			// affect what we marshal.
			entry.SuggestedScopes = append([]string{}, scopes...)
		}
		out = append(out, entry)
	}
	return map[string]interface{}{"tools": out}
}
