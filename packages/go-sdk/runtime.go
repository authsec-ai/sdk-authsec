package authsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Runtime struct {
	cfg       Config
	validator Validator
}

func NewRuntime(cfg Config) (*Runtime, error) {
	n := cfg.normalized()
	if err := n.Validate(); err != nil {
		return nil, err
	}
	validator, err := NewHybridValidator(n)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		cfg:       n,
		validator: validator,
	}, nil
}

func WrapMCPHTTP(next http.Handler, cfg Config) (http.Handler, error) {
	rt, err := NewRuntime(cfg)
	if err != nil {
		return nil, err
	}
	return rt.Wrap(next), nil
}

func AuthMiddleware(cfg Config) (func(http.Handler) http.Handler, error) {
	rt, err := NewRuntime(cfg)
	if err != nil {
		return nil, err
	}
	return rt.AuthMiddleware(), nil
}

func (rt *Runtime) ProtectedResourceHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeMetadata(w, rt.cfg)
	})
}

func (rt *Runtime) AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := parseBearerToken(r)
			if err != nil {
				if err == errMissingAuthorization {
					rt.writeUnauthorized(w)
					return
				}
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			principal, err := rt.validator.Validate(r.Context(), token)
			if err != nil {
				rt.writeUnauthorized(w)
				return
			}

			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
		})
	}
}

func (rt *Runtime) Wrap(next http.Handler) http.Handler {
	auth := rt.AuthMiddleware()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isMetadataRequest(rt.cfg.ResourceURI, r.URL.Path) {
			rt.ProtectedResourceHandler().ServeHTTP(w, r)
			return
		}

		auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			req, body, ok := parseMCPRequest(r)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			principal, _ := PrincipalFromContext(r.Context())
			switch req.Method {
			case "tools/call":
				if err := rt.AuthorizeTool(principal, req.Params.Name); err != nil {
					rt.writeInsufficientScope(w, req.Params.Name)
					return
				}
				next.ServeHTTP(w, r)
			case "tools/list":
				rec := newResponseRecorder()
				next.ServeHTTP(rec, r)
				rt.writeFilteredToolResponse(w, rec, principal)
			default:
				next.ServeHTTP(w, r)
			}
		})).ServeHTTP(w, r)
	})
}

func (rt *Runtime) AuthorizeTool(principal *Principal, toolName string) error {
	required := RequiredScopesForTool(rt.cfg.Policy, toolName)
	if principal == nil {
		return fmt.Errorf("missing principal")
	}
	if !principal.HasAnyScope(required) {
		return fmt.Errorf("insufficient scope")
	}
	return nil
}

func (rt *Runtime) writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q`, BuildResourceMetadataURL(rt.cfg.ResourceURI)))
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func (rt *Runtime) writeInsufficientScope(w http.ResponseWriter, toolName string) {
	required := RequiredScopesForTool(rt.cfg.Policy, toolName)
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer error="insufficient_scope", scope=%q, resource_metadata=%q, error_description=%q`,
		strings.Join(required, " "),
		BuildResourceMetadataURL(rt.cfg.ResourceURI),
		"Additional scopes required: "+strings.Join(required, ", "),
	))
	http.Error(w, "Forbidden: insufficient scopes", http.StatusForbidden)
}

func (rt *Runtime) writeFilteredToolResponse(w http.ResponseWriter, rec *responseRecorder, principal *Principal) {
	body := rec.body.Bytes()
	if rec.statusCode == 0 {
		rec.statusCode = http.StatusOK
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		rec.WriteTo(w)
		return
	}

	result, ok := payload["result"].(map[string]any)
	if !ok {
		rec.WriteTo(w)
		return
	}

	rawTools, ok := result["tools"].([]any)
	if !ok {
		rec.WriteTo(w)
		return
	}

	filtered := make([]any, 0, len(rawTools))
	for _, rawTool := range rawTools {
		toolMap, ok := rawTool.(map[string]any)
		if !ok {
			continue
		}
		name, _ := toolMap["name"].(string)
		if rt.AuthorizeTool(principal, name) == nil {
			filtered = append(filtered, rawTool)
		}
	}

	result["tools"] = filtered
	body, err := json.Marshal(payload)
	if err != nil {
		rec.WriteTo(w)
		return
	}

	for key, values := range rec.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.Header().Del("Content-Length")
	w.WriteHeader(rec.statusCode)
	_, _ = w.Write(body)
}

type mcpEnvelope struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Name string `json:"name"`
	} `json:"params"`
}

func parseMCPRequest(r *http.Request) (*mcpEnvelope, []byte, bool) {
	if r.Method != http.MethodPost {
		return nil, nil, false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, false
	}
	var req mcpEnvelope
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, body, false
	}
	return &req, body, true
}

var errMissingAuthorization = fmt.Errorf("missing required Authorization header")

func parseBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errMissingAuthorization
	}
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
		return authHeader[7:], nil
	}
	if strings.Contains(authHeader, " ") {
		return "", fmt.Errorf("badly formatted Authorization header")
	}
	return authHeader, nil
}

type responseRecorder struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{header: make(http.Header)}
}

func (r *responseRecorder) Header() http.Header { return r.header }

func (r *responseRecorder) Write(data []byte) (int, error) {
	if r.statusCode == 0 {
		r.statusCode = http.StatusOK
	}
	return r.body.Write(data)
}

func (r *responseRecorder) WriteHeader(statusCode int) { r.statusCode = statusCode }

func (r *responseRecorder) WriteTo(w http.ResponseWriter) {
	for key, values := range r.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(r.statusCode)
	_, _ = w.Write(r.body.Bytes())
}

func WithValidator(ctx context.Context, validator Validator) context.Context {
	return context.WithValue(ctx, validatorCtxKey{}, validator)
}

type validatorCtxKey struct{}
