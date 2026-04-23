package authsec

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

const protectedResourcePrefix = "/.well-known/oauth-protected-resource"

type protectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ResourceName           string   `json:"resource_name,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
}

func ProtectedResourceHandler(cfg Config) (http.Handler, error) {
	rt, err := NewRuntime(cfg)
	if err != nil {
		return nil, err
	}
	return rt.ProtectedResourceHandler(), nil
}

// BuildResourceMetadataPath returns the RFC 9728 metadata path for the given resource URI.
//
// For root resources (no path component), this returns /.well-known/oauth-protected-resource.
// For path-based resources (e.g. https://mcp.example.com/mcp), this returns
// /.well-known/oauth-protected-resource/mcp.
func BuildResourceMetadataPath(resourceURI string) string {
	u, err := url.Parse(resourceURI)
	if err != nil {
		return protectedResourcePrefix
	}
	path := strings.Trim(strings.TrimSpace(u.Path), "/")
	if path == "" {
		return protectedResourcePrefix
	}
	return protectedResourcePrefix + "/" + path
}

func BuildResourceMetadataURL(resourceURI string) string {
	u, err := url.Parse(resourceURI)
	if err != nil {
		return protectedResourcePrefix
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host, "/") + BuildResourceMetadataPath(resourceURI)
}

// isMetadataRequest reports whether the given path is the metadata discovery path
// for the resource. Only the path derived from the resource URI is matched
// (alias-only). For root resources the alias IS the bare well-known path, so
// bare-path requests still resolve for root resources.
//
// Path-based resources (e.g. /mcp) only match their derived alias
// (/.well-known/oauth-protected-resource/mcp). The bare
// /.well-known/oauth-protected-resource path is NOT matched for path-based
// resources — use BuildResourceMetadataPath to discover the correct path.
func isMetadataRequest(resourceURI, path string) bool {
	metadataPath := BuildResourceMetadataPath(resourceURI)
	return path == metadataPath || path == metadataPath+"/"
}

func writeMetadata(w http.ResponseWriter, cfg Config) {
	metadata := protectedResourceMetadata{
		Resource:               cfg.ResourceURI,
		AuthorizationServers:   []string{cfg.AuthorizationServer},
		ResourceName:           cfg.ResourceName,
		ScopesSupported:        append([]string(nil), cfg.SupportedScopes...),
		BearerMethodsSupported: append([]string(nil), cfg.BearerMethodsSupported...),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metadata)
}
