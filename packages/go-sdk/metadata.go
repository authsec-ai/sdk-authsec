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

func isMetadataRequest(resourceURI, path string) bool {
	metadataPath := BuildResourceMetadataPath(resourceURI)
	return path == protectedResourcePrefix || path == metadataPath || path == metadataPath+"/"
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
