package authsec

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type Config struct {
	Issuer                    string
	AuthorizationServer       string
	JWKSURL                   string
	IntrospectionURL          string
	IntrospectionClientID     string
	IntrospectionClientSecret string
	ResourceURI               string
	ResourceName              string
	SupportedScopes           []string
	BearerMethodsSupported    []string
	HTTPClient                *http.Client
	Logger                    *slog.Logger
	Policy                    ToolPolicy
	Now                       func() time.Time
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Issuer) == "" {
		return fmt.Errorf("issuer is required")
	}
	if strings.TrimSpace(c.ResourceURI) == "" {
		return fmt.Errorf("resource URI is required")
	}
	if strings.TrimSpace(c.JWKSURL) == "" && strings.TrimSpace(c.IntrospectionURL) == "" {
		return fmt.Errorf("at least one of JWKSURL or IntrospectionURL is required")
	}
	if strings.TrimSpace(c.IntrospectionURL) != "" {
		if strings.TrimSpace(c.IntrospectionClientID) == "" || strings.TrimSpace(c.IntrospectionClientSecret) == "" {
			return fmt.Errorf("introspection client credentials are required when introspection is enabled")
		}
	}
	return nil
}

func (c Config) normalized() Config {
	n := c
	if n.AuthorizationServer == "" {
		n.AuthorizationServer = n.Issuer
	}
	if n.ResourceName == "" {
		n.ResourceName = "AuthSec Protected MCP Resource"
	}
	if len(n.BearerMethodsSupported) == 0 {
		n.BearerMethodsSupported = []string{"header"}
	}
	if n.Policy == nil {
		n.Policy = AllowAllPolicy()
	}
	if n.HTTPClient == nil {
		n.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if n.Logger == nil {
		n.Logger = slog.Default()
	}
	if n.Now == nil {
		n.Now = time.Now
	}
	return n
}
