package authsec

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

type Validator interface {
	Validate(ctx context.Context, token string) (*Principal, error)
}

type HybridValidator struct {
	cfg Config

	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey
}

func NewHybridValidator(cfg Config) (*HybridValidator, error) {
	n := cfg.normalized()
	if err := n.Validate(); err != nil {
		return nil, err
	}
	return &HybridValidator{cfg: n, keys: map[string]*rsa.PublicKey{}}, nil
}

func (v *HybridValidator) Validate(ctx context.Context, token string) (*Principal, error) {
	var jwtPrincipal *Principal
	var jwtErr error

	if strings.Count(token, ".") == 2 && v.cfg.JWKSURL != "" {
		jwtPrincipal, jwtErr = v.validateJWT(ctx, token)
	}

	if v.cfg.IntrospectionURL != "" {
		introspected, err := v.introspect(ctx, token)
		if err != nil && jwtPrincipal == nil {
			return nil, err
		}
		if introspected != nil {
			if jwtPrincipal != nil && introspected.Subject != "" && jwtPrincipal.Subject != "" && introspected.Subject != jwtPrincipal.Subject {
				return nil, fmt.Errorf("jwt subject and introspection subject mismatch")
			}
			if jwtPrincipal == nil {
				jwtPrincipal = introspected
			} else {
				jwtPrincipal.Active = introspected.Active
				if len(introspected.Scopes) > 0 {
					jwtPrincipal.Scopes = introspected.Scopes
				}
				if len(introspected.Audience) > 0 {
					jwtPrincipal.Audience = introspected.Audience
				}
				for k, val := range introspected.Claims {
					jwtPrincipal.Claims[k] = val
				}
			}
		}
	}

	if jwtPrincipal == nil {
		if jwtErr != nil {
			return nil, jwtErr
		}
		return nil, fmt.Errorf("token validation failed")
	}

	if !jwtPrincipal.Active {
		return nil, fmt.Errorf("token is not active")
	}

	if !contains(jwtPrincipal.Audience, v.cfg.ResourceURI) {
		if resource, ok := jwtPrincipal.Claims["resource"].(string); !ok || resource != v.cfg.ResourceURI {
			return nil, fmt.Errorf("token audience does not include resource URI")
		}
	}

	return jwtPrincipal, nil
}

func (v *HybridValidator) validateJWT(ctx context.Context, token string) (*Principal, error) {
	parsed, err := jwt.Parse(token, func(j *jwt.Token) (any, error) {
		if _, ok := j.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unsupported signing method: %s", j.Method.Alg())
		}
		return v.lookupKey(ctx, j)
	})
	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("invalid jwt")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected jwt claims type")
	}
	if iss, _ := claims["iss"].(string); iss != v.cfg.Issuer {
		return nil, fmt.Errorf("issuer mismatch")
	}

	principal := &Principal{
		Subject:  stringClaim(claims, "sub"),
		Issuer:   stringClaim(claims, "iss"),
		Audience: audienceFromClaims(claims["aud"]),
		Scopes:   scopesFromClaims(claims["scope"]),
		Claims:   map[string]any{},
		Active:   true,
	}
	for k, val := range claims {
		principal.Claims[k] = val
	}
	return principal, nil
}

func (v *HybridValidator) lookupKey(ctx context.Context, token *jwt.Token) (*rsa.PublicKey, error) {
	kid, _ := token.Header["kid"].(string)
	v.mu.RLock()
	if key, ok := v.keys[kid]; ok {
		v.mu.RUnlock()
		return key, nil
	}
	v.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	keys := map[string]*rsa.PublicKey{}
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" {
			continue
		}
		pub, err := rsaKeyFromJWK(key.N, key.E)
		if err != nil {
			return nil, err
		}
		keys[key.Kid] = pub
	}

	v.mu.Lock()
	for keyID, key := range keys {
		v.keys[keyID] = key
	}
	v.mu.Unlock()

	if kid != "" {
		if key, ok := keys[kid]; ok {
			return key, nil
		}
	}
	if len(keys) == 1 {
		for _, key := range keys {
			return key, nil
		}
	}
	return nil, fmt.Errorf("signing key not found")
}

func rsaKeyFromJWK(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes).Int64()
	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

func (v *HybridValidator) introspect(ctx context.Context, token string) (*Principal, error) {
	form := url.Values{}
	form.Set("token", token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.cfg.IntrospectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(v.cfg.IntrospectionClientID, v.cfg.IntrospectionClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if active, _ := payload["active"].(bool); !active {
		return &Principal{Active: false, Claims: payload}, nil
	}
	return &Principal{
		Subject:  stringClaim(payload, "sub"),
		Issuer:   stringClaim(payload, "iss"),
		Audience: audienceFromClaims(payload["aud"]),
		Scopes:   scopesFromClaims(payload["scope"]),
		Claims:   payload,
		Active:   true,
	}, nil
}

func stringClaim(claims map[string]any, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

func audienceFromClaims(value any) []string {
	switch raw := value.(type) {
	case string:
		return []string{raw}
	case []string:
		return append([]string(nil), raw...)
	case []any:
		aud := make([]string, 0, len(raw))
		for _, item := range raw {
			if val, ok := item.(string); ok {
				aud = append(aud, val)
			}
		}
		return aud
	default:
		return nil
	}
}

func scopesFromClaims(value any) []string {
	switch raw := value.(type) {
	case string:
		return strings.Fields(raw)
	case []string:
		return append([]string(nil), raw...)
	case []any:
		scopes := make([]string, 0, len(raw))
		for _, item := range raw {
			if val, ok := item.(string); ok {
				scopes = append(scopes, val)
			}
		}
		return scopes
	default:
		return nil
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
