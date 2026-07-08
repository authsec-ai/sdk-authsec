package authsec

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// spiffeSvidAssertionType is the client-assertion type AuthSec uses for a
// SPIFFE JWT-SVID (shared by SpiffeSvidAuth and SpiffeWorkloadIdentity).
const spiffeSvidAssertionType = "urn:authsec:params:oauth:client-assertion-type:spiffe-svid"

// ClientAuth is a pluggable client-authentication method used at the token
// endpoint and requester-bootstrap. Implementations contribute HTTP headers
// (e.g. Basic) and/or POST body params (e.g. client_assertion for
// private_key_jwt / SPIFFE-SVID). Mirrors the Python SDK's ClientAuth base
// class in identity/credentials.py.
//
// A nil map return from either method contributes nothing.
type ClientAuth interface {
	// Headers returns HTTP headers for client authentication (e.g. an
	// Authorization: Basic header for client_secret_basic).
	Headers(clientID string) map[string]string
	// BodyParams returns POST body params for client authentication (e.g.
	// client_assertion_type + client_assertion). tokenEndpoint is the audience
	// an assertion must be bound to.
	BodyParams(clientID, tokenEndpoint string) map[string]string
}

// ClientSecretAuth implements client_secret_basic: the client id + shared
// secret are sent as HTTP Basic auth on every request. The secret crosses the
// wire each time, so protect it like a password and rotate periodically.
type ClientSecretAuth struct {
	secret string
}

// NewClientSecretAuth returns a ClientSecretAuth. It panics if secret is empty,
// consistent with NewAgentIdentity's fail-fast constructor style.
func NewClientSecretAuth(secret string) *ClientSecretAuth {
	if secret == "" {
		panic("NewClientSecretAuth: secret is required")
	}
	return &ClientSecretAuth{secret: secret}
}

// Headers returns the Authorization: Basic header for client_secret_basic.
func (a *ClientSecretAuth) Headers(clientID string) map[string]string {
	creds := clientID + ":" + a.secret
	return map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(creds)),
	}
}

// BodyParams contributes nothing — client_secret_basic authenticates via the
// Authorization header.
func (a *ClientSecretAuth) BodyParams(clientID, tokenEndpoint string) map[string]string {
	return nil
}

// String never leaks the secret in logs.
func (a *ClientSecretAuth) String() string { return "ClientSecretAuth(***)" }

// PrivateKeyJwtAuth implements private_key_jwt (RFC 7523): each request carries
// a freshly signed JWT assertion (5-minute lifetime, single-use jti, audience-
// bound to the token endpoint). The private key never leaves the process;
// AuthSec verifies it with the public key registered in the portal JWKS.
type PrivateKeyJwtAuth struct {
	key *rsa.PrivateKey
	kid string
}

// NewPrivateKeyJwtAuth builds a PrivateKeyJwtAuth from an RSA private key —
// either PEM content (contains "-----BEGIN") or a filesystem path to a .pem
// file — and the kid of the matching public key registered in AuthSec.
func NewPrivateKeyJwtAuth(privateKey, kid string) (*PrivateKeyJwtAuth, error) {
	if privateKey == "" {
		return nil, fmt.Errorf("NewPrivateKeyJwtAuth: privateKey is required")
	}
	if kid == "" {
		return nil, fmt.Errorf("NewPrivateKeyJwtAuth: kid is required (the key ID of the public key registered in AuthSec)")
	}
	key, err := loadRSAPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return &PrivateKeyJwtAuth{key: key, kid: kid}, nil
}

// Headers contributes nothing — private_key_jwt authenticates via body params.
func (a *PrivateKeyJwtAuth) Headers(clientID string) map[string]string { return nil }

// BodyParams returns the signed client_assertion. On the (near-impossible)
// event of a signing failure it returns nil, which fails closed: the request
// carries no client authentication and the server rejects it.
func (a *PrivateKeyJwtAuth) BodyParams(clientID, tokenEndpoint string) map[string]string {
	jti, err := randomHex(16)
	if err != nil {
		return nil
	}
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": tokenEndpoint,
		"jti": jti,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	})
	tok.Header["kid"] = a.kid
	assertion, err := tok.SignedString(a.key)
	if err != nil {
		return nil
	}
	return map[string]string{
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		"client_assertion":      assertion,
	}
}

// String never leaks key material in logs.
func (a *PrivateKeyJwtAuth) String() string { return fmt.Sprintf("PrivateKeyJwtAuth(kid=%q)", a.kid) }

// SpiffeSvidAuth authenticates with a pre-obtained SPIFFE JWT-SVID sent as a
// client_assertion. Low-level: use this when you already hold an SVID. For
// automatic SVID fetching + renewal inside Kubernetes, use
// SpiffeWorkloadIdentity. SVIDs are short-lived (~5 min); this type does NOT
// refresh them.
type SpiffeSvidAuth struct {
	svid string
}

// NewSpiffeSvidAuth returns a SpiffeSvidAuth. It panics if svid is empty,
// consistent with the other constructors' fail-fast style.
func NewSpiffeSvidAuth(svid string) *SpiffeSvidAuth {
	if svid == "" {
		panic("NewSpiffeSvidAuth: svid is required")
	}
	return &SpiffeSvidAuth{svid: svid}
}

// Headers contributes nothing — the SVID is sent as a body client_assertion.
func (a *SpiffeSvidAuth) Headers(clientID string) map[string]string { return nil }

// BodyParams returns the SPIFFE JWT-SVID as a client_assertion.
func (a *SpiffeSvidAuth) BodyParams(clientID, tokenEndpoint string) map[string]string {
	return map[string]string{
		"client_assertion_type": spiffeSvidAssertionType,
		"client_assertion":      a.svid,
	}
}

// String never leaks the SVID in logs.
func (a *SpiffeSvidAuth) String() string { return "SpiffeSvidAuth(***)" }

// loadRSAPrivateKey loads an RSA private key from PEM content or a file path.
func loadRSAPrivateKey(privateKey string) (*rsa.PrivateKey, error) {
	var pemBytes []byte
	if strings.Contains(privateKey, "-----BEGIN") {
		pemBytes = []byte(privateKey)
	} else {
		b, err := os.ReadFile(privateKey)
		if err != nil {
			return nil, fmt.Errorf("private key is neither PEM content nor a readable file path: %w", err)
		}
		pemBytes = b
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key PEM: %w", err)
	}
	return key, nil
}

// randomHex returns n random bytes hex-encoded (2n chars).
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
