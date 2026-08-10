package authsec

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// rsaPrivateKeyPEM returns a PKCS#1 PEM string for key (test helper shared
// across this package's tests).
func rsaPrivateKeyPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

func TestClientSecretAuth_Headers(t *testing.T) {
	a := NewClientSecretAuth("sec")
	h := a.Headers("id")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("id:sec"))
	if h["Authorization"] != want {
		t.Fatalf("expected Authorization %q, got %q", want, h["Authorization"])
	}
	if bp := a.BodyParams("id", "https://as.example/token"); bp != nil {
		t.Fatalf("expected nil body params for client_secret_basic, got %v", bp)
	}
}

func TestNewClientSecretAuth_PanicsOnEmpty(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on empty secret")
		}
	}()
	NewClientSecretAuth("")
}

// All credential types must satisfy the ClientAuth interface.
var (
	_ ClientAuth = (*ClientSecretAuth)(nil)
	_ ClientAuth = (*PrivateKeyJwtAuth)(nil)
	_ ClientAuth = (*SpiffeSvidAuth)(nil)
)

func TestPrivateKeyJwtAuth_BodyParams(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	auth, err := NewPrivateKeyJwtAuth(rsaPrivateKeyPEM(t, key), "kid-1")
	if err != nil {
		t.Fatalf("NewPrivateKeyJwtAuth: %v", err)
	}
	if auth.Headers("client-1") != nil {
		t.Fatal("expected nil headers for private_key_jwt")
	}

	bp := auth.BodyParams("client-1", "https://as.example/oauth/token")
	if bp["client_assertion_type"] != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("unexpected client_assertion_type: %q", bp["client_assertion_type"])
	}
	assertion := bp["client_assertion"]
	if assertion == "" {
		t.Fatal("expected a non-empty client_assertion")
	}

	tok, err := jwt.Parse(assertion, func(*jwt.Token) (any, error) { return &key.PublicKey, nil })
	if err != nil || !tok.Valid {
		t.Fatalf("assertion did not verify: err=%v valid=%v", err, tok.Valid)
	}
	claims := tok.Claims.(jwt.MapClaims)
	if claims["iss"] != "client-1" || claims["sub"] != "client-1" {
		t.Fatalf("expected iss=sub=client-1, got iss=%v sub=%v", claims["iss"], claims["sub"])
	}
	if claims["aud"] != "https://as.example/oauth/token" {
		t.Fatalf("expected aud bound to token endpoint, got %v", claims["aud"])
	}
	if claims["jti"] == nil || claims["jti"] == "" {
		t.Fatal("expected a jti claim")
	}
	if tok.Header["kid"] != "kid-1" {
		t.Fatalf("expected kid header kid-1, got %v", tok.Header["kid"])
	}
}

func TestNewPrivateKeyJwtAuth_LoadsFromFile(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte(rsaPrivateKeyPEM(t, key)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	auth, err := NewPrivateKeyJwtAuth(path, "kid-1")
	if err != nil {
		t.Fatalf("NewPrivateKeyJwtAuth from file: %v", err)
	}
	if auth.BodyParams("c", "https://x/token")["client_assertion"] == "" {
		t.Fatal("expected an assertion from a file-loaded key")
	}
}

func TestNewPrivateKeyJwtAuth_Errors(t *testing.T) {
	if _, err := NewPrivateKeyJwtAuth("", "kid"); err == nil {
		t.Fatal("expected error for empty private key")
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := NewPrivateKeyJwtAuth(rsaPrivateKeyPEM(t, key), ""); err == nil {
		t.Fatal("expected error for empty kid")
	}
	if _, err := NewPrivateKeyJwtAuth("-----BEGIN RSA PRIVATE KEY-----\nnotvalid\n-----END RSA PRIVATE KEY-----", "kid"); err == nil {
		t.Fatal("expected error for malformed PEM")
	}
}

func TestSpiffeSvidAuth_BodyParams(t *testing.T) {
	a := NewSpiffeSvidAuth("eyJsvid")
	if a.Headers("c") != nil {
		t.Fatal("expected nil headers for SPIFFE-SVID")
	}
	bp := a.BodyParams("c", "https://x/token")
	if bp["client_assertion_type"] != "urn:authsec:params:oauth:client-assertion-type:spiffe-svid" {
		t.Fatalf("unexpected client_assertion_type: %q", bp["client_assertion_type"])
	}
	if bp["client_assertion"] != "eyJsvid" {
		t.Fatalf("expected the SVID as client_assertion, got %q", bp["client_assertion"])
	}
}

func TestNewSpiffeSvidAuth_PanicsOnEmpty(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on empty svid")
		}
	}()
	NewSpiffeSvidAuth("")
}
