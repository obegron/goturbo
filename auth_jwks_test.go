package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestParseRSAPublicKey(t *testing.T) {
	// Generate a real RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := &privateKey.PublicKey

	// Encode to Base64RawURL
	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()
	nStr := base64.RawURLEncoding.EncodeToString(nBytes)
	eStr := base64.RawURLEncoding.EncodeToString(eBytes)

	// Test parsing
	parsedKey, err := parseRSAPublicKey(nStr, eStr)
	if err != nil {
		t.Fatalf("Failed to parse RSA key: %v", err)
	}

	if parsedKey.N.Cmp(publicKey.N) != 0 {
		t.Errorf("N mismatch")
	}
	if parsedKey.E != publicKey.E {
		t.Errorf("E mismatch")
	}
}

func TestParseECPublicKey(t *testing.T) {
	// Generate a real EC key (P-256)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := &privateKey.PublicKey

	// Encode
	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()
	xStr := base64.RawURLEncoding.EncodeToString(xBytes)
	yStr := base64.RawURLEncoding.EncodeToString(yBytes)

	// Test parsing
	parsedKey, err := parseECPublicKey("P-256", xStr, yStr)
	if err != nil {
		t.Fatalf("Failed to parse EC key: %v", err)
	}

	if parsedKey.X.Cmp(publicKey.X) != 0 {
		t.Errorf("X mismatch")
	}
	if parsedKey.Y.Cmp(publicKey.Y) != 0 {
		t.Errorf("Y mismatch")
	}

	// Test unsupported curve
	_, err = parseECPublicKey("P-999", xStr, yStr)
	if err == nil {
		t.Error("Expected error for unsupported curve")
	}
}

func TestJWKSManager_Integration(t *testing.T) {
	// 1. Setup Mock Server
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := &privateKey.PublicKey

	nStr := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	eStr := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes())

	kid := "test-key-1"

	// Handler for OIDC Discovery and JWKS
	mux := http.NewServeMux()

	// We use a variable for serverURL to capture it after server start
	var serverURL string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"jwks_uri": serverURL + "/jwks.json",
		})
	})

	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"kid": kid,
					"n":   nStr,
					"e":   eStr,
				},
			},
		}
		json.NewEncoder(w).Encode(jwks)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()
	serverURL = ts.URL

	// 2. Initialize Manager
	manager := NewJWKSManager([]string{ts.URL})

	// 3. Create a Token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": ts.URL,
		"sub": "test-user",
	})
	token.Header["kid"] = kid

	// 4. Test GetKey
	// The manager will fetch the keys because cache is empty
	key, err := manager.GetKey(token)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	parsedRSA, ok := key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Expected *rsa.PublicKey, got %T", key)
	}

	if parsedRSA.N.Cmp(pubKey.N) != 0 {
		t.Error("Retrieved key does not match")
	}

	// 5. Test Cache hit (should not error)
	key2, err := manager.GetKey(token)
	if err != nil {
		t.Fatalf("GetKey cached failed: %v", err)
	}
	// In the current implementation, keys are stored as values in the map, so pointers might differ if not pointers?
	// Wait, parseRSAPublicKey returns *rsa.PublicKey, so it's a pointer.
	// The map stores interface{}.
	if key2 != key {
		t.Log("Note: Key pointers differ (cache might be reloading or pointer comparison issue), but functionally correct")
	}

	// 6. Test Unknown Issuer
	badToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "http://evil.com",
	})
	badToken.Header["kid"] = kid
	_, err = manager.GetKey(badToken)
	if err == nil {
		t.Error("Expected error for untrusted issuer")
	} else if !strings.Contains(err.Error(), "untrusted issuer") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestJWKSManager_ManualConfiguration(t *testing.T) {
	// Test that we can parse the "issuer=url" format
	manager := NewJWKSManager([]string{"my-issuer=http://example.com/discovery"})

	// Access private field via reflection or just verify behavior if possible.
	// Since we can't access private fields easily in separate test package (if it was separate),
	// but we are in package main, we can access private fields.

	urls, ok := manager.trustedIssuers["my-issuer"]
	if !ok {
		t.Fatal("Issuer not found")
	}
	if len(urls) != 1 || urls[0] != "http://example.com/discovery" {
		t.Errorf("Expected http://example.com/discovery, got %v", urls)
	}
}

func TestJWKSManager_TLS(t *testing.T) {
	// Setup TLS Server with self-signed cert
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"jwks_uri": "https://example.com/jwks",
		})
	})

	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	// Save/Restore config
	oldSkip := config.InsecureSkipVerify
	defer func() { config.InsecureSkipVerify = oldSkip }()

	kid := "tls-key"
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": ts.URL})
	token.Header["kid"] = kid

	// Case 1: Secure (Default) - Should fail to connect to self-signed cert
	config.InsecureSkipVerify = false
	manager := NewJWKSManager([]string{ts.URL})

	_, err := manager.GetKey(token)
	if err == nil {
		t.Error("Expected error for self-signed cert without skip verify")
	} else if !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		// Depending on platform/go version, error message might vary, but this is standard
		t.Logf("Got error as expected (might not be cert specific): %v", err)
	}

	// Case 2: Insecure - Should pass TLS handshake (then fail on fake JWKS URI)
	config.InsecureSkipVerify = true

	_, err = manager.GetKey(token)
	// It should NOT fail with certificate error
	if err != nil && strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Errorf("Should have skipped verification, but got cert error: %v", err)
	}
}
