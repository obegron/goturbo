package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestParseMavenPath(t *testing.T) {
	t.Run("valid namespace and path", func(t *testing.T) {
		namespace, relPath, ok := parseMavenPath("/maven/team-a/com/acme/cache.bin")
		if !ok {
			t.Fatal("expected valid Maven path")
		}
		if namespace != "team-a" {
			t.Fatalf("expected namespace team-a, got %s", namespace)
		}
		if relPath != "com/acme/cache.bin" {
			t.Fatalf("expected relPath com/acme/cache.bin, got %s", relPath)
		}
	})

	t.Run("invalid without namespace", func(t *testing.T) {
		_, _, ok := parseMavenPath("/maven/")
		if ok {
			t.Fatal("expected invalid Maven path")
		}
	})
}

func TestHandleMaven_NoSecurity_PutGet(t *testing.T) {
	setupTest(t)

	content := []byte("maven cache object")
	putReq := httptest.NewRequest("PUT", "/maven/team-a/object.bin", bytes.NewReader(content))
	putRes := httptest.NewRecorder()
	handleMaven(putRes, putReq)

	if putRes.Code < 200 || putRes.Code >= 300 {
		t.Fatalf("expected 2xx for PUT, got %d", putRes.Code)
	}

	getReq := httptest.NewRequest("GET", "/maven/team-a/object.bin", nil)
	getRes := httptest.NewRecorder()
	handleMaven(getRes, getReq)

	if getRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET, got %d", getRes.Code)
	}
	if !bytes.Equal(getRes.Body.Bytes(), content) {
		t.Fatal("GET content mismatch")
	}

	storedPath := filepath.Join(config.CacheDir, "maven", "team-a", "object.bin")
	if _, err := os.Stat(storedPath); err != nil {
		t.Fatalf("expected stored artifact at %s: %v", storedPath, err)
	}
}

func TestHandleMaven_NoSecurity_HeadNamespaceProbe(t *testing.T) {
	setupTest(t)

	req := httptest.NewRequest("HEAD", "/maven/team-a/", nil)
	res := httptest.NewRecorder()
	handleMaven(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200 for namespace HEAD probe, got %d", res.Code)
	}
}

func TestHandleMaven_Security(t *testing.T) {
	setupTest(t)
	config.NoSecurity = false
	config.NoSecurityRead = false
	config.RoleClaimPath = "groups"
	config.RolePattern = "role-{namespace}"
	config.RequiredAudience = ""
	config.IssuerIDMap = map[string]string{}
	config.IDAdminRoles = map[string][]string{}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	staticKey = &privateKey.PublicKey
	keyManager = nil
	t.Cleanup(func() { staticKey = nil })

	teamDir := filepath.Join(config.CacheDir, "maven", "team-a")
	if err := os.MkdirAll(teamDir, 0755); err != nil {
		t.Fatalf("failed to create team dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(teamDir, "secure.bin"), []byte("secure content"), 0644); err != nil {
		t.Fatalf("failed to write artifact: %v", err)
	}

	noAuthReq := httptest.NewRequest("GET", "/maven/team-a/secure.bin", nil)
	noAuthRes := httptest.NewRecorder()
	handleMaven(noAuthRes, noAuthReq)
	if noAuthRes.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", noAuthRes.Code)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"groups": []string{"role-team-a"},
	})
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	authReq := httptest.NewRequest("GET", "/maven/team-a/secure.bin", nil)
	authReq.Header.Set("Authorization", "Bearer "+tokenString)
	authRes := httptest.NewRecorder()
	handleMaven(authRes, authReq)
	if authRes.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid token, got %d", authRes.Code)
	}
}
