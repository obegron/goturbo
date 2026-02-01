package main

import (
	"archive/tar"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestHandleBulk(t *testing.T) {
	// Setup temporary cache dir
	tmpDir, err := os.MkdirTemp("", "turbo-bulk-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Setup Config
	config = Config{
		CacheDir:      tmpDir,
		NoSecurity:    false,
		IDAdminRoles:  make(map[string][]string),
		RoleClaimPath: "groups",
	}

	// Create test files in "default" namespace
	nsDir := filepath.Join(tmpDir, "default")
	os.MkdirAll(nsDir, 0755)

	os.WriteFile(filepath.Join(nsDir, "maven-artifact-1"), []byte("content1"), 0644)
	os.WriteFile(filepath.Join(nsDir, "maven-artifact-2"), []byte("content2"), 0644)
	os.WriteFile(filepath.Join(nsDir, "npm-artifact-1"), []byte("content3"), 0644)

	// Generate Test Keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	staticKey = &privateKey.PublicKey

	// Helper to generate token
	createToken := func(role string) string {
		claims := jwt.MapClaims{
			"iss":    "test-issuer",
			"sub":    "test-user",
			"groups": []string{role},
			"exp":    time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		str, _ := token.SignedString(privateKey)
		return str
	}

	// 1. Test Unauth
	req := httptest.NewRequest("GET", "/v8/bulk?prefix=maven-", nil)
	w := httptest.NewRecorder()
	handleBulk(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}

	// 2. Test Forbidden (Non-Admin)
	config.IDAdminRoles["default"] = []string{"admin-role"}
	req = httptest.NewRequest("GET", "/v8/bulk?prefix=maven-", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user-role"))
	w = httptest.NewRecorder()
	handleBulk(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}

	// 3. Test Success (Admin)
	// We need to map issuer to ID first for the new logic
	config.IssuerIDMap = map[string]string{"default": "test-issuer"}
	
	req = httptest.NewRequest("GET", "/v8/bulk?prefix=maven-", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("admin-role"))
	w = httptest.NewRecorder()
	handleBulk(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Verify Tar Content
	tr := tar.NewReader(w.Body)
	foundFiles := make(map[string]string)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		content, _ := io.ReadAll(tr)
		foundFiles[header.Name] = string(content)
	}

	if len(foundFiles) != 2 {
		t.Errorf("Expected 2 files, got %d", len(foundFiles))
	}
	if foundFiles["maven-artifact-1"] != "content1" {
		t.Errorf("Content mismatch for maven-artifact-1")
	}
	if _, ok := foundFiles["npm-artifact-1"]; ok {
		t.Errorf("Should not contain npm-artifact-1")
	}
}
