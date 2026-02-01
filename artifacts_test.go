package main

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func setupTest(t *testing.T) {
	config.CacheDir = t.TempDir()
	config.NoSecurity = true
	config.NoSecurityRead = true
}

func TestGetArtifact_Hit(t *testing.T) {
	setupTest(t)

	// Create cache file
	teamDir := filepath.Join(config.CacheDir, "test")
	os.MkdirAll(teamDir, 0755)
	content := []byte("cached content")
	os.WriteFile(filepath.Join(teamDir, "abc123"), content, 0644)

	req := httptest.NewRequest("GET", "/v8/artifacts/abc123?teamId=test", nil)
	w := httptest.NewRecorder()

	getArtifact(w, req, "abc123")

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	if w.Header().Get("X-goTurbo-Cache") != "HIT" {
		t.Error("Expected HIT header")
	}
	if !bytes.Equal(w.Body.Bytes(), content) {
		t.Error("Content mismatch")
	}
}

func TestGetArtifact_Miss(t *testing.T) {
	setupTest(t)

	req := httptest.NewRequest("GET", "/v8/artifacts/missing?teamId=test", nil)
	w := httptest.NewRecorder()

	getArtifact(w, req, "missing")

	if w.Code != 404 {
		t.Errorf("Expected 404, got %d", w.Code)
	}
	if w.Header().Get("X-goTurbo-Cache") != "MISS" {
		t.Error("Expected MISS header")
	}
}

func TestPutArtifact_New(t *testing.T) {
	setupTest(t)

	content := []byte("new artifact")
	req := httptest.NewRequest("PUT", "/v8/artifacts/new123?teamId=test", bytes.NewReader(content))
	w := httptest.NewRecorder()

	putArtifact(w, req, "new123")

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Verify file written
	written, err := os.ReadFile(filepath.Join(config.CacheDir, "test", "new123"))
	if err != nil {
		t.Fatalf("File not written: %v", err)
	}
	if !bytes.Equal(written, content) {
		t.Error("Content mismatch")
	}
}

func TestPutArtifact_Overwrite(t *testing.T) {
	setupTest(t)

	// Create existing file
	teamDir := filepath.Join(config.CacheDir, "test")
	os.MkdirAll(teamDir, 0755)
	os.WriteFile(filepath.Join(teamDir, "existing"), []byte("old"), 0644)

	// Overwrite
	newContent := []byte("new content")
	req := httptest.NewRequest("PUT", "/v8/artifacts/existing?teamId=test", bytes.NewReader(newContent))
	w := httptest.NewRecorder()

	putArtifact(w, req, "existing")

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Verify overwrite
	written, _ := os.ReadFile(filepath.Join(teamDir, "existing"))
	if !bytes.Equal(written, newContent) {
		t.Error("File not overwritten")
	}
}

func TestHandleArtifacts_GET(t *testing.T) {
	setupTest(t)

	teamDir := filepath.Join(config.CacheDir, "test")
	os.MkdirAll(teamDir, 0755)
	os.WriteFile(filepath.Join(teamDir, "hash1"), []byte("data"), 0644)

	req := httptest.NewRequest("GET", "/v8/artifacts/hash1?teamId=test", nil)
	w := httptest.NewRecorder()

	handleArtifacts(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestHandleArtifacts_PUT(t *testing.T) {
	setupTest(t)

	req := httptest.NewRequest("PUT", "/v8/artifacts/new?teamId=test", bytes.NewReader([]byte("data")))
	w := httptest.NewRecorder()

	handleArtifacts(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestHandleArtifacts_InvalidMethod(t *testing.T) {
	setupTest(t)

	req := httptest.NewRequest("DELETE", "/v8/artifacts/hash", nil)
	w := httptest.NewRecorder()

	handleArtifacts(w, req)

	if w.Code != 405 { // Method Not Allowed
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestHandleEvents(t *testing.T) {
	req := httptest.NewRequest("POST", "/v8/artifacts/events", nil)
	w := httptest.NewRecorder()

	handleEvents(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestHandleHealth(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	handleHealth(w, req)

	if w.Code != 200 {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}
