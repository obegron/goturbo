package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/golang-jwt/jwt/v5"
)

func handleMaven(w http.ResponseWriter, r *http.Request) {
	namespace, relPath, ok := parseMavenPath(r.URL.Path)
	if !ok {
		http.Error(w, "Invalid Maven path. Expected /maven/{namespace}/...", http.StatusBadRequest)
		return
	}
	if relPath == "" && r.Method != http.MethodHead {
		http.Error(w, "Invalid Maven path. Expected /maven/{namespace}/...", http.StatusBadRequest)
		return
	}

	if shouldAuthenticateMavenRequest(r.Method) {
		token, err := parseAndValidateAuthToken(r)
		if err != nil {
			if r.Method == http.MethodPut {
				atomic.AddUint64(&mavenPutErrors, 1)
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			log.Printf("Auth failed for MAVEN %s [%s]: %v", r.Method, namespace, err)
			return
		}

		if !hasAccess(token, namespace, r.Method, relPath) {
			if r.Method == http.MethodPut {
				atomic.AddUint64(&mavenPutErrors, 1)
			}
			http.Error(w, "Forbidden: no access to this namespace", http.StatusForbidden)
			return
		}
	}
	if relPath == "" && r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	namespaceDir := filepath.Join(config.CacheDir, "maven", namespace)
	if err := os.MkdirAll(namespaceDir, 0755); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("Failed to create Maven namespace dir %s: %v", namespace, err)
		return
	}

	artifactPath := filepath.Join(namespaceDir, filepath.Clean(relPath))
	if artifactPath == namespaceDir {
		http.Error(w, "Invalid Maven path", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(artifactPath, namespaceDir+string(filepath.Separator)) {
		http.Error(w, "Invalid Maven path", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		getMavenArtifact(w, r, artifactPath, r.Method == http.MethodHead)
	case http.MethodPut:
		putMavenArtifact(w, r, artifactPath)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		recordMavenMetrics(r.Method, http.StatusMethodNotAllowed)
	}
}

func getMavenArtifact(w http.ResponseWriter, r *http.Request, path string, headOnly bool) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		http.NotFound(w, r)
		recordMavenMetrics(http.MethodGet, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		recordMavenMetrics(http.MethodGet, http.StatusInternalServerError)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err == nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	}

	w.WriteHeader(http.StatusOK)
	if !headOnly {
		_, _ = io.Copy(w, f)
	}
	recordMavenMetrics(http.MethodGet, http.StatusOK)
}

func putMavenArtifact(w http.ResponseWriter, r *http.Request, path string) {
	defer r.Body.Close()

	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0755); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		atomic.AddUint64(&mavenPutErrors, 1)
		return
	}

	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		atomic.AddUint64(&mavenPutErrors, 1)
		return
	}

	if _, err := io.Copy(f, r.Body); err != nil {
		f.Close()
		_ = os.Remove(tmpPath)
		http.Error(w, "Failed to write artifact", http.StatusInternalServerError)
		atomic.AddUint64(&mavenPutErrors, 1)
		return
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		http.Error(w, "Failed to write artifact", http.StatusInternalServerError)
		atomic.AddUint64(&mavenPutErrors, 1)
		return
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		http.Error(w, "Failed to save artifact", http.StatusInternalServerError)
		atomic.AddUint64(&mavenPutErrors, 1)
		return
	}

	w.WriteHeader(http.StatusOK)
	atomic.AddUint64(&mavenPutSuccess, 1)
}

func recordMavenMetrics(method string, status int) {
	switch method {
	case http.MethodGet, http.MethodHead:
		if status == http.StatusNotFound {
			atomic.AddUint64(&mavenMisses, 1)
			return
		}
		if status >= 200 && status < 300 {
			atomic.AddUint64(&mavenHits, 1)
		}
	case http.MethodPut:
		if status >= 200 && status < 300 {
			atomic.AddUint64(&mavenPutSuccess, 1)
		} else {
			atomic.AddUint64(&mavenPutErrors, 1)
		}
	}
}

func parseMavenPath(path string) (namespace string, relPath string, ok bool) {
	if path == "/maven" || path == "/maven/" {
		return "", "", false
	}

	prefix := "/maven/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}

	trimmed := strings.TrimPrefix(path, prefix)
	parts := strings.SplitN(trimmed, "/", 2)
	namespace, ok = sanitizePathComponent(parts[0])
	if !ok {
		return "", "", false
	}

	if len(parts) == 2 {
		relPath = strings.TrimPrefix(parts[1], "/")
	}

	return namespace, relPath, true
}

func shouldAuthenticateMavenRequest(method string) bool {
	if config.NoSecurity {
		return false
	}
	if config.NoSecurityRead && isReadLikeMavenMethod(method) {
		return false
	}
	return true
}

func isReadLikeMavenMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func parseAndValidateAuthToken(r *http.Request) (*jwt.Token, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, fmt.Errorf("invalid Authorization scheme")
	}
	tokenString := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if tokenString == "" {
		return nil, fmt.Errorf("missing bearer token")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		}
		if staticKey != nil {
			return staticKey, nil
		}
		return keyManager.GetKey(token)
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if config.RequiredAudience != "" {
		audiences, err := token.Claims.GetAudience()
		if err != nil {
			return nil, fmt.Errorf("failed to parse audience: %w", err)
		}

		validAud := false
		for _, aud := range audiences {
			if aud == config.RequiredAudience {
				validAud = true
				break
			}
		}
		if !validAud {
			return nil, fmt.Errorf("invalid audience: %v", audiences)
		}
	}

	return token, nil
}
