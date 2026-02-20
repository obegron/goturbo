package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/net/webdav"
)

var mavenLockSystem = webdav.NewMemLS()

func handleMaven(w http.ResponseWriter, r *http.Request) {
	namespace, relPath, ok := parseMavenPath(r.URL.Path)
	if !ok {
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

	namespaceDir := filepath.Join(config.CacheDir, "maven", namespace)
	if err := os.MkdirAll(namespaceDir, 0755); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("Failed to create Maven namespace dir %s: %v", namespace, err)
		return
	}

	path := "/"
	if relPath != "" {
		path = "/" + relPath
	}

	if r.Method == http.MethodPut {
		parent := filepath.Dir(relPath)
		if parent != "." && parent != "/" {
			if err := os.MkdirAll(filepath.Join(namespaceDir, parent), 0755); err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				log.Printf("Failed to create Maven parent dirs %s: %v", parent, err)
				return
			}
		}
	}

	davReq := r.Clone(r.Context())
	urlCopy := *r.URL
	urlCopy.Path = path
	davReq.URL = &urlCopy

	dav := &webdav.Handler{
		Prefix:     "/",
		FileSystem: webdav.Dir(namespaceDir),
		LockSystem: mavenLockSystem,
	}
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	dav.ServeHTTP(rec, davReq)
	recordMavenMetrics(r.Method, rec.status)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func recordMavenMetrics(method string, status int) {
	switch method {
	case http.MethodGet, http.MethodHead, "PROPFIND":
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
	case http.MethodGet, http.MethodHead, http.MethodOptions, "PROPFIND":
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
