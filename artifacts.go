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
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func handleArtifacts(w http.ResponseWriter, r *http.Request) {
	// Basic path parsing to get hash
	// Path is /v8/artifacts/:hash
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "Invalid artifact hash", http.StatusBadRequest)
		return
	}
	hash := parts[3]

	// Validate hash to prevent path injection
	if hash == "" || hash == "." || hash == ".." || strings.Contains(hash, "/") || strings.Contains(hash, "\\") {
		http.Error(w, "Invalid artifact hash", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		getArtifact(w, r, hash)
	case http.MethodPut:
		putArtifact(w, r, hash)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func getArtifact(w http.ResponseWriter, r *http.Request, hash string) {
	teamID := r.URL.Query().Get("teamId")
	if teamID == "" {
		teamID = r.URL.Query().Get("slug")
	}
	if teamID == "" {
		teamID = "default"
	}

	// Validate teamID to ensure it is a single safe path component
	teamID = strings.TrimSpace(teamID)
	if teamID == "" ||
		strings.Contains(teamID, "/") ||
		strings.Contains(teamID, "\\") ||
		strings.Contains(teamID, "..") {
		http.Error(w, "Invalid team ID", http.StatusBadRequest)
		return
	}

	// Authentication for Read (if enabled)
	if !config.NoSecurity && !config.NoSecurityRead {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

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
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			log.Printf("Auth failed for GET %s [%s]: %v", hash, teamID, err)
			return
		}

		// Audience Check
		if config.RequiredAudience != "" {
			audiences, err := token.Claims.GetAudience()
			if err != nil {
				http.Error(w, "Invalid Audience", http.StatusUnauthorized)
				return
			}
			validAud := false
			for _, aud := range audiences {
				if aud == config.RequiredAudience {
					validAud = true
					break
				}
			}
			if !validAud {
				http.Error(w, "Invalid Audience", http.StatusUnauthorized)
				return
			}
		}

		// Check access
		if !hasAccess(token, teamID, "GET", hash) {
			atomic.AddUint64(&misses, 1)
			http.Error(w, "Forbidden: no access to this namespace", http.StatusForbidden)
			return
		}
	}

	// Open Read Access
	path := filepath.Join(config.CacheDir, teamID, hash)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		atomic.AddUint64(&misses, 1)
		log.Printf("GET %s [%s] - Miss", hash, teamID)
		w.Header().Set("X-goTurbo-Cache", "MISS")
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("GET %s [%s] - Error: %v", hash, teamID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	start := time.Now()
	w.Header().Set("X-goTurbo-Cache", "HIT")
	w.WriteHeader(http.StatusOK)
	n, _ := io.Copy(w, f)
	duration := time.Since(start)
	atomic.AddUint64(&hits, 1)
	log.Printf("GET %s [%s] - %d bytes in %v", hash, teamID, n, duration)
}

func putArtifact(w http.ResponseWriter, r *http.Request, hash string) {
	defer r.Body.Close()
	teamID := r.URL.Query().Get("teamId")
	if teamID == "" {
		teamID = r.URL.Query().Get("slug")
	}
	if teamID == "" {
		teamID = "default"
	}

	// Validate teamID to ensure it is a single safe path component
	teamID = strings.TrimSpace(teamID)
	if teamID == "" ||
		strings.Contains(teamID, "/") ||
		strings.Contains(teamID, "\\") ||
		strings.Contains(teamID, "..") {
		atomic.AddUint64(&putErrors, 1)
		http.Error(w, "Invalid team ID", http.StatusBadRequest)
		return
	}

	// Authentication
	if !config.NoSecurity {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			atomic.AddUint64(&putErrors, 1)
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

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
			atomic.AddUint64(&putErrors, 1)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			log.Printf("Auth failed for %s [%s]: %v", hash, teamID, err)
			return
		}

		// Audience Check
		if config.RequiredAudience != "" {
			audiences, err := token.Claims.GetAudience()
			if err != nil {
				atomic.AddUint64(&putErrors, 1)
				http.Error(w, "Invalid Audience", http.StatusUnauthorized)
				log.Printf("Auth failed for %s [%s]: failed to parse audience", hash, teamID)
				return
			}

			validAud := false
			for _, aud := range audiences {
				if aud == config.RequiredAudience {
					validAud = true
					break
				}
			}
			if !validAud {
				atomic.AddUint64(&putErrors, 1)
				http.Error(w, "Invalid Audience", http.StatusUnauthorized)
				log.Printf("Auth failed for %s [%s]: invalid audience %v (required: %s)", hash, teamID, audiences, config.RequiredAudience)
				return
			}
		}

		// Check access
		if !hasAccess(token, teamID, "PUT", hash) {
			atomic.AddUint64(&putErrors, 1)
			http.Error(w, "Forbidden: no access to this namespace", http.StatusForbidden)
			return
		}
	}

	// Ensure team directory exists
	teamPath := filepath.Join(config.CacheDir, teamID)
	if err := os.MkdirAll(teamPath, 0755); err != nil {
		atomic.AddUint64(&putErrors, 1)
		log.Printf("Failed to create team directory %s: %v", teamID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Save artifact
	path := filepath.Join(teamPath, hash)
	var oldSize int64
	exists := false
	if info, err := os.Stat(path); err == nil {
		oldSize = info.Size()
		exists = true
	}

	// Create temp file first
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		atomic.AddUint64(&putErrors, 1)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	start := time.Now()
	written, err := io.Copy(f, r.Body)
	f.Close()
	duration := time.Since(start)
	if err != nil {
		atomic.AddUint64(&putErrors, 1)
		os.Remove(tmpPath)
		http.Error(w, "Failed to write artifact", http.StatusInternalServerError)
		return
	}

	if err := os.Rename(tmpPath, path); err != nil {
		atomic.AddUint64(&putErrors, 1)
		os.Remove(tmpPath)
		http.Error(w, "Failed to save artifact", http.StatusInternalServerError)
		return
	}

	// Update counters
	if !exists {
		atomic.AddUint64(&totalFiles, 1)
	}

	delta := int64(written) - oldSize

	if delta > 0 {
		atomic.AddUint64(&totalBytes, uint64(delta))
	} else if delta < 0 {
		atomic.AddUint64(&totalBytes, ^uint64(-delta-1))
	}

	w.WriteHeader(http.StatusOK)
	atomic.AddUint64(&putSuccess, 1)
	log.Printf("PUT %s [%s] - %d bytes in %v", hash, teamID, written, duration)
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		cleanup()
	}
}

func cleanup() {
	now := time.Now()
	err := filepath.WalkDir(config.CacheDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if now.Sub(info.ModTime()) > config.CacheMaxAge {
				size := info.Size()
				if err := os.Remove(path); err == nil {
					atomic.AddUint64(&totalFiles, ^uint64(0)) // -1
					atomic.AddUint64(&totalBytes, ^uint64(size-1))
					log.Printf("Cleaned up %s", filepath.Base(path))
				}
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("Error during cleanup walk: %v", err)
	}
}
