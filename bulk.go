package main

import (
	"archive/tar"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func handleBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Parse Query Params
	prefix := r.URL.Query().Get("prefix")
	if prefix == "" {
		http.Error(w, "prefix is required", http.StatusBadRequest)
		return
	}
	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		namespace = "default"
	}
	// Validate namespace to ensure it is a single safe path component
	var ok bool
	namespace, ok = sanitizePathComponent(namespace)
	if !ok {
		http.Error(w, "Invalid namespace", http.StatusBadRequest)
		return
	}

	// 2. Authentication & Authorization (Admin only)
	if !config.NoSecurity {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Allow parsing with registered keys (same as artifacts.go)
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
			log.Printf("Bulk Auth failed: %v", err)
			return
		}

		// Check Admin Access for Namespace
		if !hasAdminAccess(token, namespace) {
			http.Error(w, "Forbidden: requires admin access for this namespace", http.StatusForbidden)
			log.Printf("Bulk Forbidden: user does not have admin access to %s", namespace)
			return
		}
	}

	// 3. Prepare Stream
	teamPath := filepath.Join(config.CacheDir, namespace)
	// Check if directory exists
	if _, err := os.Stat(teamPath); os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"bulk-%s-%s.tar\"", namespace, prefix))

	// We are NOT compressing to .tar.gz based on "stream them not building it in memory".
	// The user mentioned "maven-{{hash}} will also be tar.gz files".
	// The prompt says: "streamed as a tar use archive/tar".
	// It basically implies wrapping the files in a tar stream.
	// Since the contained files might be compressed, wrapping them in a tar is fine.

	tw := tar.NewWriter(w)
	defer tw.Close()

	// 4. Walk and Stream
	err := filepath.WalkDir(teamPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		filename := d.Name()
		if !strings.HasPrefix(filename, prefix) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		// Create tar header
		header, err := tar.FileInfoHeader(info, filename)
		if err != nil {
			log.Printf("Error creating header for %s: %v", filename, err)
			return nil
		}

		// Ensure the name in the archive is relative/clean
		header.Name = filename

		if err := tw.WriteHeader(header); err != nil {
			log.Printf("Error writing header for %s: %v", filename, err)
			return err // Stop on write error (client disconnected?)
		}

		f, err := os.Open(path)
		if err != nil {
			log.Printf("Error opening file %s: %v", path, err)
			return nil
		}
		defer f.Close()

		if _, err := io.Copy(tw, f); err != nil {
			log.Printf("Error writing file content %s: %v", path, err)
			return err
		}

		return nil
	})

	if err != nil {
		log.Printf("Error during bulk walk: %v", err)
		// Can't really send error to client now as we started streaming
	}
}

// Helper to check for gzip content if needed, but user just said "tar".
func isGzip(r io.Reader) (bool, error) {
	return false, nil // Not implementing auto-detection for now
}
