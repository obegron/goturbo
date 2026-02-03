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
	var walkRoot string
	if namespace != "" {
		// Clean namespace to ensure it's safe (basename check)
		var ok bool
		namespace, ok = sanitizePathComponent(namespace)
		if !ok {
			http.Error(w, "Invalid namespace", http.StatusBadRequest)
			return
		}
		walkRoot = filepath.Join(config.CacheDir, namespace)
	} else {
		walkRoot = config.CacheDir
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

		// Check Admin Access
		if !hasAdminAccess(token, namespace) {
			http.Error(w, "Forbidden: requires admin access", http.StatusForbidden)
			log.Printf("Bulk Forbidden: user does not have admin access")
			return
		}
	}

	// 3. Prepare Stream
	// Check if directory exists
	if _, err := os.Stat(walkRoot); os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}

	filenamePrefix := namespace
	if filenamePrefix == "" {
		filenamePrefix = "all"
	}
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"bulk-%s-%s.tar\"", filenamePrefix, prefix))

	tw := tar.NewWriter(w)
	defer tw.Close()

	// 4. Walk and Stream
	err := filepath.WalkDir(walkRoot, func(path string, d os.DirEntry, err error) error {
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

		// Calculate relative path for tar header to preserve namespace if global
		relPath, err := filepath.Rel(config.CacheDir, path)
		if err != nil {
			log.Printf("Error calculating rel path for %s: %v", path, err)
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		// Create tar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			log.Printf("Error creating header for %s: %v", relPath, err)
			return nil
		}

		// Ensure the name in the archive is relative/clean
		header.Name = relPath

		if err := tw.WriteHeader(header); err != nil {
			log.Printf("Error writing header for %s: %v", relPath, err)
			return err
		}

		f, err := os.Open(path)
		if err != nil {
			log.Printf("Error opening file %s: %v", path, err)
			return nil
		}
		if _, err := io.Copy(tw, f); err != nil {
			log.Printf("Error writing file content %s: %v", path, err)
			f.Close()
			return err
		}
		f.Close()

		return nil
	})
	if err != nil {
		log.Printf("Error during bulk walk: %v", err)
		// Can't really send error to client now as we started streaming
	}
}
