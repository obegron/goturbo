package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const Version = "0.4.3"

var (
	keyManager *JWKSManager
	staticKey  interface{}
)

func main() {
	// Initialize configuration
	InitConfig()

	if config.NoSecurity {
		log.Printf("⚠️  Security DISABLED - both read and write are open")
	} else if config.NoSecurityRead {
		log.Printf("🔓 Read security DISABLED - writes require authentication")
	} else {
		log.Printf("🔒 Security ENABLED - all operations require authentication")
	}

	if config.InsecureSkipVerify {
		log.Println("⚠️ TLS verification for OIDC discovery DISABLED")
	}

	// Ensure cache directory exists
	if err := os.MkdirAll(config.CacheDir, 0755); err != nil {
		log.Fatalf("Failed to create cache directory: %v", err)
	}

	// Initialize counters by walking the disk once
	log.Printf("Initializing cache metrics from %s...", config.CacheDir)
	var count uint64
	var size uint64
	filepath.WalkDir(config.CacheDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		count++
		size += uint64(info.Size())
		return nil
	})
	atomic.StoreUint64(&totalFiles, count)
	atomic.StoreUint64(&totalBytes, size)
	log.Printf("Cache initialized: %d files, %d bytes", count, size)

	// Initialize Key Manager or static key
	if !config.NoSecurity {
		if config.PublicKeyPath != "" {
			keyData, err := os.ReadFile(config.PublicKeyPath)
			if err != nil {
				log.Fatalf("Failed to read public key: %v", err)
			}
			block, _ := pem.Decode(keyData)
			if block == nil {
				log.Fatal("Failed to decode PEM block")
			}
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				log.Fatalf("Failed to parse public key: %v", err)
			}
			switch pub := pub.(type) {
			case *rsa.PublicKey:
				staticKey = pub
			case *ecdsa.PublicKey:
				staticKey = pub
			default:
				log.Fatal("Public key is not RSA or ECDSA")
			}
			log.Printf("Using static public key from %s", config.PublicKeyPath)
		} else if config.TrustedIssuers != "" {
			issuers := strings.Split(config.TrustedIssuers, ",")
			var cleanedIssuers []string
			for _, iss := range issuers {
				if trimmed := strings.TrimSpace(iss); trimmed != "" {
					cleanedIssuers = append(cleanedIssuers, trimmed)
				}
			}
			keyManager = NewJWKSManager(cleanedIssuers)
		} else {
			log.Fatal("Security is enabled but no trusted issuers or public key provided. Use --trusted-issuers, --public-key-path, or --no-security.")
		}

		if config.RequiredAudience != "" {
			log.Printf("Enforcing audience: %s", config.RequiredAudience)
		}
	} else {
		log.Println("Warning: Security disabled. Authentication will be bypassed.")
	}

	// Start background cleanup
	go cleanupLoop()

	// Setup routes
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleStatus)
	mux.HandleFunc("/metrics", handleMetrics)
	mux.HandleFunc("/v8/artifacts/", handleArtifacts) // Handles GET and PUT
	mux.HandleFunc("/v8/artifacts/events", handleEvents)
	mux.HandleFunc("/health", handleHealth)

	// Apply Middleware
	handler := withServerHeader(mux)

	srv := &http.Server{
		Addr:    ":" + config.Port,
		Handler: handler,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting goTurbo/%s on %s", Version, config.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown: ", err)
	}

	log.Println("Server exiting")
}

func withServerHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "goTurbo/"+Version)
		next.ServeHTTP(w, r)
	})
}

func jsonEncode(w http.ResponseWriter, v interface{}) {
	json.NewEncoder(w).Encode(v)
}
