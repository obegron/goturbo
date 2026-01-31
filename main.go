package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
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
	// Parse flags
	flag.StringVar(&config.Port, "port", lookupEnvOr("PORT", "8080"), "HTTP server port")
	flag.StringVar(&config.CacheDir, "cache-dir", lookupEnvOr("CACHE_DIR", "/tmp/turbo-cache"), "Directory for cache storage")
	flag.StringVar(&config.TrustedIssuers, "trusted-issuers", lookupEnvOr("TRUSTED_ISSUERS", ""), "Comma-separated list of trusted issuer URLs (can be issuer=url)")
	flag.StringVar(&config.RequiredAudience, "required-audience", lookupEnvOr("REQUIRED_AUDIENCE", ""), "Required Audience (aud) claim in JWT")
	flag.StringVar(&config.PublicKeyPath, "public-key-path", lookupEnvOr("PUBLIC_KEY_PATH", ""), "Path to static RSA public key (PEM)")
	flag.BoolVar(&config.NoSecurity, "no-security", lookupEnvBool("NO_SECURITY", false), "Disable authentication checks")
	flag.BoolVar(&config.NoSecurityRead, "no-security-read", lookupEnvBool("NO_SECURITY_READ", false), "Disable authentication checks for GET/Read requests")
	flag.BoolVar(&config.InsecureSkipVerify, "insecure-skip-verify", lookupEnvBool("INSECURE_SKIP_VERIFY", false), "Skip TLS verification for OIDC discovery")
	flag.BoolVar(&config.NamespaceIsolation, "namespace-isolation", lookupEnvBool("NAMESPACE_ISOLATION", false), "Use Kubernetes namespace as team ID for isolation")
	flag.DurationVar(&config.CacheMaxAge, "cache-max-age", lookupEnvDuration("CACHE_MAX_AGE", 24*time.Hour), "Max age for cache retention")
	flag.StringVar(&config.RolePattern, "role-pattern", lookupEnvOr("ROLE_PATTERN", ""), "AD role pattern for namespace access something-{namespace}-something (use {namespace} as placeholder e.g , e.g., 'sec-role-{namespace}-dev'))")
	flag.StringVar(&config.RoleClaimPath, "role-claim-path", lookupEnvOr("ROLE_CLAIM_PATH", "groups"), "JWT claim path for roles/groups")
	flag.StringVar(&config.AdminRoles, "admin-roles", lookupEnvOr("ADMIN_ROLES", ""), "Comma-separated list of admin roles that grant write access to all namespaces")
	flag.Parse()

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

func lookupEnvOr(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func lookupEnvBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		b, err := strconv.ParseBool(val)
		if err != nil {
			log.Printf("Invalid value for %s: %v", key, err)
			return defaultVal
		}
		return b
	}
	return defaultVal
}

func lookupEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if val, ok := os.LookupEnv(key); ok {
		d, err := time.ParseDuration(val)
		if err != nil {
			log.Printf("Invalid value for %s: %v", key, err)
			return defaultVal
		}
		return d
	}
	return defaultVal
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