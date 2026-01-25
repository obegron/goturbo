package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const Version = "0.3.0"

// Config holds configuration
type Config struct {
	Port               string
	CacheDir           string
	TrustedIssuers     string
	RequiredAudience   string
	PublicKeyPath      string
	NoSecurity         bool
	InsecureSkipVerify bool
	NamespaceIsolation bool
	CacheMaxAge        time.Duration
}

var (
	config     Config
	keyManager *JWKSManager
	staticKey  *rsa.PublicKey

	// Metrics
	hits       uint64
	misses     uint64
	putSuccess uint64
	putErrors  uint64
	totalFiles uint64
	totalBytes uint64
)

func main() {
	// Parse flags
	flag.StringVar(&config.Port, "port", lookupEnvOr("PORT", "8080"), "HTTP server port")
	flag.StringVar(&config.CacheDir, "cache-dir", lookupEnvOr("CACHE_DIR", "/tmp/turbo-cache"), "Directory for cache storage")
	flag.StringVar(&config.TrustedIssuers, "trusted-issuers", lookupEnvOr("TRUSTED_ISSUERS", ""), "Comma-separated list of trusted issuer URLs")
	flag.StringVar(&config.RequiredAudience, "required-audience", lookupEnvOr("REQUIRED_AUDIENCE", ""), "Required Audience (aud) claim in JWT")
	flag.StringVar(&config.PublicKeyPath, "public-key-path", lookupEnvOr("PUBLIC_KEY_PATH", ""), "Path to static RSA public key (PEM)")
	flag.BoolVar(&config.NoSecurity, "no-security", false, "Disable authentication checks")
	flag.BoolVar(&config.InsecureSkipVerify, "insecure-skip-verify", false, "Skip TLS verification for OIDC discovery")
	flag.BoolVar(&config.NamespaceIsolation, "namespace-isolation", false, "Use Kubernetes namespace as team ID for isolation")
	flag.DurationVar(&config.CacheMaxAge, "cache-max-age", 24*time.Hour, "Max age for cache retention")
	flag.Parse()

	// Ensure cache directory exists
	if err := os.MkdirAll(config.CacheDir, 0755); err != nil {
		log.Fatalf("Failed to create cache directory: %v", err)
	}

	// Initialize counters by walking the disk once
	log.Printf("Initializing cache metrics from %s...", config.CacheDir)
	var count uint64
	var size uint64
	filepath.Walk(config.CacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
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
			var ok bool
			staticKey, ok = pub.(*rsa.PublicKey)
			if !ok {
				log.Fatal("Public key is not RSA")
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
		log.Printf("Starting goturbo/%s on %s", Version, config.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 5 seconds.
	quit := make(chan os.Signal, 1)
	// kill (no param) default send syscall.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall.SIGKILL but can't be caught, so don't need to add it
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

func withServerHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "goturbo/"+Version)
		next.ServeHTTP(w, r)
	})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	fileCount, totalBytes := getDiskUsage()

	h := atomic.LoadUint64(&hits)
	m := atomic.LoadUint64(&misses)
	hitRatio := 0.0
	if h+m > 0 {
		hitRatio = float64(h) / float64(h+m)
	}

	stats := map[string]interface{}{
		"server":        "goturbo",
		"version":       Version,
		"uptime":        time.Since(startTime).String(),
		"security":      !config.NoSecurity,
		"hits":          h,
		"misses":        m,
		"hit_ratio":     hitRatio,
		"put_success":   atomic.LoadUint64(&putSuccess),
		"put_errors":    atomic.LoadUint64(&putErrors),
		"cached_files":  fileCount,
		"total_bytes":   totalBytes,
		"cache_max_age": config.CacheMaxAge.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	fileCount, totalBytes := getDiskUsage()
	h := atomic.LoadUint64(&hits)
	m := atomic.LoadUint64(&misses)
	ps := atomic.LoadUint64(&putSuccess)
	pe := atomic.LoadUint64(&putErrors)

	hitRatio := 0.0
	if h+m > 0 {
		hitRatio = float64(h) / float64(h+m)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP goturbo_hits_total Total number of cache hits\n")
	fmt.Fprintf(w, "# TYPE goturbo_hits_total counter\n")
	fmt.Fprintf(w, "goturbo_hits_total %d\n", h)

	fmt.Fprintf(w, "# HELP goturbo_misses_total Total number of cache misses\n")
	fmt.Fprintf(w, "# TYPE goturbo_misses_total counter\n")
	fmt.Fprintf(w, "goturbo_misses_total %d\n", m)

	fmt.Fprintf(w, "# HELP goturbo_put_success_total Total number of successful puts\n")
	fmt.Fprintf(w, "# TYPE goturbo_put_success_total counter\n")
	fmt.Fprintf(w, "goturbo_put_success_total %d\n", ps)

	fmt.Fprintf(w, "# HELP goturbo_put_errors_total Total number of failed puts\n")
	fmt.Fprintf(w, "# TYPE goturbo_put_errors_total counter\n")
	fmt.Fprintf(w, "goturbo_put_errors_total %d\n", pe)

	fmt.Fprintf(w, "# HELP goturbo_cached_files_count Current number of files in cache\n")
	fmt.Fprintf(w, "# TYPE goturbo_cached_files_count gauge\n")
	fmt.Fprintf(w, "goturbo_cached_files_count %d\n", fileCount)

	fmt.Fprintf(w, "# HELP goturbo_cache_size_bytes Total size of cache in bytes\n")
	fmt.Fprintf(w, "# TYPE goturbo_cache_size_bytes gauge\n")
	fmt.Fprintf(w, "goturbo_cache_size_bytes %d\n", totalBytes)

	fmt.Fprintf(w, "# HELP goturbo_cache_hit_ratio Cache hit ratio\n")
	fmt.Fprintf(w, "# TYPE goturbo_cache_hit_ratio gauge\n")
	fmt.Fprintf(w, "goturbo_cache_hit_ratio %f\n", hitRatio)
}

func getDiskUsage() (uint64, uint64) {
	return atomic.LoadUint64(&totalFiles), atomic.LoadUint64(&totalBytes)
}

var startTime = time.Now()

// --- JWKS Implementation ---

type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWKSManager struct {
	trustedIssuers []string
	keys           map[string]*rsa.PublicKey // Map "issuer|kid" -> PublicKey
	mu             sync.RWMutex
}

func NewJWKSManager(issuers []string) *JWKSManager {
	return &JWKSManager{
		trustedIssuers: issuers,
		keys:           make(map[string]*rsa.PublicKey),
	}
}

func (m *JWKSManager) GetKey(token *jwt.Token) (interface{}, error) {
	iss, err := token.Claims.GetIssuer()
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer: %w", err)
	}

	// Verify issuer is trusted
	isTrusted := false
	for _, trusted := range m.trustedIssuers {
		if trusted == iss {
			isTrusted = true
			break
		}
	}
	if !isTrusted {
		return nil, fmt.Errorf("untrusted issuer: %s", iss)
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("missing kid in header")
	}

	keyID := fmt.Sprintf("%s|%s", iss, kid)

	// Check cache
	m.mu.RLock()
	pubKey, exists := m.keys[keyID]
	m.mu.RUnlock()

	if exists {
		return pubKey, nil
	}

	// Fetch and update cache
	if err := m.refreshKeys(iss); err != nil {
		return nil, err
	}

	m.mu.RLock()
	pubKey, exists = m.keys[keyID]
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("key not found for kid: %s", kid)
	}

	return pubKey, nil
}

func (m *JWKSManager) refreshKeys(issuer string) error {
	client := &http.Client{}
	if config.InsecureSkipVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	// 1. OIDC Discovery
	wellKnownURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	resp, err := client.Get(wellKnownURL)
	if err != nil {
		return fmt.Errorf("failed to fetch discovery config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery endpoint returned %d", resp.StatusCode)
	}

	var config struct {
		JwksURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return fmt.Errorf("failed to decode discovery config: %w", err)
	}

	// 2. Fetch JWKS
	jwksResp, err := client.Get(config.JwksURI)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer jwksResp.Body.Close()

	if jwksResp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned %d", jwksResp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// 3. Parse and Store Keys
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, jwk := range jwks.Keys {
		if jwk.Kty != "RSA" {
			continue
		}

		pubKey, err := parseRSAPublicKey(jwk.N, jwk.E)
		if err != nil {
			log.Printf("Failed to parse JWK %s: %v", jwk.Kid, err)
			continue
		}

		keyID := fmt.Sprintf("%s|%s", issuer, jwk.Kid)
		m.keys[keyID] = pubKey
	}

	return nil
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)

	var e int
	if len(eBytes) < 8 {
		// padding for binary.Read
		pad := make([]byte, 8-len(eBytes))
		eBytes = append(pad, eBytes...)
		// Since we padded front (BigEndian), checking logic...
		// Actually, binary.BigEndian.Uint64 expects 8 bytes.
		// Exponent is usually small (65537), so this manual shift is safer:
		eInt := new(big.Int).SetBytes(eBytes)
		e = int(eInt.Int64())
	} else {
		return nil, fmt.Errorf("exponent too large")
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// --- Handlers ---

func handleArtifacts(w http.ResponseWriter, r *http.Request) {
	// Basic path parsing to get hash
	// Path is /v8/artifacts/:hash
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "Invalid artifact hash", http.StatusBadRequest)
		return
	}
	hash := parts[3]

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

	// Authentication for Read (if enabled)
	if !config.NoSecurity {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				if staticKey != nil {
					return staticKey, nil
				}
				return keyManager.GetKey(token)
			})

			if err == nil && token.Valid && config.NamespaceIsolation {
				if claims, ok := token.Claims.(jwt.MapClaims); ok {
					if kubeRaw, ok := claims["kubernetes.io"]; ok {
						if kube, ok := kubeRaw.(map[string]interface{}); ok {
							if ns, ok := kube["namespace"].(string); ok {
								if teamID == "" {
									teamID = ns
								} else if teamID != ns {
									log.Printf("GET %s Warning: URL teamId %s does not match token namespace %s", hash, teamID, ns)
									http.Error(w, "Forbidden: teamId mismatch", http.StatusForbidden)
									return
								}
							}
						}
					}
				}
			}
		}
	}

	if teamID == "" {
		teamID = "default"
	}
	teamID = filepath.Base(teamID)

	// Open Read Access
	path := filepath.Join(config.CacheDir, teamID, hash)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		atomic.AddUint64(&misses, 1)
		log.Printf("GET %s [%s] - Miss", hash, teamID)
		w.Header().Set("X-Goturbo-Cache", "MISS")
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
	w.Header().Set("X-Goturbo-Cache", "HIT")
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
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
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

		// Extract namespace from token (if isolation is enabled)
		if config.NamespaceIsolation {
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				if kubeRaw, ok := claims["kubernetes.io"]; ok {
					if kube, ok := kubeRaw.(map[string]interface{}); ok {
						if ns, ok := kube["namespace"].(string); ok {
							if teamID == "" {
								teamID = ns
							} else if teamID != ns {
								atomic.AddUint64(&putErrors, 1)
								log.Printf("PUT %s Forbidden: URL teamId %s does not match token namespace %s", hash, teamID, ns)
								http.Error(w, "Forbidden: teamId mismatch", http.StatusForbidden)
								return
							}
						}
					}
				}
			}
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
	}

	if teamID == "" {
		teamID = "default"
	}
	teamID = filepath.Base(teamID)

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
	if info, err := os.Stat(path); err == nil {
		oldSize = info.Size()
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
	if oldSize == 0 {
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
	err := filepath.Walk(config.CacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
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
