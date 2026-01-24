package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
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

const Version = "0.1.1"

// Config holds configuration
type Config struct {
	Port             string
	CacheDir         string
	TrustedIssuers   string
	RequiredAudience string
	NoSecurity       bool
	CacheMaxAge      time.Duration
}

var (
	config     Config
	keyManager *JWKSManager

	// Metrics
	hits       uint64
	misses     uint64
	putSuccess uint64
	putErrors  uint64
)

func main() {
	// Parse flags
	flag.StringVar(&config.Port, "port", lookupEnvOr("PORT", "8080"), "HTTP server port")
	flag.StringVar(&config.CacheDir, "cache-dir", lookupEnvOr("CACHE_DIR", "/tmp/turbo-cache"), "Directory for cache storage")
	flag.StringVar(&config.TrustedIssuers, "trusted-issuers", lookupEnvOr("TRUSTED_ISSUERS", ""), "Comma-separated list of trusted issuer URLs")
	flag.StringVar(&config.RequiredAudience, "required-audience", lookupEnvOr("REQUIRED_AUDIENCE", ""), "Required Audience (aud) claim in JWT")
	flag.BoolVar(&config.NoSecurity, "no-security", false, "Disable authentication checks")
	flag.DurationVar(&config.CacheMaxAge, "cache-max-age", 24*time.Hour, "Max age for cache retention")
	flag.Parse()

	// Ensure cache directory exists
	if err := os.MkdirAll(config.CacheDir, 0755); err != nil {
		log.Fatalf("Failed to create cache directory: %v", err)
	}

	// Initialize Key Manager if security is enabled
	if !config.NoSecurity {
		if config.TrustedIssuers == "" {
			log.Fatal("Security is enabled but no trusted issuers provided. Use --trusted-issuers or --no-security.")
		}
		issuers := strings.Split(config.TrustedIssuers, ",")
		var cleanedIssuers []string
		for _, iss := range issuers {
			if trimmed := strings.TrimSpace(iss); trimmed != "" {
				cleanedIssuers = append(cleanedIssuers, trimmed)
			}
		}
		keyManager = NewJWKSManager(cleanedIssuers)

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
	hitRate := 0.0
	if h+m > 0 {
		hitRate = float64(h) / float64(h+m)
	}

	stats := map[string]interface{}{
		"server":        "goturbo",
		"version":       Version,
		"uptime":        time.Since(startTime).String(),
		"security":      !config.NoSecurity,
		"hits":          h,
		"misses":        m,
		"hit_rate":      hitRate,
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

	hitRate := 0.0
	if h+m > 0 {
		hitRate = float64(h) / float64(h+m)
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

	fmt.Fprintf(w, "# HELP goturbo_cache_hit_rate Cache hit rate\n")
	fmt.Fprintf(w, "# TYPE goturbo_cache_hit_rate gauge\n")
	fmt.Fprintf(w, "goturbo_cache_hit_rate %f\n", hitRate)
}

func getDiskUsage() (int, int64) {
	var count int
	var size int64
	err := filepath.Walk(config.CacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // ignore errors
		}
		if !info.IsDir() {
			count++
			size += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, 0
	}
	return count, size
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
	// 1. OIDC Discovery
	wellKnownURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	resp, err := http.Get(wellKnownURL)
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
	jwksResp, err := http.Get(config.JwksURI)
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
		teamID = r.URL.Query().Get("slug") // Fallback to slug
	}
	if teamID == "" {
		teamID = "default"
	}
	// Sanitize to prevent path traversal
	teamID = filepath.Base(teamID)

	// Open Read Access
	path := filepath.Join(config.CacheDir, teamID, hash)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		atomic.AddUint64(&misses, 1)
		log.Printf("GET %s [%s] - Miss", hash, teamID)
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("GET %s [%s] - Error: %v", hash, teamID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.WriteHeader(http.StatusOK)
	io.Copy(w, f)
	atomic.AddUint64(&hits, 1)
	log.Printf("GET %s [%s] - Hit", hash, teamID)
}

func putArtifact(w http.ResponseWriter, r *http.Request, hash string) {
	teamID := r.URL.Query().Get("teamId")
	if teamID == "" {
		teamID = r.URL.Query().Get("slug")
	}
	if teamID == "" {
		teamID = "default"
	}
	teamID = filepath.Base(teamID)

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
	// Create temp file first
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		atomic.AddUint64(&putErrors, 1)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	_, err = io.Copy(f, r.Body)
	f.Close()
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

	w.WriteHeader(http.StatusOK)
	atomic.AddUint64(&putSuccess, 1)
	log.Printf("PUT %s [%s] - Success", hash, teamID)
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
				os.Remove(path)
				log.Printf("Cleaned up %s", filepath.Base(path))
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("Error during cleanup walk: %v", err)
	}
}
