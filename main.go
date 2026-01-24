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
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config holds configuration
type Config struct {
	Port             string
	CacheDir         string
	TrustedIssuers   string
	RequiredAudience string
	NoSecurity       bool
	CacheMaxAge      time.Duration
}

var config Config
var keyManager *JWKSManager

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
	mux.HandleFunc("/v8/artifacts/", handleArtifacts) // Handles GET and PUT
	mux.HandleFunc("/v8/artifacts/events", handleEvents)
	mux.HandleFunc("/health", handleHealth)

	srv := &http.Server{
		Addr:    ":" + config.Port,
		Handler: mux,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting server on %s", config.Port)
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
	// Open Read Access
	path := filepath.Join(config.CacheDir, hash)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		log.Printf("GET %s - Miss", hash)
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("GET %s - Error: %v", hash, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.WriteHeader(http.StatusOK)
	io.Copy(w, f)
	log.Printf("GET %s - Hit", hash)
}

func putArtifact(w http.ResponseWriter, r *http.Request, hash string) {
	// Authentication
	if !config.NoSecurity {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
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
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			log.Printf("Auth failed for %s: %v", hash, err)
			return
		}

		// Audience Check
		if config.RequiredAudience != "" {
			audiences, err := token.Claims.GetAudience()
			if err != nil {
				http.Error(w, "Invalid Audience", http.StatusUnauthorized)
				log.Printf("Auth failed for %s: failed to parse audience", hash)
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
				log.Printf("Auth failed for %s: invalid audience %v (required: %s)", hash, audiences, config.RequiredAudience)
				return
			}
		}
	}

	// Save artifact
	path := filepath.Join(config.CacheDir, hash)
	// Create temp file first
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	_, err = io.Copy(f, r.Body)
	f.Close()
	if err != nil {
		os.Remove(tmpPath)
		http.Error(w, "Failed to write artifact", http.StatusInternalServerError)
		return
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		http.Error(w, "Failed to save artifact", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	log.Printf("PUT %s - Success", hash)
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
	entries, err := os.ReadDir(config.CacheDir)
	if err != nil {
		log.Printf("Error reading cache dir: %v", err)
		return
	}

	now := time.Now()
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > config.CacheMaxAge {
			os.Remove(filepath.Join(config.CacheDir, entry.Name()))
			log.Printf("Cleaned up %s", entry.Name())
		}
	}
}
