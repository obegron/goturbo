package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds configuration
type Config struct {
	Port               string
	CacheDir           string
	TrustedIssuers     string
	RequiredAudience   string
	PublicKeyPath      string
	RolePattern        string
	RoleClaimPath      string
	AdminRoles         string
	NoSecurity         bool
	NoSecurityRead     bool
	InsecureSkipVerify bool
	NamespaceIsolation bool
	CacheMaxAge        time.Duration
	IssuerIDMap        map[string]string   // id -> issuer
	IDAdminRoles       map[string][]string // id -> []roles
}

var (
	config     Config
	startTime  = time.Now()
	keyManager *JWKSManager
	staticKey  interface{}
)

func InitConfig() {
	flag.StringVar(&config.Port, "port", lookupEnvOr("PORT", "8080"), "HTTP server port")
	flag.StringVar(&config.CacheDir, "cache-dir", lookupEnvOr("CACHE_DIR", "/tmp/turbo-cache"), "Directory for cache storage")
	flag.StringVar(&config.TrustedIssuers, "trusted-issuers", lookupEnvOr("TRUSTED_ISSUERS", ""), "Comma-separated list of trusted issuer URLs (can be id=issuer=url or issuer=url)")
	flag.StringVar(&config.RequiredAudience, "required-audience", lookupEnvOr("REQUIRED_AUDIENCE", ""), "Required Audience (aud) claim in JWT")
	flag.StringVar(&config.PublicKeyPath, "public-key-path", lookupEnvOr("PUBLIC_KEY_PATH", ""), "Path to static RSA public key (PEM)")
	flag.BoolVar(&config.NoSecurity, "no-security", lookupEnvBool("NO_SECURITY", false), "Disable authentication checks")
	flag.BoolVar(&config.NoSecurityRead, "no-security-read", lookupEnvBool("NO_SECURITY_READ", false), "Disable authentication checks for GET/Read requests")
	flag.BoolVar(&config.InsecureSkipVerify, "insecure-skip-verify", lookupEnvBool("INSECURE_SKIP_VERIFY", false), "Skip TLS verification for OIDC discovery")
	flag.BoolVar(&config.NamespaceIsolation, "namespace-isolation", lookupEnvBool("NAMESPACE_ISOLATION", false), "Use Kubernetes namespace as team ID for isolation")
	flag.DurationVar(&config.CacheMaxAge, "cache-max-age", lookupEnvDuration("CACHE_MAX_AGE", 24*time.Hour), "Max age for cache retention")
	flag.StringVar(&config.RolePattern, "role-pattern", lookupEnvOr("ROLE_PATTERN", ""), "AD role pattern for namespace access something-{namespace}-something (use {namespace} as placeholder e.g , e.g., 'sec-role-{namespace}-dev'))")
	flag.StringVar(&config.RoleClaimPath, "role-claim-path", lookupEnvOr("ROLE_CLAIM_PATH", "groups"), "JWT claim path for roles/groups")
	flag.StringVar(&config.AdminRoles, "admin-roles", lookupEnvOr("ADMIN_ROLES", ""), "Comma-separated list of admin roles (global or id:role)")
	flag.Parse()

	// Parse ID Mappings
	config.IssuerIDMap = make(map[string]string)
	config.IDAdminRoles = make(map[string][]string)

	// Parse Admin Roles
	if config.AdminRoles != "" {
		roles := strings.Split(config.AdminRoles, ";") // Support semi-colon for complex lists
		if len(roles) == 1 && strings.Contains(config.AdminRoles, ",") && !strings.Contains(config.AdminRoles, ":") {
			// Fallback for comma-separated legacy global list
			roles = strings.Split(config.AdminRoles, ",")
		}

		for _, r := range roles {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}

			if strings.Contains(r, ":") {
				parts := strings.SplitN(r, ":", 2)
				id := strings.TrimSpace(parts[0])
				role := strings.TrimSpace(parts[1])
				config.IDAdminRoles[id] = append(config.IDAdminRoles[id], role)
			} else {
				// Global admin role (applies to all ids)
				config.IDAdminRoles["*"] = append(config.IDAdminRoles["*"], r)
			}
		}
	}
}

func Configure() {
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
					var err error
					var cleanedIssuers []string
					config.IssuerIDMap, cleanedIssuers, err = parseTrustedIssuers(config.TrustedIssuers)
					if err != nil {
						log.Fatalf("Invalid TRUSTED_ISSUERS config: %v", err)
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
		}
		
		func parseTrustedIssuers(input string) (map[string]string, []string, error) {
			idMap := make(map[string]string)
			var cleanedIssuers []string
		
			// Split by semicolon
			rawIssuers := strings.Split(input, ";")
			isMulti := len(rawIssuers) > 1
		
			for _, entry := range rawIssuers {
				entry = strings.TrimSpace(entry)
				if entry == "" {
					continue
				}
		
				// Check for id prefix: id=issuer=url OR id=issuer
				parts := strings.SplitN(entry, "=", 2)
				
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					val := strings.TrimSpace(parts[1])
		
					// Check if 'key' looks like a URL (Legacy Format)
					if strings.HasPrefix(key, "http") {
						if isMulti {
							return nil, nil, fmt.Errorf("multi-issuer config requires ID mapping (id=issuer...) for entry: %s", entry)
						}
						// Allow legacy for single entry
						cleanedIssuers = append(cleanedIssuers, entry)
					} else {
						// Valid ID mapping found
						if strings.Contains(val, "=") {
							// Format: id=issuer=url
							subParts := strings.SplitN(val, "=", 2)
							issuer := strings.TrimSpace(subParts[0])
							idMap[key] = issuer
							cleanedIssuers = append(cleanedIssuers, val) // "issuer=url"
						} else {
							// Format: id=issuer (where issuer might be URL)
							idMap[key] = val
							cleanedIssuers = append(cleanedIssuers, val)
						}
					}
				} else {
					// No equals sign -> Just a URL (Legacy)
					if isMulti {
						return nil, nil, fmt.Errorf("multi-issuer config requires ID mapping (id=issuer...) for entry: %s", entry)
					}
					cleanedIssuers = append(cleanedIssuers, entry)
				}
			}
			return idMap, cleanedIssuers, nil
		}
func timeSinceStart() time.Duration {
	return time.Since(startTime)
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
