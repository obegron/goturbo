package main

import (
	"flag"
	"log"
	"os"
	"strconv"
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
}

var (
	config    Config
	startTime = time.Now()
)

func InitConfig() {
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