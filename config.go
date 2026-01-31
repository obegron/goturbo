package main

import (
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

func timeSinceStart() time.Duration {
	return time.Since(startTime)
}
