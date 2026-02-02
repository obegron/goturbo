package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

// --- JWKS Implementation ---

type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWKSManager struct {
	trustedIssuers map[string][]string    // issuer -> []discoveryURL
	keys           map[string]interface{} // Map "issuer|kid" -> PublicKey
	mu             sync.RWMutex
}

func NewJWKSManager(issuers []string) *JWKSManager {
	issuerMap := make(map[string][]string)
	for _, iss := range issuers {
		parts := strings.SplitN(iss, "=", 2)
		var issuer, discoveryURL string
		if len(parts) == 2 {
			issuer = strings.TrimSpace(parts[0])
			discoveryURL = strings.TrimSpace(parts[1])
		} else {
			issuer = strings.TrimSpace(iss)
			discoveryURL = issuer
		}
		issuerMap[issuer] = append(issuerMap[issuer], discoveryURL)
	}
	return &JWKSManager{
		trustedIssuers: issuerMap,
		keys:           make(map[string]interface{}),
	}
}

func (m *JWKSManager) GetKey(token *jwt.Token) (interface{}, error) {
	iss, err := token.Claims.GetIssuer()
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer: %w", err)
	}

	// Verify issuer is trusted
	if _, trusted := m.trustedIssuers[iss]; !trusted {
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

	discoveryURLs, ok := m.trustedIssuers[issuer]
	if !ok || len(discoveryURLs) == 0 {
		return fmt.Errorf("unknown issuer: %s", issuer)
	}

	var lastErr error
	var jwks JWKS
	found := false

	for _, discoveryURL := range discoveryURLs {
		// 1. OIDC Discovery
		wellKnownURL := strings.TrimSuffix(discoveryURL, "/") + "/.well-known/openid-configuration"
		resp, err := client.Get(wellKnownURL)
		if err != nil {
			lastErr = fmt.Errorf("failed to fetch discovery config from %s: %w", discoveryURL, err)
			log.Printf("Warning: %v", lastErr)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("discovery endpoint %s returned %d", discoveryURL, resp.StatusCode)
			log.Printf("Warning: %v", lastErr)
			continue
		}

		var discoveryConfig struct {
			JwksURI string `json:"jwks_uri"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&discoveryConfig); err != nil {
			resp.Body.Close()
			lastErr = fmt.Errorf("failed to decode discovery config from %s: %w", discoveryURL, err)
			log.Printf("Warning: %v", lastErr)
			continue
		}
		resp.Body.Close()

		// 2. Fetch JWKS
		jwksResp, err := client.Get(discoveryConfig.JwksURI)
		if err != nil {
			lastErr = fmt.Errorf("failed to fetch JWKS from %s: %w", discoveryConfig.JwksURI, err)
			log.Printf("Warning: %v", lastErr)
			continue
		}

		if jwksResp.StatusCode != http.StatusOK {
			jwksResp.Body.Close()
			lastErr = fmt.Errorf("jwks endpoint %s returned %d", discoveryConfig.JwksURI, jwksResp.StatusCode)
			log.Printf("Warning: %v", lastErr)
			continue
		}

		if err := json.NewDecoder(jwksResp.Body).Decode(&jwks); err != nil {
			jwksResp.Body.Close()
			lastErr = fmt.Errorf("failed to decode JWKS from %s: %w", discoveryConfig.JwksURI, err)
			log.Printf("Warning: %v", lastErr)
			continue
		}
		jwksResp.Body.Close()

		found = true
		break // Success, stop trying other URLs
	}

	if !found {
		return fmt.Errorf("failed to refresh keys for issuer %s: %w", issuer, lastErr)
	}

	// 3. Parse and Store Keys
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, jwk := range jwks.Keys {
		var pubKey interface{}
		var err error

		if jwk.Kty == "RSA" {
			pubKey, err = parseRSAPublicKey(jwk.N, jwk.E)
		} else if jwk.Kty == "EC" {
			pubKey, err = parseECPublicKey(jwk.Crv, jwk.X, jwk.Y)
		} else {
			continue
		}

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
	eInt := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{N: n, E: int(eInt.Int64())}, nil
}

func parseECPublicKey(crv, xStr, yStr string) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("invalid x coordinate: %v", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("invalid y coordinate: %v", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func hasAccess(token *jwt.Token, namespace string, operation string, hash string) bool {
	// 0. Verify Issuer consistency if an ID mapping exists for this namespace
	if expectedIss, ok := config.IssuerIDMap[namespace]; ok {
		iss, err := token.Claims.GetIssuer()
		if err != nil || iss != expectedIss {
			log.Printf("%s %s [%s] - Forbidden: issuer mismatch (expected: %s, got: %s)",
				operation, hash, namespace, expectedIss, iss)
			return false
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}

	// 1. Check if it's a ServiceAccount (CI pipeline)
	if saNamespace := extractServiceAccountNamespace(claims); saNamespace != "" {
		if saNamespace == namespace {
			return true
		}
	}

	// 2. Check AD roles / Groups
	roles := extractRoles(claims, config.RoleClaimPath)

	// Include K8s namespace as a potential admin role
	if saNS := extractServiceAccountNamespace(claims); saNS != "" {
		roles = append(roles, saNS)
	}

	// Check for admin roles (Global or ID-based)
	// Check Global (*)
	if globalAdmins, ok := config.IDAdminRoles["*"]; ok {
		for _, role := range roles {
			for _, admin := range globalAdmins {
				if role == admin {
					return true
				}
			}
		}
	}

	// Check ID-scoped Admins
	if iss, err := token.Claims.GetIssuer(); err == nil {
		for id, issuerURL := range config.IssuerIDMap {
			if issuerURL == iss {
				if admins, ok := config.IDAdminRoles[id]; ok {
					for _, role := range roles {
						for _, admin := range admins {
							if role == admin {
								return true
							}
						}
					}
				}
			}
		}
	}

	// Check namespace-specific role
	var requiredRole string
	if config.RolePattern != "" {
		requiredRole = strings.ReplaceAll(config.RolePattern, "{namespace}", namespace)
		for _, role := range roles {
			if role == requiredRole {
				return true
			}
		}
	}

	log.Printf("%s %s [%s] - Forbidden: no matching role (required: %s, has: %v)",
		operation, hash, namespace, requiredRole, roles)
	return false
}

func hasAdminAccess(token *jwt.Token, namespace string) bool {
	// Global Admins (Check across all ID mappings)
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}
	roles := extractRoles(claims, config.RoleClaimPath)

	// Include K8s namespace as a "role" for admin checks
	if saNS := extractServiceAccountNamespace(claims); saNS != "" {
		roles = append(roles, saNS)
	}

	// 1. Check Legacy Global Admins (*)
	if globalAdmins, ok := config.IDAdminRoles["*"]; ok {
		for _, role := range roles {
			for _, admin := range globalAdmins {
				if role == admin {
					return true
				}
			}
		}
	}

	// 2. Check ID-scoped Admins
	// We need to find if the token's issuer maps to any known ID
	iss, err := token.Claims.GetIssuer()
	if err != nil {
		return false
	}

	for id, issuerURL := range config.IssuerIDMap {
		if issuerURL == iss {
			// Found the ID for this issuer. Check if user has admin role for this ID.
			if admins, ok := config.IDAdminRoles[id]; ok {
				for _, role := range roles {
					for _, admin := range admins {
						if role == admin {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

func extractServiceAccountNamespace(claims jwt.MapClaims) string {
	if kubeRaw, ok := claims["kubernetes.io"]; ok {
		if kube, ok := kubeRaw.(map[string]interface{}); ok {
			if ns, ok := kube["namespace"].(string); ok {
				return ns
			}
		}
	}
	return ""
}

func extractRoles(claims jwt.MapClaims, claimPath string) []string {
	var roles []string

	parts := strings.Split(claimPath, ".")
	var current interface{} = claims

	for _, part := range parts {
		if m, ok := current.(map[string]interface{}); ok {
			current = m[part]
		} else if m, ok := current.(jwt.MapClaims); ok {
			current = m[part]
		} else {
			return roles
		}
	}

	switch v := current.(type) {
	case []interface{}:
		for _, role := range v {
			if s, ok := role.(string); ok {
				roles = append(roles, s)
			}
		}
	case []string:
		roles = v
	case string:
		roles = append(roles, v)
	}

	return roles
}