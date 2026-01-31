package main

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestExtractRoles(t *testing.T) {
	claims := jwt.MapClaims{
		"groups": []interface{}{"role1", "role2"},
		"nested": map[string]interface{}{
			"roles": []interface{}{"admin", "user"},
		},
		"single": "onlyone",
	}

	t.Run("Default path", func(t *testing.T) {
		roles := extractRoles(claims, "groups")
		if len(roles) != 2 || roles[0] != "role1" || roles[1] != "role2" {
			t.Errorf("expected [role1 role2], got %v", roles)
		}
	})

	t.Run("Nested path", func(t *testing.T) {
		roles := extractRoles(claims, "nested.roles")
		if len(roles) != 2 || roles[0] != "admin" || roles[1] != "user" {
			t.Errorf("expected [admin user], got %v", roles)
		}
	})

	t.Run("Single string", func(t *testing.T) {
		roles := extractRoles(claims, "single")
		if len(roles) != 1 || roles[0] != "onlyone" {
			t.Errorf("expected [onlyone], got %v", roles)
		}
	})

	t.Run("Invalid path", func(t *testing.T) {
		roles := extractRoles(claims, "invalid.path")
		if len(roles) != 0 {
			t.Errorf("expected empty roles, got %v", roles)
		}
	})
}

func TestExtractServiceAccountNamespace(t *testing.T) {
	claims := jwt.MapClaims{
		"kubernetes.io": map[string]interface{}{
			"namespace": "my-ns",
		},
	}

	ns := extractServiceAccountNamespace(claims)
	if ns != "my-ns" {
		t.Errorf("expected my-ns, got %s", ns)
	}

	emptyClaims := jwt.MapClaims{}
	ns = extractServiceAccountNamespace(emptyClaims)
	if ns != "" {
		t.Errorf("expected empty string, got %s", ns)
	}
}

func TestHasAccess(t *testing.T) {
	config.RoleClaimPath = "groups"
	config.RolePattern = "role-{namespace}"
	config.AdminRoles = "global-admin"

	t.Run("Service account access", func(t *testing.T) {
		token := &jwt.Token{
			Claims: jwt.MapClaims{
				"kubernetes.io": map[string]interface{}{
					"namespace": "test-ns",
				},
			},
		}
		if !hasAccess(token, "test-ns", "GET", "hash") {
			t.Error("expected access for matching namespace")
		}
		if hasAccess(token, "other-ns", "GET", "hash") {
			t.Error("expected no access for mismatching namespace")
		}
	})

	t.Run("Role pattern access", func(t *testing.T) {
		token := &jwt.Token{
			Claims: jwt.MapClaims{
				"groups": []interface{}{"role-test-ns"},
			},
		}
		if !hasAccess(token, "test-ns", "GET", "hash") {
			t.Error("expected access for matching role")
		}
		if hasAccess(token, "other-ns", "GET", "hash") {
			t.Error("expected no access for mismatching role")
		}
	})

	t.Run("Admin role access", func(t *testing.T) {
		token := &jwt.Token{
			Claims: jwt.MapClaims{
				"groups": []interface{}{"global-admin"},
			},
		}
		if !hasAccess(token, "any-ns", "GET", "hash") {
			t.Error("expected access for admin role")
		}
	})

	t.Run("Forbidden access", func(t *testing.T) {
		token := &jwt.Token{
			Claims: jwt.MapClaims{
				"groups": []interface{}{"some-other-role"},
			},
		}
		if hasAccess(token, "test-ns", "GET", "hash") {
			t.Error("expected no access")
		}
	})
}
