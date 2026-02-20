package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildMux_FeatureFlags(t *testing.T) {
	oldConfig := config
	t.Cleanup(func() { config = oldConfig })

	tests := []struct {
		name            string
		disableTurbo    bool
		disableMaven    bool
		turboStatusCode int
		mavenStatusCode int
	}{
		{
			name:            "both enabled",
			disableTurbo:    false,
			disableMaven:    false,
			turboStatusCode: http.StatusMethodNotAllowed,
			mavenStatusCode: http.StatusBadRequest,
		},
		{
			name:            "only turbo",
			disableTurbo:    false,
			disableMaven:    true,
			turboStatusCode: http.StatusMethodNotAllowed,
			mavenStatusCode: http.StatusNotFound,
		},
		{
			name:            "only maven",
			disableTurbo:    true,
			disableMaven:    false,
			turboStatusCode: http.StatusNotFound,
			mavenStatusCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.DisableTurbo = tt.disableTurbo
			config.DisableMaven = tt.disableMaven
			config.NoSecurity = true
			config.NoSecurityRead = true
			config.CacheDir = t.TempDir()

			mux := buildMux()

			turboReq := httptest.NewRequest(http.MethodDelete, "/v8/artifacts/testhash", nil)
			turboRes := httptest.NewRecorder()
			mux.ServeHTTP(turboRes, turboReq)
			if turboRes.Code != tt.turboStatusCode {
				t.Fatalf("turbo status = %d, want %d", turboRes.Code, tt.turboStatusCode)
			}

			mavenReq := httptest.NewRequest(http.MethodGet, "/maven/", nil)
			mavenRes := httptest.NewRecorder()
			mux.ServeHTTP(mavenRes, mavenReq)
			if mavenRes.Code != tt.mavenStatusCode {
				t.Fatalf("maven status = %d, want %d", mavenRes.Code, tt.mavenStatusCode)
			}
		})
	}
}
