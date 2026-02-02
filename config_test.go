package main

import (
	"reflect"
	"testing"
)

func TestParseTrustedIssuers(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedMap  map[string]string
		expectedList []string
		expectError  bool
	}{
		{
			name:         "Legacy Single URL",
			input:        "https://issuer1.com",
			expectedMap:  map[string]string{},
			expectedList: []string{"https://issuer1.com"},
			expectError:  false,
		},
		{
			name:         "Legacy Comma Separated (Invalid Multi)",
			input:        "https://issuer1.com,https://issuer2.com",
			expectedMap:  map[string]string{},
			expectedList: []string{"https://issuer1.com,https://issuer2.com"}, // Treated as single entry, technically valid structure but will fail URL parsing later.
			expectError:  false,
		},
		{
			name:  "New ID Mapping (id=issuer=url)",
			input: "prod=https://prod.iss=https://prod.disc;dev=https://dev.iss=https://dev.disc",
			expectedMap: map[string]string{
				"prod": "https://prod.iss",
				"dev":  "https://dev.iss",
			},
			expectedList: []string{"https://prod.iss=https://prod.disc", "https://dev.iss=https://dev.disc"},
			expectError:  false,
		},
		{
			name:        "Mixed Legacy and New (Error)",
			input:       "prod=https://prod.iss=https://prod.disc;https://legacy.iss",
			expectError: true,
		},
		{
			name:  "Single Entry New Format",
			input: "prod=https://prod.iss=https://prod.disc",
			expectedMap: map[string]string{
				"prod": "https://prod.iss",
			},
			expectedList: []string{"https://prod.iss=https://prod.disc"},
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMap, gotList, err := parseTrustedIssuers(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if !reflect.DeepEqual(gotMap, tt.expectedMap) {
				t.Errorf("Map mismatch.\nGot:  %v\nWant: %v", gotMap, tt.expectedMap)
			}

			if !reflect.DeepEqual(gotList, tt.expectedList) {
				t.Errorf("List mismatch.\nGot:  %v\nWant: %v", gotList, tt.expectedList)
			}
		})
	}
}
