package main

import (
	"strings"
)

func sanitizePathComponent(component string) (string, bool) {
	clean := strings.TrimSpace(component)
	if clean == "" ||
		strings.Contains(clean, "/") ||
		strings.Contains(clean, "\\") ||
		strings.Contains(clean, "..") {
		return "", false
	}
	return clean, true
}
