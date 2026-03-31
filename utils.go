package main

import (
	"io"
	"os"
	"path/filepath"
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

func writeAtomically(path string, body io.Reader) (int64, error) {
	parent := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(parent, filepath.Base(path)+".tmp-*")
	if err != nil {
		return 0, err
	}

	tmpPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	written, err := io.Copy(tmpFile, body)
	if err != nil {
		_ = tmpFile.Close()
		return written, err
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return written, err
	}

	if err := tmpFile.Close(); err != nil {
		return written, err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return written, err
	}

	return written, nil
}
