// Copyright 2026 Carlos Fuentes. Licensed under the Apache License, Version 2.0.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServeReadSecretEnvOrFile_FailClosedWhenFileUnreadable(t *testing.T) {
	tmp := t.TempDir()
	missingPath := filepath.Join(tmp, "missing.secret")

	t.Setenv("TEST_SERVE_SECRET", "env-value")
	t.Setenv("TEST_SERVE_SECRET_FILE", missingPath)
	got, err := readSecretEnvOrFile("TEST_SERVE_SECRET", "TEST_SERVE_SECRET_FILE")
	if err == nil || got != "" || !strings.Contains(err.Error(), "TEST_SERVE_SECRET_FILE") {
		t.Fatalf("expected unreadable *_FILE to fail closed, got=%q err=%v", got, err)
	}

	validPath := filepath.Join(tmp, "ok.secret")
	if err := os.WriteFile(validPath, []byte("from-file\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("TEST_SERVE_SECRET_FILE", validPath)
	gotOK, errOK := readSecretEnvOrFile("TEST_SERVE_SECRET", "TEST_SERVE_SECRET_FILE")
	if errOK != nil || gotOK != "from-file" {
		t.Fatalf("expected file value, got=%q err=%v", gotOK, errOK)
	}
}
