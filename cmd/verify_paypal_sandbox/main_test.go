// Copyright 2026 Carlos Fuentes. Licensed under the Apache License, Version 2.0.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSecretEnvOrFile_FailClosedWhenFileUnreadableOrEmpty(t *testing.T) {
	tmp := t.TempDir()
	missingPath := filepath.Join(tmp, "does-not-exist.secret")

	t.Setenv("TEST_PAYPAL_SECRET", "fallback-env-should-never-be-used")
	t.Setenv("TEST_PAYPAL_SECRET_FILE", missingPath)
	got, err := readSecretEnvOrFile("TEST_PAYPAL_SECRET", "TEST_PAYPAL_SECRET_FILE")
	if err == nil || got != "" || !strings.Contains(err.Error(), "TEST_PAYPAL_SECRET_FILE") {
		t.Fatalf("expected missing *_FILE to fail closed without falling back to env, got=%q err=%v", got, err)
	}

	emptyPath := filepath.Join(tmp, "empty.secret")
	if err := os.WriteFile(emptyPath, []byte("   \n"), 0600); err != nil {
		t.Fatalf("WriteFile empty: %v", err)
	}
	t.Setenv("TEST_PAYPAL_SECRET_FILE", emptyPath)
	gotEmpty, errEmpty := readSecretEnvOrFile("TEST_PAYPAL_SECRET", "TEST_PAYPAL_SECRET_FILE")
	if errEmpty == nil || gotEmpty != "" {
		t.Fatalf("expected whitespace-only *_FILE to fail closed, got=%q err=%v", gotEmpty, errEmpty)
	}

	validPath := filepath.Join(tmp, "valid.secret")
	if err := os.WriteFile(validPath, []byte("  file-credential-ok\n"), 0600); err != nil {
		t.Fatalf("WriteFile valid: %v", err)
	}
	t.Setenv("TEST_PAYPAL_SECRET_FILE", validPath)
	gotValid, errValid := readSecretEnvOrFile("TEST_PAYPAL_SECRET", "TEST_PAYPAL_SECRET_FILE")
	if errValid != nil || gotValid != "file-credential-ok" {
		t.Fatalf("expected trimmed file secret, got=%q err=%v", gotValid, errValid)
	}

	t.Setenv("TEST_PAYPAL_SECRET_FILE", "")
	gotEnv, errEnv := readSecretEnvOrFile("TEST_PAYPAL_SECRET", "TEST_PAYPAL_SECRET_FILE")
	if errEnv != nil || gotEnv != "fallback-env-should-never-be-used" {
		t.Fatalf("expected env value when *_FILE is unset, got=%q err=%v", gotEnv, errEnv)
	}
}
