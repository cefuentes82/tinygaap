// Copyright 2026 Carlos Fuentes. Licensed under the Apache License, Version 2.0.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"tinygaap.io/paypal-edi"
)

func readSecretEnvOrFile(envVar, fileEnvVar string) (string, error) {
	if p := strings.TrimSpace(os.Getenv(fileEnvVar)); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("cannot read %s (%s): %w", fileEnvVar, p, err)
		}
		v := strings.TrimSpace(string(b))
		if v == "" {
			return "", fmt.Errorf("%s (%s) is empty", fileEnvVar, p)
		}
		return v, nil
	}
	return strings.TrimSpace(os.Getenv(envVar)), nil
}

func mustReadSecretEnvOrFile(envVar, fileEnvVar string) string {
	v, err := readSecretEnvOrFile(envVar, fileEnvVar)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERR: %v\n", err)
		os.Exit(1)
	}
	return v
}

func defaultKeysDir() string {
	if d := strings.TrimSpace(os.Getenv("TINYGAAP_KEYS_DIR")); d != "" {
		return d
	}
	return "./keys"
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8090", "HTTP listen address for the x402-style + EDI 3-Way Match gate")
	hourlyLimit := flag.Int64("hourly-limit-cents", 500000, "Rolling hourly spend limit in integer cents")
	allowPayTo := flag.String("allow-payto", "paypal:treasury@acme-metal.example", "Comma-separated list of allowlisted PayTo beneficiaries")
	keyFile := flag.String("key-file", strings.TrimSpace(os.Getenv("TINYGAAP_ED25519_KEY_FILE")), "Path to persistent 0600 Ed25519 private key file (or TINYGAAP_ED25519_KEY_FILE)")
	initKey := flag.Bool("init-key", false, "Exclusively create a new 0600 Ed25519 private key file (O_CREATE|O_EXCL)")
	keysDir := flag.String("keys-dir", defaultKeysDir(), "Directory containing trusted <kid>.pub Ed25519 public keys")
	ledgerFile := flag.String("ledger-file", strings.TrimSpace(os.Getenv("TINYGAAP_LEDGER_FILE")), "Path to persistent 0600 hash-chained JSONL ledger file (or TINYGAAP_LEDGER_FILE)")
	initLedger := flag.Bool("init-ledger", false, "Exclusively create a new 0600 hash-chained ledger file (O_CREATE|O_EXCL)")
	demoEphemeral := flag.Bool("demo-ephemeral", strings.TrimSpace(os.Getenv("TINYGAAP_DEMO_EPHEMERAL")) == "1", "Allow an ephemeral per-run Ed25519 key (kid=efimera) instead of requiring -key-file")
	flag.Parse()

	hmacSecret := mustReadSecretEnvOrFile("TINYGAAP_HMAC_SECRET", "TINYGAAP_HMAC_SECRET_FILE")
	if hmacSecret == "" {
		fmt.Fprintln(os.Stderr, "ERR: TINYGAAP_HMAC_SECRET(_FILE) (>= 16 non-trivial bytes) is required to start serve_tinygaap.")
		os.Exit(1)
	}

	whitelist := make(map[string]bool)
	for _, entry := range strings.Split(*allowPayTo, ",") {
		trimmed := strings.TrimSpace(entry)
		if trimmed != "" {
			whitelist[trimmed] = true
		}
	}

	ppClientID := mustReadSecretEnvOrFile("PAYPAL_CLIENT_ID", "PAYPAL_CLIENT_ID_FILE")
	ppClientSecret := mustReadSecretEnvOrFile("PAYPAL_CLIENT_SECRET", "PAYPAL_CLIENT_SECRET_FILE")

	eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
		HMACSecret:              []byte(hmacSecret),
		RollingHourlyLimitCents: *hourlyLimit,
		Require861Receipt:       true,
		WhitelistedPayTo:        whitelist,
		PayPalClientID:          ppClientID,
		PayPalClientSecret:      ppClientSecret,
		PayPalBaseURL:           strings.TrimSpace(os.Getenv("PAYPAL_BASE_URL")),
		Ed25519KeyFile:          *keyFile,
		InitEd25519Key:          *initKey,
		RequirePersistentKey:    !*demoEphemeral,
		KeysDir:                 *keysDir,
		LedgerFile:              *ledgerFile,
		InitLedger:              *initLedger,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERR initializing TinyGAAPEngine: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		_ = eng.Close()
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":           "ok",
			"protocol_version": tinygaap.ProtocolVersion,
			"kid":              eng.KeyID(),
			"ed25519_pubkey":   eng.PublicKeyHex(),
		})
	})
	mux.HandleFunc("/v1/edi/850/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		po, err := eng.RegisterPO850(string(b))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(po)
	})
	mux.HandleFunc("/v1/edi/861/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		rcpt, err := eng.RegisterReceivingAdvice861(string(b))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rcpt)
	})
	mux.HandleFunc("/v1/edi/810/settle", eng.ServeSettle810)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Printf("tinyGAAP (%s) listening on http://%s (Ed25519 PubKey: %s)\n", tinygaap.ProtocolVersion, *addr, eng.PublicKeyHex())
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "ERR HTTP server: %v\n", err)
		os.Exit(1)
	}
}
