// Copyright 2026 Carlos Fuentes. Licensed under the Apache License, Version 2.0.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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
	outPath := flag.String("out", "./paypal_sandbox_live_proof.json", "Relative or explicit path to write the JSON proof")
	invSuffix := flag.String("inv-suffix", "", "Optional invoice suffix to avoid duplicate invoice_id across repeated sandbox runs")
	captureOrderID := flag.String("capture-order", "", "Optional buyer-approved PayPal Order ID to verify and capture into COMPLETED")
	explicitInvoiceID := flag.String("invoice-id", "", "Explicit invoice_id matching an existing PayPal Order when using -capture-order")
	waitApproval := flag.Duration("wait-approval", 0, "Create Sandbox order, print ONLY the rel=approve URL to stdout, poll until buyer approves, then capture into COMPLETED")
	pollInterval := flag.Duration("poll-interval", 10*time.Second, "Polling interval while waiting for interactive Sandbox buyer approval")
	keyFile := flag.String("key-file", strings.TrimSpace(os.Getenv("TINYGAAP_ED25519_KEY_FILE")), "Path to persistent 0600 Ed25519 private key file (or TINYGAAP_ED25519_KEY_FILE)")
	initKey := flag.Bool("init-key", false, "Exclusively create a new 0600 Ed25519 private key file (O_CREATE|O_EXCL)")
	keysDir := flag.String("keys-dir", defaultKeysDir(), "Directory containing trusted <kid>.pub Ed25519 public keys")
	ledgerFile := flag.String("ledger-file", strings.TrimSpace(os.Getenv("TINYGAAP_LEDGER_FILE")), "Path to persistent 0600 hash-chained JSONL ledger file (or TINYGAAP_LEDGER_FILE)")
	initLedger := flag.Bool("init-ledger", false, "Exclusively create a new 0600 hash-chained ledger file (O_CREATE|O_EXCL)")
	demoEphemeral := flag.Bool("demo-ephemeral", strings.TrimSpace(os.Getenv("TINYGAAP_DEMO_EPHEMERAL")) == "1", "Allow an ephemeral per-run Ed25519 key (kid=efimera) instead of requiring -key-file")
	flag.Parse()

	clientID := mustReadSecretEnvOrFile("PAYPAL_CLIENT_ID", "PAYPAL_CLIENT_ID_FILE")
	clientSecret := mustReadSecretEnvOrFile("PAYPAL_CLIENT_SECRET", "PAYPAL_CLIENT_SECRET_FILE")
	baseURL := strings.TrimSpace(os.Getenv("PAYPAL_BASE_URL"))
	if baseURL == "" {
		baseURL = "https://api-m.sandbox.paypal.com"
	}

	if clientID == "" || clientSecret == "" {
		fmt.Fprintln(os.Stderr, "ERR: PAYPAL_CLIENT_ID(_FILE) and PAYPAL_CLIENT_SECRET(_FILE) are required.")
		os.Exit(1)
	}

	var hmacSecret []byte
	if envSecret := mustReadSecretEnvOrFile("TINYGAAP_HMAC_SECRET", "TINYGAAP_HMAC_SECRET_FILE"); envSecret != "" {
		hmacSecret = []byte(envSecret)
	} else {
		hmacSecret = make([]byte, 32)
		if _, err := rand.Read(hmacSecret); err != nil {
			fmt.Fprintf(os.Stderr, "ERR generating ephemeral HMAC key: %v\n", err)
			os.Exit(1)
		}
	}

	invoiceID := strings.TrimSpace(*explicitInvoiceID)
	if invoiceID == "" {
		if *invSuffix != "" {
			invoiceID = "INV-TG-20261108-01-" + *invSuffix
		} else {
			invoiceID = fmt.Sprintf("INV-TG-%d", time.Now().UTC().Unix())
		}
	}

	raw850 := strings.Join([]string{
		"ISA*00*          *00*          *ZZ*BUYER01        *ZZ*SUPPLIER01     *261108*0900*^*00501*000001001*0*T*:~",
		"GS*PO*BUYER01*SUPPLIER01*20261108*090000*1001*X*005010~",
		"ST*850*0001~",
		"BEG*00*SA*PO-850-9001**20261108~",
		"N1*BY*ACME BUYER CORP*92*BUYER-01~",
		"N1*SE*ACME CLOUD METAL INC*92*paypal:treasury@acme-metal.example~",
		"PO1*1*2*EA*50.00*PE*VP*BARE-METAL-GPU-HR~",
		"PO1*2*1*EA*25.00*PE*VP*NVME-STORAGE-TB~",
		"CTT*2*3~",
		"AMT*TT*125.00~",
		"SE*9*0001~",
		"GE*1*1001~",
		"IEA*1*000001001~",
	}, "\n")

	raw861 := strings.Join([]string{
		"ISA*00*          *00*          *ZZ*BUYER01        *ZZ*SUPPLIER01     *261108*0902*^*00501*000001501*0*T*:~",
		"GS*RC*BUYER01*SUPPLIER01*20261108*090200*1501*X*005010~",
		"ST*861*0001~",
		"BRA*RCV-861-9001*20261108*00*5~",
		"PRF*PO-850-9001~",
		"RCD*1*2*EA*0~",
		"LIN*1*VP*BARE-METAL-GPU-HR~",
		"RCD*2*1*EA*0~",
		"LIN*2*VP*NVME-STORAGE-TB~",
		"CTT*2*3~",
		"SE*9*0001~",
		"GE*1*1501~",
		"IEA*1*000001501~",
	}, "\n")

	raw810 := strings.Join([]string{
		"ISA*00*          *00*          *ZZ*SUPPLIER01     *ZZ*BUYER01        *261108*0910*^*00501*000002001*0*T*:~",
		"GS*IN*SUPPLIER01*BUYER01*20261108*091000*810001*X*005010~",
		"ST*810*0001~",
		fmt.Sprintf("BIG*20261108*%s*20261108*PO-850-9001~", invoiceID),
		"N1*SE*ACME CLOUD METAL INC*92*paypal:treasury@acme-metal.example~",
		"IT1*1*2*EA*50.00*PE*VP*BARE-METAL-GPU-HR~",
		"IT1*2*1*EA*25.00*PE*VP*NVME-STORAGE-TB~",
		"TDS*12500~",
		"CAD*****PAYPAL*paypal:treasury@acme-metal.example~",
		"CTT*2*3~",
		"SE*9*0001~",
		"GE*1*810001~",
		"IEA*1*000002001~",
	}, "\n")

	engine, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
		HMACSecret:              hmacSecret,
		RollingHourlyLimitCents: 50000,
		Require861Receipt:       true,
		WhitelistedPayTo: map[string]bool{
			"paypal:treasury@acme-metal.example": true,
		},
		PayPalClientID:       clientID,
		PayPalClientSecret:   clientSecret,
		PayPalBaseURL:        baseURL,
		Ed25519KeyFile:       *keyFile,
		InitEd25519Key:       *initKey,
		RequirePersistentKey: !*demoEphemeral,
		KeysDir:              *keysDir,
		LedgerFile:           *ledgerFile,
		InitLedger:           *initLedger,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERR engine init: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		_ = engine.Close()
	}()

	ctxTimeout := 30 * time.Second
	if *waitApproval > 0 {
		ctxTimeout = *waitApproval + 60*time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	var proof *tinygaap.PayPalLiveSandboxProof
	switch {
	case *waitApproval > 0:
		proof, err = engine.VerifyWaitApprovalAndCapturePayPalOrderE2E(ctx, raw850, raw861, raw810, *waitApproval, *pollInterval, func(approveURL string) {
			fmt.Println(approveURL)
		})
	case strings.TrimSpace(*captureOrderID) != "":
		proof, err = engine.VerifyAndCaptureApprovedPayPalOrderE2E(ctx, raw850, raw861, raw810, *captureOrderID)
	default:
		proof, err = engine.VerifyLivePayPalSandboxE2E(ctx, raw850, raw861, raw810)
	}

	var outJSON []byte
	if proof != nil {
		var marshalErr error
		outJSON, marshalErr = json.MarshalIndent(proof, "", "  ")
		if marshalErr != nil {
			fmt.Fprintf(os.Stderr, "ERR marshaling proof: %v\n", marshalErr)
			os.Exit(1)
		}
		if *waitApproval <= 0 {
			fmt.Println(string(outJSON))
		}
	}

	if *waitApproval > 0 && proof != nil && proof.LivePayPalOrderID != "" {
		if writeErr := os.WriteFile(*outPath, append(outJSON, '\n'), 0644); writeErr != nil {
			fmt.Fprintf(os.Stderr, "ERR writing proof to %s: %v\n", *outPath, writeErr)
			os.Exit(1)
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "ERR live sandbox E2E failed: %v\n", err)
		if *waitApproval > 0 && errors.Is(err, tinygaap.ErrPayPalCaptureNotCompleted) {
			os.Exit(2)
		}
		os.Exit(1)
	}

	if *waitApproval <= 0 {
		if writeErr := os.WriteFile(*outPath, append(outJSON, '\n'), 0644); writeErr != nil {
			fmt.Fprintf(os.Stderr, "ERR writing proof to %s: %v\n", *outPath, writeErr)
			os.Exit(1)
		}
	}
}
