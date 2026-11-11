// Copyright 2026 Carlos Fuentes. Licensed under the Apache License, Version 2.0.
package tinygaap_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tinygaap.io/paypal-edi"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newInMemoryHTTPClient(h http.HandlerFunc) *http.Client {
	return &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			h(rec, req)
			return rec.Result(), nil
		}),
	}
}

func clearLLMEnv(t *testing.T) {
	t.Helper()
	t.Setenv("TINYGAAP_LLM_ENDPOINT", "")
	t.Setenv("TINYGAAP_LLM_API_KEY", "")
	t.Setenv("TINYGAAP_LLM_MODEL", "")
	t.Setenv("GEMINI_API_KEY", "")
}

func canonicalPO850() string {
	return strings.Join([]string{
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
}

func canonicalReceipt861() string {
	return strings.Join([]string{
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
}

func validInvoice810(invNumber string) string {
	return strings.Join([]string{
		"ISA*00*          *00*          *ZZ*SUPPLIER01     *ZZ*BUYER01        *261108*0905*^*00501*000002001*0*T*:~",
		"GS*IN*SUPPLIER01*BUYER01*20261108*090500*810777*X*005010~",
		"ST*810*0042~",
		"BIG*20261108*" + invNumber + "*20261108*PO-850-9001~",
		"N1*SE*ACME CLOUD METAL INC*92*paypal:treasury@acme-metal.example~",
		"IT1*1*2*EA*50.00*PE*VP*BARE-METAL-GPU-HR~",
		"IT1*2*1*EA*25.00*PE*VP*NVME-STORAGE-TB~",
		"TDS*12500~",
		"CAD*****PAYPAL*paypal:treasury@acme-metal.example~",
		"CTT*2*3~",
		"SE*9*0042~",
		"GE*1*810777~",
		"IEA*1*000002001~",
	}, "\n")
}

func assertX12EnvelopeValid(t *testing.T, rawX12 string) {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(rawX12), "\n")
	if len(lines) < 4 {
		t.Fatalf("X12 has fewer than 4 lines:\n%s", rawX12)
	}
	isaLine := strings.TrimSpace(lines[0])
	if len(isaLine) != 106 {
		t.Fatalf("ISA segment length = %d, want 106:\n%q", len(isaLine), isaLine)
	}
	var stCtrl string
	var stCount int
	var inST bool
	for _, l := range lines {
		l = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(l), "~"))
		parts := strings.Split(l, "*")
		switch parts[0] {
		case "ST":
			inST = true
			stCount = 1
			stCtrl = parts[2]
		case "SE":
			if !inST {
				t.Fatalf("SE without ST")
			}
			stCount++
			inST = false
			decl, err := strconv.Atoi(parts[1])
			if err != nil || decl != stCount {
				t.Fatalf("SE01 count = %s, want %d", parts[1], stCount)
			}
			if parts[2] != stCtrl {
				t.Fatalf("SE02 = %s, want ST02 = %s", parts[2], stCtrl)
			}
		default:
			if inST {
				stCount++
			}
		}
	}
}

func TestTinyGAAP_NewEngine_FailClosedWithoutHMACSecret(t *testing.T) {
	clearLLMEnv(t)
	badSecrets := [][]byte{
		nil,
		[]byte("short"),
		[]byte("15bytes-secret!"),
		make([]byte, 16),           // 16 all-zero bytes
		make([]byte, 32),           // 32 all-zero bytes
		[]byte("aaaaaaaaaaaaaaaa"), // 16 identical bytes
		[]byte("abababababababab"), // only 2 distinct byte values
		[]byte("abcabcabcabcabca"), // only 3 distinct byte values
	}
	for i, secret := range badSecrets {
		if _, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{HMACSecret: secret}); !errors.Is(err, tinygaap.ErrMissingHMACSecret) {
			t.Fatalf("case %d (%q): expected ErrMissingHMACSecret, got %v", i, string(secret), err)
		}
	}

	// Exact 16-byte secret with >= 4 distinct bytes succeeds.
	if _, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
		HMACSecret: []byte("0123456789abcdef"),
	}); err != nil {
		t.Fatalf("expected 16-byte high-entropy secret to succeed, got %v", err)
	}
}

func TestTinyGAAP_VerifyReceiptHMAC_And_VerifyReceiptSignature(t *testing.T) {
	clearLLMEnv(t)
	secret := []byte("tinygaap-hmac-verification-secret-32b")
	eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
		HMACSecret:              secret,
		RollingHourlyLimitCents: 50000,
		WhitelistedPayTo: map[string]bool{
			"paypal:treasury@acme-metal.example": true,
		},
	})
	if err != nil {
		t.Fatalf("NewTinyGAAPEngine: %v", err)
	}
	if _, err := eng.RegisterPO850(canonicalPO850()); err != nil {
		t.Fatalf("RegisterPO850: %v", err)
	}
	if _, err := eng.RegisterReceivingAdvice861(canonicalReceipt861()); err != nil {
		t.Fatalf("RegisterReceivingAdvice861: %v", err)
	}

	res, err := eng.EvaluateAndSettle810(context.Background(), validInvoice810("INV-SIG-01"), "agent-sig", "paypal:treasury@acme-metal.example")
	if err != nil {
		t.Fatalf("EvaluateAndSettle810: %v", err)
	}

	if !strings.HasPrefix(res.ReceiptHeader, "tinygaap:v=3;") {
		t.Fatalf("expected ReceiptHeader prefix tinygaap:v=3;, got %q", res.ReceiptHeader)
	}
	if !tinygaap.VerifyReceiptHMAC(secret, res.ReceiptHeader) {
		t.Fatalf("VerifyReceiptHMAC failed on valid receipt")
	}
	if tinygaap.VerifyReceiptHMAC([]byte("wrong-secret-key-with-high-entropy"), res.ReceiptHeader) {
		t.Fatalf("VerifyReceiptHMAC succeeded with wrong secret")
	}
	if tinygaap.VerifyReceiptHMAC(secret, strings.Replace(res.ReceiptHeader, "inv=INV-SIG-01", "inv=INV-TAMPERED", 1)) {
		t.Fatalf("VerifyReceiptHMAC succeeded with tampered header")
	}
	if tinygaap.VerifyReceiptHMAC(make([]byte, 16), res.ReceiptHeader) {
		t.Fatalf("VerifyReceiptHMAC succeeded with low-entropy secret")
	}

	if !tinygaap.VerifyReceiptSignature(res.Ed25519PubKeyHex, res.ReceiptHeader, res.Ed25519SignatureHex) {
		t.Fatalf("VerifyReceiptSignature failed on valid signature")
	}
	if tinygaap.VerifyReceiptSignature(res.Ed25519PubKeyHex, res.ReceiptHeader+"x", res.Ed25519SignatureHex) {
		t.Fatalf("VerifyReceiptSignature succeeded on modified message")
	}
	if tinygaap.VerifyReceiptSignature("badhex", res.ReceiptHeader, res.Ed25519SignatureHex) {
		t.Fatalf("VerifyReceiptSignature succeeded on invalid pubkey hex")
	}
}

func TestTinyGAAP_X402PaymentSignature_CryptographicVerification(t *testing.T) {
	clearLLMEnv(t)
	secret := []byte("tinygaap-x402-hmac-test-secret-key")
	eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
		HMACSecret:              secret,
		RollingHourlyLimitCents: 100000,
		WhitelistedPayTo: map[string]bool{
			"paypal:treasury@acme-metal.example": true,
		},
	})
	if err != nil {
		t.Fatalf("NewTinyGAAPEngine: %v", err)
	}
	if _, err := eng.RegisterPO850(canonicalPO850()); err != nil {
		t.Fatalf("RegisterPO850: %v", err)
	}
	if _, err := eng.RegisterReceivingAdvice861(canonicalReceipt861()); err != nil {
		t.Fatalf("RegisterReceivingAdvice861: %v", err)
	}

	body := validInvoice810("INV-X402-01")
	validHeader := eng.SignX402Header(body)

	// Rejects missing header, bare scheme prefix, forged hex, and signature for different body.
	invalidHeaders := []string{
		"",
		"exact:x402:paypal-order-v2",
		"exact:x402:paypal-order-v2;sig=0000000000000000000000000000000000000000000000000000000000000000",
		eng.SignX402Header(validInvoice810("INV-OTHER-BODY")),
	}
	for i, hdr := range invalidHeaders {
		req := httptest.NewRequest(http.MethodPost, "/v1/edi/810/settle", bytes.NewBufferString(body))
		if hdr != "" {
			req.Header.Set("Payment-Signature", hdr)
		}
		req.Header.Set("X-Agent-Key", "agent-x402")
		req.Header.Set("X-PayTo-Beneficiary", "paypal:treasury@acme-metal.example")
		rec := httptest.NewRecorder()
		eng.ServeSettle810(rec, req)
		if rec.Code != http.StatusPaymentRequired {
			t.Fatalf("case %d (%q): expected HTTP 402, got %d", i, hdr, rec.Code)
		}
	}

	// Succeeds with valid Payment-Signature.
	req := httptest.NewRequest(http.MethodPost, "/v1/edi/810/settle", bytes.NewBufferString(body))
	req.Header.Set("Payment-Signature", validHeader)
	req.Header.Set("X-Agent-Key", "agent-x402")
	req.Header.Set("X-PayTo-Beneficiary", "paypal:treasury@acme-metal.example")
	rec := httptest.NewRecorder()
	eng.ServeSettle810(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 with valid Payment-Signature, got %d: %s", rec.Code, rec.Body.String())
	}

	// Succeeds with X-Payment fallback header.
	body2 := validInvoice810("INV-X402-02")
	// Re-register PO/861 on a second engine to test X-Payment header cleanly.
	eng2, _ := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
		HMACSecret:              secret,
		RollingHourlyLimitCents: 100000,
		WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
	})
	_, _ = eng2.RegisterPO850(canonicalPO850())
	_, _ = eng2.RegisterReceivingAdvice861(canonicalReceipt861())
	req2 := httptest.NewRequest(http.MethodPost, "/v1/edi/810/settle", bytes.NewBufferString(body2))
	req2.Header.Set("X-Payment", eng2.SignX402Header(body2))
	req2.Header.Set("X-Agent-Key", "agent-x402")
	req2.Header.Set("X-PayTo-Beneficiary", "paypal:treasury@acme-metal.example")
	rec2 := httptest.NewRecorder()
	eng2.ServeSettle810(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 with valid X-Payment header, got %d", rec2.Code)
	}
}

func TestTinyGAAP_ParseCentsDecimal_StrictValidation(t *testing.T) {
	validCases := map[string]int64{
		"0":      0,
		"125":    12500,
		"125.0":  12500,
		"125.00": 12500,
		"60.5":   6050,
		"0.01":   1,
	}
	for in, want := range validCases {
		got, err := tinygaap.ParseCentsDecimal(in)
		if err != nil || got != want {
			t.Fatalf("ParseCentsDecimal(%q) = (%d, %v), want (%d, nil)", in, got, err, want)
		}
	}

	invalidCases := []string{
		"",
		"-10.00",
		"+10.00",
		"100.009",
		"100.",
		".50",
		"12.3a",
		"abc",
	}
	for _, in := range invalidCases {
		if _, err := tinygaap.ParseCentsDecimal(in); err == nil {
			t.Fatalf("ParseCentsDecimal(%q) unexpectedly succeeded", in)
		}
	}
}

func TestTinyGAAP_MutationKilling_Guardrails(t *testing.T) {
	clearLLMEnv(t)
	newEngine := func(t *testing.T) *tinygaap.TinyGAAPEngine {
		t.Helper()
		eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              []byte("tinygaap-unit-test-hmac-secret-key-32b"),
			RollingHourlyLimitCents: 20000,
			WhitelistedPayTo: map[string]bool{
				"paypal:treasury@acme-metal.example": true,
			},
		})
		if err != nil {
			t.Fatalf("NewTinyGAAPEngine: %v", err)
		}
		if _, err := eng.RegisterPO850(canonicalPO850()); err != nil {
			t.Fatalf("RegisterPO850: %v", err)
		}
		if _, err := eng.RegisterReceivingAdvice861(canonicalReceipt861()); err != nil {
			t.Fatalf("RegisterReceivingAdvice861: %v", err)
		}
		return eng
	}

	t.Run("Baseline_HappyPath_3WayMatch_HonestPreCaptureState", func(t *testing.T) {
		eng := newEngine(t)
		body := validInvoice810("INV-HAPPY-01")
		req := httptest.NewRequest(http.MethodPost, "/v1/edi/810/settle", bytes.NewBufferString(body))
		req.Header.Set("Payment-Signature", eng.SignX402Header(body))
		req.Header.Set("X-Agent-Key", "buyer-agent-01")
		req.Header.Set("X-PayTo-Beneficiary", "paypal:treasury@acme-metal.example")

		rec := httptest.NewRecorder()
		eng.ServeSettle810(rec, req)
		resp := rec.Result()
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}

		var res tinygaap.SettlementEvaluationResult
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !res.SettlementAuthorized {
			t.Fatalf("expected SettlementAuthorized = true")
		}
		if res.PayPalCaptured || res.PayPalCaptureID != "" || res.RawEDI820 != "" {
			t.Fatalf("expected honest pre-capture state (PayPalCaptured=false, RawEDI820 empty), got captured=%v id=%q", res.PayPalCaptured, res.PayPalCaptureID)
		}
		assertX12EnvelopeValid(t, res.RawEDI997)
		if !strings.Contains(res.RawEDI997, "AK1*IN*810777~") || !strings.Contains(res.RawEDI997, "AK2*810*0042~") || !strings.Contains(res.RawEDI997, "AK5*A~") || !strings.Contains(res.RawEDI997, "AK9*A*1*1*1~") {
			t.Fatalf("EDI 997 missing expected AK1/AK2/AK5/AK9 segments:\n%s", res.RawEDI997)
		}
		if !tinygaap.VerifyReceiptSignature(res.Ed25519PubKeyHex, res.ReceiptHeader, res.Ed25519SignatureHex) {
			t.Fatalf("Ed25519 signature verification failed on receipt header")
		}
	})

	t.Run("DefaultConfig_Requires861Receipt_FailClosed", func(t *testing.T) {
		eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              []byte("tinygaap-default-861-hmac-secret-32b"),
			RollingHourlyLimitCents: 50000,
			WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
		})
		if err != nil {
			t.Fatalf("NewTinyGAAPEngine: %v", err)
		}
		if _, err := eng.RegisterPO850(canonicalPO850()); err != nil {
			t.Fatalf("RegisterPO850: %v", err)
		}
		// No 861 registered -> must fail closed with ErrReceivingAdviceNotFound pointing to BIG in 810.
		res, err := eng.EvaluateAndSettle810(context.Background(), validInvoice810("INV-NO-861"), "agent-1", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrReceivingAdviceNotFound) || res.EDI997AckCode != "R" || res.ErrorSegmentID != "BIG" {
			t.Fatalf("expected ErrReceivingAdviceNotFound (ErrorSegmentID=BIG) when 861 omitted by default, got err=%v seg=%q", err, res.ErrorSegmentID)
		}
	})

	t.Run("EmptyWhitelistedPayTo_FailsClosed", func(t *testing.T) {
		eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              []byte("tinygaap-empty-allowlist-hmac-32b"),
			RollingHourlyLimitCents: 50000,
		})
		if err != nil {
			t.Fatalf("NewTinyGAAPEngine: %v", err)
		}
		if _, err := eng.RegisterPO850(canonicalPO850()); err != nil {
			t.Fatalf("RegisterPO850: %v", err)
		}
		if _, err := eng.RegisterReceivingAdvice861(canonicalReceipt861()); err != nil {
			t.Fatalf("RegisterReceivingAdvice861: %v", err)
		}
		if _, err := eng.EvaluateAndSettle810(context.Background(), validInvoice810("INV-NO-WL"), "agent-1", "paypal:treasury@acme-metal.example"); !errors.Is(err, tinygaap.ErrUnapprovedBeneficiary) {
			t.Fatalf("expected ErrUnapprovedBeneficiary when WhitelistedPayTo is empty, got %v", err)
		}
	})

	t.Run("OrderIndependent_IT1_LinePermutation_Approved", func(t *testing.T) {
		eng := newEngine(t)
		permuted := strings.Join([]string{
			"ISA*00*          *00*          *ZZ*SUPPLIER01     *ZZ*BUYER01        *261108*0905*^*00501*000002001*0*T*:~",
			"GS*IN*SUPPLIER01*BUYER01*20261108*090500*810777*X*005010~",
			"ST*810*0042~",
			"BIG*20261108*INV-PERM-OK*20261108*PO-850-9001~",
			"N1*SE*ACME CLOUD METAL INC*92*paypal:treasury@acme-metal.example~",
			"IT1*1*1*EA*25.00*PE*VP*NVME-STORAGE-TB~",
			"IT1*2*2*EA*50.00*PE*VP*BARE-METAL-GPU-HR~",
			"TDS*12500~",
			"CAD*****PAYPAL*paypal:treasury@acme-metal.example~",
			"CTT*2*3~",
			"SE*9*0042~",
			"GE*1*810777~",
			"IEA*1*000002001~",
		}, "\n")
		res, err := eng.EvaluateAndSettle810(context.Background(), permuted, "agent-perm", "paypal:treasury@acme-metal.example")
		if err != nil || !res.SettlementAuthorized || res.EDI997AckCode != "A" {
			t.Fatalf("expected permuted IT1 lines with matching SKUs to be approved, got err=%v res=%+v", err, res)
		}
	})

	t.Run("CustomDelimiter_PipeElementSeparator_Approved", func(t *testing.T) {
		eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              []byte("tinygaap-custom-delim-hmac-key-32b"),
			RollingHourlyLimitCents: 50000,
			WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
		})
		if err != nil {
			t.Fatalf("NewTinyGAAPEngine: %v", err)
		}
		pipePO := strings.ReplaceAll(canonicalPO850(), "*", "|")
		pipe861 := strings.ReplaceAll(canonicalReceipt861(), "*", "|")
		pipe810 := strings.ReplaceAll(validInvoice810("INV-PIPE-01"), "*", "|")
		if _, err := eng.RegisterPO850(pipePO); err != nil {
			t.Fatalf("RegisterPO850 pipe delimiter: %v", err)
		}
		if _, err := eng.RegisterReceivingAdvice861(pipe861); err != nil {
			t.Fatalf("RegisterReceivingAdvice861 pipe delimiter: %v", err)
		}
		res, err := eng.EvaluateAndSettle810(context.Background(), pipe810, "agent-pipe", "paypal:treasury@acme-metal.example")
		if err != nil || !res.SettlementAuthorized {
			t.Fatalf("expected pipe-delimited X12 to succeed, got err=%v", err)
		}
	})

	t.Run("Kill_M1_ThirdPartyNote_Alone", func(t *testing.T) {
		eng := newEngine(t)
		raw := strings.Replace(validInvoice810("INV-M1"), "N1*SE*", "NTE*3P*Please review note~\nN1*SE*", 1)
		raw = strings.Replace(raw, "SE*9*0042~", "SE*10*0042~", 1)
		res, err := eng.EvaluateAndSettle810(context.Background(), raw, "agent-1", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrUnapprovedBeneficiary) || errors.Is(err, tinygaap.ErrAIAuditorRejected) || res.EDI997AckCode != "R" || res.ErrorSegmentID != "NTE" || !strings.Contains(res.RawEDI997, "UNAPPROVED-3P-NOTE") {
			t.Fatalf("expected deterministic ErrUnapprovedBeneficiary (UNAPPROVED-3P-NOTE) for ThirdPartyNote alone, got err=%v seg=%q 997=%s", err, res.ErrorSegmentID, res.RawEDI997)
		}
	})

	t.Run("Kill_M2_SellerID_Mismatch_Alone", func(t *testing.T) {
		eng := newEngine(t)
		raw := strings.Replace(validInvoice810("INV-M2"),
			"N1*SE*ACME CLOUD METAL INC*92*paypal:treasury@acme-metal.example~",
			"N1*SE*ROGUE VENDOR*92*paypal:rogue@offshore.example~", 1)
		res, err := eng.EvaluateAndSettle810(context.Background(), raw, "agent-1", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrUnapprovedBeneficiary) || res.ErrorSegmentID != "N1" {
			t.Fatalf("expected ErrUnapprovedBeneficiary on N1*SE alone, got err=%v seg=%q", err, res.ErrorSegmentID)
		}
	})

	t.Run("Kill_M3_CADPayTo_Mismatch_Alone", func(t *testing.T) {
		eng := newEngine(t)
		raw := strings.Replace(validInvoice810("INV-M3"),
			"CAD*****PAYPAL*paypal:treasury@acme-metal.example~",
			"CAD*****PAYPAL*paypal:rogue@offshore.example~", 1)
		res, err := eng.EvaluateAndSettle810(context.Background(), raw, "agent-1", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrUnapprovedBeneficiary) || res.ErrorSegmentID != "CAD" {
			t.Fatalf("expected ErrUnapprovedBeneficiary on CAD alone, got err=%v seg=%q", err, res.ErrorSegmentID)
		}
	})

	t.Run("Kill_RequestedPayTo_Unwhitelisted_Alone", func(t *testing.T) {
		eng := newEngine(t)
		res, err := eng.EvaluateAndSettle810(context.Background(), validInvoice810("INV-PAYTO"), "agent-1", "paypal:rogue@offshore.example")
		if !errors.Is(err, tinygaap.ErrUnapprovedBeneficiary) || res.ErrorSegmentID != "N1" {
			t.Fatalf("expected ErrUnapprovedBeneficiary on RequestedPayTo alone, got err=%v", err)
		}
	})

	t.Run("Kill_M4_VendorSKU_Mismatch_Alone", func(t *testing.T) {
		eng := newEngine(t)
		raw := strings.Replace(validInvoice810("INV-M4"), "VP*BARE-METAL-GPU-HR~", "VP*WRONG-SKU-GPU-HR~", 1)
		res, err := eng.EvaluateAndSettle810(context.Background(), raw, "agent-1", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrEDI810PriceQtyDrift) || res.ErrorSegmentID != "IT1" {
			t.Fatalf("expected ErrEDI810PriceQtyDrift on SKU mismatch alone, got err=%v", err)
		}
	})

	t.Run("Kill_M5_Quantity_Mismatch_Preserving_Total_Alone", func(t *testing.T) {
		eng := newEngine(t)
		raw := strings.Replace(validInvoice810("INV-M5"),
			"IT1*1*2*EA*50.00*PE*VP*BARE-METAL-GPU-HR~",
			"IT1*1*1*EA*100.00*PE*VP*BARE-METAL-GPU-HR~", 1)
		res, err := eng.EvaluateAndSettle810(context.Background(), raw, "agent-1", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrEDI810PriceQtyDrift) || res.ErrorSegmentID != "IT1" {
			t.Fatalf("expected ErrEDI810PriceQtyDrift on quantity swap alone, got err=%v", err)
		}
	})

	t.Run("Kill_M6_LineCount_Mismatch_Alone", func(t *testing.T) {
		eng := newEngine(t)
		raw := strings.Replace(validInvoice810("INV-M6"), "IT1*2*1*EA*25.00*PE*VP*NVME-STORAGE-TB~\n", "", 1)
		raw = strings.Replace(raw, "SE*9*0042~", "SE*8*0042~", 1)
		res, err := eng.EvaluateAndSettle810(context.Background(), raw, "agent-1", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrEDI810PriceQtyDrift) || res.ErrorSegmentID != "IT1" {
			t.Fatalf("expected ErrEDI810PriceQtyDrift on line count mismatch alone, got err=%v", err)
		}
	})

	t.Run("Kill_M7_Missing_PO_404", func(t *testing.T) {
		eng := newEngine(t)
		raw := strings.Replace(validInvoice810("INV-M7"), "PO-850-9001~", "PO-850-DOES-NOT-EXIST~", 1)
		res, err := eng.EvaluateAndSettle810(context.Background(), raw, "agent-1", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrPONotFound) || res.ErrorSegmentID != "BIG" {
			t.Fatalf("expected ErrPONotFound on unknown PO, got err=%v", err)
		}
	})

	t.Run("Kill_M8_TDS_Inflation_With_Intact_IT1_Lines", func(t *testing.T) {
		eng := newEngine(t)
		raw := strings.Replace(validInvoice810("INV-TDS-DRIFT"), "TDS*12500~", "TDS*99999~", 1)
		res, err := eng.EvaluateAndSettle810(context.Background(), raw, "agent-1", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrEDI810PriceQtyDrift) || res.ErrorSegmentID != "TDS" {
			t.Fatalf("expected ErrEDI810PriceQtyDrift on TDS inflation, got err=%v seg=%q", err, res.ErrorSegmentID)
		}
	})

	t.Run("Kill_M9_UnitOfMeasure_Mismatch_And_SecondLine_AK3_Position", func(t *testing.T) {
		eng := newEngine(t)
		// Modify 2nd IT1 line (segment position 5 inside ST..SE) to have UOM "HR" instead of "EA".
		raw := strings.Replace(validInvoice810("INV-UOM-POS"),
			"IT1*2*1*EA*25.00*PE*VP*NVME-STORAGE-TB~",
			"IT1*2*1*HR*25.00*PE*VP*NVME-STORAGE-TB~", 1)
		res, err := eng.EvaluateAndSettle810(context.Background(), raw, "agent-1", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrEDI810PriceQtyDrift) || res.ErrorSegmentID != "IT1" || res.ErrorSegmentPos != 5 {
			t.Fatalf("expected IT1 error at segment pos 5, got err=%v seg=%q pos=%d", err, res.ErrorSegmentID, res.ErrorSegmentPos)
		}
		if !strings.Contains(res.RawEDI997, "AK3*IT1*5**8~") || !strings.Contains(res.RawEDI997, "AK5*R~") || !strings.Contains(res.RawEDI997, "AK9*R*1*1*0~") {
			t.Fatalf("RawEDI997 missing AK3*IT1*5**8~ / AK5*R~ / AK9*R*1*1*0~:\n%s", res.RawEDI997)
		}
	})

	t.Run("Kill_M10_MalformedEnvelope_Checks_And_Honest_997_Without_GS", func(t *testing.T) {
		eng := newEngine(t)
		base := validInvoice810("INV-ENV")
		noGS := strings.Replace(base, "GS*IN*SUPPLIER01*BUYER01*20261108*090500*810777*X*005010~\n", "", 1)
		res, err := eng.EvaluateAndSettle810(context.Background(), noGS, "agent-env", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrX12MalformedEnvelope) {
			t.Fatalf("expected ErrX12MalformedEnvelope when GS is missing, got %v", err)
		}
		if strings.Contains(res.RawEDI997, "AK1*IN*1~") || !strings.Contains(res.RawEDI997, "AK1*FA*0~") {
			t.Fatalf("expected AK1*FA*0~ when GS is missing, got:\n%s", res.RawEDI997)
		}

		malformedCases := []string{
			strings.Replace(base, "GS*IN*", "GS*PO*", 1),
			strings.Replace(base, "ST*810*0042~", "ST*850*0042~", 1),
			strings.Replace(base, "GE*1*810777~", "GE*1*999999~", 1),
			strings.Replace(base, "IEA*1*000002001~", "IEA*1*999999999~", 1),
			strings.Replace(base, "SE*9*0042~", "SE*0*0042~", 1),
		}
		for i, tc := range malformedCases {
			if _, err := eng.EvaluateAndSettle810(context.Background(), tc, "agent-env", "paypal:treasury@acme-metal.example"); !errors.Is(err, tinygaap.ErrX12MalformedEnvelope) {
				t.Fatalf("malformed case %d: expected ErrX12MalformedEnvelope, got %v", i, err)
			}
		}
	})

	t.Run("Kill_M11_Cumulative_PO_DoubleBilling_Across_Distinct_BIG02", func(t *testing.T) {
		eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              []byte("tinygaap-cumulative-po-secret-32b"),
			RollingHourlyLimitCents: 100000,
			WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
		})
		if err != nil {
			t.Fatalf("NewTinyGAAPEngine: %v", err)
		}
		_, _ = eng.RegisterPO850(canonicalPO850())
		_, _ = eng.RegisterReceivingAdvice861(canonicalReceipt861())

		if _, err := eng.EvaluateAndSettle810(context.Background(), validInvoice810("INV-BILL-A"), "agent-1", "paypal:treasury@acme-metal.example"); err != nil {
			t.Fatalf("first invoice INV-BILL-A failed: %v", err)
		}
		// Second invoice with distinct BIG02 (INV-BILL-B) against the same already-billed PO/861 must fail closed.
		if _, err := eng.EvaluateAndSettle810(context.Background(), validInvoice810("INV-BILL-B"), "agent-1", "paypal:treasury@acme-metal.example"); !errors.Is(err, tinygaap.ErrDuplicateInvoiceReplay) {
			t.Fatalf("expected ErrDuplicateInvoiceReplay on cumulative PO over-billing across distinct BIG02, got %v", err)
		}
	})

	t.Run("Kill_M12_GlobalBudgetBreaker_AgentKeyRotation_And_SeedAgentSpendCents", func(t *testing.T) {
		eng := newEngine(t)
		eng.SeedAgentSpendCents("seeded-agent", 10000)
		// Remaining global budget is 20000 - 10000 = 10000 cents ($100.00).
		// Invoice is 12500 cents ($125.00), so even a brand-new X-Agent-Key must trip the global breaker.
		if _, err := eng.EvaluateAndSettle810(context.Background(), validInvoice810("INV-ROTATE-1"), "brand-new-agent-key", "paypal:treasury@acme-metal.example"); !errors.Is(err, tinygaap.ErrBudgetBreakerTripped) {
			t.Fatalf("expected global budget breaker to reject rotated agent key, got %v", err)
		}
	})
}

func TestTinyGAAP_AIAuditorAgent_LiveLLM(t *testing.T) {
	if strings.TrimSpace(os.Getenv("TINYGAAP_LLM_ENDPOINT")) == "" {
		t.Skip("TINYGAAP_LLM_ENDPOINT unset; skipping live external LLM test")
	}
	auditor := tinygaap.NewDefaultAIAuditorAgent(nil)
	po, err := tinygaap.ParseEDI850(canonicalPO850())
	if err != nil {
		t.Fatalf("ParseEDI850: %v", err)
	}
	rcpt, err := tinygaap.ParseEDI861(canonicalReceipt861())
	if err != nil {
		t.Fatalf("ParseEDI861: %v", err)
	}
	inv, _, _, err := tinygaap.ParseEDI810(validInvoice810("INV-LIVE-LLM-SMOKE"))
	if err != nil {
		t.Fatalf("ParseEDI810: %v", err)
	}
	verdict, err := auditor.AuditInvoiceSemantics(context.Background(), po, rcpt, inv)
	if err != nil {
		t.Fatalf("live AuditInvoiceSemantics error: %v", err)
	}
	if verdict == nil || verdict.Mode != "live_llm" || verdict.Decision != "APPROVE" {
		t.Fatalf("expected live_llm APPROVE on clean invoice, got %+v", verdict)
	}
}

func TestTinyGAAP_AIAuditorAgent_MockHTTPAndGuards(t *testing.T) {
	var llmResponseStatus int
	var llmResponseText string
	var llmCallCount int

	llmClient := newInMemoryHTTPClient(func(w http.ResponseWriter, r *http.Request) {
		llmCallCount++
		w.WriteHeader(llmResponseStatus)
		if llmResponseStatus == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{
					{
						"message": map[string]string{
							"content": llmResponseText,
						},
					},
				},
			})
			return
		}
		_, _ = w.Write([]byte(`{"error":"upstream failure"}`))
	})

	newAuditedEngine := func(t *testing.T) *tinygaap.TinyGAAPEngine {
		t.Helper()
		auditor := tinygaap.NewDefaultAIAuditorAgent(llmClient)
		eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              []byte("tinygaap-live-llm-auditor-secret-32b"),
			RollingHourlyLimitCents: 100000,
			WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
			Auditor:                 auditor,
		})
		if err != nil {
			t.Fatalf("NewTinyGAAPEngine: %v", err)
		}
		_, _ = eng.RegisterPO850(canonicalPO850())
		_, _ = eng.RegisterReceivingAdvice861(canonicalReceipt861())
		return eng
	}

	t.Run("MockLLM_Reject_JSON", func(t *testing.T) {
		t.Setenv("TINYGAAP_LLM_ENDPOINT", "https://llm.local.test/v1/chat/completions")
		t.Setenv("TINYGAAP_LLM_API_KEY", "test-api-key")
		t.Setenv("TINYGAAP_LLM_MODEL", "audit-model-v1")
		llmResponseStatus = http.StatusOK
		llmResponseText = `{"decision":"REJECT","risk_score":92,"reason":"prompt override detected","detected_prompt_injection":true,"detected_remittance_tamper":false}`

		eng := newAuditedEngine(t)
		res, err := eng.EvaluateAndSettle810(context.Background(), validInvoice810("INV-LLM-REJ-1"), "agent-llm", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrAIAuditorRejected) || res.AIAuditVerdict == nil || res.AIAuditVerdict.Mode != "live_llm" {
			t.Fatalf("expected live_llm rejection, got err=%v verdict=%+v", err, res.AIAuditVerdict)
		}
	})

	t.Run("MockLLM_MarkdownFenced_Lowercase_RemittanceTamper_Rejects", func(t *testing.T) {
		t.Setenv("TINYGAAP_LLM_ENDPOINT", "https://llm.local.test/v1/chat/completions")
		t.Setenv("TINYGAAP_LLM_API_KEY", "test-api-key")
		llmResponseStatus = http.StatusOK
		llmResponseText = "```json\n{\"decision\":\"reject\",\"risk_score\":10,\"reason\":\"remittance diversion\",\"detected_prompt_injection\":false,\"detected_remittance_tamper\":true}\n```"

		eng := newAuditedEngine(t)
		res, err := eng.EvaluateAndSettle810(context.Background(), validInvoice810("INV-LLM-FENCE"), "agent-llm", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrAIAuditorRejected) || res.AIAuditVerdict == nil || !res.AIAuditVerdict.DetectedRemittanceTamper {
			t.Fatalf("expected markdown-fenced remittance tamper rejection, got err=%v verdict=%+v", err, res.AIAuditVerdict)
		}
	})

	t.Run("MockLLM_HTTP500_FailsClosed", func(t *testing.T) {
		t.Setenv("TINYGAAP_LLM_ENDPOINT", "https://llm.local.test/v1/chat/completions")
		t.Setenv("TINYGAAP_LLM_API_KEY", "test-api-key")
		llmResponseStatus = http.StatusInternalServerError
		llmResponseText = ""

		eng := newAuditedEngine(t)
		res, err := eng.EvaluateAndSettle810(context.Background(), validInvoice810("INV-LLM-500"), "agent-llm", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrAIAuditorRejected) || res.AIAuditVerdict == nil || res.AIAuditVerdict.Mode != "live_llm_error_fail_closed" {
			t.Fatalf("expected fail-closed rejection on HTTP 500, got err=%v verdict=%+v", err, res.AIAuditVerdict)
		}
	})

	t.Run("MockLLM_NonLoopbackWithoutAPIKey_And_GEMINI_API_KEY_Ignored_FailsClosed", func(t *testing.T) {
		t.Setenv("TINYGAAP_LLM_ENDPOINT", "https://llm.local.test/v1/chat/completions")
		t.Setenv("TINYGAAP_LLM_API_KEY", "")
		t.Setenv("GEMINI_API_KEY", "ambient-gemini-key-must-not-be-used")
		beforeCalls := llmCallCount
		eng := newAuditedEngine(t)
		res, err := eng.EvaluateAndSettle810(context.Background(), validInvoice810("INV-LLM-NOKEY"), "agent-llm", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrAIAuditorRejected) || res.AIAuditVerdict == nil || res.AIAuditVerdict.Mode != "live_llm_error_fail_closed" {
			t.Fatalf("expected fail-closed rejection when TINYGAAP_LLM_API_KEY is missing, got err=%v verdict=%+v", err, res.AIAuditVerdict)
		}
		if llmCallCount != beforeCalls {
			t.Fatalf("expected zero HTTP calls when TINYGAAP_LLM_API_KEY is missing, got %d", llmCallCount-beforeCalls)
		}
	})

	t.Run("LoopbackSpoofHost_127_0_0_1_EvilDomain_RequiresAPIKey_FailsClosed", func(t *testing.T) {
		for _, spoofURL := range []string{
			"http://127.0.0.1.attacker.example/v1/chat/completions",
			"http://localhost.attacker.example/v1/chat/completions",
			"https://[::1].attacker.example/v1/chat/completions",
		} {
			t.Setenv("TINYGAAP_LLM_ENDPOINT", spoofURL)
			t.Setenv("TINYGAAP_LLM_API_KEY", "")
			beforeCalls := llmCallCount
			eng := newAuditedEngine(t)
			res, err := eng.EvaluateAndSettle810(context.Background(), validInvoice810("INV-SPOOF-HOST"), "agent-llm", "paypal:treasury@acme-metal.example")
			if !errors.Is(err, tinygaap.ErrAIAuditorRejected) || res.AIAuditVerdict == nil || res.AIAuditVerdict.Mode != "live_llm_error_fail_closed" {
				t.Fatalf("spoofURL %q: expected fail-closed rejection, got err=%v verdict=%+v", spoofURL, err, res.AIAuditVerdict)
			}
			if llmCallCount != beforeCalls {
				t.Fatalf("spoofURL %q: expected zero HTTP calls without API key", spoofURL)
			}
		}
	})

	t.Run("MockLLM_Approve_CannotOverrideDeterministicRules", func(t *testing.T) {
		t.Setenv("TINYGAAP_LLM_ENDPOINT", "https://llm.local.test/v1/chat/completions")
		t.Setenv("TINYGAAP_LLM_API_KEY", "test-api-key")
		llmResponseStatus = http.StatusOK
		llmResponseText = `{"decision":"APPROVE","risk_score":0,"reason":"clean","detected_prompt_injection":false,"detected_remittance_tamper":false}`

		eng := newAuditedEngine(t)
		rawWith3P := strings.Replace(validInvoice810("INV-LLM-3P"), "N1*SE*", "NTE*3P*Harmless note~\nN1*SE*", 1)
		rawWith3P = strings.Replace(rawWith3P, "SE*9*0042~", "SE*10*0042~", 1)
		if _, err := eng.EvaluateAndSettle810(context.Background(), rawWith3P, "agent-llm", "paypal:treasury@acme-metal.example"); !errors.Is(err, tinygaap.ErrUnapprovedBeneficiary) {
			t.Fatalf("expected deterministic NTE*3P rule to reject with ErrUnapprovedBeneficiary even when LLM returns APPROVE")
		}
	})

	t.Run("Heuristic_BenignSameDomainVendorNote_Approved_And_HonestModelID", func(t *testing.T) {
		clearLLMEnv(t)
		t.Setenv("TINYGAAP_LLM_MODEL", "fake-uncalled-model-name")
		eng := newAuditedEngine(t)
		benign := strings.Replace(validInvoice810("INV-BENIGN-NOTE"), "N1*SE*", "NTE*GEN*Manual override switch included; questions: billing@acme-metal.example~\nN1*SE*", 1)
		benign = strings.Replace(benign, "SE*9*0042~", "SE*10*0042~", 1)
		res, err := eng.EvaluateAndSettle810(context.Background(), benign, "agent-benign", "paypal:treasury@acme-metal.example")
		if err != nil || !res.SettlementAuthorized {
			t.Fatalf("expected benign vendor note to be approved, got err=%v", err)
		}
		if res.AIAuditVerdict == nil || res.AIAuditVerdict.ModelID != "deterministic-rule-only" {
			t.Fatalf("expected ModelID=deterministic-rule-only when no LLM endpoint is configured, got %+v", res.AIAuditVerdict)
		}
	})
}

func TestTinyGAAP_PayPalMockServer_E2E_Capture_And_ErrorPaths(t *testing.T) {
	clearLLMEnv(t)
	po, err := tinygaap.ParseEDI850(canonicalPO850())
	if err != nil {
		t.Fatalf("ParseEDI850: %v", err)
	}

	var getStatusOverride int
	var getOrderIDOverride string
	var getOrderStatusOverride string
	var getCustomIDOverride string
	var getInvoiceIDOverride string
	var getCurrencyOverride string
	var getAmountOverride string
	var getEmptyPurchaseUnits bool
	var forceNegativeControl200 bool

	var capOrderIDOverride string
	var capOrderStatusOverride string
	var capItemStatusOverride string
	var capItemIDOverride string
	var capCurrencyOverride string
	var capAmountOverride string
	var lastCreateReqID string
	var lastCaptureReqID string

	resetMockOverrides := func() {
		getStatusOverride = http.StatusOK
		getOrderIDOverride = ""
		getOrderStatusOverride = "APPROVED"
		getCustomIDOverride = ""
		getInvoiceIDOverride = ""
		getCurrencyOverride = "USD"
		getAmountOverride = "125.00"
		getEmptyPurchaseUnits = false
		forceNegativeControl200 = false

		capOrderIDOverride = ""
		capOrderStatusOverride = "COMPLETED"
		capItemStatusOverride = "COMPLETED"
		capItemIDOverride = "CAP-REAL-778899"
		capCurrencyOverride = "USD"
		capAmountOverride = "125.00"
	}
	resetMockOverrides()

	mockClient := newInMemoryHTTPClient(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Paypal-Debug-Id", "mock-debug-12345")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/oauth2/token":
			user, pass, _ := r.BasicAuth()
			if user != "valid-client" || pass != "valid-secret" {
				if forceNegativeControl200 {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"access_token":"bad"}`))
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"mock-bearer-tok","app_id":"APP-MOCK-01","expires_in":32400}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v2/checkout/orders":
			lastCreateReqID = r.Header.Get("PayPal-Request-Id")
			if lastCreateReqID == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"ORD-MOCK-9001","status":"CREATED","create_time":"2026-11-08T18:00:00Z"}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/checkout/orders/"):
			if getStatusOverride != http.StatusOK {
				w.WriteHeader(getStatusOverride)
				_, _ = w.Write([]byte(`{"error":"order_lookup_failed"}`))
				return
			}
			ordID := strings.TrimPrefix(r.URL.Path, "/v2/checkout/orders/")
			if getOrderIDOverride != "" {
				ordID = getOrderIDOverride
			}
			customID := po.SHA256Hex
			if getCustomIDOverride != "" {
				customID = getCustomIDOverride
			}
			invID := "INV-PP-E2E-01"
			if getInvoiceIDOverride != "" {
				invID = getInvoiceIDOverride
			}
			var units []map[string]any
			if !getEmptyPurchaseUnits {
				units = []map[string]any{
					{
						"reference_id": po.PONumber,
						"custom_id":    customID,
						"invoice_id":   invID,
						"amount": map[string]string{
							"currency_code": getCurrencyOverride,
							"value":         getAmountOverride,
						},
					},
				}
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":             ordID,
				"status":         getOrderStatusOverride,
				"create_time":    "2026-11-08T18:00:00Z",
				"purchase_units": units,
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/capture"):
			lastCaptureReqID = r.Header.Get("PayPal-Request-Id")
			trimmed := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v2/checkout/orders/"), "/capture")
			ordID := trimmed
			if capOrderIDOverride != "" {
				ordID = capOrderIDOverride
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":     ordID,
				"status": capOrderStatusOverride,
				"purchase_units": []map[string]any{
					{
						"payments": map[string]any{
							"captures": []map[string]any{
								{
									"id":     capItemIDOverride,
									"status": capItemStatusOverride,
									"amount": map[string]string{
										"currency_code": capCurrencyOverride,
										"value":         capAmountOverride,
									},
								},
							},
						},
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	newPayPalEngine := func(t *testing.T) *tinygaap.TinyGAAPEngine {
		t.Helper()
		eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:                []byte("tinygaap-mock-paypal-hmac-secret-key"),
			RollingHourlyLimitCents:   500000,
			WhitelistedPayTo:          map[string]bool{"paypal:treasury@acme-metal.example": true},
			VerifyPayPalOrderOnSettle: true,
			PayPalClientID:            "valid-client",
			PayPalClientSecret:        "valid-secret",
			PayPalBaseURL:             "https://api-m.sandbox.paypal.com",
			HTTPClient:                mockClient,
		})
		if err != nil {
			t.Fatalf("NewTinyGAAPEngine: %v", err)
		}
		return eng
	}

	eng := newPayPalEngine(t)
	proof, err := eng.VerifyLivePayPalSandboxE2E(context.Background(), canonicalPO850(), canonicalReceipt861(), validInvoice810("INV-PP-E2E-01"))
	if err != nil {
		t.Fatalf("VerifyLivePayPalSandboxE2E failed: %v", err)
	}
	if proof.NegativeControlBadCredsHTTP != http.StatusUnauthorized || proof.VerifiedCustomIDEDI850SHA256 != po.SHA256Hex {
		t.Fatalf("unexpected proof: %+v", proof)
	}

	// Verify ServeSettle810?capture=true end-to-end production path on a fresh engine.
	engHTTP := newPayPalEngine(t)
	_, _ = engHTTP.RegisterPO850(canonicalPO850())
	_, _ = engHTTP.RegisterReceivingAdvice861(canonicalReceipt861())
	raw810 := strings.Replace(validInvoice810("INV-PP-E2E-01"),
		"CAD*****PAYPAL*paypal:treasury@acme-metal.example~",
		"REF*PP*ORD-MOCK-9001~\nCAD*****PAYPAL*paypal:treasury@acme-metal.example~", 1)
	raw810 = strings.Replace(raw810, "SE*9*0042~", "SE*10*0042~", 1)
	req := httptest.NewRequest(http.MethodPost, "/v1/edi/810/settle?capture=true", bytes.NewBufferString(raw810))
	req.Header.Set("Payment-Signature", engHTTP.SignX402Header(raw810))
	req.Header.Set("X-Agent-Key", "buyer-agent-pp")
	req.Header.Set("X-PayTo-Beneficiary", "paypal:treasury@acme-metal.example")
	rec := httptest.NewRecorder()
	engHTTP.ServeSettle810(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ServeSettle810?capture=true status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var capRes tinygaap.SettlementEvaluationResult
	if err := json.NewDecoder(rec.Body).Decode(&capRes); err != nil {
		t.Fatalf("decode capture result: %v", err)
	}
	if !capRes.PayPalCaptured || capRes.PayPalCaptureID != "CAP-REAL-778899" || capRes.RawEDI820 == "" {
		t.Fatalf("expected PayPalCaptured=true and RawEDI820 populated, got %+v", capRes)
	}
	if lastCreateReqID == lastCaptureReqID || !strings.HasPrefix(lastCaptureReqID, "cap-") {
		t.Fatalf("expected distinct capture PayPal-Request-Id with cap- prefix, got create=%q capture=%q", lastCreateReqID, lastCaptureReqID)
	}
	assertX12EnvelopeValid(t, capRes.RawEDI820)
	if !strings.Contains(capRes.RawEDI820, "GS*RA*TINYGAAP*SUPPLIER01*") ||
		!strings.Contains(capRes.RawEDI820, "BPR*I*125.00*C*PAYPAL*CTX*") ||
		!strings.Contains(capRes.RawEDI820, "N1*PE*ACME CLOUD METAL INC*92*paypal:treasury@acme-metal.example~") ||
		!strings.Contains(capRes.RawEDI820, "REF*R8*RCV-861-9001*SHA256:") ||
		!strings.Contains(capRes.RawEDI820, "REF*AR*") ||
		!strings.Contains(capRes.RawEDI820, "RMR*IV*INV-PP-E2E-01**125.00*125.00~") ||
		!strings.Contains(capRes.RawEDI820, "REF*PO*PO-850-9001*SHA256:"+po.SHA256Hex+"~") ||
		!strings.Contains(capRes.RawEDI820, "TRN*1*CAP-REAL-778899*1999999999*ED25519:"+capRes.EDI820SignatureHex+"~") {
		t.Fatalf("RawEDI820 missing expected GS/BPR/N1*PE/REF/RMR/TRN segments:\n%s", capRes.RawEDI820)
	}
	if !tinygaap.VerifyReceiptSignature(capRes.Ed25519PubKeyHex, capRes.ReceiptHeader, capRes.Ed25519SignatureHex) {
		t.Fatalf("VerifyReceiptSignature failed on post-capture ReceiptHeader")
	}
	if !tinygaap.VerifyEDI820Signature(capRes.Ed25519PubKeyHex, capRes.RawEDI820) {
		t.Fatalf("VerifyEDI820Signature failed on full canonical RawEDI820")
	}
	if !tinygaap.VerifyReceiptSignature(capRes.Ed25519PubKeyHex, capRes.RawEDI820, capRes.EDI820SignatureHex) {
		t.Fatalf("VerifyReceiptSignature failed on RawEDI820 + EDI820SignatureHex")
	}
	// Kill R1: tampering with N1*PE payee or CUR currency inside RawEDI820 invalidates Ed25519 signature.
	tamperedPayee820 := strings.Replace(capRes.RawEDI820, "N1*PE*ACME CLOUD METAL INC*92*paypal:treasury@acme-metal.example~", "N1*PE*ROGUE SHELL LLC*92*paypal:rogue@offshore.example~", 1)
	if tinygaap.VerifyEDI820Signature(capRes.Ed25519PubKeyHex, tamperedPayee820) {
		t.Fatalf("VerifyEDI820Signature succeeded after N1*PE payee tampering")
	}
	tamperedCur820 := strings.Replace(capRes.RawEDI820, "CUR*BY*USD~", "CUR*BY*MXN~", 1)
	if tinygaap.VerifyEDI820Signature(capRes.Ed25519PubKeyHex, tamperedCur820) {
		t.Fatalf("VerifyEDI820Signature succeeded after CUR currency tampering")
	}
	// Single-TRN canonicalization guard: injecting a second ED25519: token anywhere in the 820 must be rejected.
	doubleToken820 := strings.Replace(capRes.RawEDI820, "ENT*1~", "REF*ZZ*ED25519:"+capRes.EDI820SignatureHex+"~\nENT*1~", 1)
	if tinygaap.CanonicalEDI820ForSigning(doubleToken820) != "" || tinygaap.VerifyEDI820Signature(capRes.Ed25519PubKeyHex, doubleToken820) {
		t.Fatalf("expected double ED25519: token in 820 to fail CanonicalEDI820ForSigning and VerifyEDI820Signature")
	}

	// Double capture on the same invoice must fail with ErrDuplicateInvoiceReplay.
	inv, _, _, _ := tinygaap.ParseEDI810(raw810)
	if err := engHTTP.CaptureApprovedPayPalOrder(context.Background(), &capRes, po, inv, "ORD-MOCK-9001"); !errors.Is(err, tinygaap.ErrDuplicateInvoiceReplay) {
		t.Fatalf("expected ErrDuplicateInvoiceReplay on second capture of same invoice, got %v", err)
	}

	// Hand-crafted SettlementEvaluationResult without engine evaluation grant must be rejected.
	forgedEval := &tinygaap.SettlementEvaluationResult{
		SettlementAuthorized: true,
		ReceiptHashHex:       "deadbeef",
		ReceiptHeader:        "tinygaap:v=3;forged=1",
	}
	ungrantedInv, _, _, _ := tinygaap.ParseEDI810(validInvoice810("INV-UNGRANTED-99"))
	if err := engHTTP.CaptureApprovedPayPalOrder(context.Background(), forgedEval, po, ungrantedInv, "ORD-MOCK-9001"); !errors.Is(err, tinygaap.ErrPayPalCaptureNotCompleted) {
		t.Fatalf("expected ErrPayPalCaptureNotCompleted on ungranted invoice capture, got %v", err)
	}

	// Grant for INV-A cannot be used to capture INV-B.
	engCross := newPayPalEngine(t)
	_, _ = engCross.RegisterPO850(canonicalPO850())
	_, _ = engCross.RegisterReceivingAdvice861(canonicalReceipt861())
	getInvoiceIDOverride = "INV-GRANT-A"
	resA, err := engCross.EvaluateAndSettle810(context.Background(), validInvoice810("INV-GRANT-A"), "agent-a", "paypal:treasury@acme-metal.example")
	if err != nil {
		t.Fatalf("EvaluateAndSettle810 INV-GRANT-A: %v", err)
	}
	invB, _, _, _ := tinygaap.ParseEDI810(validInvoice810("INV-GRANT-B"))
	if err := engCross.CaptureApprovedPayPalOrder(context.Background(), resA, po, invB, "ORD-MOCK-9001"); !errors.Is(err, tinygaap.ErrPayPalCaptureNotCompleted) {
		t.Fatalf("expected cross-invoice capture using INV-GRANT-A's resA for INV-GRANT-B to fail, got %v", err)
	}
	resetMockOverrides()

	// Capture negative controls (PENDING capture, mismatched order ID, mismatched amount, empty capture ID).
	captureFailureCases := []func(){
		func() { capItemStatusOverride = "PENDING" },
		func() { capOrderStatusOverride = "APPROVED" },
		func() { capOrderIDOverride = "ORD-WRONG-ID" },
		func() { capCurrencyOverride = "EUR" },
		func() { capAmountOverride = "125.01" },
		func() { capItemIDOverride = "" },
	}
	for i, mutate := range captureFailureCases {
		resetMockOverrides()
		getInvoiceIDOverride = "INV-CAP-NEG"
		engNeg := newPayPalEngine(t)
		_, _ = engNeg.RegisterPO850(canonicalPO850())
		_, _ = engNeg.RegisterReceivingAdvice861(canonicalReceipt861())
		evalNeg, err := engNeg.EvaluateAndSettle810(context.Background(), validInvoice810("INV-CAP-NEG"), "agent-neg", "paypal:treasury@acme-metal.example")
		if err != nil {
			t.Fatalf("case %d EvaluateAndSettle810: %v", i, err)
		}
		invNeg, _, _, _ := tinygaap.ParseEDI810(validInvoice810("INV-CAP-NEG"))
		mutate()
		if err := engNeg.CaptureApprovedPayPalOrder(context.Background(), evalNeg, po, invNeg, "ORD-MOCK-9001"); !errors.Is(err, tinygaap.ErrPayPalCaptureNotCompleted) {
			t.Fatalf("capture negative case %d: expected ErrPayPalCaptureNotCompleted, got %v", i, err)
		}
	}

	// GET readback negative controls on VerifyLivePayPalSandboxE2E.
	getReadbackFailureCases := []func(){
		func() { getStatusOverride = http.StatusNotFound },
		func() { getStatusOverride = http.StatusInternalServerError },
		func() { getOrderIDOverride = "ORD-DIFFERENT" },
		func() { getEmptyPurchaseUnits = true },
		func() { getOrderStatusOverride = "VOIDED" },
		func() { getCustomIDOverride = "00000000000000000000000000000000000000000000000000000000deadbeef" },
		func() { getInvoiceIDOverride = "INV-WRONG-ID" },
		func() { getCurrencyOverride = "EUR" },
		func() { getAmountOverride = "125.01" },
		func() { forceNegativeControl200 = true },
	}
	for i, mutate := range getReadbackFailureCases {
		resetMockOverrides()
		mutate()
		engReadback := newPayPalEngine(t)
		if _, err := engReadback.VerifyLivePayPalSandboxE2E(context.Background(), canonicalPO850(), canonicalReceipt861(), validInvoice810("INV-PP-E2E-01")); err == nil {
			t.Fatalf("GET readback negative case %d: expected failure, got nil", i)
		}
	}
}

func TestTinyGAAP_CrossFamilyAdversarialCorpus_12Vectors(t *testing.T) {
	clearLLMEnv(t)
	rawCorpus, err := os.ReadFile("adversarial_corpus.json")
	if err != nil {
		t.Fatalf("ReadFile adversarial_corpus.json: %v", err)
	}
	var corpus struct {
		BaselinePO850      string `json:"baseline_po_850"`
		BaselineReceipt861 string `json:"baseline_receipt_861"`
		Vectors            []struct {
			ID                     string `json:"id"`
			Title                  string `json:"title"`
			OverrideReceipt861     string `json:"override_receipt_861"`
			EDI810                 string `json:"edi_810"`
			PaymentSignature       string `json:"payment_signature"`
			RequestedPayTo         string `json:"requested_pay_to"`
			MockPayPalCustomID     string `json:"mock_paypal_custom_id"`
			ExpectedHTTPStatus     int    `json:"expected_http_status"`
			Expected997Ack         string `json:"expected_997_ack"`
			Expected997ErrorSeg    string `json:"expected_997_error_seg"`
			ExpectedPayPalCaptured bool   `json:"expected_paypal_captured"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(rawCorpus, &corpus); err != nil {
		t.Fatalf("Unmarshal adversarial_corpus.json: %v", err)
	}
	if len(corpus.Vectors) != 12 {
		t.Fatalf("expected 12 adversarial vectors, got %d", len(corpus.Vectors))
	}

	mockClient := newInMemoryHTTPClient(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/oauth2/token" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"tok","app_id":"APP-1","expires_in":3600}`))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v2/checkout/orders/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"ORD-TAMPERED-CUSTOM-ID","status":"CREATED","purchase_units":[{"reference_id":"PO-850-1001","custom_id":"00000000000000000000000000000000000000000000000000000000deadbeef","invoice_id":"INV-ADV-12","amount":{"currency_code":"USD","value":"1200.00"}}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	for _, vec := range corpus.Vectors {
		t.Run(vec.ID+"_"+vec.Title, func(t *testing.T) {
			eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
				HMACSecret:                []byte("tinygaap-adversarial-corpus-hmac-secret"),
				RollingHourlyLimitCents:   500000,
				Require861Receipt:         true,
				VerifyPayPalOrderOnSettle: true,
				PayPalClientID:            "mock-id",
				PayPalClientSecret:        "mock-secret",
				PayPalBaseURL:             "https://api-m.sandbox.paypal.com",
				HTTPClient:                mockClient,
				WhitelistedPayTo: map[string]bool{
					"paypal:treasury@acme-metal.example": true,
				},
			})
			if err != nil {
				t.Fatalf("NewTinyGAAPEngine: %v", err)
			}
			if _, err := eng.RegisterPO850(corpus.BaselinePO850); err != nil {
				t.Fatalf("RegisterPO850: %v", err)
			}
			rcptRaw := corpus.BaselineReceipt861
			if vec.OverrideReceipt861 != "" {
				rcptRaw = vec.OverrideReceipt861
			}
			if _, err := eng.RegisterReceivingAdvice861(rcptRaw); err != nil {
				t.Fatalf("RegisterReceivingAdvice861: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/v1/edi/810/settle", bytes.NewBufferString(vec.EDI810))
			switch vec.PaymentSignature {
			case "SIGNED":
				req.Header.Set("Payment-Signature", eng.SignX402Header(vec.EDI810))
			case "":
				// leave empty
			default:
				req.Header.Set("Payment-Signature", vec.PaymentSignature)
			}
			req.Header.Set("X-Agent-Key", "adversarial-runner-"+vec.ID)
			req.Header.Set("X-PayTo-Beneficiary", vec.RequestedPayTo)

			rec := httptest.NewRecorder()
			eng.ServeSettle810(rec, req)
			resp := rec.Result()
			defer resp.Body.Close()

			if resp.StatusCode != vec.ExpectedHTTPStatus {
				t.Fatalf("[%s] HTTP status = %d, want %d", vec.ID, resp.StatusCode, vec.ExpectedHTTPStatus)
			}

			if vec.ExpectedHTTPStatus == http.StatusPaymentRequired {
				if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "x402") {
					t.Fatalf("[%s] missing WWW-Authenticate x402 header on 402 response", vec.ID)
				}
				return
			}

			var errEnvelope struct {
				Error  string                              `json:"error"`
				Result tinygaap.SettlementEvaluationResult `json:"result"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&errEnvelope); err != nil {
				t.Fatalf("[%s] decode response: %v", vec.ID, err)
			}
			if errEnvelope.Result.EDI997AckCode != vec.Expected997Ack {
				t.Fatalf("[%s] 997 Ack = %q, want %q", vec.ID, errEnvelope.Result.EDI997AckCode, vec.Expected997Ack)
			}
			if vec.Expected997ErrorSeg != "" && errEnvelope.Result.ErrorSegmentID != vec.Expected997ErrorSeg {
				t.Fatalf("[%s] ErrorSegmentID = %q, want %q", vec.ID, errEnvelope.Result.ErrorSegmentID, vec.Expected997ErrorSeg)
			}
			if errEnvelope.Result.PayPalCaptured != vec.ExpectedPayPalCaptured {
				t.Fatalf("[%s] PayPalCaptured = %v, want %v", vec.ID, errEnvelope.Result.PayPalCaptured, vec.ExpectedPayPalCaptured)
			}
			assertX12EnvelopeValid(t, errEnvelope.Result.RawEDI997)
			if !strings.Contains(errEnvelope.Result.RawEDI997, "AK5*R~") || !strings.Contains(errEnvelope.Result.RawEDI997, "AK9*R*1*1*0~") {
				t.Fatalf("[%s] RawEDI997 missing AK5*R~ or AK9*R*1*1*0~:\n%s", vec.ID, errEnvelope.Result.RawEDI997)
			}
		})
	}
}

func TestTinyGAAP_LiveProofArtifact_SchemaAndSignature(t *testing.T) {
	rawProof, err := os.ReadFile("paypal_sandbox_live_proof.json")
	if err != nil {
		t.Fatalf("ReadFile paypal_sandbox_live_proof.json: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(rawProof))
	dec.DisallowUnknownFields()
	var proof tinygaap.PayPalLiveSandboxProof
	if err := dec.Decode(&proof); err != nil {
		t.Fatalf("Decode paypal_sandbox_live_proof.json with DisallowUnknownFields failed: %v", err)
	}
	if proof.ProtocolVersion != "tinygaap/0.3.0" {
		t.Fatalf("ProtocolVersion = %q, want tinygaap/0.3.0", proof.ProtocolVersion)
	}
	if proof.NegativeControlBadCredsHTTP != http.StatusUnauthorized || proof.OAuth2TokenHTTPCode != http.StatusOK || proof.GetOrderHTTPCode != http.StatusOK {
		t.Fatalf("unexpected HTTP codes in live proof: %+v", proof)
	}
	if !proof.PayPalCaptured && proof.CreateOrderHTTPCode != http.StatusCreated {
		t.Fatalf("expected CreateOrderHTTPCode=201 when PayPalCaptured=false, got %d", proof.CreateOrderHTTPCode)
	}
	if proof.CaptureOrderHTTPCode != 0 && proof.CaptureOrderHTTPCode != http.StatusOK && proof.CaptureOrderHTTPCode != http.StatusCreated {
		t.Fatalf("unexpected CaptureOrderHTTPCode=%d in live proof", proof.CaptureOrderHTTPCode)
	}
	if proof.AIAuditVerdict == nil || proof.AIAuditVerdict.Decision != "APPROVE" || (proof.AIAuditVerdict.Mode != "live_llm" && proof.AIAuditVerdict.Mode != "deterministic_rule_guard") {
		t.Fatalf("expected APPROVE verdict in proof, got %+v", proof.AIAuditVerdict)
	}
	if len(proof.VerifiedCustomIDEDI850SHA256) != 64 {
		t.Fatalf("VerifiedCustomIDEDI850SHA256 length = %d, want 64", len(proof.VerifiedCustomIDEDI850SHA256))
	}
	if !tinygaap.VerifyReceiptSignature(proof.Ed25519PubKeyHex, proof.ReceiptHeader, proof.Ed25519SignatureHex) {
		t.Fatalf("VerifyReceiptSignature failed on paypal_sandbox_live_proof.json")
	}
	if proof.KeyID != "" && proof.KeyID != tinygaap.EphemeralKeyID {
		if err := tinygaap.VerifyReceiptWithRegistry("keys", proof.ReceiptHeader, proof.Ed25519SignatureHex); err != nil {
			t.Fatalf("VerifyReceiptWithRegistry failed on paypal_sandbox_live_proof.json (kid=%s): %v", proof.KeyID, err)
		}
	}
	if proof.PayPalCaptured {
		if proof.LivePayPalOrderStatus != "COMPLETED" || proof.LivePayPalCaptureID == "" || proof.EDI820Remittance == "" {
			t.Fatalf("expected COMPLETED status, capture ID, and EDI820Remittance when PayPalCaptured=true, got %+v", proof)
		}
		if !tinygaap.VerifyEDI820Signature(proof.Ed25519PubKeyHex, proof.EDI820Remittance) {
			t.Fatalf("VerifyEDI820Signature failed on live proof EDI820Remittance")
		}
		if proof.KeyID != "" && proof.KeyID != tinygaap.EphemeralKeyID {
			if err := tinygaap.VerifyEDI820WithRegistry("keys", proof.EDI820Remittance); err != nil {
				t.Fatalf("VerifyEDI820WithRegistry failed on live proof EDI820Remittance: %v", err)
			}
		}
	} else {
		if proof.LivePayPalOrderStatus != "CREATED" || proof.EDI820Remittance != "" {
			t.Fatalf("expected CREATED status and empty EDI820Remittance when PayPalCaptured=false, got %+v", proof)
		}
	}
}

type staticAuditor struct {
	verdict *tinygaap.AIAuditVerdict
}

func (s staticAuditor) AuditInvoiceSemantics(_ context.Context, _ *tinygaap.EDI850PO, _ *tinygaap.EDI861Receipt, _ *tinygaap.EDI810Invoice) (*tinygaap.AIAuditVerdict, error) {
	return s.verdict, nil
}

func TestTinyGAAP_ExtendedMutantGaps_And_SecurityFixes(t *testing.T) {
	clearLLMEnv(t)

	t.Run("Kill_B1_B2_ExactHourlySpendLimitBoundary_AgentAndGlobal", func(t *testing.T) {
		// Exact limit == 12500 cents ($125.00): must succeed (spent + total == limit is allowed).
		engExact, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              []byte("tinygaap-boundary-b1-b2-secret-32b"),
			RollingHourlyLimitCents: 12500,
			WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
		})
		if err != nil {
			t.Fatalf("NewTinyGAAPEngine: %v", err)
		}
		_, _ = engExact.RegisterPO850(canonicalPO850())
		_, _ = engExact.RegisterReceivingAdvice861(canonicalReceipt861())
		if _, err := engExact.EvaluateAndSettle810(context.Background(), validInvoice810("INV-B1-EXACT"), "agent-b1", "paypal:treasury@acme-metal.example"); err != nil {
			t.Fatalf("expected exact boundary (12500 == 12500) to succeed, got %v", err)
		}

		// 1 cent over limit (1 + 12500 > 12500): must trip ErrBudgetBreakerTripped.
		engOver, _ := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              []byte("tinygaap-boundary-b1-b2-secret-32b"),
			RollingHourlyLimitCents: 12500,
			WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
		})
		_, _ = engOver.RegisterPO850(canonicalPO850())
		_, _ = engOver.RegisterReceivingAdvice861(canonicalReceipt861())
		engOver.SeedAgentSpendCents("agent-b2", 1)
		if _, err := engOver.EvaluateAndSettle810(context.Background(), validInvoice810("INV-B2-OVER"), "agent-b2", "paypal:treasury@acme-metal.example"); !errors.Is(err, tinygaap.ErrBudgetBreakerTripped) {
			t.Fatalf("expected 1 cent over limit to fail with ErrBudgetBreakerTripped, got %v", err)
		}

		// Global exact boundary across distinct agents: 2500 seeded + 12500 invoice == 15000 limit -> must succeed!
		engGlobalExact, _ := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              []byte("tinygaap-boundary-global-secret-32b"),
			RollingHourlyLimitCents: 15000,
			WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
		})
		_, _ = engGlobalExact.RegisterPO850(canonicalPO850())
		_, _ = engGlobalExact.RegisterReceivingAdvice861(canonicalReceipt861())
		engGlobalExact.SeedAgentSpendCents("other-agent", 2500)
		if _, err := engGlobalExact.EvaluateAndSettle810(context.Background(), validInvoice810("INV-B2-GLOBAL-EXACT"), "fresh-agent", "paypal:treasury@acme-metal.example"); err != nil {
			t.Fatalf("expected exact global boundary (2500+12500 == 15000) to succeed, got %v", err)
		}
	})

	t.Run("Kill_R2_GrantReceiptHeaderMismatch_RejectedOnCapture", func(t *testing.T) {
		mockPP := newInMemoryHTTPClient(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/oauth2/token" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token":"tok","app_id":"APP","expires_in":3600}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"ORD-R2","status":"COMPLETED","purchase_units":[{"payments":{"captures":[{"id":"CAP-R2","status":"COMPLETED","amount":{"currency_code":"USD","value":"125.00"}}]}}]} `))
		})
		eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              []byte("tinygaap-r2-grant-header-secret-32b"),
			RollingHourlyLimitCents: 50000,
			WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
			PayPalClientID:          "cid",
			PayPalClientSecret:      "csec",
			PayPalBaseURL:           "https://api-m.sandbox.paypal.com",
			HTTPClient:              mockPP,
		})
		if err != nil {
			t.Fatalf("NewTinyGAAPEngine: %v", err)
		}
		po, _ := eng.RegisterPO850(canonicalPO850())
		_, _ = eng.RegisterReceivingAdvice861(canonicalReceipt861())
		raw := validInvoice810("INV-R2-01")
		evalRes, err := eng.EvaluateAndSettle810(context.Background(), raw, "agent-r2", "paypal:treasury@acme-metal.example")
		if err != nil {
			t.Fatalf("EvaluateAndSettle810: %v", err)
		}
		// Keep ReceiptHashHex intact, mutate ReceiptHeader -> kills mutant R2!
		evalRes.ReceiptHeader += ";tampered=1"
		inv, _, _, _ := tinygaap.ParseEDI810(raw)
		if err := eng.CaptureApprovedPayPalOrder(context.Background(), evalRes, po, inv, "ORD-R2"); !errors.Is(err, tinygaap.ErrPayPalCaptureNotCompleted) {
			t.Fatalf("expected ErrPayPalCaptureNotCompleted when ReceiptHeader differs from grant, got %v", err)
		}
	})

	t.Run("Kill_R6_And_N4_DuplicateBIG02AcrossSecondPOBlocked_SellerNamespaceIsolated_And_N9_OrderReuseBlocked", func(t *testing.T) {
		eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              []byte("tinygaap-r6-n4-n9-secret-key-32bytes"),
			RollingHourlyLimitCents: 500000,
			WhitelistedPayTo: map[string]bool{
				"paypal:treasury@acme-metal.example":  true,
				"paypal:billing@beta-silicon.example": true,
			},
		})
		if err != nil {
			t.Fatalf("NewTinyGAAPEngine: %v", err)
		}
		_, _ = eng.RegisterPO850(canonicalPO850())
		_, _ = eng.RegisterReceivingAdvice861(canonicalReceipt861())

		// Register a second unbilled PO + 861 for Seller A so billedLines[PO-850-9001B] is 0 (isolating R6 from billedLines!).
		poSellerA2 := strings.ReplaceAll(canonicalPO850(), "PO-850-9001", "PO-850-9001B")
		rcptSellerA2 := strings.ReplaceAll(canonicalReceipt861(), "PO-850-9001", "PO-850-9001B")
		rcptSellerA2 = strings.ReplaceAll(rcptSellerA2, "RCV-861-9001", "RCV-861-9001B")
		if _, err := eng.RegisterPO850(poSellerA2); err != nil {
			t.Fatalf("RegisterPO850 PO-850-9001B: %v", err)
		}
		if _, err := eng.RegisterReceivingAdvice861(rcptSellerA2); err != nil {
			t.Fatalf("RegisterReceivingAdvice861 RCV-861-9001B: %v", err)
		}

		invoiceForPO := func(invNum, poNum, ppOrd string) string {
			raw := strings.ReplaceAll(validInvoice810(invNum), "PO-850-9001", poNum)
			if ppOrd != "" {
				raw = strings.Replace(raw,
					"CAD*****PAYPAL*paypal:treasury@acme-metal.example~",
					"REF*PP*"+ppOrd+"~\nCAD*****PAYPAL*paypal:treasury@acme-metal.example~", 1)
				raw = strings.Replace(raw, "SE*9*0042~", "SE*10*0042~", 1)
			}
			return raw
		}

		// First invoice INV-SHARED-100 on PO-850-9001 with ORD-UNIQ-1 succeeds.
		if _, err := eng.EvaluateAndSettle810(context.Background(), invoiceForPO("INV-SHARED-100", "PO-850-9001", "ORD-UNIQ-1"), "agent-a", "paypal:treasury@acme-metal.example"); err != nil {
			t.Fatalf("first invoice INV-SHARED-100 failed: %v", err)
		}

		// Replay of same BIG02 (INV-SHARED-100) by Seller A on fresh unbilled PO-850-9001B MUST fail on BIG (kills R6!).
		resReplay, err := eng.EvaluateAndSettle810(context.Background(), invoiceForPO("INV-SHARED-100", "PO-850-9001B", "ORD-UNIQ-2"), "agent-a", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrDuplicateInvoiceReplay) || resReplay.ErrorSegmentID != "BIG" {
			t.Fatalf("expected ErrDuplicateInvoiceReplay on BIG for Seller A BIG02 replay across fresh PO, got err=%v seg=%q", err, resReplay.ErrorSegmentID)
		}

		// N9: Distinct invoice BIG02 (INV-SHARED-101) on fresh PO-850-9001B reusing ORD-UNIQ-1 MUST fail on REF!
		resOrdReuse, err := eng.EvaluateAndSettle810(context.Background(), invoiceForPO("INV-SHARED-101", "PO-850-9001B", "ORD-UNIQ-1"), "agent-a", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrDuplicateInvoiceReplay) || resOrdReuse.ErrorSegmentID != "REF" {
			t.Fatalf("expected ErrDuplicateInvoiceReplay on REF for reused PayPal order ID, got err=%v seg=%q", err, resOrdReuse.ErrorSegmentID)
		}

		// N4: Distinct Seller B submitting its own PO-850-9002 invoice with the SAME BIG02 ("INV-SHARED-100") MUST succeed!
		poSellerB := strings.Join([]string{
			"ISA*00*          *00*          *ZZ*BUYER01        *ZZ*SUPPLIER02     *261108*0900*^*00501*000001002*0*T*:~",
			"GS*PO*BUYER01*SUPPLIER02*20261108*090000*1002*X*005010~",
			"ST*850*0001~",
			"BEG*00*SA*PO-850-9002**20261108~",
			"N1*BY*ACME BUYER CORP*92*BUYER-01~",
			"N1*SE*BETA SILICON CORP*92*paypal:billing@beta-silicon.example~",
			"PO1*1*1*EA*40.00*PE*VP*BETA-CHIP-01~",
			"CTT*1*1~",
			"AMT*TT*40.00~",
			"SE*8*0001~",
			"GE*1*1002~",
			"IEA*1*000001002~",
		}, "\n")
		rcptSellerB := strings.Join([]string{
			"ISA*00*          *00*          *ZZ*BUYER01        *ZZ*SUPPLIER02     *261108*0902*^*00501*000001502*0*T*:~",
			"GS*RC*BUYER01*SUPPLIER02*20261108*090200*1502*X*005010~",
			"ST*861*0001~",
			"BRA*RCV-861-9002*20261108*00*5~",
			"PRF*PO-850-9002~",
			"RCD*1*1*EA*0~",
			"LIN*1*VP*BETA-CHIP-01~",
			"CTT*1*1~",
			"SE*7*0001~",
			"GE*1*1502~",
			"IEA*1*000001502~",
		}, "\n")
		invSellerB := strings.Join([]string{
			"ISA*00*          *00*          *ZZ*SUPPLIER02     *ZZ*BUYER01        *261108*0905*^*00501*000002002*0*T*:~",
			"GS*IN*SUPPLIER02*BUYER01*20261108*090500*810778*X*005010~",
			"ST*810*0043~",
			"BIG*20261108*INV-SHARED-100*20261108*PO-850-9002~",
			"N1*SE*BETA SILICON CORP*92*paypal:billing@beta-silicon.example~",
			"IT1*1*1*EA*40.00*PE*VP*BETA-CHIP-01~",
			"TDS*4000~",
			"CAD*****PAYPAL*paypal:billing@beta-silicon.example~",
			"CTT*1*1~",
			"SE*8*0043~",
			"GE*1*810778~",
			"IEA*1*000002002~",
		}, "\n")
		if _, err := eng.RegisterPO850(poSellerB); err != nil {
			t.Fatalf("RegisterPO850 Seller B: %v", err)
		}
		if _, err := eng.RegisterReceivingAdvice861(rcptSellerB); err != nil {
			t.Fatalf("RegisterReceivingAdvice861 Seller B: %v", err)
		}
		if _, err := eng.EvaluateAndSettle810(context.Background(), invSellerB, "agent-b", "paypal:billing@beta-silicon.example"); err != nil {
			t.Fatalf("expected Seller B with same BIG02 INV-SHARED-100 to succeed (N4), got %v", err)
		}
	})

	t.Run("Kill_R11_And_C3_ZeroReceiptHeadersOnEvaluationOrCaptureFailure", func(t *testing.T) {
		poParsed, _ := tinygaap.ParseEDI850(canonicalPO850())
		mockFailCap := newInMemoryHTTPClient(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/oauth2/token" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token":"tok","app_id":"APP","expires_in":3600}`))
				return
			}
			if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/checkout/orders/") {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id":     "ORD-FAIL-402",
					"status": "CREATED",
					"purchase_units": []map[string]any{
						{
							"reference_id": poParsed.PONumber,
							"custom_id":    poParsed.SHA256Hex,
							"invoice_id":   "INV-C3-CAPFAIL",
							"amount":       map[string]string{"currency_code": "USD", "value": "125.00"},
						},
					},
				})
				return
			}
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"name":"UNPROCESSABLE_ENTITY","message":"ORDER_NOT_APPROVED"}`))
		})
		eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              []byte("tinygaap-r11-c3-no-receipt-on-fail"),
			RollingHourlyLimitCents: 100000,
			WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
			PayPalClientID:          "cid",
			PayPalClientSecret:      "csec",
			PayPalBaseURL:           "https://api-m.sandbox.paypal.com",
			HTTPClient:              mockFailCap,
		})
		if err != nil {
			t.Fatalf("NewTinyGAAPEngine: %v", err)
		}
		_, _ = eng.RegisterPO850(canonicalPO850())
		// Missing 861 -> 422 rejection: must NOT emit X-Payment-Receipt or X-Ed25519-Signature (kills R11!).
		bodyRej := validInvoice810("INV-R11-422")
		reqRej := httptest.NewRequest(http.MethodPost, "/v1/edi/810/settle", bytes.NewBufferString(bodyRej))
		reqRej.Header.Set("Payment-Signature", eng.SignX402Header(bodyRej))
		reqRej.Header.Set("X-Agent-Key", "agent-r11")
		reqRej.Header.Set("X-PayTo-Beneficiary", "paypal:treasury@acme-metal.example")
		recRej := httptest.NewRecorder()
		eng.ServeSettle810(recRej, reqRej)
		if recRej.Code != http.StatusUnprocessableEntity {
			t.Fatalf("expected 422, got %d", recRej.Code)
		}
		if recRej.Header().Get("X-Payment-Receipt") != "" || recRej.Header().Get("X-Ed25519-Signature") != "" {
			t.Fatalf("expected empty X-Payment-Receipt / X-Ed25519-Signature on 422 rejection, got %q / %q",
				recRej.Header().Get("X-Payment-Receipt"), recRej.Header().Get("X-Ed25519-Signature"))
		}

		// Register 861, then call ?capture=true with failing PayPal capture -> 402 and NO receipt headers (C3!).
		_, _ = eng.RegisterReceivingAdvice861(canonicalReceipt861())
		rawCapFail := strings.Replace(validInvoice810("INV-C3-CAPFAIL"),
			"CAD*****PAYPAL*paypal:treasury@acme-metal.example~",
			"REF*PP*ORD-FAIL-402~\nCAD*****PAYPAL*paypal:treasury@acme-metal.example~", 1)
		rawCapFail = strings.Replace(rawCapFail, "SE*9*0042~", "SE*10*0042~", 1)
		reqCap := httptest.NewRequest(http.MethodPost, "/v1/edi/810/settle?capture=true", bytes.NewBufferString(rawCapFail))
		reqCap.Header.Set("Payment-Signature", eng.SignX402Header(rawCapFail))
		reqCap.Header.Set("X-Agent-Key", "agent-c3")
		reqCap.Header.Set("X-PayTo-Beneficiary", "paypal:treasury@acme-metal.example")
		recCap := httptest.NewRecorder()
		eng.ServeSettle810(recCap, reqCap)
		if recCap.Code != http.StatusPaymentRequired {
			t.Fatalf("expected 402 on failed capture, got %d", recCap.Code)
		}
		if recCap.Header().Get("X-Payment-Receipt") != "" || recCap.Header().Get("X-Ed25519-Signature") != "" {
			t.Fatalf("expected empty X-Payment-Receipt / X-Ed25519-Signature on failed capture, got %q / %q",
				recCap.Header().Get("X-Payment-Receipt"), recCap.Header().Get("X-Ed25519-Signature"))
		}
	})

	t.Run("C4_C6_H7_ReceiptHeaderBinding_DelimiterSanitization_And_ISA15_BRA04", func(t *testing.T) {
		secret := []byte("tinygaap-c4-c6-h7-delimiter-secret")
		engLive, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              secret,
			RollingHourlyLimitCents: 100000,
			PayPalBaseURL:           "https://api-m.paypal.com", // non-sandbox -> ISA15 = "P"
			WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
			Auditor: staticAuditor{verdict: &tinygaap.AIAuditVerdict{
				Mode:     "live;injected=1",
				ModelID:  "model=evil;payto=attacker\r\n",
				Decision: "APPROVE",
			}},
		})
		if err != nil {
			t.Fatalf("NewTinyGAAPEngine: %v", err)
		}
		_, _ = engLive.RegisterPO850(canonicalPO850())
		_, _ = engLive.RegisterReceivingAdvice861(canonicalReceipt861())

		res, err := engLive.EvaluateAndSettle810(context.Background(), validInvoice810("INV-C6-01"), "agent-c6", "paypal:treasury@acme-metal.example")
		if err != nil {
			t.Fatalf("EvaluateAndSettle810: %v", err)
		}
		if strings.Count(res.ReceiptHeader, ";payto=") != 1 || strings.ContainsAny(res.ReceiptHeader, "\r\n") {
			t.Fatalf("delimiter injection was not sanitized in ReceiptHeader: %q", res.ReceiptHeader)
		}
		for _, mustContain := range []string{"seller=", "r861=RCV-861-9001:", "r997=", "aud_mode=live_injected_1", "aud_model=model_evil_payto_attacker"} {
			if !strings.Contains(res.ReceiptHeader, mustContain) {
				t.Fatalf("ReceiptHeader missing %q: %q", mustContain, res.ReceiptHeader)
			}
		}
		if !tinygaap.VerifyReceiptHMAC(secret, res.ReceiptHeader) || !tinygaap.VerifyReceiptSignature(res.Ed25519PubKeyHex, res.ReceiptHeader, res.Ed25519SignatureHex) {
			t.Fatalf("HMAC or Ed25519 verification failed on C4/C6 ReceiptHeader")
		}
		// Non-sandbox PayPalBaseURL must emit ISA15 = "P" in 997.
		firstLine997 := strings.Split(res.RawEDI997, "\n")[0]
		if !strings.HasSuffix(firstLine997, "*0*P*:~") {
			t.Fatalf("expected ISA15='P' when PayPalBaseURL is live, got %q", firstLine997)
		}

		// X12 005010 BRA04="4" (Reject All) must fail closed with ErrEDI861ReceivingDrift and ErrorSegmentID="IT1".
		engRej861, _ := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              secret,
			RollingHourlyLimitCents: 100000,
			WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
		})
		_, _ = engRej861.RegisterPO850(canonicalPO850())
		bra4 := strings.Replace(canonicalReceipt861(), "BRA*RCV-861-9001*20261108*00*5~", "BRA*RCV-861-9001*20261108*00*4~", 1)
		if _, err := engRej861.RegisterReceivingAdvice861(bra4); err != nil {
			t.Fatalf("RegisterReceivingAdvice861 BRA04=4: %v", err)
		}
		resBra4, err := engRej861.EvaluateAndSettle810(context.Background(), validInvoice810("INV-BRA4"), "agent-bra4", "paypal:treasury@acme-metal.example")
		if !errors.Is(err, tinygaap.ErrEDI861ReceivingDrift) || resBra4.ErrorSegmentID != "IT1" {
			t.Fatalf("expected ErrEDI861ReceivingDrift with ErrorSegmentID=IT1 on BRA04=4, got err=%v seg=%q", err, resBra4.ErrorSegmentID)
		}
	})

	t.Run("PostCaptureReceiptHeader_VerifyReceiptHMAC_TailGuard_And_E2ECaptureTelemetry", func(t *testing.T) {
		secret := []byte("tinygaap-e2e-capture-telemetry-32b!")
		poParsed, err := tinygaap.ParseEDI850(canonicalPO850())
		if err != nil {
			t.Fatalf("ParseEDI850: %v", err)
		}

		var mu sync.Mutex
		orderState := "APPROVED"
		captureHits := 0
		configuredCapStatus := http.StatusCreated

		mockClient := newInMemoryHTTPClient(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/v1/oauth2/token" {
				u, p, ok := r.BasicAuth()
				if !ok || u != "live-cap-client" || p != "live-cap-secret" {
					w.Header().Set("Paypal-Debug-Id", "dbg-neg-401")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
					return
				}
				w.Header().Set("Paypal-Debug-Id", "dbg-oauth-200")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token":"tok-e2e-cap","expires_in":32400}`))
				return
			}
			if r.Method == http.MethodPost && r.URL.Path == "/v2/checkout/orders" {
				var req map[string]any
				_ = json.NewDecoder(r.Body).Decode(&req)
				pus, _ := req["purchase_units"].([]any)
				pu, _ := pus[0].(map[string]any)
				invID, _ := pu["invoice_id"].(string)
				mu.Lock()
				orderState = "CREATED"
				mu.Unlock()
				w.Header().Set("Paypal-Debug-Id", "dbg-create-201")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id":          "ORD-E2E-CREATE-" + invID,
					"status":      "CREATED",
					"create_time": "2026-11-10T18:00:00Z",
				})
				return
			}
			if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/checkout/orders/") {
				ordID := strings.TrimPrefix(r.URL.Path, "/v2/checkout/orders/")
				mu.Lock()
				st := orderState
				mu.Unlock()
				invID := "INV-E2E-CAP-01"
				if strings.HasPrefix(ordID, "ORD-E2E-CREATE-") {
					invID = strings.TrimPrefix(ordID, "ORD-E2E-CREATE-")
				} else if strings.HasSuffix(ordID, "-DONE") {
					invID = "INV-E2E-DONE-01"
				} else if strings.HasSuffix(ordID, "-CREATED") {
					invID = "INV-E2E-UNAPPROVED-01"
				}
				respObj := map[string]any{
					"id":          ordID,
					"status":      st,
					"create_time": "2026-11-10T18:00:00Z",
					"purchase_units": []map[string]any{
						{
							"reference_id": "PO-850-9001",
							"custom_id":    poParsed.SHA256Hex,
							"invoice_id":   invID,
							"amount":       map[string]any{"currency_code": "USD", "value": "125.00"},
						},
					},
				}
				if st == "COMPLETED" {
					respObj["purchase_units"].([]map[string]any)[0]["payments"] = map[string]any{
						"captures": []map[string]any{
							{
								"id":     "CAP-OBSERVED-9911",
								"status": "COMPLETED",
								"amount": map[string]any{"currency_code": "USD", "value": "125.00"},
							},
						},
					}
				}
				w.Header().Set("Paypal-Debug-Id", "dbg-get-200")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(respObj)
				return
			}
			if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/capture") {
				ordID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v2/checkout/orders/"), "/capture")
				mu.Lock()
				captureHits++
				orderState = "COMPLETED"
				code := configuredCapStatus
				mu.Unlock()
				w.Header().Set("Paypal-Debug-Id", "dbg-cap-real")
				w.WriteHeader(code)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id":     ordID,
					"status": "COMPLETED",
					"purchase_units": []map[string]any{
						{
							"payments": map[string]any{
								"captures": []map[string]any{
									{
										"id":     "CAP-OBSERVED-9911",
										"status": "COMPLETED",
										"amount": map[string]any{"currency_code": "USD", "value": "125.00"},
									},
								},
							},
						},
					},
				})
				return
			}
			http.NotFound(w, r)
		})

		newE2EEngine := func() *tinygaap.TinyGAAPEngine {
			eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
				HMACSecret:              secret,
				RollingHourlyLimitCents: 200000,
				PayPalClientID:          "live-cap-client",
				PayPalClientSecret:      "live-cap-secret",
				PayPalBaseURL:           "https://api-m.sandbox.paypal.com",
				HTTPClient:              mockClient,
				WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
			})
			if err != nil {
				t.Fatalf("NewTinyGAAPEngine: %v", err)
			}
			return eng
		}

		// 1) VerifyLivePayPalSandboxE2E (CREATED): ";hmac=" MUST be at the very end, and trailing tokens MUST fail VerifyReceiptHMAC.
		engCreate := newE2EEngine()
		proofCreated, err := engCreate.VerifyLivePayPalSandboxE2E(context.Background(), canonicalPO850(), canonicalReceipt861(), validInvoice810("INV-E2E-CREATE-01"))
		if err != nil {
			t.Fatalf("VerifyLivePayPalSandboxE2E: %v", err)
		}
		if proofCreated.PayPalCaptured || proofCreated.CreateOrderHTTPCode != http.StatusCreated || proofCreated.CaptureOrderHTTPCode != 0 {
			t.Fatalf("unexpected CREATED proof telemetry: %+v", proofCreated)
		}
		if !tinygaap.VerifyReceiptHMAC(secret, proofCreated.ReceiptHeader) {
			t.Fatalf("VerifyReceiptHMAC failed on CREATED proof ReceiptHeader: %q", proofCreated.ReceiptHeader)
		}
		if tinygaap.VerifyReceiptHMAC(secret, proofCreated.ReceiptHeader+";status=COMPLETED") {
			t.Fatalf("VerifyReceiptHMAC accepted trailing parameter after ;hmac=!")
		}

		// 2) VerifyAndCaptureApprovedPayPalOrderE2E (APPROVED -> capture HTTP 200 -> post-capture GET COMPLETED).
		mu.Lock()
		orderState = "APPROVED"
		captureHits = 0
		configuredCapStatus = http.StatusOK
		mu.Unlock()
		engApprove := newE2EEngine()
		proofCap, err := engApprove.VerifyAndCaptureApprovedPayPalOrderE2E(context.Background(), canonicalPO850(), canonicalReceipt861(), validInvoice810("INV-E2E-CAP-01"), "ORD-E2E-CAP-01")
		if err != nil {
			t.Fatalf("VerifyAndCaptureApprovedPayPalOrderE2E (APPROVED): %v", err)
		}
		mu.Lock()
		gotHits := captureHits
		mu.Unlock()
		if gotHits != 1 {
			t.Fatalf("expected exactly 1 POST /capture call on APPROVED order, got %d", gotHits)
		}
		if !proofCap.PayPalCaptured || proofCap.LivePayPalOrderStatus != "COMPLETED" || proofCap.LivePayPalCaptureID != "CAP-OBSERVED-9911" {
			t.Fatalf("unexpected post-capture proof state: %+v", proofCap)
		}
		if proofCap.CreateOrderHTTPCode != 0 || proofCap.CaptureOrderHTTPCode != http.StatusOK || proofCap.GetOrderHTTPCode != http.StatusOK {
			t.Fatalf("expected CreateOrderHTTPCode=0 (unobserved), CaptureOrderHTTPCode=200 (observed), GetOrderHTTPCode=200, got create=%d cap=%d get=%d",
				proofCap.CreateOrderHTTPCode, proofCap.CaptureOrderHTTPCode, proofCap.GetOrderHTTPCode)
		}
		if !strings.Contains(proofCap.ReceiptHeader, ";pp_ord=ORD-E2E-CAP-01;pp_cap=CAP-OBSERVED-9911;status=COMPLETED;hmac=") {
			t.Fatalf("post-capture ReceiptHeader missing exact pp_ord/pp_cap/status before ;hmac=: %q", proofCap.ReceiptHeader)
		}
		if !tinygaap.VerifyReceiptHMAC(secret, proofCap.ReceiptHeader) || !tinygaap.VerifyReceiptSignature(proofCap.Ed25519PubKeyHex, proofCap.ReceiptHeader, proofCap.Ed25519SignatureHex) {
			t.Fatalf("post-capture ReceiptHeader failed HMAC or Ed25519 verification")
		}
		if !tinygaap.VerifyReceiptSignature(proofCap.Ed25519PubKeyHex, proofCap.EDI820Remittance, proofCap.EDI820SignatureHex) {
			t.Fatalf("VerifyReceiptSignature failed on valid EDI 820 with matching sigHex")
		}
		// Mismatched or empty sigHex on VerifyReceiptSignature(pub, raw820, sigHex) MUST return false.
		wrongSigHex := strings.Repeat("a", 128)
		if wrongSigHex == proofCap.EDI820SignatureHex {
			wrongSigHex = strings.Repeat("b", 128)
		}
		if tinygaap.VerifyReceiptSignature(proofCap.Ed25519PubKeyHex, proofCap.EDI820Remittance, wrongSigHex) {
			t.Fatalf("VerifyReceiptSignature accepted mismatched sigHex against EDI 820!")
		}
		if tinygaap.VerifyReceiptSignature(proofCap.Ed25519PubKeyHex, proofCap.EDI820Remittance, "") {
			t.Fatalf("VerifyReceiptSignature accepted empty sigHex against EDI 820!")
		}

		// 3) VerifyAndCaptureApprovedPayPalOrderE2E on already-COMPLETED order: 0 capture POSTs, Create=0, Capture=0, Get=200.
		mu.Lock()
		orderState = "COMPLETED"
		captureHits = 0
		mu.Unlock()
		engDone := newE2EEngine()
		proofDone, err := engDone.VerifyAndCaptureApprovedPayPalOrderE2E(context.Background(), canonicalPO850(), canonicalReceipt861(), validInvoice810("INV-E2E-DONE-01"), "ORD-E2E-DONE")
		if err != nil {
			t.Fatalf("VerifyAndCaptureApprovedPayPalOrderE2E (COMPLETED): %v", err)
		}
		mu.Lock()
		doneHits := captureHits
		mu.Unlock()
		if doneHits != 0 || proofDone.CreateOrderHTTPCode != 0 || proofDone.CaptureOrderHTTPCode != 0 || proofDone.GetOrderHTTPCode != http.StatusOK {
			t.Fatalf("already-COMPLETED branch must make 0 capture calls and omit unobserved Create/Capture codes: hits=%d create=%d cap=%d get=%d",
				doneHits, proofDone.CreateOrderHTTPCode, proofDone.CaptureOrderHTTPCode, proofDone.GetOrderHTTPCode)
		}
		if !tinygaap.VerifyReceiptHMAC(secret, proofDone.ReceiptHeader) {
			t.Fatalf("VerifyReceiptHMAC failed on already-COMPLETED ReceiptHeader: %q", proofDone.ReceiptHeader)
		}

		// 4) VerifyAndCaptureApprovedPayPalOrderE2E on unapproved CREATED order: MUST fail closed with PayPalCaptured=false.
		mu.Lock()
		orderState = "CREATED"
		mu.Unlock()
		engUnapproved := newE2EEngine()
		proofUnapp, err := engUnapproved.VerifyAndCaptureApprovedPayPalOrderE2E(context.Background(), canonicalPO850(), canonicalReceipt861(), validInvoice810("INV-E2E-UNAPPROVED-01"), "ORD-E2E-CREATED")
		if !errors.Is(err, tinygaap.ErrPayPalCaptureNotCompleted) || (proofUnapp != nil && proofUnapp.PayPalCaptured) {
			t.Fatalf("expected ErrPayPalCaptureNotCompleted and PayPalCaptured=false on CREATED order, got err=%v proof=%+v", err, proofUnapp)
		}
	})
}

func TestTinyGAAP_PersistentKeyCustody_ChainedLedger_And_WaitApproval(t *testing.T) {
	clearLLMEnv(t)

	t.Run("CommittedPublicKeyRegistry_ExactDigest_And_EphemeralRejection", func(t *testing.T) {
		pubFileBytes, err := os.ReadFile(filepath.Join("keys", "dcaa4e385c20a8af.pub"))
		if err != nil {
			t.Fatalf("ReadFile keys/dcaa4e385c20a8af.pub: %v", err)
		}
		if len(pubFileBytes) != 65 {
			t.Fatalf("keys/dcaa4e385c20a8af.pub length = %d, want 65 bytes", len(pubFileBytes))
		}
		fileSum := sha256.Sum256(pubFileBytes)
		if got := hex.EncodeToString(fileSum[:]); got != "95c638474a6f2c5bbdfc079da91483471ac752938f89c4e50f2a7780d83dfee3" {
			t.Fatalf("keys/dcaa4e385c20a8af.pub sha256 = %s, want 95c638474a6f2c5bbdfc079da91483471ac752938f89c4e50f2a7780d83dfee3", got)
		}
		pub, err := tinygaap.LoadPublicKeyFromRegistry("keys", "dcaa4e385c20a8af")
		if err != nil {
			t.Fatalf("LoadPublicKeyFromRegistry(dcaa4e385c20a8af): %v", err)
		}
		if gotKID := tinygaap.ComputeKeyID(pub); gotKID != "dcaa4e385c20a8af" {
			t.Fatalf("ComputeKeyID = %q, want dcaa4e385c20a8af", gotKID)
		}

		// N1: Ephemeral engine receipts (kid=efimera) MUST be rejected by VerifyReceiptWithRegistry and VerifyEDI820WithRegistry.
		ephEng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              []byte("tinygaap-ephemeral-reject-secret-32b"),
			RollingHourlyLimitCents: 100000,
			WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
		})
		if err != nil {
			t.Fatalf("NewTinyGAAPEngine ephemeral: %v", err)
		}
		if ephEng.KeyID() != tinygaap.EphemeralKeyID {
			t.Fatalf("expected ephemeral KeyID=%q, got %q", tinygaap.EphemeralKeyID, ephEng.KeyID())
		}
		_, _ = ephEng.RegisterPO850(canonicalPO850())
		_, _ = ephEng.RegisterReceivingAdvice861(canonicalReceipt861())
		ephRes, err := ephEng.EvaluateAndSettle810(context.Background(), validInvoice810("INV-EPH-01"), "agent-eph", "paypal:treasury@acme-metal.example")
		if err != nil {
			t.Fatalf("EvaluateAndSettle810 ephemeral: %v", err)
		}
		if err := tinygaap.VerifyReceiptWithRegistry("keys", ephRes.ReceiptHeader, ephRes.Ed25519SignatureHex); !errors.Is(err, tinygaap.ErrUntrustedKeyID) {
			t.Fatalf("expected ErrUntrustedKeyID for kid=efimera receipt, got %v", err)
		}
	})

	t.Run("KeyCustody_0600_NoImplicitCreate_And_RegistrySigned820", func(t *testing.T) {
		tmp := t.TempDir()
		keyPath := filepath.Join(tmp, "ed25519_priv.hex")
		keysDir := filepath.Join(tmp, "keys")
		secret := []byte("tinygaap-key-custody-0600-secret!")

		// RequirePersistentKey without key file -> fail closed.
		if _, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:           secret,
			RequirePersistentKey: true,
			WhitelistedPayTo:     map[string]bool{"paypal:treasury@acme-metal.example": true},
		}); !errors.Is(err, tinygaap.ErrKeyCustodyInvalid) {
			t.Fatalf("expected ErrKeyCustodyInvalid when RequirePersistentKey=true without key path, got %v", err)
		}

		ledgerPath := filepath.Join(tmp, "key_custody_ledger.jsonl")

		// Persistent key WITHOUT persistent ledger -> fail closed (prevents persistent-kid signing without replay state).
		if _, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:     secret,
			Ed25519KeyFile: keyPath,
			InitEd25519Key: true,
			KeysDir:        keysDir,
			WhitelistedPayTo: map[string]bool{
				"paypal:treasury@acme-metal.example": true,
			},
		}); !errors.Is(err, tinygaap.ErrLedgerInvalid) {
			t.Fatalf("expected ErrLedgerInvalid when Ed25519KeyFile is set without LedgerFile, got %v", err)
		}

		// Missing key file without InitEd25519Key -> fail closed (must NOT O_CREATE).
		if _, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:     secret,
			Ed25519KeyFile: keyPath,
			LedgerFile:     ledgerPath,
			InitLedger:     true,
			WhitelistedPayTo: map[string]bool{
				"paypal:treasury@acme-metal.example": true,
			},
		}); !errors.Is(err, tinygaap.ErrKeyCustodyInvalid) {
			t.Fatalf("expected ErrKeyCustodyInvalid on missing key file without InitEd25519Key, got %v", err)
		}

		// Explicit InitEd25519Key + InitLedger creates 0600 private key + <keysDir>/<kid>.pub + 0600 ledger.
		engInit, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:       secret,
			Ed25519KeyFile:   keyPath,
			InitEd25519Key:   true,
			KeysDir:          keysDir,
			LedgerFile:       ledgerPath,
			InitLedger:       true,
			WhitelistedPayTo: map[string]bool{"paypal:treasury@acme-metal.example": true},
		})
		if err != nil {
			t.Fatalf("InitEd25519Key engine failed: %v", err)
		}
		kid := engInit.KeyID()
		pubHex := engInit.PublicKeyHex()
		_ = engInit.Close()

		// Second InitEd25519Key on existing file -> fail closed (O_EXCL guard).
		if _, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:       secret,
			Ed25519KeyFile:   keyPath,
			InitEd25519Key:   true,
			LedgerFile:       ledgerPath,
			WhitelistedPayTo: map[string]bool{"paypal:treasury@acme-metal.example": true},
		}); !errors.Is(err, tinygaap.ErrKeyCustodyInvalid) {
			t.Fatalf("expected ErrKeyCustodyInvalid when InitEd25519Key is used on existing file, got %v", err)
		}

		// Insecure 0644 permissions -> fail closed.
		if err := os.Chmod(keyPath, 0644); err != nil {
			t.Fatalf("Chmod 0644: %v", err)
		}
		if _, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:       secret,
			Ed25519KeyFile:   keyPath,
			LedgerFile:       ledgerPath,
			WhitelistedPayTo: map[string]bool{"paypal:treasury@acme-metal.example": true},
		}); !errors.Is(err, tinygaap.ErrKeyCustodyInvalid) {
			t.Fatalf("expected ErrKeyCustodyInvalid on 0644 key file, got %v", err)
		}
		if err := os.Chmod(keyPath, 0600); err != nil {
			t.Fatalf("Chmod 0600: %v", err)
		}

		// Reload persistent key across restart -> identical KID & PublicKeyHex, and signed 820 verifies against KeysDir (N5 + H9).
		poParsed, _ := tinygaap.ParseEDI850(canonicalPO850())
		mockCap := newInMemoryHTTPClient(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/oauth2/token" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
				return
			}
			if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/checkout/orders/") {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id":     "ORD-KEY-820",
					"status": "APPROVED",
					"purchase_units": []map[string]any{
						{
							"reference_id": poParsed.PONumber,
							"custom_id":    poParsed.SHA256Hex,
							"invoice_id":   "INV-KEY-820",
							"amount":       map[string]any{"currency_code": "USD", "value": "125.00"},
						},
					},
				})
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":     "ORD-KEY-820",
				"status": "COMPLETED",
				"purchase_units": []map[string]any{
					{
						"payments": map[string]any{
							"captures": []map[string]any{
								{"id": "CAP-KEY-820", "status": "COMPLETED", "amount": map[string]any{"currency_code": "USD", "value": "125.00"}},
							},
						},
					},
				},
			})
		})
		engReload, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:         secret,
			Ed25519KeyFile:     keyPath,
			KeysDir:            keysDir,
			LedgerFile:         ledgerPath,
			PayPalClientID:     "cid",
			PayPalClientSecret: "csec",
			HTTPClient:         mockCap,
			WhitelistedPayTo:   map[string]bool{"paypal:treasury@acme-metal.example": true},
		})
		if err != nil {
			t.Fatalf("reload persistent key failed: %v", err)
		}
		defer engReload.Close()
		if engReload.KeyID() != kid || engReload.PublicKeyHex() != pubHex {
			t.Fatalf("reloaded key mismatch: got (%s, %s), want (%s, %s)", engReload.KeyID(), engReload.PublicKeyHex(), kid, pubHex)
		}
		po, _ := engReload.RegisterPO850(canonicalPO850())
		_, _ = engReload.RegisterReceivingAdvice861(canonicalReceipt861())
		raw810 := validInvoice810("INV-KEY-820")
		evalRes, err := engReload.EvaluateAndSettle810(context.Background(), raw810, "agent-k", "paypal:treasury@acme-metal.example")
		if err != nil {
			t.Fatalf("EvaluateAndSettle810: %v", err)
		}
		inv, _, _, _ := tinygaap.ParseEDI810(raw810)
		if err := engReload.CaptureApprovedPayPalOrder(context.Background(), evalRes, po, inv, "ORD-KEY-820"); err != nil {
			t.Fatalf("CaptureApprovedPayPalOrder: %v", err)
		}
		if err := tinygaap.VerifyReceiptWithRegistry(keysDir, evalRes.ReceiptHeader, evalRes.Ed25519SignatureHex); err != nil {
			t.Fatalf("VerifyReceiptWithRegistry post-capture failed: %v", err)
		}
		if err := tinygaap.VerifyEDI820WithRegistry(keysDir, evalRes.RawEDI820); err != nil {
			t.Fatalf("VerifyEDI820WithRegistry failed: %v", err)
		}
		// Tampering REF*LK*<kid> inside 820 MUST fail VerifyEDI820WithRegistry (H9).
		tamperedKID820 := strings.Replace(evalRes.RawEDI820, "REF*LK*"+kid, "REF*LK*0000000000000000", 1)
		if err := tinygaap.VerifyEDI820WithRegistry(keysDir, tamperedKID820); err == nil {
			t.Fatalf("VerifyEDI820WithRegistry accepted tampered REF*LK* kid!")
		}
	})

	t.Run("PersistentHashChainedLedger_Flock_RestartReplay_Truncation_And_TamperGuards", func(t *testing.T) {
		tmp := t.TempDir()
		keyPath := filepath.Join(tmp, "ed25519_priv.hex")
		keysDir := filepath.Join(tmp, "keys")
		seedLedgerPath := filepath.Join(tmp, "seed_ledger.jsonl")
		ledgerPath := filepath.Join(tmp, "ledger.jsonl")
		secret := []byte("tinygaap-ledger-chain-secret-32b!")

		// Missing ledger without InitLedger -> fail closed (H3: no silent O_CREATE!).
		engKeySeed, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:       secret,
			Ed25519KeyFile:   keyPath,
			InitEd25519Key:   true,
			KeysDir:          keysDir,
			LedgerFile:       seedLedgerPath,
			InitLedger:       true,
			WhitelistedPayTo: map[string]bool{"paypal:treasury@acme-metal.example": true},
		})
		if err != nil {
			t.Fatalf("seed key engine: %v", err)
		}
		_ = engKeySeed.Close()

		if _, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:       secret,
			Ed25519KeyFile:   keyPath,
			KeysDir:          keysDir,
			LedgerFile:       ledgerPath,
			WhitelistedPayTo: map[string]bool{"paypal:treasury@acme-metal.example": true},
		}); !errors.Is(err, tinygaap.ErrLedgerInvalid) {
			t.Fatalf("expected ErrLedgerInvalid when ledger does not exist and InitLedger=false, got %v", err)
		}

		// Initialize ledger explicitly (InitLedger=true), and verify exclusive flock blocks a second concurrent engine.
		eng1, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              secret,
			RollingHourlyLimitCents: 20000, // $200.00/hr -> first $125 passes, second $125 after restart trips budget!
			Ed25519KeyFile:          keyPath,
			KeysDir:                 keysDir,
			LedgerFile:              ledgerPath,
			InitLedger:              true,
			WhitelistedPayTo: map[string]bool{
				"paypal:treasury@acme-metal.example":  true,
				"paypal:billing@beta-silicon.example": true,
			},
		})
		if err != nil {
			t.Fatalf("InitLedger engine failed: %v", err)
		}
		if _, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:       secret,
			Ed25519KeyFile:   keyPath,
			KeysDir:          keysDir,
			LedgerFile:       ledgerPath,
			WhitelistedPayTo: map[string]bool{"paypal:treasury@acme-metal.example": true},
		}); !errors.Is(err, tinygaap.ErrLedgerInvalid) {
			_ = eng1.Close()
			t.Fatalf("expected exclusive flock to reject second concurrent engine on same ledger, got %v", err)
		}

		_, _ = eng1.RegisterPO850(canonicalPO850())
		_, _ = eng1.RegisterReceivingAdvice861(canonicalReceipt861())
		inv1 := strings.Replace(validInvoice810("INV-PERSIST-100"),
			"CAD*****PAYPAL*paypal:treasury@acme-metal.example~",
			"REF*PP*ORD-PERSIST-1~\nCAD*****PAYPAL*paypal:treasury@acme-metal.example~", 1)
		inv1 = strings.Replace(inv1, "SE*9*0042~", "SE*10*0042~", 1)

		res1, err := eng1.EvaluateAndSettle810(context.Background(), inv1, "agent-persist", "paypal:treasury@acme-metal.example")
		if err != nil {
			_ = eng1.Close()
			t.Fatalf("EvaluateAndSettle810 on eng1 failed: %v", err)
		}
		if res1.LedgerSeq != 1 || res1.LedgerEntryHashHex == "" {
			_ = eng1.Close()
			t.Fatalf("expected LedgerSeq=1 and non-empty LedgerEntryHashHex, got %+v", res1)
		}
		if err := tinygaap.VerifyReceiptAgainstLedger(ledgerPath, keysDir, res1.ReceiptHeader, res1.Ed25519SignatureHex); err != nil {
			_ = eng1.Close()
			t.Fatalf("VerifyReceiptAgainstLedger seq=1 failed: %v", err)
		}
		if err := eng1.Close(); err != nil {
			t.Fatalf("eng1.Close: %v", err)
		}

		// Restart engine on the same ledger (InitLedger=false) -> replays settled invoices, bound orders, PO SKU qty, and hourly spend!
		eng2, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              secret,
			RollingHourlyLimitCents: 20000, // $200.00/hr
			Ed25519KeyFile:          keyPath,
			KeysDir:                 keysDir,
			LedgerFile:              ledgerPath,
			WhitelistedPayTo: map[string]bool{
				"paypal:treasury@acme-metal.example":  true,
				"paypal:billing@beta-silicon.example": true,
			},
		})
		if err != nil {
			t.Fatalf("restart eng2 on existing ledger failed: %v", err)
		}
		_, _ = eng2.RegisterPO850(canonicalPO850())
		_, _ = eng2.RegisterReceivingAdvice861(canonicalReceipt861())

		// Fresh unbilled PO for Seller A to test BIG02 replay, PayPalOrderID reuse, and rolling spend across restart!
		poA2 := strings.ReplaceAll(canonicalPO850(), "PO-850-9001", "PO-850-9001R")
		rcptA2 := strings.ReplaceAll(canonicalReceipt861(), "PO-850-9001", "PO-850-9001R")
		rcptA2 = strings.ReplaceAll(rcptA2, "RCV-861-9001", "RCV-861-9001R")
		_, _ = eng2.RegisterPO850(poA2)
		_, _ = eng2.RegisterReceivingAdvice861(rcptA2)

		// 1) Replay of INV-PERSIST-100 by Seller A after restart -> blocked on BIG!
		invReplay := strings.ReplaceAll(validInvoice810("INV-PERSIST-100"), "PO-850-9001", "PO-850-9001R")
		if r, err := eng2.EvaluateAndSettle810(context.Background(), invReplay, "other-agent", "paypal:treasury@acme-metal.example"); !errors.Is(err, tinygaap.ErrDuplicateInvoiceReplay) || r.ErrorSegmentID != "BIG" {
			_ = eng2.Close()
			t.Fatalf("expected BIG02 replay blocked after restart, got err=%v seg=%q", err, r.ErrorSegmentID)
		}

		// 2) Reuse of PayPalOrderID ORD-PERSIST-1 on new invoice INV-PERSIST-101 after restart -> blocked on REF!
		invOrdReuse := strings.ReplaceAll(validInvoice810("INV-PERSIST-101"), "PO-850-9001", "PO-850-9001R")
		invOrdReuse = strings.Replace(invOrdReuse,
			"CAD*****PAYPAL*paypal:treasury@acme-metal.example~",
			"REF*PP*ORD-PERSIST-1~\nCAD*****PAYPAL*paypal:treasury@acme-metal.example~", 1)
		invOrdReuse = strings.Replace(invOrdReuse, "SE*9*0042~", "SE*10*0042~", 1)
		if r, err := eng2.EvaluateAndSettle810(context.Background(), invOrdReuse, "other-agent", "paypal:treasury@acme-metal.example"); !errors.Is(err, tinygaap.ErrDuplicateInvoiceReplay) || r.ErrorSegmentID != "REF" {
			_ = eng2.Close()
			t.Fatalf("expected PayPalOrderID reuse blocked after restart, got err=%v seg=%q", err, r.ErrorSegmentID)
		}

		// 3) Re-billing already-consumed PO-850-9001 with new invoice INV-PERSIST-102 after restart -> blocked on IT1!
		if r, err := eng2.EvaluateAndSettle810(context.Background(), validInvoice810("INV-PERSIST-102"), "other-agent", "paypal:treasury@acme-metal.example"); !errors.Is(err, tinygaap.ErrDuplicateInvoiceReplay) || r.ErrorSegmentID != "IT1" {
			_ = eng2.Close()
			t.Fatalf("expected cumulative PO SKU overbilling blocked after restart, got err=%v seg=%q", err, r.ErrorSegmentID)
		}

		// 4) Rolling hourly spend limit ($125 replayed + $125 new > $200 ceiling) -> trips ErrBudgetBreakerTripped after restart!
		invOverBudget := strings.ReplaceAll(validInvoice810("INV-PERSIST-103"), "PO-850-9001", "PO-850-9001R")
		if _, err := eng2.EvaluateAndSettle810(context.Background(), invOverBudget, "other-agent", "paypal:treasury@acme-metal.example"); !errors.Is(err, tinygaap.ErrBudgetBreakerTripped) {
			_ = eng2.Close()
			t.Fatalf("expected replayed rolling hourly spend to trip ErrBudgetBreakerTripped, got %v", err)
		}

		// 5) Seller B with same BIG02 INV-PERSIST-100 ($40; $125 + $40 = $165 <= $200) -> succeeds (seller-scoped N4 + seq=2)!
		poSellerB := strings.Join([]string{
			"ISA*00*          *00*          *ZZ*BUYER01        *ZZ*SUPPLIER02     *261108*0900*^*00501*000001002*0*T*:~",
			"GS*PO*BUYER01*SUPPLIER02*20261108*090000*1002*X*005010~",
			"ST*850*0001~",
			"BEG*00*SA*PO-850-9002**20261108~",
			"N1*BY*ACME BUYER CORP*92*BUYER-01~",
			"N1*SE*BETA SILICON CORP*92*paypal:billing@beta-silicon.example~",
			"PO1*1*1*EA*40.00*PE*VP*BETA-CHIP-01~",
			"CTT*1*1~",
			"AMT*TT*40.00~",
			"SE*8*0001~",
			"GE*1*1002~",
			"IEA*1*000001002~",
		}, "\n")
		rcptSellerB := strings.Join([]string{
			"ISA*00*          *00*          *ZZ*BUYER01        *ZZ*SUPPLIER02     *261108*0902*^*00501*000001502*0*T*:~",
			"GS*RC*BUYER01*SUPPLIER02*20261108*090200*1502*X*005010~",
			"ST*861*0001~",
			"BRA*RCV-861-9002*20261108*00*5~",
			"PRF*PO-850-9002~",
			"RCD*1*1*EA*0~",
			"LIN*1*VP*BETA-CHIP-01~",
			"CTT*1*1~",
			"SE*7*0001~",
			"GE*1*1502~",
			"IEA*1*000001502~",
		}, "\n")
		invSellerB := strings.Join([]string{
			"ISA*00*          *00*          *ZZ*SUPPLIER02     *ZZ*BUYER01        *261108*0905*^*00501*000002002*0*T*:~",
			"GS*IN*SUPPLIER02*BUYER01*20261108*090500*810778*X*005010~",
			"ST*810*0043~",
			"BIG*20261108*INV-PERSIST-100*20261108*PO-850-9002~",
			"N1*SE*BETA SILICON CORP*92*paypal:billing@beta-silicon.example~",
			"IT1*1*1*EA*40.00*PE*VP*BETA-CHIP-01~",
			"TDS*4000~",
			"CAD*****PAYPAL*paypal:billing@beta-silicon.example~",
			"CTT*1*1~",
			"SE*8*0043~",
			"GE*1*810778~",
			"IEA*1*000002002~",
		}, "\n")
		_, _ = eng2.RegisterPO850(poSellerB)
		_, _ = eng2.RegisterReceivingAdvice861(rcptSellerB)
		res2, err := eng2.EvaluateAndSettle810(context.Background(), invSellerB, "agent-b", "paypal:billing@beta-silicon.example")
		if err != nil || res2.LedgerSeq != 2 {
			_ = eng2.Close()
			t.Fatalf("expected Seller B settlement at LedgerSeq=2, got err=%v res=%+v", err, res2)
		}
		_ = eng2.Close()

		// H6: Once the persistent ledger is closed/unavailable, attempting settlement MUST fail closed at write-ahead without issuing any receipt or signature!
		eng3, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              secret,
			RollingHourlyLimitCents: 500000,
			Ed25519KeyFile:          keyPath,
			KeysDir:                 keysDir,
			LedgerFile:              ledgerPath,
			WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
		})
		if err != nil {
			t.Fatalf("eng3 open ledger: %v", err)
		}
		_, _ = eng3.RegisterPO850(poA2)
		_, _ = eng3.RegisterReceivingAdvice861(rcptA2)
		_ = eng3.Close()
		resClosed, errClosed := eng3.EvaluateAndSettle810(context.Background(), strings.ReplaceAll(validInvoice810("INV-AFTER-CLOSE"), "PO-850-9001", "PO-850-9001R"), "agent-closed", "paypal:treasury@acme-metal.example")
		if !errors.Is(errClosed, tinygaap.ErrLedgerInvalid) || (resClosed != nil && (resClosed.SettlementAuthorized || resClosed.ReceiptHeader != "" || resClosed.Ed25519SignatureHex != "")) {
			t.Fatalf("expected closed ledger to fail closed with zero receipt/signature (H6), got err=%v res=%+v", errClosed, resClosed)
		}

		if err := tinygaap.VerifyReceiptAgainstLedger(ledgerPath, keysDir, res2.ReceiptHeader, res2.Ed25519SignatureHex); err != nil {
			t.Fatalf("VerifyReceiptAgainstLedger seq=2 failed: %v", err)
		}

		// H4: Truncating the tail line (seq=2) from the ledger MUST cause VerifyReceiptAgainstLedger(res2) to fail!
		rawLedger, err := os.ReadFile(ledgerPath)
		if err != nil {
			t.Fatalf("ReadFile ledger: %v", err)
		}
		lines := strings.Split(strings.TrimRight(string(rawLedger), "\n"), "\n")
		if len(lines) != 2 {
			t.Fatalf("expected 2 ledger lines, got %d", len(lines))
		}
		truncatedPath := filepath.Join(tmp, "ledger_truncated.jsonl")
		if err := os.WriteFile(truncatedPath, []byte(lines[0]+"\n"), 0600); err != nil {
			t.Fatalf("WriteFile truncated: %v", err)
		}
		if err := tinygaap.VerifyReceiptAgainstLedger(truncatedPath, keysDir, res2.ReceiptHeader, res2.Ed25519SignatureHex); !errors.Is(err, tinygaap.ErrLedgerInvalid) {
			t.Fatalf("expected VerifyReceiptAgainstLedger to detect tail truncation (lseq=2 > head=1), got %v", err)
		}

		// Tampering a field inside the ledger MUST fail both VerifyLedgerFile and engine startup!
		corruptPath := filepath.Join(tmp, "ledger_corrupt.jsonl")
		corruptBytes := strings.Replace(string(rawLedger), `"total_cents":12500`, `"total_cents":12501`, 1)
		if err := os.WriteFile(corruptPath, []byte(corruptBytes), 0600); err != nil {
			t.Fatalf("WriteFile corrupt: %v", err)
		}
		if _, err := tinygaap.VerifyLedgerFile(corruptPath, keysDir); !errors.Is(err, tinygaap.ErrLedgerInvalid) {
			t.Fatalf("expected VerifyLedgerFile to fail on tampered total_cents, got %v", err)
		}
		if _, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:       secret,
			Ed25519KeyFile:   keyPath,
			KeysDir:          keysDir,
			LedgerFile:       corruptPath,
			WhitelistedPayTo: map[string]bool{"paypal:treasury@acme-metal.example": true},
		}); !errors.Is(err, tinygaap.ErrLedgerInvalid) {
			t.Fatalf("expected engine startup to fail closed on tampered ledger, got %v", err)
		}
	})

	t.Run("WaitApprovalAndCapture_PollingToCompleted_And_TimeoutHonesty", func(t *testing.T) {
		tmp := t.TempDir()
		keyPath := filepath.Join(tmp, "ed25519_priv.hex")
		keysDir := filepath.Join(tmp, "keys")
		ledgerPath := filepath.Join(tmp, "ledger_wait.jsonl")
		secret := []byte("tinygaap-wait-approval-secret-32b")
		poParsed, _ := tinygaap.ParseEDI850(canonicalPO850())

		var mu sync.Mutex
		getReads := 0
		stayCreated := false
		captured := false
		lastRefID := poParsed.PONumber
		lastCustomID := poParsed.SHA256Hex

		mockWait := newInMemoryHTTPClient(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/v1/oauth2/token" {
				u, p, ok := r.BasicAuth()
				if !ok || u != "wait-cid" || p != "wait-csec" {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token":"tok-wait","expires_in":3600}`))
				return
			}
			if r.Method == http.MethodPost && r.URL.Path == "/v2/checkout/orders" {
				var req map[string]any
				_ = json.NewDecoder(r.Body).Decode(&req)
				pus, _ := req["purchase_units"].([]any)
				pu, _ := pus[0].(map[string]any)
				invID, _ := pu["invoice_id"].(string)
				refID, _ := pu["reference_id"].(string)
				custID, _ := pu["custom_id"].(string)
				mu.Lock()
				getReads = 0
				captured = false
				lastRefID = refID
				lastCustomID = custID
				mu.Unlock()
				w.Header().Set("Paypal-Debug-Id", "dbg-wait-create")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id":          "ORD-WAIT-" + invID,
					"status":      "CREATED",
					"create_time": "2026-11-11T10:00:00Z",
					"links": []map[string]string{
						{"href": "https://www.sandbox.paypal.com/checkoutnow?token=ORD-WAIT-" + invID, "rel": "approve"},
					},
				})
				return
			}
			if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/checkout/orders/") {
				ordID := strings.TrimPrefix(r.URL.Path, "/v2/checkout/orders/")
				invID := strings.TrimPrefix(ordID, "ORD-WAIT-")
				mu.Lock()
				getReads++
				reads := getReads
				isCap := captured
				forceCreated := stayCreated
				refID := lastRefID
				custID := lastCustomID
				mu.Unlock()
				st := "CREATED"
				if isCap {
					st = "COMPLETED"
				} else if !forceCreated && reads >= 3 {
					st = "APPROVED"
				}
				resp := map[string]any{
					"id":          ordID,
					"status":      st,
					"create_time": "2026-11-11T10:00:00Z",
					"purchase_units": []map[string]any{
						{
							"reference_id": refID,
							"custom_id":    custID,
							"invoice_id":   invID,
							"amount":       map[string]any{"currency_code": "USD", "value": "125.00"},
						},
					},
				}
				if st == "COMPLETED" {
					resp["purchase_units"].([]map[string]any)[0]["payments"] = map[string]any{
						"captures": []map[string]any{
							{"id": "CAP-WAIT-777", "status": "COMPLETED", "amount": map[string]any{"currency_code": "USD", "value": "125.00"}},
						},
					}
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)
				return
			}
			if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/capture") {
				ordID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v2/checkout/orders/"), "/capture")
				mu.Lock()
				captured = true
				mu.Unlock()
				w.Header().Set("Paypal-Debug-Id", "dbg-wait-cap")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id":     ordID,
					"status": "COMPLETED",
					"purchase_units": []map[string]any{
						{
							"payments": map[string]any{
								"captures": []map[string]any{
									{"id": "CAP-WAIT-777", "status": "COMPLETED", "amount": map[string]any{"currency_code": "USD", "value": "125.00"}},
								},
							},
						},
					},
				})
				return
			}
			http.NotFound(w, r)
		})

		eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              secret,
			RollingHourlyLimitCents: 500000,
			PayPalClientID:          "wait-cid",
			PayPalClientSecret:      "wait-csec",
			PayPalBaseURL:           "https://api-m.sandbox.paypal.com",
			HTTPClient:              mockWait,
			Ed25519KeyFile:          keyPath,
			InitEd25519Key:          true,
			KeysDir:                 keysDir,
			LedgerFile:              ledgerPath,
			InitLedger:              true,
			WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
		})
		if err != nil {
			t.Fatalf("NewTinyGAAPEngine wait-approval: %v", err)
		}
		defer eng.Close()

		var gotApproveURL string
		proof, err := eng.VerifyWaitApprovalAndCapturePayPalOrderE2E(
			context.Background(),
			canonicalPO850(),
			canonicalReceipt861(),
			validInvoice810("INV-WAIT-OK-01"),
			2*time.Second,
			5*time.Millisecond,
			func(u string) { gotApproveURL = u },
		)
		if err != nil {
			t.Fatalf("VerifyWaitApprovalAndCapturePayPalOrderE2E failed: %v", err)
		}
		if gotApproveURL != "https://www.sandbox.paypal.com/checkoutnow?token=ORD-WAIT-INV-WAIT-OK-01" {
			t.Fatalf("unexpected approveURL: %q", gotApproveURL)
		}
		if !proof.PayPalCaptured || proof.LivePayPalOrderStatus != "COMPLETED" || proof.LivePayPalCaptureID != "CAP-WAIT-777" || proof.LedgerSeq != 2 {
			t.Fatalf("unexpected completed wait-approval proof: %+v", proof)
		}
		if err := tinygaap.VerifyReceiptAgainstLedger(ledgerPath, keysDir, proof.ReceiptHeader, proof.Ed25519SignatureHex); err != nil {
			t.Fatalf("VerifyReceiptAgainstLedger on wait-approval proof failed: %v", err)
		}
		if err := tinygaap.VerifyEDI820WithRegistry(keysDir, proof.EDI820Remittance); err != nil {
			t.Fatalf("VerifyEDI820WithRegistry on wait-approval proof failed: %v", err)
		}

		// Timeout case: stays CREATED -> returns ErrPayPalCaptureNotCompleted with honest CREATED / PayPalCaptured=false proof.
		mu.Lock()
		stayCreated = true
		mu.Unlock()
		po2 := strings.ReplaceAll(canonicalPO850(), "PO-850-9001", "PO-850-9009")
		rcpt2 := strings.ReplaceAll(canonicalReceipt861(), "PO-850-9001", "PO-850-9009")
		rcpt2 = strings.ReplaceAll(rcpt2, "RCV-861-9001", "RCV-861-9009")
		inv2 := strings.ReplaceAll(validInvoice810("INV-WAIT-TIMEOUT-01"), "PO-850-9001", "PO-850-9009")
		proofTimeout, err := eng.VerifyWaitApprovalAndCapturePayPalOrderE2E(
			context.Background(),
			po2,
			rcpt2,
			inv2,
			35*time.Millisecond,
			10*time.Millisecond,
			nil,
		)
		if !errors.Is(err, tinygaap.ErrPayPalCaptureNotCompleted) {
			t.Fatalf("expected ErrPayPalCaptureNotCompleted on timeout, got %v", err)
		}
		if proofTimeout == nil || proofTimeout.PayPalCaptured || proofTimeout.LivePayPalOrderStatus != "CREATED" || proofTimeout.EDI820Remittance != "" {
			t.Fatalf("expected honest CREATED proof with PayPalCaptured=false on timeout, got %+v", proofTimeout)
		}
		if err := tinygaap.VerifyReceiptAgainstLedger(ledgerPath, keysDir, proofTimeout.ReceiptHeader, proofTimeout.Ed25519SignatureHex); err != nil {
			t.Fatalf("VerifyReceiptAgainstLedger on timeout CREATED proof failed: %v", err)
		}
	})

	t.Run("MutantKillSuite_And_LedgerKeyHardening", func(t *testing.T) {
		tmp := t.TempDir()
		keyPath := filepath.Join(tmp, "ed25519_priv.hex")
		keysDir := filepath.Join(tmp, "keys")
		ledgerPath := filepath.Join(tmp, "ledger.jsonl")
		secret := []byte("tinygaap-ledger-key-hardening-32")

		eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:              secret,
			RollingHourlyLimitCents: 900000,
			Ed25519KeyFile:          keyPath,
			InitEd25519Key:          true,
			KeysDir:                 keysDir,
			LedgerFile:              ledgerPath,
			InitLedger:              true,
			WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
		})
		if err != nil {
			t.Fatalf("NewTinyGAAPEngine: %v", err)
		}
		kid := eng.KeyID()
		rawPrivHex, err := os.ReadFile(keyPath)
		if err != nil {
			_ = eng.Close()
			t.Fatalf("ReadFile keyPath: %v", err)
		}
		privBytes, _ := hex.DecodeString(strings.TrimSpace(string(rawPrivHex)))
		priv := ed25519.PrivateKey(privBytes)

		po, _ := eng.RegisterPO850(canonicalPO850())
		_, _ = eng.RegisterReceivingAdvice861(canonicalReceipt861())
		raw810 := validInvoice810("INV-MK-01")
		evalRes, err := eng.EvaluateAndSettle810(context.Background(), raw810, "agent-mk", "paypal:treasury@acme-metal.example")
		if err != nil {
			_ = eng.Close()
			t.Fatalf("EvaluateAndSettle810: %v", err)
		}

		// Kill K5/K5b: VerifyReceiptWithRegistry MUST reject a corrupted 64-byte signature even when kid is valid & registered!
		sigBytes, _ := hex.DecodeString(evalRes.Ed25519SignatureHex)
		sigBytes[0] ^= 0xff
		badSigHex := hex.EncodeToString(sigBytes)
		if err := tinygaap.VerifyReceiptWithRegistry(keysDir, evalRes.ReceiptHeader, badSigHex); !errors.Is(err, tinygaap.ErrUntrustedKeyID) {
			_ = eng.Close()
			t.Fatalf("K5b: expected VerifyReceiptWithRegistry to reject bad signature for valid kid, got %v", err)
		}

		// Kill K3: LoadPublicKeyFromRegistry MUST reject a .pub file whose 32-byte key does not hash to kid!
		otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
		otherPubHex := hex.EncodeToString(otherPub) + "\n"
		mismatchDir := filepath.Join(tmp, "keys_k3")
		_ = os.MkdirAll(mismatchDir, 0700)
		_ = os.WriteFile(filepath.Join(mismatchDir, kid+".pub"), []byte(otherPubHex), 0644)
		if _, err := tinygaap.LoadPublicKeyFromRegistry(mismatchDir, kid); !errors.Is(err, tinygaap.ErrUntrustedKeyID) {
			_ = eng.Close()
			t.Fatalf("K3: expected LoadPublicKeyFromRegistry to reject content mismatch for kid %q, got %v", kid, err)
		}

		// Kill K7: LoadPublicKeyFromRegistry MUST reject "efimera" or malformed kids even if <keysDir>/efimera.pub exists on disk!
		_ = os.WriteFile(filepath.Join(mismatchDir, "efimera.pub"), []byte(otherPubHex), 0644)
		if _, err := tinygaap.LoadPublicKeyFromRegistry(mismatchDir, "efimera"); !errors.Is(err, tinygaap.ErrUntrustedKeyID) {
			_ = eng.Close()
			t.Fatalf("K7: expected LoadPublicKeyFromRegistry to reject kid=efimera even with file on disk, got %v", err)
		}

		// Capture INV-MK-01 so we also get a valid EDI 820 for L12 and a 2-entry ledger.
		mockCap := newInMemoryHTTPClient(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/oauth2/token" {
				_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
				return
			}
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id":     "ORD-MK-01",
					"status": "APPROVED",
					"purchase_units": []map[string]any{{
						"reference_id": po.PONumber,
						"custom_id":    po.SHA256Hex,
						"invoice_id":   "INV-MK-01",
						"amount":       map[string]any{"currency_code": "USD", "value": "125.00"},
					}},
				})
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":     "ORD-MK-01",
				"status": "COMPLETED",
				"purchase_units": []map[string]any{{
					"payments": map[string]any{
						"captures": []map[string]any{
							{"id": "CAP-MK-01", "status": "COMPLETED", "amount": map[string]any{"currency_code": "USD", "value": "125.00"}},
						},
					},
				}},
			})
		})
		_ = eng.Close()

		engCap, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:         secret,
			Ed25519KeyFile:     keyPath,
			KeysDir:            keysDir,
			LedgerFile:         ledgerPath,
			PayPalClientID:     "cid",
			PayPalClientSecret: "csec",
			HTTPClient:         mockCap,
			WhitelistedPayTo:   map[string]bool{"paypal:treasury@acme-metal.example": true},
		})
		if err != nil {
			t.Fatalf("engCap reload: %v", err)
		}
		_, _ = engCap.RegisterPO850(canonicalPO850())
		_, _ = engCap.RegisterReceivingAdvice861(canonicalReceipt861())
		invParsed, _, _, _ := tinygaap.ParseEDI810(raw810)

		// Kill R2d: After restart (replayedGrant == true), presenting a tampered HMAC in evalRes.ReceiptHeader MUST fail capture!
		badHMACEval := *evalRes
		if idx := strings.LastIndex(badHMACEval.ReceiptHeader, ";hmac="); idx > 0 {
			badHMACEval.ReceiptHeader = badHMACEval.ReceiptHeader[:idx] + ";hmac=" + strings.Repeat("0", 64)
		}
		if err := engCap.CaptureApprovedPayPalOrder(context.Background(), &badHMACEval, po, invParsed, "ORD-MK-01"); !errors.Is(err, tinygaap.ErrPayPalCaptureNotCompleted) {
			_ = engCap.Close()
			t.Fatalf("R2d: expected CaptureApprovedPayPalOrder after restart to reject invalid HMAC on ReceiptHeader, got %v", err)
		}

		// Valid capture succeeds and writes seq=2 (PAYPAL_ORDER_CAPTURED).
		if err := engCap.CaptureApprovedPayPalOrder(context.Background(), evalRes, po, invParsed, "ORD-MK-01"); err != nil {
			_ = engCap.Close()
			t.Fatalf("CaptureApprovedPayPalOrder valid: %v", err)
		}
		_ = engCap.Close()

		// Kill L12: Injecting an inline second "REF*LK*" substring inside a re-signed EDI 820 MUST fail VerifyEDI820WithRegistry!
		inlineSecondLK := strings.Replace(evalRes.RawEDI820, "SE*", "NTE*GEN*REF*LK*extra~\nSE*", 1)
		canonSpoof := tinygaap.CanonicalEDI820ForSigning(inlineSecondLK)
		spoofSig := hex.EncodeToString(ed25519.Sign(priv, []byte(canonSpoof)))
		reSignedSpoof820 := strings.Replace(canonSpoof, "ED25519:<SIG>", "ED25519:"+spoofSig, 1)
		if err := tinygaap.VerifyEDI820WithRegistry(keysDir, reSignedSpoof820); !errors.Is(err, tinygaap.ErrUntrustedKeyID) {
			t.Fatalf("L12: expected VerifyEDI820WithRegistry to reject second REF*LK* occurrence, got %v", err)
		}

		// Fix 3.5: VerifyLedgerFile with empty keysDir MUST fail closed!
		if _, err := tinygaap.VerifyLedgerFile(ledgerPath, ""); !errors.Is(err, tinygaap.ErrLedgerInvalid) {
			t.Fatalf("3.5: expected VerifyLedgerFile with empty keysDir to fail closed, got %v", err)
		}

		entries, err := tinygaap.VerifyLedgerFile(ledgerPath, keysDir)
		if err != nil || len(entries) != 2 {
			t.Fatalf("VerifyLedgerFile expected 2 entries, got len=%d err=%v", len(entries), err)
		}

		// Kill L11: VerifyReceiptAgainstLedger MUST reject a validly signed & HMAC'd receipt whose lhash disagrees with target.EntryHashHex!
		idxLhash := strings.Index(evalRes.ReceiptHeader, ";lhash=")
		idxHMAC := strings.LastIndex(evalRes.ReceiptHeader, ";hmac=")
		coreBadLhash := evalRes.ReceiptHeader[:idxLhash] + ";lhash=ffffffffffffffff" + evalRes.ReceiptHeader[idxLhash+23:idxHMAC]
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(coreBadLhash))
		hdrBadLhash := fmt.Sprintf("%s;hmac=%s", coreBadLhash, hex.EncodeToString(mac.Sum(nil)))
		sigBadLhash := hex.EncodeToString(ed25519.Sign(priv, []byte(hdrBadLhash)))
		if err := tinygaap.VerifyReceiptAgainstLedger(ledgerPath, keysDir, hdrBadLhash, sigBadLhash); !errors.Is(err, tinygaap.ErrLedgerInvalid) {
			t.Fatalf("L11: expected VerifyReceiptAgainstLedger to reject mismatched lhash, got %v", err)
		}

		// Kill L13: Parameter appended AFTER ;hmac=<hex> (even with valid Ed25519 signature over the full string) MUST be rejected!
		hdrAfterHMAC := evalRes.ReceiptHeader + ";tail=evil"
		sigAfterHMAC := hex.EncodeToString(ed25519.Sign(priv, []byte(hdrAfterHMAC)))
		if err := tinygaap.VerifyReceiptWithRegistry(keysDir, hdrAfterHMAC, sigAfterHMAC); err == nil || !strings.Contains(err.Error(), "trailing parameters after hmac") {
			t.Fatalf("L13: VerifyReceiptWithRegistry did not trigger trailing-after-hmac guard: %v", err)
		}

		writeSingleLedger := func(name string, e tinygaap.LedgerEntry) string {
			p := filepath.Join(tmp, name)
			b, _ := json.Marshal(e)
			if err := os.WriteFile(p, append(b, '\n'), 0600); err != nil {
				t.Fatalf("WriteFile %s: %v", name, err)
			}
			return p
		}

		// Kill L16: Wrong Seq (Seq=2 at line 1) with recomputed valid EntryHashHex + valid EntrySigHex!
		eSeq := entries[0]
		eSeq.Seq = 2
		eSeq.EntryHashHex = tinygaap.ComputeLedgerEntryHash(eSeq)
		eSeq.EntrySigHex = hex.EncodeToString(ed25519.Sign(priv, []byte(eSeq.EntryHashHex)))
		pSeq := writeSingleLedger("l16_seq.jsonl", eSeq)
		if _, err := tinygaap.VerifyLedgerFile(pSeq, keysDir); !errors.Is(err, tinygaap.ErrLedgerInvalid) {
			t.Fatalf("L16: VerifyLedgerFile accepted wrong Seq=2 at line 1: %v", err)
		}

		// Wrong PrevHashHex with recomputed valid EntryHashHex + valid EntrySigHex MUST fail closed!
		ePrev := entries[0]
		ePrev.PrevHashHex = strings.Repeat("a", 64)
		ePrev.EntryHashHex = tinygaap.ComputeLedgerEntryHash(ePrev)
		ePrev.EntrySigHex = hex.EncodeToString(ed25519.Sign(priv, []byte(ePrev.EntryHashHex)))
		pPrev := writeSingleLedger("prev_hash_tamper.jsonl", ePrev)
		if _, err := tinygaap.VerifyLedgerFile(pPrev, keysDir); !errors.Is(err, tinygaap.ErrLedgerInvalid) {
			t.Fatalf("prev_hash: VerifyLedgerFile accepted broken PrevHashHex: %v", err)
		}

		// Wrong EntryHashHex signed with valid Ed25519 EntrySigHex MUST fail closed!
		eHash := entries[0]
		eHash.EntryHashHex = strings.Repeat("b", 64)
		eHash.EntrySigHex = hex.EncodeToString(ed25519.Sign(priv, []byte(eHash.EntryHashHex)))
		pHash := writeSingleLedger("entry_hash_tamper.jsonl", eHash)
		if _, err := tinygaap.VerifyLedgerFile(pHash, keysDir); !errors.Is(err, tinygaap.ErrLedgerInvalid) {
			t.Fatalf("entry_hash: VerifyLedgerFile accepted wrong EntryHashHex: %v", err)
		}

		// Valid Seq, PrevHashHex, and EntryHashHex, but corrupted EntrySigHex -> fails BOTH VerifyLedgerFile AND engine startup!
		eSig := entries[0]
		esb, _ := hex.DecodeString(eSig.EntrySigHex)
		esb[0] ^= 0xff
		eSig.EntrySigHex = hex.EncodeToString(esb)
		pSig := writeSingleLedger("entry_sig_tamper.jsonl", eSig)
		if _, err := tinygaap.VerifyLedgerFile(pSig, keysDir); !errors.Is(err, tinygaap.ErrLedgerInvalid) {
			t.Fatalf("entry_sig: VerifyLedgerFile accepted invalid EntrySigHex: %v", err)
		}
		if _, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:       secret,
			Ed25519KeyFile:   keyPath,
			KeysDir:          keysDir,
			LedgerFile:       pSig,
			WhitelistedPayTo: map[string]bool{"paypal:treasury@acme-metal.example": true},
		}); !errors.Is(err, tinygaap.ErrLedgerInvalid) {
			t.Fatalf("L4b: NewTinyGAAPEngine startup accepted invalid EntrySigHex: %v", err)
		}

		// Kill L15: Duplicate PAYPAL_ORDER_CAPTURED at seq=3 in ledger on engine startup!
		rawOrig, _ := os.ReadFile(ledgerPath)
		origLines := strings.Split(strings.TrimRight(string(rawOrig), "\n"), "\n")
		line2Sum := sha256.Sum256([]byte(origLines[1]))
		dupCap := entries[1]
		dupCap.Seq = 3
		dupCap.PrevHashHex = hex.EncodeToString(line2Sum[:])
		dupCap.EntryHashHex = tinygaap.ComputeLedgerEntryHash(dupCap)
		dupCap.EntrySigHex = hex.EncodeToString(ed25519.Sign(priv, []byte(dupCap.EntryHashHex)))
		dupBytes, _ := json.Marshal(dupCap)
		pDupCap := filepath.Join(tmp, "l15_dup_cap.jsonl")
		_ = os.WriteFile(pDupCap, []byte(origLines[0]+"\n"+origLines[1]+"\n"+string(dupBytes)+"\n"), 0600)
		if _, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:       secret,
			Ed25519KeyFile:   keyPath,
			KeysDir:          keysDir,
			LedgerFile:       pDupCap,
			WhitelistedPayTo: map[string]bool{"paypal:treasury@acme-metal.example": true},
		}); !errors.Is(err, tinygaap.ErrLedgerInvalid) {
			t.Fatalf("L15: NewTinyGAAPEngine accepted duplicate PAYPAL_ORDER_CAPTURED at seq=3: %v", err)
		}

		// Kill W1, W4, and Fix 3.1 (COMPLETED without capture fails closed; CreateOrderHTTPCode=200 observed; post-capture GET!=COMPLETED fails closed)!
		var mode string
		var getCalls int
		mockW := newInMemoryHTTPClient(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/oauth2/token" {
				if r.Header.Get("Authorization") != "Basic Y2lkOmNzZWM=" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
				return
			}
			if r.Method == http.MethodPost && r.URL.Path == "/v2/checkout/orders" {
				// Return HTTP 200 OK (not 201!) so W4 (hardcoding 201) is caught!
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id":     "ORD-W-TEST",
					"status": "CREATED",
					"links":  []map[string]any{{"href": "https://www.sandbox.paypal.com/checkoutnow?token=ORD-W-TEST", "rel": "approve"}},
				})
				return
			}
			if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/checkout/orders/") {
				getCalls++
				st := "APPROVED"
				if mode == "completed_no_cap" {
					st = "COMPLETED"
				} else if mode == "w1_post_not_completed" && getCalls >= 2 {
					st = "APPROVED" // post-capture readback regresses to APPROVED instead of COMPLETED!
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id":     "ORD-W-TEST",
					"status": st,
					"purchase_units": []map[string]any{{
						"reference_id": po.PONumber,
						"custom_id":    po.SHA256Hex,
						"invoice_id":   "INV-W-TEST",
						"amount":       map[string]any{"currency_code": "USD", "value": "125.00"},
					}},
				})
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":     "ORD-W-TEST",
				"status": "COMPLETED",
				"purchase_units": []map[string]any{{
					"payments": map[string]any{
						"captures": []map[string]any{
							{"id": "CAP-W-TEST", "status": "COMPLETED", "amount": map[string]any{"currency_code": "USD", "value": "125.00"}},
						},
					},
				}},
			})
		})

		// 3.1 + W4: COMPLETED without capture object fails closed AND records CreateOrderHTTPCode == 200!
		mode = "completed_no_cap"
		getCalls = 0
		eng31, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:         secret,
			PayPalClientID:     "cid",
			PayPalClientSecret: "csec",
			HTTPClient:         mockW,
			WhitelistedPayTo:   map[string]bool{"paypal:treasury@acme-metal.example": true},
		})
		if err != nil {
			t.Fatalf("eng31: %v", err)
		}
		proof31, err31 := eng31.VerifyWaitApprovalAndCapturePayPalOrderE2E(context.Background(), canonicalPO850(), canonicalReceipt861(), validInvoice810("INV-W-TEST"), time.Second, 5*time.Millisecond, nil)
		if !errors.Is(err31, tinygaap.ErrPayPalCaptureNotCompleted) || (proof31 != nil && proof31.PayPalCaptured) {
			t.Fatalf("3.1: expected COMPLETED without capture object to fail closed with PayPalCaptured=false, got err=%v proof=%+v", err31, proof31)
		}
		if proof31 == nil || proof31.CreateOrderHTTPCode != http.StatusOK {
			t.Fatalf("W4: expected observed CreateOrderHTTPCode=200, got %+v", proof31)
		}

		// W1: Post-capture GET returning APPROVED instead of COMPLETED MUST fail closed!
		mode = "w1_post_not_completed"
		getCalls = 0
		engW1, _ := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
			HMACSecret:         secret,
			PayPalClientID:     "cid",
			PayPalClientSecret: "csec",
			HTTPClient:         mockW,
			WhitelistedPayTo:   map[string]bool{"paypal:treasury@acme-metal.example": true},
		})
		proofW1, errW1 := engW1.VerifyWaitApprovalAndCapturePayPalOrderE2E(context.Background(), canonicalPO850(), canonicalReceipt861(), validInvoice810("INV-W-TEST"), time.Second, 5*time.Millisecond, nil)
		if !errors.Is(errW1, tinygaap.ErrPayPalCaptureNotCompleted) || (proofW1 != nil && proofW1.PayPalCaptured) {
			t.Fatalf("W1: expected post-capture GET!=COMPLETED to fail closed, got err=%v proof=%+v", errW1, proofW1)
		}
	})
}

func TestTinyGAAP_EnvelopeDeterminism_And_AuditorAttributionGuards(t *testing.T) {
	secret := []byte("tinygaap-shared-envelope-guard32")

	// Kill G2: DeterministicPayPalRequestID MUST be strictly 36 hex chars and deterministic across repeated calls!
	id1 := tinygaap.DeterministicPayPalRequestID("po-sha", "inv-sha", "INV-1")
	time.Sleep(2 * time.Nanosecond)
	id2 := tinygaap.DeterministicPayPalRequestID("po-sha", "inv-sha", "INV-1")
	if len(id1) != 36 || id1 != id2 {
		t.Fatalf("G2: DeterministicPayPalRequestID non-deterministic or wrong length: %q vs %q (len=%d)", id1, id2, len(id1))
	}

	eng, err := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
		HMACSecret:              secret,
		RollingHourlyLimitCents: 500000,
		WhitelistedPayTo:        map[string]bool{"paypal:treasury@acme-metal.example": true},
	})
	if err != nil {
		t.Fatalf("NewTinyGAAPEngine: %v", err)
	}

	// Kill T9b (850), T9 (861), and T9c (810): 105-character trimmed ISA segment ("*0*T* ~") MUST be rejected with ErrX12MalformedEnvelope!
	shortPO := strings.Replace(canonicalPO850(), "*0*T*:~", "*0*T* ~", 1)
	if _, err := eng.RegisterPO850(shortPO); !errors.Is(err, tinygaap.ErrX12MalformedEnvelope) {
		t.Fatalf("T9b: expected 105-char 850 ISA to fail with ErrX12MalformedEnvelope, got %v", err)
	}
	po, err := eng.RegisterPO850(canonicalPO850())
	if err != nil {
		t.Fatalf("RegisterPO850: %v", err)
	}
	short861 := strings.Replace(canonicalReceipt861(), "*0*T*:~", "*0*T* ~", 1)
	if _, err := eng.RegisterReceivingAdvice861(short861); !errors.Is(err, tinygaap.ErrX12MalformedEnvelope) {
		t.Fatalf("T9: expected 105-char 861 ISA to fail with ErrX12MalformedEnvelope, got %v", err)
	}
	if _, err := eng.RegisterReceivingAdvice861(canonicalReceipt861()); err != nil {
		t.Fatalf("RegisterReceivingAdvice861: %v", err)
	}
	short810 := strings.Replace(validInvoice810("INV-SHORT-ISA"), "*0*T*:~", "*0*T* ~", 1)
	if _, err := eng.EvaluateAndSettle810(context.Background(), short810, "agent-isa", "paypal:treasury@acme-metal.example"); !errors.Is(err, tinygaap.ErrX12MalformedEnvelope) {
		t.Fatalf("T9c: expected 105-char 810 ISA to fail with ErrX12MalformedEnvelope, got %v", err)
	}

	// Kill T2: Outbound 997 ISA06 MUST echo incoming 810 ISA08 ("BUYER01        "), NOT hardcoded "TINYGAAP       "!
	resT2, err := eng.EvaluateAndSettle810(context.Background(), validInvoice810("INV-T2-997"), "agent-t2", "paypal:treasury@acme-metal.example")
	if err != nil {
		t.Fatalf("EvaluateAndSettle810 T2: %v", err)
	}
	want997Prefix := "ISA*00*          *00*          *ZZ*BUYER01        *ZZ*SUPPLIER01     *"
	if !strings.HasPrefix(resT2.RawEDI997, want997Prefix) {
		t.Fatalf("T2: outbound 997 ISA06/ISA08 did not mirror 810 receiver/sender:\ngot:  %q\nwant prefix: %q", resT2.RawEDI997[:80], want997Prefix)
	}

	// Kill T11b: Pre-capture GET readback returning status=COMPLETED MUST be rejected before POST /capture!
	mockAlreadyCompleted := newInMemoryHTTPClient(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/oauth2/token" {
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
			return
		}
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":     "ORD-T11B",
				"status": "COMPLETED",
				"purchase_units": []map[string]any{{
					"reference_id": po.PONumber,
					"custom_id":    po.SHA256Hex,
					"invoice_id":   "INV-T11B",
					"amount":       map[string]any{"currency_code": "USD", "value": "125.00"},
				}},
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	engT11, _ := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
		HMACSecret:         secret,
		PayPalClientID:     "cid",
		PayPalClientSecret: "csec",
		HTTPClient:         mockAlreadyCompleted,
		WhitelistedPayTo:   map[string]bool{"paypal:treasury@acme-metal.example": true},
	})
	poT11, _ := engT11.RegisterPO850(canonicalPO850())
	_, _ = engT11.RegisterReceivingAdvice861(canonicalReceipt861())
	rawT11 := validInvoice810("INV-T11B")
	evalT11, err := engT11.EvaluateAndSettle810(context.Background(), rawT11, "agent-t11", "paypal:treasury@acme-metal.example")
	if err != nil {
		t.Fatalf("EvaluateAndSettle810 T11b: %v", err)
	}
	invT11, _, _, _ := tinygaap.ParseEDI810(rawT11)
	if err := engT11.CaptureApprovedPayPalOrder(context.Background(), evalT11, poT11, invT11, "ORD-T11B"); !errors.Is(err, tinygaap.ErrPayPalOrderVerificationFailed) {
		t.Fatalf("T11b: expected pre-capture COMPLETED order to fail with ErrPayPalOrderVerificationFailed, got %v", err)
	}

	// Fix 3.4 (H5): Custom auditor returning APPROVE with empty Mode or ModelID MUST fail closed with ErrAIAuditorRejected!
	engNoAttr, _ := tinygaap.NewTinyGAAPEngine(tinygaap.TinyGAAPConfig{
		HMACSecret:       secret,
		WhitelistedPayTo: map[string]bool{"paypal:treasury@acme-metal.example": true},
		Auditor: staticAuditor{verdict: &tinygaap.AIAuditVerdict{
			Decision: "APPROVE",
			Mode:     "",
			ModelID:  "",
		}},
	})
	_, _ = engNoAttr.RegisterPO850(canonicalPO850())
	_, _ = engNoAttr.RegisterReceivingAdvice861(canonicalReceipt861())
	resNoAttr, errNoAttr := engNoAttr.EvaluateAndSettle810(context.Background(), validInvoice810("INV-H5-NO-ATTR"), "agent-h5", "paypal:treasury@acme-metal.example")
	if !errors.Is(errNoAttr, tinygaap.ErrAIAuditorRejected) || (resNoAttr != nil && resNoAttr.SettlementAuthorized) {
		t.Fatalf("3.4/H5: expected APPROVE verdict without Mode/ModelID to be rejected with ErrAIAuditorRejected, got err=%v res=%+v", errNoAttr, resNoAttr)
	}
}
