// Copyright 2026 Carlos Fuentes. Licensed under the Apache License, Version 2.0.
// Package tinygaap is an independent, open-source implementation that reads and writes
// a minimal subset of ASC X12 005010 transaction sets (850 Purchase Order, 861 Receiving
// Advice, 810 Invoice, 997 Functional Ack, and 820 Remittance Advice) with an x402-style
// HTTP 402 HMAC-SHA256 Payment-Signature gate (not wire-compatible with the x402 spec),
// a fail-closed semantic procurement auditor, and PayPal Orders v2 verification and capture.
package tinygaap

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
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProtocolVersion identifies the public protocol release.
const ProtocolVersion = "tinygaap/0.3.0"

var (
	ErrMissingHMACSecret             = errors.New("tinygaap: HMACSecret must be at least 16 non-trivial bytes (fail-closed)")
	ErrX402PaymentRequired           = errors.New("402 x402 Payment-Signature Header Missing or Invalid HMAC Signature")
	ErrX12MalformedEnvelope          = errors.New("400 ANSI X12 Structural or Segment Syntax Error")
	ErrEDI810PriceQtyDrift           = errors.New("422 EDI 810 Line Item or Total Drift vs EDI 850 PO")
	ErrEDI861ReceivingDrift          = errors.New("422 EDI 810 Quantity Exceeds or Drifts from EDI 861 Receiving Advice")
	ErrReceivingAdviceNotFound       = errors.New("422 Referenced EDI 861 Receiving Advice Not Found for PO")
	ErrUnapprovedBeneficiary         = errors.New("403 PayTo Beneficiary Not Allowlisted or Remittance Hijack Detected")
	ErrAIAuditorRejected             = errors.New("403 Procurement Auditor Flagged Prompt Injection, Remittance Anomaly, or Endpoint Failure")
	ErrBudgetBreakerTripped          = errors.New("429 Rolling Hourly Agentic Spend Limit Exceeded")
	ErrDuplicateInvoiceReplay        = errors.New("409 Duplicate BIG02 Invoice Replay or Cumulative PO Overbilling Blocked by Ledger")
	ErrPONotFound                    = errors.New("404 Referenced EDI 850 Purchase Order Not Found")
	ErrPayPalOrderVerificationFailed = errors.New("502 PayPal Orders v2 Readback Verification Failed")
	ErrPayPalCaptureNotCompleted     = errors.New("402 PayPal Order Not Yet Approved or Captured on PayPal Servers")
)

// LineItem represents an integer-cent commercial line item in an EDI 850 PO or EDI 810 Invoice.
type LineItem struct {
	LineNumber     string `json:"line_number"`
	Quantity       int64  `json:"quantity"`
	UOM            string `json:"uom"`
	UnitPriceCents int64  `json:"unit_price_cents"`
	VendorSKU      string `json:"vendor_sku"`
}

// EDI850PO represents an originating ANSI X12 850 Purchase Order.
type EDI850PO struct {
	PONumber   string     `json:"po_number"`
	PODate     string     `json:"po_date"`
	BuyerName  string     `json:"buyer_name"`
	BuyerID    string     `json:"buyer_id"`
	SellerName string     `json:"seller_name"`
	SellerID   string     `json:"seller_id"`
	Lines      []LineItem `json:"lines"`
	TotalCents int64      `json:"total_cents"`
	RawX12     string     `json:"raw_x12"`
	SHA256Hex  string     `json:"sha256_hex"`
}

// ReceivedLine represents a warehouse-verified line item in an ANSI X12 861 Receiving Advice.
type ReceivedLine struct {
	LineNumber       string `json:"line_number"`
	AcceptedQuantity int64  `json:"accepted_quantity"`
	RejectedQuantity int64  `json:"rejected_quantity"`
	UOM              string `json:"uom"`
	VendorSKU        string `json:"vendor_sku"`
}

// EDI861Receipt represents an ANSI X12 861 Receiving Advice / Acceptance Certificate.
type EDI861Receipt struct {
	ReceiptNumber string         `json:"receipt_number"`
	ReceiptDate   string         `json:"receipt_date"`
	PONumber      string         `json:"po_number"`
	ConditionCode string         `json:"condition_code"`
	Lines         []ReceivedLine `json:"lines"`
	RawX12        string         `json:"raw_x12"`
	SHA256Hex     string         `json:"sha256_hex"`
}

// EDI810Invoice represents an incoming ANSI X12 810 Commercial Invoice.
type EDI810Invoice struct {
	HasISA         bool           `json:"has_isa"`
	HasGS          bool           `json:"has_gs"`
	ISASenderID    string         `json:"isa_sender_id,omitempty"`
	ISAReceiverID  string         `json:"isa_receiver_id,omitempty"`
	ISAControl     string         `json:"isa_control"`
	GSFunctionalID string         `json:"gs_functional_id"`
	GSSenderID     string         `json:"gs_sender_id,omitempty"`
	GSReceiverID   string         `json:"gs_receiver_id,omitempty"`
	GSControl      string         `json:"gs_control"`
	GSVersion      string         `json:"gs_version"`
	STSetID        string         `json:"st_set_id"`
	STControl      string         `json:"st_control"`
	InvoiceDate    string         `json:"invoice_date"`
	InvoiceNumber  string         `json:"invoice_number"`
	PONumber       string         `json:"po_number"`
	SellerName     string         `json:"seller_name"`
	SellerID       string         `json:"seller_id"`
	PayPalOrderID  string         `json:"paypal_order_id,omitempty"`
	CADPayTo       string         `json:"cad_pay_to,omitempty"`
	ThirdPartyNote string         `json:"third_party_note,omitempty"`
	Notes          []string       `json:"notes,omitempty"`
	Lines          []LineItem     `json:"lines"`
	IT1Positions   []int          `json:"it1_positions,omitempty"`
	TotalCents     int64          `json:"total_cents"`
	SegmentPos     map[string]int `json:"segment_pos,omitempty"`
	RawX12         string         `json:"raw_x12"`
	SHA256Hex      string         `json:"sha256_hex"`
}

// SettlementEvaluationResult records the outcome of evaluating an EDI 810 Invoice.
// Honesty Invariant: SettlementAuthorized indicates that the 3-Way Match and guardrails passed.
// PayPalCaptured is true ONLY when a live POST /v2/checkout/orders/{id}/capture succeeded with COMPLETED.
type SettlementEvaluationResult struct {
	ProtocolVersion      string          `json:"protocol_version"`
	InvoiceNumber        string          `json:"invoice_number"`
	PONumber             string          `json:"po_number"`
	ReceiptNumber861     string          `json:"receipt_number_861,omitempty"`
	TotalCents           int64           `json:"total_cents"`
	EDI997AckCode        string          `json:"edi_997_ack_code"`
	ErrorSegmentID       string          `json:"error_segment_id,omitempty"`
	ErrorSegmentPos      int             `json:"error_segment_pos,omitempty"`
	RawEDI997            string          `json:"raw_edi_997"`
	RawEDI820            string          `json:"raw_edi_820,omitempty"`
	SettlementAuthorized bool            `json:"settlement_authorized"`
	PayPalCaptured       bool            `json:"paypal_captured"`
	PayPalOrderID        string          `json:"paypal_order_id,omitempty"`
	PayPalOrderStatus    string          `json:"paypal_order_status,omitempty"`
	PayPalCaptureID      string          `json:"paypal_capture_id,omitempty"`
	PayPalRequestID      string          `json:"paypal_request_id,omitempty"`
	AIAuditVerdict       *AIAuditVerdict `json:"ai_audit_verdict,omitempty"`
	ReceiptHeader        string          `json:"receipt_header"`
	ReceiptHashHex       string          `json:"receipt_hash_hex"`
	KeyID                string          `json:"kid,omitempty"`
	LedgerSeq            int64           `json:"ledger_seq,omitempty"`
	LedgerPrevHashHex    string          `json:"ledger_prev_hash_hex,omitempty"`
	LedgerEntryHashHex   string          `json:"ledger_entry_hash_hex,omitempty"`
	Ed25519PubKeyHex     string          `json:"ed25519_pub_key_hex"`
	Ed25519SignatureHex  string          `json:"ed25519_signature_hex,omitempty"`
	EDI820SignatureHex   string          `json:"edi_820_signature_hex,omitempty"`
}

// TinyGAAPConfig configures the fail-closed B2B x402-style + EDI + PayPal engine.
// By default, 3-Way Match (requiring an EDI 861 Receiving Advice) is strictly enforced
// unless AllowTwoWayMatch is explicitly set to true.
type TinyGAAPConfig struct {
	HMACSecret                []byte
	RollingHourlyLimitCents   int64
	WhitelistedPayTo          map[string]bool
	Require861Receipt         bool
	AllowTwoWayMatch          bool
	VerifyPayPalOrderOnSettle bool
	PayPalClientID            string
	PayPalClientSecret        string
	PayPalBaseURL             string
	HTTPClient                *http.Client
	Auditor                   AuditorAgent
	ControlNumberSeed         uint64
	Ed25519KeyFile            string
	InitEd25519Key            bool
	RequirePersistentKey      bool
	KeysDir                   string
	LedgerFile                string
	InitLedger                bool
}

type spendRecord struct {
	Timestamp time.Time
	Cents     int64
}

type authGrant struct {
	AgentKey       string
	SellerID       string
	InvoiceNumber  string
	PONumber       string
	PayPalOrderID  string
	TotalCents     int64
	ReceiptHashHex string
	ReceiptHeader  string
	Ed25519SigHex  string
	AuditorMode    string
	AuditorModel   string
	Captured       bool
	CaptureID      string
}

// TinyGAAPEngine enforces 3-Way Match (850 <-> 861 <-> 810), x402-style Payment-Signature gates,
// semantic auditing, rolling hourly circuit-breakers, and PayPal Orders v2 settlement.
type TinyGAAPEngine struct {
	mu               sync.Mutex
	cfg              TinyGAAPConfig
	pos              map[string]*EDI850PO
	receipts861      map[string]*EDI861Receipt
	settledInv       map[string]string
	settledSellerInv map[string]string
	boundOrders      map[string]string
	authGrants       map[string]*authGrant
	billedLines      map[string]map[string]int64
	agentSpend       map[string][]spendRecord
	globalSpend      []spendRecord
	edPriv           ed25519.PrivateKey
	edPub            ed25519.PublicKey
	keyID            string
	ledgerFile       *os.File
	ledgerSeq        int64
	ledgerLastHash   string
	httpClient       *http.Client
	auditor          AuditorAgent
	controlSeq       uint64
}

func hasSufficientEntropy(secret []byte) bool {
	if len(secret) < 16 {
		return false
	}
	seen := make(map[byte]struct{}, len(secret))
	for _, b := range secret {
		seen[b] = struct{}{}
	}
	return len(seen) >= 4
}

// NewTinyGAAPEngine initializes a fail-closed TinyGAAPEngine.
// Returns ErrMissingHMACSecret if cfg.HMACSecret has fewer than 16 bytes or is all-zero/trivial.
func NewTinyGAAPEngine(cfg TinyGAAPConfig) (*TinyGAAPEngine, error) {
	if !hasSufficientEntropy(cfg.HMACSecret) {
		return nil, ErrMissingHMACSecret
	}
	if cfg.PayPalBaseURL == "" {
		cfg.PayPalBaseURL = "https://api-m.sandbox.paypal.com"
	}
	if cfg.RollingHourlyLimitCents <= 0 {
		cfg.RollingHourlyLimitCents = 500000 // Default fail-closed $5,000.00/hr ceiling if unset
	}
	if !cfg.AllowTwoWayMatch {
		cfg.Require861Receipt = true
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	auditor := cfg.Auditor
	if auditor == nil {
		auditor = NewDefaultAIAuditorAgent(client)
	}

	keyPath := strings.TrimSpace(cfg.Ed25519KeyFile)
	if keyPath == "" {
		keyPath = strings.TrimSpace(os.Getenv("TINYGAAP_ED25519_KEY_FILE"))
	}
	keysDir := strings.TrimSpace(cfg.KeysDir)
	if keysDir == "" {
		keysDir = strings.TrimSpace(os.Getenv("TINYGAAP_KEYS_DIR"))
	}
	ledgerPath := strings.TrimSpace(cfg.LedgerFile)
	if ledgerPath == "" {
		ledgerPath = strings.TrimSpace(os.Getenv("TINYGAAP_LEDGER_FILE"))
	}
	cfg.Ed25519KeyFile = keyPath
	cfg.KeysDir = keysDir
	cfg.LedgerFile = ledgerPath

	if cfg.InitLedger && ledgerPath == "" {
		return nil, fmt.Errorf("%w: TINYGAAP_LEDGER_FILE is required when InitLedger is enabled", ErrLedgerInvalid)
	}
	if keyPath != "" && ledgerPath == "" {
		return nil, fmt.Errorf("%w: TINYGAAP_LEDGER_FILE is required when TINYGAAP_ED25519_KEY_FILE is configured", ErrLedgerInvalid)
	}

	var pub ed25519.PublicKey
	var priv ed25519.PrivateKey
	var keyID string
	if keyPath != "" {
		var err error
		priv, pub, err = loadOrInitEd25519Key0600(keyPath, cfg.InitEd25519Key, keysDir)
		if err != nil {
			return nil, err
		}
		keyID = ComputeKeyID(pub)
	} else {
		if cfg.RequirePersistentKey || cfg.InitEd25519Key {
			return nil, fmt.Errorf("%w: TINYGAAP_ED25519_KEY_FILE is required when persistent key custody is enabled", ErrKeyCustodyInvalid)
		}
		var err error
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ed25519 keygen failed: %w", err)
		}
		keyID = EphemeralKeyID
	}

	allowCopy := make(map[string]bool, len(cfg.WhitelistedPayTo))
	for k, v := range cfg.WhitelistedPayTo {
		if v {
			allowCopy[strings.TrimSpace(k)] = true
		}
	}
	cfg.WhitelistedPayTo = allowCopy

	secretCopy := make([]byte, len(cfg.HMACSecret))
	copy(secretCopy, cfg.HMACSecret)
	cfg.HMACSecret = secretCopy

	seqSeed := cfg.ControlNumberSeed
	if seqSeed == 0 {
		seqSeed = uint64(time.Now().UTC().Unix()%800000) + 1000
	}

	eng := &TinyGAAPEngine{
		cfg:              cfg,
		pos:              make(map[string]*EDI850PO),
		receipts861:      make(map[string]*EDI861Receipt),
		settledInv:       make(map[string]string),
		settledSellerInv: make(map[string]string),
		boundOrders:      make(map[string]string),
		authGrants:       make(map[string]*authGrant),
		billedLines:      make(map[string]map[string]int64),
		agentSpend:       make(map[string][]spendRecord),
		edPriv:           priv,
		edPub:            pub,
		keyID:            keyID,
		httpClient:       client,
		auditor:          auditor,
		controlSeq:       seqSeed,
	}
	if ledgerPath != "" {
		if err := eng.openLockAndReplayLedger(ledgerPath, cfg.InitLedger); err != nil {
			return nil, err
		}
	}
	return eng, nil
}

// PublicKeyHex returns the hex-encoded 32-byte Ed25519 public key of the engine instance.
func (e *TinyGAAPEngine) PublicKeyHex() string {
	return hex.EncodeToString(e.edPub)
}

var edi820TRNSigRegex = regexp.MustCompile(`(?m)^(TRN\*[^~\r\n]*\*)ED25519:([0-9a-fA-F]{128})(~)$`)

// CanonicalEDI820ForSigning replaces the single embedded ED25519:<128-hex> token in an EDI 820
// TRN segment with ED25519:<SIG> so the signature covers the full 820 document (including
// N1*PE payee, currency, amounts, PO SHA-256, 861 SHA-256, and authorization receipt hash).
// Returns "" if there is not exactly one ED25519: token anchored to the TRN segment.
func CanonicalEDI820ForSigning(raw820 string) string {
	if strings.Count(raw820, "ED25519:") != 1 {
		return ""
	}
	matches := edi820TRNSigRegex.FindAllStringSubmatchIndex(raw820, -1)
	if len(matches) != 1 {
		return ""
	}
	return edi820TRNSigRegex.ReplaceAllString(raw820, "${1}ED25519:<SIG>${3}")
}

// VerifyEDI820Signature extracts the single TRN-anchored ED25519:<sig> token from a full EDI 820
// document and verifies that it signs the complete canonical EDI 820 payload (C2 + C4).
func VerifyEDI820Signature(pubKeyHex, raw820 string) bool {
	if strings.Count(raw820, "ED25519:") != 1 {
		return false
	}
	sub := edi820TRNSigRegex.FindStringSubmatch(raw820)
	if len(sub) != 4 {
		return false
	}
	sigHex := sub[2]
	canonical := CanonicalEDI820ForSigning(raw820)
	if canonical == "" {
		return false
	}
	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubBytes), []byte(canonical), sigBytes)
}

// VerifyReceiptSignature verifies a 64-byte hex-encoded Ed25519 signature over a receipt header
// or an EDI 820 document.
func VerifyReceiptSignature(pubKeyHex, message, sigHex string) bool {
	if strings.HasPrefix(message, "ISA*") {
		if sigHex == "" || !strings.Contains(message, "ED25519:"+sigHex) {
			return false
		}
		return VerifyEDI820Signature(pubKeyHex, message)
	}
	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubBytes), []byte(message), sigBytes)
}

// VerifyReceiptHMAC verifies the HMAC-SHA256 tag embedded at the end of a receipt_header ("...;hmac=<64-hex>").
// Rejects headers with multiple ";hmac=" tags or any trailing parameters after the HMAC digest.
func VerifyReceiptHMAC(hmacSecret []byte, receiptHeader string) bool {
	if !hasSufficientEntropy(hmacSecret) {
		return false
	}
	if strings.Count(receiptHeader, ";hmac=") != 1 {
		return false
	}
	idx := strings.LastIndex(receiptHeader, ";hmac=")
	if idx <= 0 {
		return false
	}
	core := receiptHeader[:idx]
	gotHex := strings.TrimSpace(receiptHeader[idx+len(";hmac="):])
	if strings.Contains(gotHex, ";") {
		return false
	}
	gotBytes, err := hex.DecodeString(gotHex)
	if err != nil || len(gotBytes) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, hmacSecret)
	mac.Write([]byte(core))
	return hmac.Equal(gotBytes, mac.Sum(nil))
}

// SignX402PaymentHeader computes a cryptographic x402 Payment-Signature header binding the
// request to the SHA-256 digest of the raw EDI 810 payload using HMAC-SHA256.
func SignX402PaymentHeader(hmacSecret []byte, raw810 string) string {
	bodyHash := sha256.Sum256([]byte(raw810))
	mac := hmac.New(sha256.New, hmacSecret)
	mac.Write([]byte("exact:x402:paypal-order-v2|" + hex.EncodeToString(bodyHash[:])))
	return "exact:x402:paypal-order-v2:sig=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyX402PaymentHeader cryptographically verifies an x402 Payment-Signature header against the raw EDI 810 body.
func VerifyX402PaymentHeader(hmacSecret []byte, raw810, headerVal string) bool {
	if !hasSufficientEntropy(hmacSecret) {
		return false
	}
	const prefix = "exact:x402:paypal-order-v2:sig="
	headerVal = strings.TrimSpace(headerVal)
	if !strings.HasPrefix(headerVal, prefix) {
		return false
	}
	sigHex := strings.TrimSpace(headerVal[len(prefix):])
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != sha256.Size {
		return false
	}
	bodyHash := sha256.Sum256([]byte(raw810))
	mac := hmac.New(sha256.New, hmacSecret)
	mac.Write([]byte("exact:x402:paypal-order-v2|" + hex.EncodeToString(bodyHash[:])))
	return hmac.Equal(sigBytes, mac.Sum(nil))
}

// SignX402Header is a convenience method on TinyGAAPEngine that signs an EDI 810 payload for ServeSettle810.
func (e *TinyGAAPEngine) SignX402Header(raw810 string) string {
	return SignX402PaymentHeader(e.cfg.HMACSecret, raw810)
}

// ParseCentsDecimal strictly converts a USD decimal string (e.g. "125.00" or "60.5") into integer cents.
// Rejects empty strings, signed numbers ("-" or "+"), >2 fractional digits, and non-numeric characters.
func ParseCentsDecimal(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty decimal amount")
	}
	if strings.HasPrefix(s, "-") || strings.HasPrefix(s, "+") {
		return 0, fmt.Errorf("signed decimal not permitted: %q", s)
	}
	parts := strings.Split(s, ".")
	if len(parts) > 2 || parts[0] == "" {
		return 0, fmt.Errorf("malformed decimal amount: %q", s)
	}
	for _, ch := range parts[0] {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("non-digit in dollar amount %q", s)
		}
	}
	dollars, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || dollars < 0 {
		return 0, fmt.Errorf("invalid dollar integer in %q: %w", s, err)
	}
	if len(parts) == 1 {
		return dollars * 100, nil
	}
	frac := parts[1]
	if len(frac) == 0 || len(frac) > 2 {
		return 0, fmt.Errorf("fractional cents must be 1 or 2 digits in %q", s)
	}
	for _, ch := range frac {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("non-digit in fractional cents %q", s)
		}
	}
	if len(frac) == 1 {
		frac += "0"
	}
	cents, err := strconv.ParseInt(frac, 10, 64)
	if err != nil || cents < 0 {
		return 0, fmt.Errorf("invalid fractional cents in %q: %w", s, err)
	}
	return dollars*100 + cents, nil
}

// FormatCentsDecimal formats integer cents into a 2-decimal string (e.g. 12500 -> "125.00").
func FormatCentsDecimal(cents int64) string {
	sign := ""
	if cents < 0 {
		sign = "-"
		cents = -cents
	}
	return fmt.Sprintf("%s%d.%02d", sign, cents/100, cents%100)
}

func splitX12Segments(raw string) ([][]string, error) {
	trimmedRaw := strings.TrimSpace(raw)
	if trimmedRaw == "" {
		return nil, fmt.Errorf("%w: empty X12 payload", ErrX12MalformedEnvelope)
	}
	elemSep := "*"
	segTerm := "~"
	if strings.HasPrefix(trimmedRaw, "ISA") {
		if len(trimmedRaw) < 106 {
			return nil, fmt.Errorf("%w: ISA segment shorter than 106 characters (%d)", ErrX12MalformedEnvelope, len(trimmedRaw))
		}
		elemSep = string(trimmedRaw[3])
		segTerm = string(trimmedRaw[105])
		if elemSep == "" || segTerm == "" || elemSep == segTerm || (elemSep >= "A" && elemSep <= "Z") || (elemSep >= "0" && elemSep <= "9") {
			return nil, fmt.Errorf("%w: invalid ISA element/segment delimiters (%q, %q)", ErrX12MalformedEnvelope, elemSep, segTerm)
		}
	}
	var out [][]string
	rawSegs := strings.Split(trimmedRaw, segTerm)
	for _, rs := range rawSegs {
		trimmed := strings.TrimSpace(rs)
		if trimmed == "" {
			continue
		}
		out = append(out, strings.Split(trimmed, elemSep))
	}
	return out, nil
}

// ParseEDI850 parses an ANSI X12 850 Purchase Order into an EDI850PO struct.
func ParseEDI850(raw string) (*EDI850PO, error) {
	segs, err := splitX12Segments(raw)
	if err != nil || len(segs) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: empty EDI 850 payload", ErrX12MalformedEnvelope)
	}
	h := sha256.Sum256([]byte(raw))
	po := &EDI850PO{
		RawX12:    raw,
		SHA256Hex: hex.EncodeToString(h[:]),
	}
	var sumLineCents int64
	var hasAMT, sawISA, sawGS, sawST, sawSE bool
	var stCount, declaredSE int
	var inST bool
	var stCtrl, seCtrl, gsCtrl, geCtrl, isaCtrl, ieaCtrl string

	for _, el := range segs {
		segID := el[0]
		if segID == "ISA" {
			rawISA := strings.Join(el, "*") + "~"
			if len(rawISA) != 106 || len(el) != 17 {
				return nil, fmt.Errorf("%w: EDI 850 ISA segment length is %d (want 106)", ErrX12MalformedEnvelope, len(rawISA))
			}
			isaCtrl = strings.TrimSpace(el[13])
			sawISA = true
		}
		if segID == "GS" {
			if len(el) < 7 || strings.TrimSpace(el[1]) != "PO" {
				return nil, fmt.Errorf("%w: EDI 850 requires GS01='PO'", ErrX12MalformedEnvelope)
			}
			gsCtrl = strings.TrimSpace(el[6])
			sawGS = true
		}
		if segID == "ST" {
			if len(el) < 3 || strings.TrimSpace(el[1]) != "850" {
				return nil, fmt.Errorf("%w: EDI 850 requires ST01='850'", ErrX12MalformedEnvelope)
			}
			inST = true
			sawST = true
			stCount = 0
			stCtrl = strings.TrimSpace(el[2])
		}
		if inST {
			stCount++
		}
		switch segID {
		case "BEG":
			if len(el) < 4 || strings.TrimSpace(el[3]) == "" {
				return nil, fmt.Errorf("%w: malformed BEG segment in EDI 850", ErrX12MalformedEnvelope)
			}
			po.PONumber = strings.TrimSpace(el[3])
			if len(el) > 5 {
				po.PODate = strings.TrimSpace(el[5])
			}
		case "N1":
			if len(el) >= 3 {
				role := strings.TrimSpace(el[1])
				name := strings.TrimSpace(el[2])
				id := ""
				if len(el) >= 5 {
					id = strings.TrimSpace(el[4])
				}
				switch role {
				case "BY":
					po.BuyerName = name
					po.BuyerID = id
				case "SE":
					po.SellerName = name
					po.SellerID = id
				}
			}
		case "PO1":
			if len(el) < 5 {
				return nil, fmt.Errorf("%w: malformed PO1 segment in EDI 850", ErrX12MalformedEnvelope)
			}
			qty, err := strconv.ParseInt(strings.TrimSpace(el[2]), 10, 64)
			if err != nil || qty <= 0 {
				return nil, fmt.Errorf("%w: invalid PO102 quantity %q", ErrX12MalformedEnvelope, el[2])
			}
			unitCents, err := ParseCentsDecimal(el[4])
			if err != nil || unitCents <= 0 {
				return nil, fmt.Errorf("%w: invalid PO104 unit price %q: %v", ErrX12MalformedEnvelope, el[4], err)
			}
			sku := ""
			for i := 5; i+1 < len(el); i++ {
				if el[i] == "VP" || el[i] == "BP" {
					sku = strings.TrimSpace(el[i+1])
					break
				}
			}
			if sku == "" {
				return nil, fmt.Errorf("%w: missing VP/BP SKU in PO1 segment", ErrX12MalformedEnvelope)
			}
			li := LineItem{
				LineNumber:     strings.TrimSpace(el[1]),
				Quantity:       qty,
				UOM:            strings.TrimSpace(el[3]),
				UnitPriceCents: unitCents,
				VendorSKU:      sku,
			}
			po.Lines = append(po.Lines, li)
			sumLineCents += qty * unitCents
		case "AMT":
			if len(el) >= 3 && el[1] == "TT" {
				amtCents, err := ParseCentsDecimal(el[2])
				if err != nil {
					return nil, fmt.Errorf("%w: invalid AMT*TT amount %q: %v", ErrX12MalformedEnvelope, el[2], err)
				}
				po.TotalCents = amtCents
				hasAMT = true
			}
		case "SE":
			if len(el) < 3 {
				return nil, fmt.Errorf("%w: malformed SE segment in EDI 850", ErrX12MalformedEnvelope)
			}
			n, err := strconv.Atoi(strings.TrimSpace(el[1]))
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("%w: invalid SE01 count in EDI 850", ErrX12MalformedEnvelope)
			}
			declaredSE = n
			seCtrl = strings.TrimSpace(el[2])
			sawSE = true
			inST = false
		case "GE":
			if len(el) >= 3 {
				geCtrl = strings.TrimSpace(el[2])
			}
		case "IEA":
			if len(el) >= 3 {
				ieaCtrl = strings.TrimSpace(el[2])
			}
		}
	}
	if !sawISA || !sawGS || !sawST || !sawSE {
		return nil, fmt.Errorf("%w: EDI 850 missing mandatory ISA/GS/ST/SE envelope", ErrX12MalformedEnvelope)
	}
	if po.PONumber == "" || len(po.Lines) == 0 {
		return nil, fmt.Errorf("%w: EDI 850 missing BEG03 PO Number or PO1 line items", ErrX12MalformedEnvelope)
	}
	if declaredSE != stCount {
		return nil, fmt.Errorf("%w: EDI 850 SE01 segment count %d != actual %d", ErrX12MalformedEnvelope, declaredSE, stCount)
	}
	if stCtrl != seCtrl {
		return nil, fmt.Errorf("%w: EDI 850 ST02 %q != SE02 %q", ErrX12MalformedEnvelope, stCtrl, seCtrl)
	}
	if gsCtrl != "" && geCtrl != "" && gsCtrl != geCtrl {
		return nil, fmt.Errorf("%w: EDI 850 GS06 %q != GE02 %q", ErrX12MalformedEnvelope, gsCtrl, geCtrl)
	}
	if isaCtrl != "" && ieaCtrl != "" && isaCtrl != ieaCtrl {
		return nil, fmt.Errorf("%w: EDI 850 ISA13 %q != IEA02 %q", ErrX12MalformedEnvelope, isaCtrl, ieaCtrl)
	}
	if !hasAMT {
		po.TotalCents = sumLineCents
	} else if po.TotalCents != sumLineCents {
		return nil, fmt.Errorf("%w: EDI 850 AMT*TT (%d) != sum of PO1 lines (%d)", ErrX12MalformedEnvelope, po.TotalCents, sumLineCents)
	}
	return po, nil
}

// ParseEDI861 parses an ANSI X12 861 Receiving Advice / Acceptance Certificate (BRA, PRF, RCD).
func ParseEDI861(raw string) (*EDI861Receipt, error) {
	segs, err := splitX12Segments(raw)
	if err != nil || len(segs) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: empty EDI 861 payload", ErrX12MalformedEnvelope)
	}
	h := sha256.Sum256([]byte(raw))
	rcpt := &EDI861Receipt{
		RawX12:    raw,
		SHA256Hex: hex.EncodeToString(h[:]),
	}
	var stCount, declaredSE int
	var inST, sawISA, sawGS, sawST, sawSE bool
	var stCtrl, seCtrl, gsCtrl, geCtrl, isaCtrl, ieaCtrl string

	for _, el := range segs {
		segID := el[0]
		if segID == "ISA" {
			rawISA := strings.Join(el, "*") + "~"
			if len(rawISA) != 106 || len(el) != 17 {
				return nil, fmt.Errorf("%w: EDI 861 ISA segment length is %d (want 106)", ErrX12MalformedEnvelope, len(rawISA))
			}
			isaCtrl = strings.TrimSpace(el[13])
			sawISA = true
		}
		if segID == "GS" {
			if len(el) < 7 || strings.TrimSpace(el[1]) != "RC" {
				return nil, fmt.Errorf("%w: EDI 861 requires GS01='RC'", ErrX12MalformedEnvelope)
			}
			gsCtrl = strings.TrimSpace(el[6])
			sawGS = true
		}
		if segID == "ST" {
			if len(el) < 3 || strings.TrimSpace(el[1]) != "861" {
				return nil, fmt.Errorf("%w: EDI 861 requires ST01='861'", ErrX12MalformedEnvelope)
			}
			inST = true
			sawST = true
			stCount = 0
			stCtrl = strings.TrimSpace(el[2])
		}
		if inST {
			stCount++
		}
		switch segID {
		case "BRA":
			if len(el) < 5 || strings.TrimSpace(el[1]) == "" {
				return nil, fmt.Errorf("%w: malformed BRA segment in EDI 861", ErrX12MalformedEnvelope)
			}
			rcpt.ReceiptNumber = strings.TrimSpace(el[1])
			rcpt.ReceiptDate = strings.TrimSpace(el[2])
			rcpt.ConditionCode = strings.TrimSpace(el[4])
		case "PRF":
			if len(el) < 2 || strings.TrimSpace(el[1]) == "" {
				return nil, fmt.Errorf("%w: missing PRF01 PO Number in EDI 861", ErrX12MalformedEnvelope)
			}
			rcpt.PONumber = strings.TrimSpace(el[1])
		case "RCD":
			if len(el) < 4 {
				return nil, fmt.Errorf("%w: malformed RCD segment in EDI 861", ErrX12MalformedEnvelope)
			}
			accQty, err := strconv.ParseInt(strings.TrimSpace(el[2]), 10, 64)
			if err != nil || accQty < 0 {
				return nil, fmt.Errorf("%w: invalid RCD02 accepted quantity %q", ErrX12MalformedEnvelope, el[2])
			}
			var rejQty int64
			if len(el) > 4 && strings.TrimSpace(el[4]) != "" {
				rejQty, err = strconv.ParseInt(strings.TrimSpace(el[4]), 10, 64)
				if err != nil || rejQty < 0 {
					return nil, fmt.Errorf("%w: invalid RCD04 rejected quantity %q", ErrX12MalformedEnvelope, el[4])
				}
			}
			sku := ""
			for i := 4; i+1 < len(el); i++ {
				if el[i] == "VP" || el[i] == "BP" {
					sku = strings.TrimSpace(el[i+1])
					break
				}
			}
			rcpt.Lines = append(rcpt.Lines, ReceivedLine{
				LineNumber:       strings.TrimSpace(el[1]),
				AcceptedQuantity: accQty,
				RejectedQuantity: rejQty,
				UOM:              strings.TrimSpace(el[3]),
				VendorSKU:        sku,
			})
		case "LIN":
			if len(rcpt.Lines) > 0 && len(el) >= 4 && (el[2] == "VP" || el[2] == "BP") {
				rcpt.Lines[len(rcpt.Lines)-1].VendorSKU = strings.TrimSpace(el[3])
			}
		case "SE":
			if len(el) < 3 {
				return nil, fmt.Errorf("%w: malformed SE segment in EDI 861", ErrX12MalformedEnvelope)
			}
			n, err := strconv.Atoi(strings.TrimSpace(el[1]))
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("%w: non-integer or non-positive SE01 in EDI 861", ErrX12MalformedEnvelope)
			}
			declaredSE = n
			seCtrl = strings.TrimSpace(el[2])
			sawSE = true
			inST = false
		case "GE":
			if len(el) >= 3 {
				geCtrl = strings.TrimSpace(el[2])
			}
		case "IEA":
			if len(el) >= 3 {
				ieaCtrl = strings.TrimSpace(el[2])
			}
		}
	}
	if !sawISA || !sawGS || !sawST || !sawSE {
		return nil, fmt.Errorf("%w: EDI 861 missing mandatory ISA/GS/ST/SE envelope", ErrX12MalformedEnvelope)
	}
	if rcpt.ReceiptNumber == "" || rcpt.PONumber == "" || len(rcpt.Lines) == 0 {
		return nil, fmt.Errorf("%w: EDI 861 missing BRA, PRF, or RCD segments", ErrX12MalformedEnvelope)
	}
	for _, rl := range rcpt.Lines {
		if strings.TrimSpace(rl.VendorSKU) == "" {
			return nil, fmt.Errorf("%w: missing VP/BP SKU in RCD or LIN segment of EDI 861", ErrX12MalformedEnvelope)
		}
	}
	if declaredSE != stCount {
		return nil, fmt.Errorf("%w: EDI 861 SE01 count %d != actual %d", ErrX12MalformedEnvelope, declaredSE, stCount)
	}
	if stCtrl != seCtrl {
		return nil, fmt.Errorf("%w: EDI 861 ST02 %q != SE02 %q", ErrX12MalformedEnvelope, stCtrl, seCtrl)
	}
	if gsCtrl != "" && geCtrl != "" && gsCtrl != geCtrl {
		return nil, fmt.Errorf("%w: EDI 861 GS06 %q != GE02 %q", ErrX12MalformedEnvelope, gsCtrl, geCtrl)
	}
	if isaCtrl != "" && ieaCtrl != "" && isaCtrl != ieaCtrl {
		return nil, fmt.Errorf("%w: EDI 861 ISA13 %q != IEA02 %q", ErrX12MalformedEnvelope, isaCtrl, ieaCtrl)
	}
	return rcpt, nil
}

// ParseEDI810 parses an ANSI X12 810 Commercial Invoice into an EDI810Invoice struct.
// Returns the offending segment ID (e.g. "IT1", "TDS", "SE", "ISA") alongside any syntax error.
func ParseEDI810(raw string) (*EDI810Invoice, string, int, error) {
	segs, err := splitX12Segments(raw)
	if err != nil || len(segs) == 0 {
		return nil, "ISA", 1, fmt.Errorf("%w: %v", ErrX12MalformedEnvelope, err)
	}
	h := sha256.Sum256([]byte(raw))
	inv := &EDI810Invoice{
		ISAControl: "000000001",
		GSVersion:  "005010",
		SegmentPos: make(map[string]int),
		RawX12:     raw,
		SHA256Hex:  hex.EncodeToString(h[:]),
	}
	var stPos, declaredSE, stOccurrences int
	var inST, sawTDS, sawISA, sawGS, sawST, sawSE bool
	var stCtrl, seCtrl, gsCtrl, geCtrl, isaCtrl, ieaCtrl string

	for _, el := range segs {
		segID := el[0]
		switch segID {
		case "ISA":
			rawISA := strings.Join(el, "*") + "~"
			if len(rawISA) != 106 || len(el) != 17 {
				return inv, "ISA", 1, fmt.Errorf("%w: EDI 810 ISA length is %d (want 106)", ErrX12MalformedEnvelope, len(rawISA))
			}
			inv.HasISA = true
			sawISA = true
			if len(el) >= 9 {
				inv.ISASenderID = strings.TrimSpace(el[6])
				inv.ISAReceiverID = strings.TrimSpace(el[8])
			}
			if len(el) >= 14 {
				isaCtrl = strings.TrimSpace(el[13])
				inv.ISAControl = isaCtrl
			}
		case "GS":
			if len(el) < 7 {
				return inv, "GS", 1, fmt.Errorf("%w: malformed GS segment in EDI 810", ErrX12MalformedEnvelope)
			}
			inv.HasGS = true
			sawGS = true
			inv.GSFunctionalID = strings.TrimSpace(el[1])
			inv.GSSenderID = strings.TrimSpace(el[2])
			inv.GSReceiverID = strings.TrimSpace(el[3])
			gsCtrl = strings.TrimSpace(el[6])
			inv.GSControl = gsCtrl
			if len(el) >= 9 {
				inv.GSVersion = strings.TrimSpace(el[8])
			}
			if inv.GSFunctionalID != "IN" {
				return inv, "GS", 1, fmt.Errorf("%w: EDI 810 requires GS01='IN', got %q", ErrX12MalformedEnvelope, inv.GSFunctionalID)
			}
		case "ST":
			stOccurrences++
			if stOccurrences > 1 {
				return inv, "ST", stPos + 1, fmt.Errorf("%w: multiple ST segments in a single EDI 810 interchange are not supported", ErrX12MalformedEnvelope)
			}
			if len(el) < 3 {
				return inv, "ST", 1, fmt.Errorf("%w: malformed ST segment in EDI 810", ErrX12MalformedEnvelope)
			}
			inST = true
			sawST = true
			stPos = 1
			inv.SegmentPos["ST"] = 1
			inv.STSetID = strings.TrimSpace(el[1])
			stCtrl = strings.TrimSpace(el[2])
			inv.STControl = stCtrl
			if inv.STSetID != "810" {
				return inv, "ST", 1, fmt.Errorf("%w: EDI 810 requires ST01='810', got %q", ErrX12MalformedEnvelope, inv.STSetID)
			}
			continue
		}

		if inST {
			stPos++
			if _, exists := inv.SegmentPos[segID]; !exists {
				inv.SegmentPos[segID] = stPos
			}
		}

		switch segID {
		case "BIG":
			if len(el) < 5 || strings.TrimSpace(el[2]) == "" || strings.TrimSpace(el[4]) == "" {
				return inv, "BIG", stPos, fmt.Errorf("%w: malformed BIG segment in EDI 810", ErrX12MalformedEnvelope)
			}
			inv.InvoiceDate = strings.TrimSpace(el[1])
			inv.InvoiceNumber = strings.TrimSpace(el[2])
			inv.PONumber = strings.TrimSpace(el[4])
		case "NTE":
			if len(el) >= 3 {
				qual := strings.TrimSpace(el[1])
				msg := strings.TrimSpace(el[2])
				inv.Notes = append(inv.Notes, qual+":"+msg)
				if qual == "3P" || qual == "ORI" || qual == "ALT" {
					inv.ThirdPartyNote = msg
				}
			}
		case "REF":
			if len(el) >= 3 && el[1] == "PP" {
				inv.PayPalOrderID = strings.TrimSpace(el[2])
			}
		case "N1":
			if len(el) >= 3 && el[1] == "SE" {
				inv.SellerName = strings.TrimSpace(el[2])
				if len(el) >= 5 {
					inv.SellerID = strings.TrimSpace(el[4])
				}
			}
		case "IT1":
			if len(el) < 5 {
				return inv, "IT1", stPos, fmt.Errorf("%w: malformed IT1 segment", ErrX12MalformedEnvelope)
			}
			qty, err := strconv.ParseInt(strings.TrimSpace(el[2]), 10, 64)
			if err != nil || qty <= 0 {
				return inv, "IT1", stPos, fmt.Errorf("%w: invalid or negative IT102 quantity %q", ErrX12MalformedEnvelope, el[2])
			}
			unitCents, err := ParseCentsDecimal(el[4])
			if err != nil || unitCents <= 0 {
				return inv, "IT1", stPos, fmt.Errorf("%w: invalid IT104 unit price %q: %v", ErrX12MalformedEnvelope, el[4], err)
			}
			sku := ""
			for i := 5; i+1 < len(el); i++ {
				if el[i] == "VP" || el[i] == "BP" {
					sku = strings.TrimSpace(el[i+1])
					break
				}
			}
			if sku == "" {
				return inv, "IT1", stPos, fmt.Errorf("%w: missing VP/BP SKU in IT1 segment", ErrX12MalformedEnvelope)
			}
			inv.Lines = append(inv.Lines, LineItem{
				LineNumber:     strings.TrimSpace(el[1]),
				Quantity:       qty,
				UOM:            strings.TrimSpace(el[3]),
				UnitPriceCents: unitCents,
				VendorSKU:      sku,
			})
			inv.IT1Positions = append(inv.IT1Positions, stPos)
		case "TDS":
			if len(el) < 2 || strings.TrimSpace(el[1]) == "" {
				return inv, "TDS", stPos, fmt.Errorf("%w: empty TDS01 segment", ErrX12MalformedEnvelope)
			}
			tdsRaw := strings.TrimSpace(el[1])
			// ANSI X12 TDS01 is N2 (implied cents, digits only; decimal points are illegal).
			for _, ch := range tdsRaw {
				if ch < '0' || ch > '9' {
					return inv, "TDS", stPos, fmt.Errorf("%w: TDS01 must be integer cents (N2) without decimal point, got %q", ErrX12MalformedEnvelope, tdsRaw)
				}
			}
			cents, err := strconv.ParseInt(tdsRaw, 10, 64)
			if err != nil || cents <= 0 {
				return inv, "TDS", stPos, fmt.Errorf("%w: invalid TDS01 integer cents %q", ErrX12MalformedEnvelope, tdsRaw)
			}
			inv.TotalCents = cents
			sawTDS = true
		case "CAD":
			if len(el) >= 7 {
				inv.CADPayTo = strings.TrimSpace(el[6])
			} else if len(el) >= 2 {
				inv.CADPayTo = strings.TrimSpace(el[len(el)-1])
			}
		case "SE":
			if len(el) < 3 {
				return inv, "SE", stPos, fmt.Errorf("%w: malformed SE segment in EDI 810", ErrX12MalformedEnvelope)
			}
			n, err := strconv.Atoi(strings.TrimSpace(el[1]))
			if err != nil || n <= 0 {
				return inv, "SE", stPos, fmt.Errorf("%w: non-integer or non-positive SE01 in EDI 810", ErrX12MalformedEnvelope)
			}
			declaredSE = n
			seCtrl = strings.TrimSpace(el[2])
			sawSE = true
			inST = false
		case "GE":
			if len(el) >= 3 {
				geCtrl = strings.TrimSpace(el[2])
			}
		case "IEA":
			if len(el) >= 3 {
				ieaCtrl = strings.TrimSpace(el[2])
			}
		}
	}

	if !sawISA || !sawGS || !sawST || !sawSE {
		missingSeg := "ISA"
		if sawISA && !sawGS {
			missingSeg = "GS"
		} else if sawISA && sawGS && !sawST {
			missingSeg = "ST"
		} else if sawST && !sawSE {
			missingSeg = "SE"
		}
		return inv, missingSeg, stPos, fmt.Errorf("%w: EDI 810 missing mandatory %s envelope segment", ErrX12MalformedEnvelope, missingSeg)
	}
	if declaredSE != stPos {
		return inv, "SE", stPos, fmt.Errorf("%w: EDI 810 SE01 declared %d segments, actual ST..SE count is %d", ErrX12MalformedEnvelope, declaredSE, stPos)
	}
	if stCtrl != seCtrl {
		return inv, "SE", stPos, fmt.Errorf("%w: EDI 810 ST02 (%s) != SE02 (%s)", ErrX12MalformedEnvelope, stCtrl, seCtrl)
	}
	if gsCtrl != "" && geCtrl != "" && gsCtrl != geCtrl {
		return inv, "GE", stPos, fmt.Errorf("%w: EDI 810 GS06 (%s) != GE02 (%s)", ErrX12MalformedEnvelope, gsCtrl, geCtrl)
	}
	if isaCtrl != "" && ieaCtrl != "" && isaCtrl != ieaCtrl {
		return inv, "IEA", stPos, fmt.Errorf("%w: EDI 810 ISA13 (%s) != IEA02 (%s)", ErrX12MalformedEnvelope, isaCtrl, ieaCtrl)
	}
	if inv.InvoiceNumber == "" || inv.PONumber == "" {
		return inv, "BIG", inv.SegmentPos["BIG"], fmt.Errorf("%w: EDI 810 missing BIG02 InvoiceNumber or BIG04 PONumber", ErrX12MalformedEnvelope)
	}
	if len(inv.Lines) == 0 {
		return inv, "IT1", 1, fmt.Errorf("%w: EDI 810 contains zero IT1 line items", ErrX12MalformedEnvelope)
	}
	if !sawTDS {
		return inv, "TDS", stPos, fmt.Errorf("%w: EDI 810 missing mandatory TDS segment", ErrX12MalformedEnvelope)
	}
	return inv, "", 0, nil
}

// RegisterPO850 parses and registers a canonical EDI 850 Purchase Order in the engine.
// Note: Does NOT auto-populate WhitelistedPayTo; allowlist entries must be explicitly configured by the buyer.
func (e *TinyGAAPEngine) RegisterPO850(raw850 string) (*EDI850PO, error) {
	po, err := ParseEDI850(raw850)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pos[po.PONumber] = po
	return po, nil
}

// RegisterReceivingAdvice861 parses and registers a warehouse EDI 861 Receiving Advice for 3-Way Match.
func (e *TinyGAAPEngine) RegisterReceivingAdvice861(raw861 string) (*EDI861Receipt, error) {
	rcpt, err := ParseEDI861(raw861)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.receipts861[rcpt.PONumber] = rcpt
	return rcpt, nil
}

// SeedAgentSpendCents records prior agentic spend (in integer cents) within the rolling 1-hour window.
func (e *TinyGAAPEngine) SeedAgentSpendCents(agentKey string, amountCents int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now().UTC()
	rec := spendRecord{
		Timestamp: now,
		Cents:     amountCents,
	}
	e.agentSpend[agentKey] = append(e.agentSpend[agentKey], rec)
	e.globalSpend = append(e.globalSpend, rec)
}

func (e *TinyGAAPEngine) nextControlNumbers() (isaCtrl string, gsCtrl string, stCtrl string, yymmdd string, yyyymmdd string, hhmm string) {
	seq := atomic.AddUint64(&e.controlSeq, 1)
	now := time.Now().UTC()
	return fmt.Sprintf("%09d", seq%1000000000),
		fmt.Sprintf("%d", seq),
		fmt.Sprintf("%04d", seq%10000),
		now.Format("060102"),
		now.Format("20060102"),
		now.Format("1504")
}

func padISA15(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		s = "TINYGAAP"
	}
	if len(s) > 15 {
		return s[:15]
	}
	return fmt.Sprintf("%-15s", s)
}

// buildEDI997 generates an ANSI X12 997 Functional Acknowledgment echoing the incoming
// GS01/GS06 and ST01/ST02 control numbers, swapping ISA/GS sender/receiver IDs, and reporting AK3/AK4 positions.
func (e *TinyGAAPEngine) buildEDI997(inv *EDI810Invoice, ackCode string, errSegID string, errSegPos int, errCode string) string {
	isaCtrl, gsCtrl, stCtrl, yymmdd, yyyymmdd, hhmm := e.nextControlNumbers()
	inGSFunc := "FA"
	inGSCtrl := "0"
	inSTSet := "810"
	inSTCtrl := "0000"
	gsVer := "005010"
	outSenderISA := padISA15("TINYGAAP")
	outReceiverISA := padISA15("VENDORAGENT")
	outSenderGS := "TINYGAAP"
	outReceiverGS := "VENDORAGENT"

	if inv != nil {
		if inv.HasGS {
			if inv.GSFunctionalID != "" {
				inGSFunc = inv.GSFunctionalID
			}
			if inv.GSControl != "" {
				inGSCtrl = inv.GSControl
			}
		}
		if inv.STSetID != "" {
			inSTSet = inv.STSetID
		}
		if inv.STControl != "" {
			inSTCtrl = inv.STControl
		}
		if inv.GSVersion != "" {
			gsVer = inv.GSVersion
		}
		if inv.ISAReceiverID != "" {
			outSenderISA = padISA15(inv.ISAReceiverID)
		}
		if inv.ISASenderID != "" {
			outReceiverISA = padISA15(inv.ISASenderID)
		}
		if inv.GSReceiverID != "" {
			outSenderGS = inv.GSReceiverID
		}
		if inv.GSSenderID != "" {
			outReceiverGS = inv.GSSenderID
		}
	}
	// Fixed 106-character ISA header
	isaUsage := e.isaUsageIndicator()
	isa := fmt.Sprintf("ISA*00*          *00*          *ZZ*%s*ZZ*%s*%s*%s*^*00501*%s*0*%s*:~", outSenderISA, outReceiverISA, yymmdd, hhmm, isaCtrl, isaUsage)
	gs := fmt.Sprintf("GS*FA*%s*%s*%s*%s00*%s*X*%s~", outSenderGS, outReceiverGS, yyyymmdd, hhmm, gsCtrl, gsVer)

	var body []string
	body = append(body, fmt.Sprintf("ST*997*%s~", stCtrl))
	body = append(body, fmt.Sprintf("AK1*%s*%s~", inGSFunc, inGSCtrl))
	body = append(body, fmt.Sprintf("AK2*%s*%s~", inSTSet, inSTCtrl))
	if ackCode == "R" && errSegID != "" {
		if errSegPos <= 0 {
			errSegPos = 1
		}
		if errCode == "" {
			errCode = "FAIL-CLOSED-GUARDRAIL"
		}
		body = append(body, fmt.Sprintf("AK3*%s*%d**8~", errSegID, errSegPos))
		body = append(body, fmt.Sprintf("AK4*1**7*%s~", errCode))
	}
	body = append(body, fmt.Sprintf("AK5*%s~", ackCode))
	if ackCode == "A" {
		body = append(body, "AK9*A*1*1*1~")
	} else {
		body = append(body, "AK9*R*1*1*0~")
	}
	seCount := len(body) + 1
	body = append(body, fmt.Sprintf("SE*%d*%s~", seCount, stCtrl))

	ge := fmt.Sprintf("GE*1*%s~", gsCtrl)
	iea := fmt.Sprintf("IEA*1*%s~", isaCtrl)

	all := append([]string{isa, gs}, body...)
	all = append(all, ge, iea)
	return strings.Join(all, "\n")
}

// buildEDI820 generates an ANSI X12 820 Payment Order/Remittance Advice and signs the full
// canonical 820 payload (covering N1*PE payee, currency, amounts, PO SHA-256, 861 SHA-256, and auth receipt hash).
// Called ONLY when PayPalCaptured is true with a verified PayPalCaptureID.
func (e *TinyGAAPEngine) buildEDI820(po *EDI850PO, rcpt861 *EDI861Receipt, inv *EDI810Invoice, authReceiptHashHex, ppOrderID, ppCaptureID string) (raw820 string, sigHex string) {
	return e.buildEDI820WithLedger(po, rcpt861, inv, authReceiptHashHex, ppOrderID, ppCaptureID, 0, "")
}

func (e *TinyGAAPEngine) buildEDI820WithLedger(po *EDI850PO, rcpt861 *EDI861Receipt, inv *EDI810Invoice, authReceiptHashHex, ppOrderID, ppCaptureID string, ledgerSeq int64, ledgerEntryHashHex string) (raw820 string, sigHex string) {
	isaCtrl, gsCtrl, stCtrl, yymmdd, yyyymmdd, hhmm := e.nextControlNumbers()
	amtStr := FormatCentsDecimal(inv.TotalCents)
	envLabel := e.paypalEnvLabel()
	isaUsage := e.isaUsageIndicator()

	outReceiverISA := padISA15("VENDORAGENT")
	outReceiverGS := "VENDORAGENT"
	if inv != nil {
		if strings.TrimSpace(inv.ISASenderID) != "" {
			outReceiverISA = padISA15(inv.ISASenderID)
		}
		if strings.TrimSpace(inv.GSSenderID) != "" {
			outReceiverGS = strings.TrimSpace(inv.GSSenderID)
		}
	}

	isa := fmt.Sprintf("ISA*00*          *00*          *ZZ*TINYGAAP       *ZZ*%s*%s*%s*^*00501*%s*0*%s*:~", outReceiverISA, yymmdd, hhmm, isaCtrl, isaUsage)
	gs := fmt.Sprintf("GS*RA*TINYGAAP*%s*%s*%s00*%s*X*005010~", outReceiverGS, yyyymmdd, hhmm, gsCtrl)

	body := []string{
		fmt.Sprintf("ST*820*%s~", stCtrl),
		fmt.Sprintf("BPR*I*%s*C*PAYPAL*CTX*01*%s*DA*%s*1999999999**01*%s*DA*%s*%s~",
			amtStr, envLabel, po.BuyerID, envLabel, inv.SellerID, yyyymmdd),
		fmt.Sprintf("TRN*1*%s*1999999999*ED25519:<SIG>~", ppCaptureID),
		"CUR*BY*USD~",
		fmt.Sprintf("REF*PP*%s*CAPTURE:%s~", ppOrderID, ppCaptureID),
		fmt.Sprintf("REF*PO*%s*SHA256:%s~", po.PONumber, po.SHA256Hex),
	}
	if rcpt861 != nil && rcpt861.ReceiptNumber != "" {
		body = append(body, fmt.Sprintf("REF*R8*%s*SHA256:%s~", rcpt861.ReceiptNumber, rcpt861.SHA256Hex))
	}
	if strings.TrimSpace(authReceiptHashHex) != "" {
		body = append(body, fmt.Sprintf("REF*AR*%s~", strings.TrimSpace(authReceiptHashHex)))
	}
	if strings.TrimSpace(e.keyID) != "" {
		if ledgerSeq > 0 && len(ledgerEntryHashHex) >= 16 {
			body = append(body, fmt.Sprintf("REF*LK*%s*LSEQ:%d*LHASH:%s~", e.keyID, ledgerSeq, ledgerEntryHashHex[:16]))
		} else {
			body = append(body, fmt.Sprintf("REF*LK*%s~", e.keyID))
		}
	}
	body = append(body,
		fmt.Sprintf("N1*PR*%s*92*%s~", po.BuyerName, po.BuyerID),
		fmt.Sprintf("N1*PE*%s*92*%s~", po.SellerName, inv.SellerID),
		"ENT*1~",
		fmt.Sprintf("RMR*IV*%s**%s*%s~", inv.InvoiceNumber, amtStr, amtStr),
	)
	seCount := len(body) + 1
	body = append(body, fmt.Sprintf("SE*%d*%s~", seCount, stCtrl))
	ge := fmt.Sprintf("GE*1*%s~", gsCtrl)
	iea := fmt.Sprintf("IEA*1*%s~", isaCtrl)

	all := append([]string{isa, gs}, body...)
	all = append(all, ge, iea)
	canonical820 := strings.Join(all, "\n")

	sig := ed25519.Sign(e.edPriv, []byte(canonical820))
	sigHex = hex.EncodeToString(sig)
	raw820 = strings.Replace(canonical820, "ED25519:<SIG>", "ED25519:"+sigHex, 1)
	return raw820, sigHex
}

func (e *TinyGAAPEngine) isaUsageIndicator() string {
	if e.paypalEnvLabel() == "PAYPAL-SANDBOX" {
		return "T"
	}
	return "P"
}

func sanitizeReceiptToken(s string) string {
	s = strings.TrimSpace(s)
	r := strings.NewReplacer(";", "_", "=", "_", "\r", "", "\n", "")
	out := r.Replace(s)
	if out == "" {
		return "none"
	}
	return out
}

func (e *TinyGAAPEngine) paypalEnvLabel() string {
	if strings.Contains(strings.ToLower(e.cfg.PayPalBaseURL), "sandbox") {
		return "PAYPAL-SANDBOX"
	}
	return "PAYPAL-LIVE"
}

func (e *TinyGAAPEngine) shortHMAC(data string) string {
	mac := hmac.New(sha256.New, e.cfg.HMACSecret)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// DeterministicPayPalRequestID computes a deterministic 36-char hex idempotency key
// for order creation derived from the PO SHA-256, Invoice SHA-256, and Invoice Number.
func DeterministicPayPalRequestID(poSHA256, invSHA256, invoiceNumber string) string {
	h := sha256.Sum256([]byte("TINYGAAP-PP-REQ-V1|" + poSHA256 + "|" + invSHA256 + "|" + invoiceNumber))
	return hex.EncodeToString(h[:])[:36]
}

// DeterministicPayPalCaptureRequestID computes a distinct deterministic 36-char idempotency key
// for POST /v2/checkout/orders/{id}/capture so create and capture never share the same PayPal-Request-Id.
func DeterministicPayPalCaptureRequestID(receiptHashHex, orderID string) string {
	h := sha256.Sum256([]byte("TINYGAAP-PP-CAP-V1|" + receiptHashHex + "|" + orderID))
	return "cap-" + hex.EncodeToString(h[:])[:32]
}

// EvaluateAndSettle810 executes the fail-closed semantic audit, deterministic 3-Way Match
// (850 PO <-> 861 Receipt <-> 810 Invoice), allowlist check, cumulative PO billing guard,
// and rolling budget circuit-breaker.
func (e *TinyGAAPEngine) EvaluateAndSettle810(ctx context.Context, raw810 string, agentKey string, requestedPayTo string) (*SettlementEvaluationResult, error) {
	inv, syntaxSeg, syntaxPos, err := ParseEDI810(raw810)
	if err != nil {
		if syntaxSeg == "" {
			syntaxSeg = "ST"
		}
		res := &SettlementEvaluationResult{
			ProtocolVersion:  ProtocolVersion,
			EDI997AckCode:    "R",
			ErrorSegmentID:   syntaxSeg,
			ErrorSegmentPos:  syntaxPos,
			RawEDI997:        e.buildEDI997(inv, "R", syntaxSeg, syntaxPos, "X12-SYNTAX-ERROR"),
			Ed25519PubKeyHex: e.PublicKeyHex(),
		}
		if inv != nil {
			res.InvoiceNumber = inv.InvoiceNumber
			res.PONumber = inv.PONumber
		}
		return res, err
	}

	e.mu.Lock()
	po, ok := e.pos[inv.PONumber]
	rcpt861, has861 := e.receipts861[inv.PONumber]
	e.mu.Unlock()

	if !ok {
		bigPos := inv.SegmentPos["BIG"]
		return &SettlementEvaluationResult{
			ProtocolVersion:  ProtocolVersion,
			InvoiceNumber:    inv.InvoiceNumber,
			PONumber:         inv.PONumber,
			TotalCents:       inv.TotalCents,
			EDI997AckCode:    "R",
			ErrorSegmentID:   "BIG",
			ErrorSegmentPos:  bigPos,
			RawEDI997:        e.buildEDI997(inv, "R", "BIG", bigPos, "PO-NOT-FOUND"),
			Ed25519PubKeyHex: e.PublicKeyHex(),
		}, ErrPONotFound
	}

	// 1. Fail-Closed Semantic Auditor Veto & Beneficiary Hijack Guardrail
	verdict, auditErr := e.auditor.AuditInvoiceSemantics(ctx, po, rcpt861, inv)
	payTo := strings.TrimSpace(requestedPayTo)
	if payTo == "" {
		payTo = inv.SellerID
	}

	e.mu.Lock()
	whitelisted := len(e.cfg.WhitelistedPayTo) > 0 && e.cfg.WhitelistedPayTo[payTo]
	e.mu.Unlock()

	if inv.ThirdPartyNote != "" {
		ntePos := inv.SegmentPos["NTE"]
		return &SettlementEvaluationResult{
			ProtocolVersion:  ProtocolVersion,
			InvoiceNumber:    inv.InvoiceNumber,
			PONumber:         inv.PONumber,
			TotalCents:       inv.TotalCents,
			EDI997AckCode:    "R",
			ErrorSegmentID:   "NTE",
			ErrorSegmentPos:  ntePos,
			RawEDI997:        e.buildEDI997(inv, "R", "NTE", ntePos, "UNAPPROVED-3P-NOTE"),
			AIAuditVerdict:   verdict,
			Ed25519PubKeyHex: e.PublicKeyHex(),
		}, ErrUnapprovedBeneficiary
	}

	if auditErr != nil || verdict == nil || strings.ToUpper(strings.TrimSpace(verdict.Decision)) != "APPROVE" || strings.TrimSpace(verdict.Mode) == "" || strings.TrimSpace(verdict.ModelID) == "" || strings.TrimSpace(agentKey) == "" || verdict.DetectedPromptInjection || verdict.DetectedRemittanceTamper || verdict.RiskScore >= 50 {
		ntePos := inv.SegmentPos["NTE"]
		if ntePos == 0 {
			ntePos = inv.SegmentPos["N1"]
		}
		return &SettlementEvaluationResult{
			ProtocolVersion:  ProtocolVersion,
			InvoiceNumber:    inv.InvoiceNumber,
			PONumber:         inv.PONumber,
			TotalCents:       inv.TotalCents,
			EDI997AckCode:    "R",
			ErrorSegmentID:   "NTE",
			ErrorSegmentPos:  ntePos,
			RawEDI997:        e.buildEDI997(inv, "R", "NTE", ntePos, "AUDITOR-VETO"),
			AIAuditVerdict:   verdict,
			Ed25519PubKeyHex: e.PublicKeyHex(),
		}, ErrAIAuditorRejected
	}

	if inv.CADPayTo != "" && !strings.EqualFold(inv.CADPayTo, po.SellerID) {
		cadPos := inv.SegmentPos["CAD"]
		return &SettlementEvaluationResult{
			ProtocolVersion:  ProtocolVersion,
			InvoiceNumber:    inv.InvoiceNumber,
			PONumber:         inv.PONumber,
			TotalCents:       inv.TotalCents,
			EDI997AckCode:    "R",
			ErrorSegmentID:   "CAD",
			ErrorSegmentPos:  cadPos,
			RawEDI997:        e.buildEDI997(inv, "R", "CAD", cadPos, "CAD-PAYTO-MISMATCH"),
			AIAuditVerdict:   verdict,
			Ed25519PubKeyHex: e.PublicKeyHex(),
		}, ErrUnapprovedBeneficiary
	}

	if !whitelisted || !strings.EqualFold(payTo, po.SellerID) || (inv.SellerID != "" && !strings.EqualFold(inv.SellerID, po.SellerID)) {
		n1Pos := inv.SegmentPos["N1"]
		return &SettlementEvaluationResult{
			ProtocolVersion:  ProtocolVersion,
			InvoiceNumber:    inv.InvoiceNumber,
			PONumber:         inv.PONumber,
			TotalCents:       inv.TotalCents,
			EDI997AckCode:    "R",
			ErrorSegmentID:   "N1",
			ErrorSegmentPos:  n1Pos,
			RawEDI997:        e.buildEDI997(inv, "R", "N1", n1Pos, "BENEFICIARY-NOT-ALLOWLISTED"),
			AIAuditVerdict:   verdict,
			Ed25519PubKeyHex: e.PublicKeyHex(),
		}, ErrUnapprovedBeneficiary
	}

	// 2. Strict Integer-Cent 3-Way Match: EDI 850 (PO) <-> EDI 861 (Receiving Advice) <-> EDI 810 (Invoice)
	// Match lines by VendorSKU (allowing order-independent SKU matching while rejecting missing/extra SKUs or price/qty/UOM drift).
	poBySKU := make(map[string]LineItem, len(po.Lines))
	for _, pl := range po.Lines {
		poBySKU[pl.VendorSKU] = pl
	}
	var sumInvLineCents int64
	lineMismatch := false
	mismatchLineIdx := 0
	seenInvSKU := make(map[string]bool, len(inv.Lines))
	if len(inv.Lines) != len(po.Lines) {
		lineMismatch = true
	} else {
		for i, il := range inv.Lines {
			pl, exists := poBySKU[il.VendorSKU]
			if !exists || seenInvSKU[il.VendorSKU] || pl.Quantity != il.Quantity || pl.UnitPriceCents != il.UnitPriceCents || !strings.EqualFold(pl.UOM, il.UOM) {
				lineMismatch = true
				mismatchLineIdx = i
				break
			}
			seenInvSKU[il.VendorSKU] = true
			sumInvLineCents += il.Quantity * il.UnitPriceCents
		}
	}
	if lineMismatch || sumInvLineCents != po.TotalCents || inv.TotalCents != po.TotalCents {
		errSeg := "IT1"
		pos := inv.SegmentPos["IT1"]
		if lineMismatch && mismatchLineIdx < len(inv.IT1Positions) {
			pos = inv.IT1Positions[mismatchLineIdx]
		}
		if !lineMismatch && inv.TotalCents != po.TotalCents {
			errSeg = "TDS"
			pos = inv.SegmentPos["TDS"]
		}
		return &SettlementEvaluationResult{
			ProtocolVersion:  ProtocolVersion,
			InvoiceNumber:    inv.InvoiceNumber,
			PONumber:         inv.PONumber,
			TotalCents:       inv.TotalCents,
			EDI997AckCode:    "R",
			ErrorSegmentID:   errSeg,
			ErrorSegmentPos:  pos,
			RawEDI997:        e.buildEDI997(inv, "R", errSeg, pos, "PO-850-PRICE-QTY-DRIFT"),
			AIAuditVerdict:   verdict,
			Ed25519PubKeyHex: e.PublicKeyHex(),
		}, ErrEDI810PriceQtyDrift
	}

	// Enforce EDI 861 Receiving Advice (mandatory by default unless AllowTwoWayMatch is true)
	if (e.cfg.Require861Receipt || !e.cfg.AllowTwoWayMatch) && !has861 {
		pos := inv.SegmentPos["BIG"]
		return &SettlementEvaluationResult{
			ProtocolVersion:  ProtocolVersion,
			InvoiceNumber:    inv.InvoiceNumber,
			PONumber:         inv.PONumber,
			TotalCents:       inv.TotalCents,
			EDI997AckCode:    "R",
			ErrorSegmentID:   "BIG",
			ErrorSegmentPos:  pos,
			RawEDI997:        e.buildEDI997(inv, "R", "BIG", pos, "MISSING-861-RECEIPT"),
			AIAuditVerdict:   verdict,
			Ed25519PubKeyHex: e.PublicKeyHex(),
		}, ErrReceivingAdviceNotFound
	}
	rcptBySKU := make(map[string]ReceivedLine)
	if has861 {
		for _, rl := range rcpt861.Lines {
			rcptBySKU[rl.VendorSKU] = rl
		}
		rcptMismatch := rcpt861.ConditionCode == "4" || rcpt861.ConditionCode == "07"
		rcptMismatchIdx := 0
		if len(rcpt861.Lines) != len(inv.Lines) {
			rcptMismatch = true
		} else if !rcptMismatch {
			for i, il := range inv.Lines {
				rl, exists := rcptBySKU[il.VendorSKU]
				if !exists || rl.AcceptedQuantity != il.Quantity || !strings.EqualFold(rl.UOM, il.UOM) {
					rcptMismatch = true
					rcptMismatchIdx = i
					break
				}
			}
		}
		if rcptMismatch {
			pos := inv.SegmentPos["IT1"]
			if rcptMismatchIdx < len(inv.IT1Positions) {
				pos = inv.IT1Positions[rcptMismatchIdx]
			}
			return &SettlementEvaluationResult{
				ProtocolVersion:  ProtocolVersion,
				InvoiceNumber:    inv.InvoiceNumber,
				PONumber:         inv.PONumber,
				ReceiptNumber861: rcpt861.ReceiptNumber,
				TotalCents:       inv.TotalCents,
				EDI997AckCode:    "R",
				ErrorSegmentID:   "IT1",
				ErrorSegmentPos:  pos,
				RawEDI997:        e.buildEDI997(inv, "R", "IT1", pos, "EDI-861-RECEIVING-DRIFT"),
				AIAuditVerdict:   verdict,
				Ed25519PubKeyHex: e.PublicKeyHex(),
			}, ErrEDI861ReceivingDrift
		}
	}

	// Optional Live PayPal Order Readback Verification when REF*PP*<order_id> is present on the 810
	if inv.PayPalOrderID != "" && (e.cfg.VerifyPayPalOrderOnSettle || e.cfg.PayPalClientID != "") {
		if err := e.VerifyPayPalOrderBeforeCapture(ctx, inv.PayPalOrderID, po, inv.InvoiceNumber, inv.TotalCents); err != nil {
			refPos := inv.SegmentPos["REF"]
			return &SettlementEvaluationResult{
				ProtocolVersion:  ProtocolVersion,
				InvoiceNumber:    inv.InvoiceNumber,
				PONumber:         inv.PONumber,
				TotalCents:       inv.TotalCents,
				EDI997AckCode:    "R",
				ErrorSegmentID:   "REF",
				ErrorSegmentPos:  refPos,
				RawEDI997:        e.buildEDI997(inv, "R", "REF", refPos, "PAYPAL-READBACK-MISMATCH"),
				AIAuditVerdict:   verdict,
				Ed25519PubKeyHex: e.PublicKeyHex(),
			}, err
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// 3. Duplicate BIG02 Invoice Replay (Seller-Scoped), Cross-Invoice Order Reuse & Cumulative PO/861 Line Overbilling Guard
	sellerScopedKey := strings.ToLower(strings.TrimSpace(po.SellerID)) + "|" + inv.InvoiceNumber
	if _, alreadySettled := e.settledInv[inv.InvoiceNumber]; alreadySettled {
		if _, sellerSettled := e.settledSellerInv[sellerScopedKey]; sellerSettled {
			bigPos := inv.SegmentPos["BIG"]
			return &SettlementEvaluationResult{
				ProtocolVersion:  ProtocolVersion,
				InvoiceNumber:    inv.InvoiceNumber,
				PONumber:         inv.PONumber,
				TotalCents:       inv.TotalCents,
				EDI997AckCode:    "R",
				ErrorSegmentID:   "BIG",
				ErrorSegmentPos:  bigPos,
				RawEDI997:        e.buildEDI997(inv, "R", "BIG", bigPos, "DUPLICATE-BIG02-REPLAY"),
				AIAuditVerdict:   verdict,
				Ed25519PubKeyHex: e.PublicKeyHex(),
			}, ErrDuplicateInvoiceReplay
		}
	}
	if inv.PayPalOrderID != "" {
		if boundKey, alreadyBound := e.boundOrders[inv.PayPalOrderID]; alreadyBound && boundKey != sellerScopedKey {
			refPos := inv.SegmentPos["REF"]
			return &SettlementEvaluationResult{
				ProtocolVersion:  ProtocolVersion,
				InvoiceNumber:    inv.InvoiceNumber,
				PONumber:         inv.PONumber,
				TotalCents:       inv.TotalCents,
				EDI997AckCode:    "R",
				ErrorSegmentID:   "REF",
				ErrorSegmentPos:  refPos,
				RawEDI997:        e.buildEDI997(inv, "R", "REF", refPos, "PAYPAL-ORDER-REUSE"),
				AIAuditVerdict:   verdict,
				Ed25519PubKeyHex: e.PublicKeyHex(),
			}, ErrDuplicateInvoiceReplay
		}
	}

	if e.billedLines[po.PONumber] == nil {
		e.billedLines[po.PONumber] = make(map[string]int64)
	}
	for i, il := range inv.Lines {
		pl := poBySKU[il.VendorSKU]
		maxQty := pl.Quantity
		if has861 {
			if rl, ok := rcptBySKU[il.VendorSKU]; ok && rl.AcceptedQuantity < maxQty {
				maxQty = rl.AcceptedQuantity
			}
		}
		if e.billedLines[po.PONumber][il.VendorSKU]+il.Quantity > maxQty {
			pos := inv.SegmentPos["IT1"]
			if i < len(inv.IT1Positions) {
				pos = inv.IT1Positions[i]
			}
			return &SettlementEvaluationResult{
				ProtocolVersion:  ProtocolVersion,
				InvoiceNumber:    inv.InvoiceNumber,
				PONumber:         inv.PONumber,
				TotalCents:       inv.TotalCents,
				EDI997AckCode:    "R",
				ErrorSegmentID:   "IT1",
				ErrorSegmentPos:  pos,
				RawEDI997:        e.buildEDI997(inv, "R", "IT1", pos, "PO-LINE-ALREADY-BILLED"),
				AIAuditVerdict:   verdict,
				Ed25519PubKeyHex: e.PublicKeyHex(),
			}, ErrDuplicateInvoiceReplay
		}
	}

	// 4. Rolling Hourly Agentic Spend Limit Circuit-Breaker (both per-agent and global engine spend)
	now := time.Now().UTC()
	windowStart := now.Add(-1 * time.Hour)
	var rollingAgentCents int64
	var activeAgentRecords []spendRecord
	for _, rec := range e.agentSpend[agentKey] {
		if rec.Timestamp.After(windowStart) {
			activeAgentRecords = append(activeAgentRecords, rec)
			rollingAgentCents += rec.Cents
		}
	}
	e.agentSpend[agentKey] = activeAgentRecords

	var rollingGlobalCents int64
	var activeGlobalRecords []spendRecord
	for _, rec := range e.globalSpend {
		if rec.Timestamp.After(windowStart) {
			activeGlobalRecords = append(activeGlobalRecords, rec)
			rollingGlobalCents += rec.Cents
		}
	}
	e.globalSpend = activeGlobalRecords

	if e.cfg.RollingHourlyLimitCents > 0 && (rollingAgentCents+inv.TotalCents > e.cfg.RollingHourlyLimitCents || rollingGlobalCents+inv.TotalCents > e.cfg.RollingHourlyLimitCents) {
		tdsPos := inv.SegmentPos["TDS"]
		return &SettlementEvaluationResult{
			ProtocolVersion:  ProtocolVersion,
			InvoiceNumber:    inv.InvoiceNumber,
			PONumber:         inv.PONumber,
			TotalCents:       inv.TotalCents,
			EDI997AckCode:    "R",
			ErrorSegmentID:   "TDS",
			ErrorSegmentPos:  tdsPos,
			RawEDI997:        e.buildEDI997(inv, "R", "TDS", tdsPos, "HOURLY-BUDGET-EXCEEDED"),
			AIAuditVerdict:   verdict,
			Ed25519PubKeyHex: e.PublicKeyHex(),
		}, ErrBudgetBreakerTripped
	}

	// 5. Write-Ahead Persistent Ledger Entry (fsync BEFORE mutating state or emitting signed receipt),
	// Authorize Settlement, Record Cumulative PO Line Consumption & Mint Deterministic Receipt
	reqID := DeterministicPayPalRequestID(po.SHA256Hex, inv.SHA256Hex, inv.InvoiceNumber)
	audMode := strings.TrimSpace(verdict.Mode)
	audModel := strings.TrimSpace(verdict.ModelID)
	agentKey = strings.TrimSpace(agentKey)

	ledgerEntry := LedgerEntry{
		TimestampUTC:    now.Format(time.RFC3339),
		EventType:       "SETTLEMENT_AUTHORIZED",
		AgentKey:        agentKey,
		SellerID:        po.SellerID,
		InvoiceNumber:   inv.InvoiceNumber,
		PONumber:        po.PONumber,
		BilledLines:     append([]LineItem(nil), inv.Lines...),
		TotalCents:      inv.TotalCents,
		PayPalRequestID: reqID,
		PayPalOrderID:   inv.PayPalOrderID,
		PayPalCaptured:  false,
		AuditorMode:     audMode,
		AuditorModelID:  audModel,
	}
	if err := e.appendLedgerLocked(&ledgerEntry); err != nil {
		bigPos := inv.SegmentPos["BIG"]
		return &SettlementEvaluationResult{
			ProtocolVersion:  ProtocolVersion,
			InvoiceNumber:    inv.InvoiceNumber,
			PONumber:         inv.PONumber,
			TotalCents:       inv.TotalCents,
			EDI997AckCode:    "R",
			ErrorSegmentID:   "BIG",
			ErrorSegmentPos:  bigPos,
			RawEDI997:        e.buildEDI997(inv, "R", "BIG", bigPos, "LEDGER-WRITE-FAILED"),
			AIAuditVerdict:   verdict,
			KeyID:            e.keyID,
			Ed25519PubKeyHex: e.PublicKeyHex(),
		}, err
	}

	spendRec := spendRecord{
		Timestamp: now,
		Cents:     inv.TotalCents,
	}
	e.agentSpend[agentKey] = append(e.agentSpend[agentKey], spendRec)
	e.globalSpend = append(e.globalSpend, spendRec)
	for _, il := range inv.Lines {
		e.billedLines[po.PONumber][il.VendorSKU] += il.Quantity
	}

	e.settledInv[inv.InvoiceNumber] = reqID
	e.settledSellerInv[sellerScopedKey] = reqID
	if inv.PayPalOrderID != "" {
		e.boundOrders[inv.PayPalOrderID] = sellerScopedKey
	}

	rcptNum := ""
	r861Token := "none"
	if has861 {
		rcptNum = rcpt861.ReceiptNumber
		r861Hash := rcpt861.SHA256Hex
		if len(r861Hash) > 16 {
			r861Hash = r861Hash[:16]
		}
		r861Token = rcpt861.ReceiptNumber + ":" + r861Hash
	}

	raw997 := e.buildEDI997(inv, "A", "", 0, "")
	h997 := sha256.Sum256([]byte(raw997))
	r997Token := "A:" + hex.EncodeToString(h997[:])[:16]
	envTag := e.paypalEnvLabel()
	receiptCore := fmt.Sprintf("tinygaap:v=3;kid=%s;inv=%s;po=%s;seller=%s;r861=%s;r997=%s;aud_mode=%s;aud_model=%s;payto=%s;rail=%s:%s;req_id=%s",
		sanitizeReceiptToken(e.keyID),
		sanitizeReceiptToken(inv.InvoiceNumber),
		sanitizeReceiptToken(po.PONumber),
		sanitizeReceiptToken(po.SellerID),
		sanitizeReceiptToken(r861Token),
		sanitizeReceiptToken(r997Token),
		sanitizeReceiptToken(audMode),
		sanitizeReceiptToken(audModel),
		sanitizeReceiptToken(payTo),
		envTag,
		FormatCentsDecimal(inv.TotalCents),
		reqID,
	)
	if ledgerEntry.Seq > 0 && len(ledgerEntry.EntryHashHex) >= 16 {
		receiptCore = fmt.Sprintf("%s;lseq=%d;lhash=%s", receiptCore, ledgerEntry.Seq, ledgerEntry.EntryHashHex[:16])
	}
	hmacDigest := e.shortHMAC(receiptCore)
	receiptHeader := fmt.Sprintf("%s;hmac=%s", receiptCore, hmacDigest)
	receiptSig := hex.EncodeToString(ed25519.Sign(e.edPriv, []byte(receiptHeader)))

	e.authGrants[sellerScopedKey] = &authGrant{
		AgentKey:       agentKey,
		SellerID:       po.SellerID,
		InvoiceNumber:  inv.InvoiceNumber,
		PONumber:       po.PONumber,
		PayPalOrderID:  inv.PayPalOrderID,
		TotalCents:     inv.TotalCents,
		ReceiptHashHex: reqID,
		ReceiptHeader:  receiptHeader,
		Ed25519SigHex:  receiptSig,
		AuditorMode:    audMode,
		AuditorModel:   audModel,
		Captured:       false,
	}

	return &SettlementEvaluationResult{
		ProtocolVersion:      ProtocolVersion,
		InvoiceNumber:        inv.InvoiceNumber,
		PONumber:             inv.PONumber,
		ReceiptNumber861:     rcptNum,
		TotalCents:           inv.TotalCents,
		EDI997AckCode:        "A",
		RawEDI997:            raw997,
		SettlementAuthorized: true,
		PayPalCaptured:       false,
		PayPalOrderID:        inv.PayPalOrderID,
		PayPalRequestID:      reqID,
		AIAuditVerdict:       verdict,
		ReceiptHeader:        receiptHeader,
		ReceiptHashHex:       reqID,
		KeyID:                e.keyID,
		LedgerSeq:            ledgerEntry.Seq,
		LedgerPrevHashHex:    ledgerEntry.PrevHashHex,
		LedgerEntryHashHex:   ledgerEntry.EntryHashHex,
		Ed25519PubKeyHex:     e.PublicKeyHex(),
		Ed25519SignatureHex:  receiptSig,
	}, nil
}

// ServeSettle810 provides an HTTP x402-style + EDI 810 settlement gate for httptest and live servers.
// If the query parameter `?capture=true` or header `X-PayPal-Capture: true` is set and the EDI 810
// contains a `REF*PP*<order_id>` segment, ServeSettle810 also executes live PayPal order capture (`CaptureApprovedPayPalOrder`).
func (e *TinyGAAPEngine) ServeSettle810(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	raw810 := string(body)

	// Enforce Cryptographic x402-style HTTP 402 Payment-Signature Gate (not wire-compatible with the x402 spec)
	sigHdr := strings.TrimSpace(r.Header.Get("Payment-Signature"))
	if sigHdr == "" {
		sigHdr = strings.TrimSpace(r.Header.Get("X-Payment"))
	}
	if !VerifyX402PaymentHeader(e.cfg.HMACSecret, raw810, sigHdr) {
		w.Header().Set("WWW-Authenticate", `x402 realm="tinygaap.io", scheme="exact:x402:paypal-order-v2", alg="HMAC-SHA256", currency="USD"`)
		w.Header().Set("Payment-Required", "exact:x402:paypal-order-v2:sig=<hmac-sha256>")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPaymentRequired)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":            ErrX402PaymentRequired.Error(),
			"x402_version":     "1.0",
			"accepted_schemes": []string{"exact:x402:paypal-order-v2:sig=<hmac-sha256>"},
			"settlement_rail":  "paypal-orders-v2",
			"protocol_version": ProtocolVersion,
		})
		return
	}

	agentID := strings.TrimSpace(r.Header.Get("X-Agent-Key"))
	if agentID == "" {
		agentID = "default-buyer-agent"
	}
	payTo := strings.TrimSpace(r.Header.Get("X-PayTo-Beneficiary"))

	res, evalErr := e.EvaluateAndSettle810(r.Context(), raw810, agentID, payTo)
	if evalErr == nil && res != nil && res.SettlementAuthorized {
		wantCapture := r.URL.Query().Get("capture") == "true" || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-PayPal-Capture")), "true")
		if wantCapture {
			inv, _, _, _ := ParseEDI810(raw810)
			e.mu.Lock()
			po := e.pos[res.PONumber]
			e.mu.Unlock()
			orderID := strings.TrimSpace(r.Header.Get("X-PayPal-Order-ID"))
			if orderID == "" && inv != nil {
				orderID = inv.PayPalOrderID
			}
			if capErr := e.CaptureApprovedPayPalOrder(r.Context(), res, po, inv, orderID); capErr != nil {
				evalErr = capErr
			}
		}
	}

	w.Header().Set("X-Protocol-Version", ProtocolVersion)
	w.Header().Set("Content-Type", "application/json")
	if res != nil {
		w.Header().Set("X-EDI-997-Ack", res.EDI997AckCode)
		w.Header().Set("X-Ed25519-PubKey", res.Ed25519PubKeyHex)
		if res.KeyID != "" {
			w.Header().Set("X-Ed25519-Key-ID", res.KeyID)
		}
		if res.ReceiptHeader != "" && evalErr == nil {
			w.Header().Set("X-Payment-Receipt", res.ReceiptHeader)
		}
		if res.Ed25519SignatureHex != "" && evalErr == nil {
			w.Header().Set("X-Ed25519-Signature", res.Ed25519SignatureHex)
		}
	}

	if evalErr != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(evalErr, ErrEDI810PriceQtyDrift), errors.Is(evalErr, ErrEDI861ReceivingDrift), errors.Is(evalErr, ErrReceivingAdviceNotFound):
			status = http.StatusUnprocessableEntity
		case errors.Is(evalErr, ErrUnapprovedBeneficiary), errors.Is(evalErr, ErrAIAuditorRejected):
			status = http.StatusForbidden
		case errors.Is(evalErr, ErrBudgetBreakerTripped):
			status = http.StatusTooManyRequests
		case errors.Is(evalErr, ErrDuplicateInvoiceReplay):
			status = http.StatusConflict
		case errors.Is(evalErr, ErrPONotFound):
			status = http.StatusNotFound
		case errors.Is(evalErr, ErrPayPalOrderVerificationFailed):
			status = http.StatusBadGateway
		case errors.Is(evalErr, ErrPayPalCaptureNotCompleted):
			status = http.StatusPaymentRequired
		case errors.Is(evalErr, ErrLedgerInvalid), errors.Is(evalErr, ErrKeyCustodyInvalid):
			status = http.StatusInternalServerError
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":  evalErr.Error(),
			"result": res,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

// PayPalLiveSandboxProof captures the verifiable cryptographic and HTTP telemetry from PayPal REST APIs.
// Unobserved HTTP status codes (such as order creation when inspecting an existing order, or capture
// when reading back an already-completed order) are left zero and omitted from JSON.
type PayPalLiveSandboxProof struct {
	ProtocolVersion              string          `json:"protocol_version"`
	TimestampUTC                 string          `json:"timestamp_utc"`
	EndpointBase                 string          `json:"endpoint_base"`
	NegativeControlBadCredsHTTP  int             `json:"negative_control_bad_creds_http"`
	OAuth2TokenHTTPCode          int             `json:"oauth2_token_http_code"`
	OAuth2DebugID                string          `json:"oauth2_debug_id,omitempty"`
	OAuth2ExpiresIn              int             `json:"oauth2_expires_in"`
	AIAuditVerdict               *AIAuditVerdict `json:"ai_audit_verdict,omitempty"`
	CreateOrderHTTPCode          int             `json:"create_order_http_code,omitempty"`
	CreateOrderDebugID           string          `json:"create_order_debug_id,omitempty"`
	PayPalRequestID              string          `json:"paypal_request_id"`
	LivePayPalOrderID            string          `json:"live_paypal_order_id"`
	LivePayPalOrderStatus        string          `json:"live_paypal_order_status"`
	LivePayPalCreateTime         string          `json:"live_paypal_create_time,omitempty"`
	GetOrderHTTPCode             int             `json:"get_order_http_code,omitempty"`
	GetOrderDebugID              string          `json:"get_order_debug_id,omitempty"`
	VerifiedCustomIDEDI850SHA256 string          `json:"verified_custom_id_edi850_sha256"`
	VerifiedInvoiceID            string          `json:"verified_invoice_id"`
	VerifiedAmountUSD            string          `json:"verified_amount_usd"`
	PayPalCaptured               bool            `json:"paypal_captured"`
	CaptureOrderHTTPCode         int             `json:"capture_order_http_code,omitempty"`
	CaptureOrderDebugID          string          `json:"capture_order_debug_id,omitempty"`
	LivePayPalCaptureID          string          `json:"live_paypal_capture_id,omitempty"`
	EDI997FunctionalAckCode      string          `json:"edi_997_functional_ack_code"`
	EDI820Remittance             string          `json:"edi_820_remittance,omitempty"`
	EDI820SignatureHex           string          `json:"edi_820_signature_hex,omitempty"`
	KeyID                        string          `json:"kid,omitempty"`
	LedgerSeq                    int64           `json:"ledger_seq,omitempty"`
	LedgerPrevHashHex            string          `json:"ledger_prev_hash_hex,omitempty"`
	LedgerEntryHashHex           string          `json:"ledger_entry_hash_hex,omitempty"`
	ReceiptHeader                string          `json:"receipt_header"`
	Ed25519PubKeyHex             string          `json:"ed25519_pub_key_hex"`
	Ed25519SignatureHex          string          `json:"ed25519_signature_hex"`
}

func (e *TinyGAAPEngine) acquirePayPalAccessToken(ctx context.Context) (string, int, string, error) {
	base := strings.TrimRight(e.cfg.PayPalBaseURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/oauth2/token", strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		return "", 0, "", err
	}
	req.SetBasicAuth(strings.TrimSpace(e.cfg.PayPalClientID), strings.TrimSpace(e.cfg.PayPalClientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", 0, "", fmt.Errorf("paypal oauth2 request failed: %w", err)
	}
	defer resp.Body.Close()
	debugID := resp.Header.Get("Paypal-Debug-Id")
	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, debugID, fmt.Errorf("paypal oauth2 failed with status %d (debug_id=%s)", resp.StatusCode, debugID)
	}

	var tokData struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(bodyBytes, &tokData); err != nil || tokData.AccessToken == "" {
		return "", resp.StatusCode, debugID, fmt.Errorf("paypal oauth2 invalid json response (debug_id=%s)", debugID)
	}
	return tokData.AccessToken, tokData.ExpiresIn, debugID, nil
}

// VerifyPayPalOrderBeforeCapture fetches GET /v2/checkout/orders/{id} and strictly compares
// ID, Status, CustomID (full 64-char PO SHA-256), InvoiceID, CurrencyCode, and Amount.Value.
func (e *TinyGAAPEngine) VerifyPayPalOrderBeforeCapture(ctx context.Context, orderID string, po *EDI850PO, expectedInvoiceID string, expectedCents int64) error {
	if po == nil {
		return fmt.Errorf("%w: nil PO", ErrPayPalOrderVerificationFailed)
	}
	tok, _, _, err := e.acquirePayPalAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPayPalOrderVerificationFailed, err)
	}
	_, _, _, err = e.getAndVerifyPayPalOrderWithToken(ctx, tok, orderID, po.SHA256Hex, expectedInvoiceID, FormatCentsDecimal(expectedCents))
	return err
}

type paypalOrderReadback struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	CreateTime    string `json:"create_time"`
	PurchaseUnits []struct {
		ReferenceID string `json:"reference_id"`
		CustomID    string `json:"custom_id"`
		InvoiceID   string `json:"invoice_id"`
		Amount      struct {
			CurrencyCode string `json:"currency_code"`
			Value        string `json:"value"`
		} `json:"amount"`
		Payments struct {
			Captures []struct {
				ID     string `json:"id"`
				Status string `json:"status"`
				Amount struct {
					CurrencyCode string `json:"currency_code"`
					Value        string `json:"value"`
				} `json:"amount"`
			} `json:"captures"`
		} `json:"payments"`
	} `json:"purchase_units"`
}

func (e *TinyGAAPEngine) getAndVerifyPayPalOrderWithToken(ctx context.Context, bearerToken, orderID, expectedCustomID, expectedInvoiceID, expectedAmount string) (*paypalOrderReadback, int, string, error) {
	return e.getAndVerifyPayPalOrderStatusWithToken(ctx, bearerToken, orderID, expectedCustomID, expectedInvoiceID, expectedAmount, false)
}

func (e *TinyGAAPEngine) getAndVerifyPayPalOrderStatusWithToken(ctx context.Context, bearerToken, orderID, expectedCustomID, expectedInvoiceID, expectedAmount string, allowCompleted bool) (*paypalOrderReadback, int, string, error) {
	if strings.TrimSpace(orderID) == "" {
		return nil, 0, "", fmt.Errorf("%w: empty PayPal order ID", ErrPayPalOrderVerificationFailed)
	}
	base := strings.TrimRight(e.cfg.PayPalBaseURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v2/checkout/orders/"+orderID, nil)
	if err != nil {
		return nil, 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Accept", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, 0, "", fmt.Errorf("%w: GET order transport error: %v", ErrPayPalOrderVerificationFailed, err)
	}
	defer resp.Body.Close()
	debugID := resp.Header.Get("Paypal-Debug-Id")
	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, debugID, fmt.Errorf("%w: GET order %s returned HTTP %d (debug_id=%s)", ErrPayPalOrderVerificationFailed, orderID, resp.StatusCode, debugID)
	}

	var ord paypalOrderReadback
	if err := json.Unmarshal(bodyBytes, &ord); err != nil {
		return nil, resp.StatusCode, debugID, fmt.Errorf("%w: invalid GET order JSON: %v", ErrPayPalOrderVerificationFailed, err)
	}
	if ord.ID != orderID || len(ord.PurchaseUnits) != 1 {
		return nil, resp.StatusCode, debugID, fmt.Errorf("%w: order ID or purchase_units count mismatch on %s", ErrPayPalOrderVerificationFailed, orderID)
	}
	switch ord.Status {
	case "CREATED", "APPROVED", "PAYER_ACTION_REQUIRED":
	case "COMPLETED":
		if !allowCompleted {
			return nil, resp.StatusCode, debugID, fmt.Errorf("%w: unexpected order status %q on %s before capture", ErrPayPalOrderVerificationFailed, ord.Status, orderID)
		}
	default:
		return nil, resp.StatusCode, debugID, fmt.Errorf("%w: unexpected order status %q on %s before capture", ErrPayPalOrderVerificationFailed, ord.Status, orderID)
	}
	pu := ord.PurchaseUnits[0]
	if pu.CustomID != expectedCustomID {
		return nil, resp.StatusCode, debugID, fmt.Errorf("%w: custom_id mismatch on %s (got %q, want %q)", ErrPayPalOrderVerificationFailed, orderID, pu.CustomID, expectedCustomID)
	}
	if expectedInvoiceID == "" || pu.InvoiceID != expectedInvoiceID {
		return nil, resp.StatusCode, debugID, fmt.Errorf("%w: invoice_id mismatch on %s (got %q, want %q)", ErrPayPalOrderVerificationFailed, orderID, pu.InvoiceID, expectedInvoiceID)
	}
	if pu.Amount.CurrencyCode != "USD" || pu.Amount.Value != expectedAmount {
		return nil, resp.StatusCode, debugID, fmt.Errorf("%w: amount mismatch on %s (got %s %s, want USD %s)", ErrPayPalOrderVerificationFailed, orderID, pu.Amount.CurrencyCode, pu.Amount.Value, expectedAmount)
	}
	return &ord, resp.StatusCode, debugID, nil
}

// CaptureApprovedPayPalOrder executes POST /v2/checkout/orders/{id}/capture after verifying
// that the evaluation result matches the engine's unforgeable authorization ledger for this invoice,
// verifying the order via GET, and checking that PayPal's capture status is COMPLETED with matching ID and amount.
func (e *TinyGAAPEngine) CaptureApprovedPayPalOrder(ctx context.Context, evalRes *SettlementEvaluationResult, po *EDI850PO, inv *EDI810Invoice, orderID string) error {
	_, _, err := e.captureApprovedPayPalOrderWithTelemetry(ctx, evalRes, po, inv, orderID)
	return err
}

func (e *TinyGAAPEngine) captureApprovedPayPalOrderWithTelemetry(ctx context.Context, evalRes *SettlementEvaluationResult, po *EDI850PO, inv *EDI810Invoice, orderID string) (int, string, error) {
	if evalRes == nil || po == nil || inv == nil || !evalRes.SettlementAuthorized {
		return 0, "", fmt.Errorf("%w: cannot capture unauthorized or nil settlement", ErrPayPalCaptureNotCompleted)
	}
	orderID = strings.TrimSpace(orderID)
	if orderID == "" {
		return 0, "", fmt.Errorf("%w: empty orderID for capture", ErrPayPalCaptureNotCompleted)
	}

	sellerScopedKey := strings.ToLower(strings.TrimSpace(po.SellerID)) + "|" + inv.InvoiceNumber
	e.mu.Lock()
	grant, ok := e.authGrants[sellerScopedKey]
	if !ok || grant == nil {
		e.mu.Unlock()
		return 0, "", fmt.Errorf("%w: no engine authorization grant found for invoice %q", ErrPayPalCaptureNotCompleted, inv.InvoiceNumber)
	}
	replayedGrant := grant.ReceiptHeader == ""
	if evalRes.InvoiceNumber != inv.InvoiceNumber ||
		grant.InvoiceNumber != inv.InvoiceNumber ||
		evalRes.PONumber != po.PONumber ||
		grant.PONumber != po.PONumber ||
		inv.PONumber != po.PONumber ||
		evalRes.TotalCents != inv.TotalCents ||
		grant.TotalCents != inv.TotalCents ||
		evalRes.ReceiptHashHex == "" ||
		evalRes.ReceiptHashHex != grant.ReceiptHashHex ||
		(!replayedGrant && evalRes.ReceiptHeader != grant.ReceiptHeader) ||
		(replayedGrant && !VerifyReceiptHMAC(e.cfg.HMACSecret, evalRes.ReceiptHeader)) {
		e.mu.Unlock()
		return 0, "", fmt.Errorf("%w: authorization grant mismatch between evaluation result (%s) and invoice (%s)", ErrPayPalCaptureNotCompleted, evalRes.InvoiceNumber, inv.InvoiceNumber)
	}
	if grant.PayPalOrderID != "" && grant.PayPalOrderID != orderID {
		e.mu.Unlock()
		return 0, "", fmt.Errorf("%w: orderID %q does not match invoice authorized PayPalOrderID %q", ErrPayPalCaptureNotCompleted, orderID, grant.PayPalOrderID)
	}
	if grant.Captured {
		e.mu.Unlock()
		return 0, "", fmt.Errorf("%w: invoice %q already captured (capture_id=%s)", ErrDuplicateInvoiceReplay, inv.InvoiceNumber, grant.CaptureID)
	}
	e.mu.Unlock()

	tok, _, _, err := e.acquirePayPalAccessToken(ctx)
	if err != nil {
		return 0, "", err
	}
	expectedAmt := FormatCentsDecimal(inv.TotalCents)
	if _, _, _, err := e.getAndVerifyPayPalOrderWithToken(ctx, tok, orderID, po.SHA256Hex, inv.InvoiceNumber, expectedAmt); err != nil {
		return 0, "", err
	}

	base := strings.TrimRight(e.cfg.PayPalBaseURL, "/")
	capReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v2/checkout/orders/"+orderID+"/capture", strings.NewReader("{}"))
	if err != nil {
		return 0, "", err
	}
	capReqID := DeterministicPayPalCaptureRequestID(evalRes.ReceiptHashHex, orderID)
	capReq.Header.Set("Authorization", "Bearer "+tok)
	capReq.Header.Set("Content-Type", "application/json")
	capReq.Header.Set("PayPal-Request-Id", capReqID)

	capResp, err := e.httpClient.Do(capReq)
	if err != nil {
		return 0, "", fmt.Errorf("paypal capture request failed: %w", err)
	}
	defer capResp.Body.Close()
	debugID := capResp.Header.Get("Paypal-Debug-Id")
	capBytes, _ := io.ReadAll(capResp.Body)

	if capResp.StatusCode != http.StatusCreated && capResp.StatusCode != http.StatusOK {
		return capResp.StatusCode, debugID, fmt.Errorf("%w: status=%d debug_id=%s body=%s", ErrPayPalCaptureNotCompleted, capResp.StatusCode, debugID, string(capBytes))
	}

	var capData struct {
		ID            string `json:"id"`
		Status        string `json:"status"`
		PurchaseUnits []struct {
			Payments struct {
				Captures []struct {
					ID     string `json:"id"`
					Status string `json:"status"`
					Amount struct {
						CurrencyCode string `json:"currency_code"`
						Value        string `json:"value"`
					} `json:"amount"`
				} `json:"captures"`
			} `json:"payments"`
		} `json:"purchase_units"`
	}
	if err := json.Unmarshal(capBytes, &capData); err != nil {
		return capResp.StatusCode, debugID, fmt.Errorf("%w: invalid capture response JSON: %v", ErrPayPalCaptureNotCompleted, err)
	}
	if capData.ID != orderID {
		return capResp.StatusCode, debugID, fmt.Errorf("%w: capture response order ID %q != expected %q", ErrPayPalCaptureNotCompleted, capData.ID, orderID)
	}
	if capData.Status != "COMPLETED" || len(capData.PurchaseUnits) != 1 || len(capData.PurchaseUnits[0].Payments.Captures) == 0 {
		return capResp.StatusCode, debugID, fmt.Errorf("%w: order status is %q", ErrPayPalCaptureNotCompleted, capData.Status)
	}
	capObj := capData.PurchaseUnits[0].Payments.Captures[0]
	if capObj.Status != "COMPLETED" {
		return capResp.StatusCode, debugID, fmt.Errorf("%w: capture[0].status is %q (want COMPLETED)", ErrPayPalCaptureNotCompleted, capObj.Status)
	}
	captureID := strings.TrimSpace(capObj.ID)
	if captureID == "" {
		return capResp.StatusCode, debugID, fmt.Errorf("%w: empty capture ID from PayPal", ErrPayPalCaptureNotCompleted)
	}
	if capObj.Amount.CurrencyCode != "USD" || capObj.Amount.Value != expectedAmt {
		return capResp.StatusCode, debugID, fmt.Errorf("%w: captured amount %s %s != expected USD %s", ErrPayPalCaptureNotCompleted, capObj.Amount.CurrencyCode, capObj.Amount.Value, expectedAmt)
	}

	e.mu.Lock()
	if grant.Captured {
		e.mu.Unlock()
		return capResp.StatusCode, debugID, fmt.Errorf("%w: invoice %q already captured concurrently", ErrDuplicateInvoiceReplay, inv.InvoiceNumber)
	}
	grantAgent := strings.TrimSpace(grant.AgentKey)
	grantAudMode := strings.TrimSpace(grant.AuditorMode)
	grantAudModel := strings.TrimSpace(grant.AuditorModel)
	if grantAgent == "" || grantAudMode == "" || grantAudModel == "" {
		e.mu.Unlock()
		return capResp.StatusCode, debugID, fmt.Errorf("%w: authorization grant for %q is missing agent or auditor attribution", ErrPayPalCaptureNotCompleted, inv.InvoiceNumber)
	}
	capEntry := LedgerEntry{
		TimestampUTC:      time.Now().UTC().Format(time.RFC3339),
		EventType:         "PAYPAL_ORDER_CAPTURED",
		AgentKey:          grantAgent,
		SellerID:          po.SellerID,
		InvoiceNumber:     inv.InvoiceNumber,
		PONumber:          po.PONumber,
		TotalCents:        inv.TotalCents,
		PayPalRequestID:   grant.ReceiptHashHex,
		PayPalOrderID:     orderID,
		PayPalOrderStatus: "COMPLETED",
		PayPalCaptured:    true,
		PayPalCaptureID:   captureID,
		AuditorMode:       grantAudMode,
		AuditorModelID:    grantAudModel,
	}
	if err := e.appendLedgerLocked(&capEntry); err != nil {
		e.mu.Unlock()
		return capResp.StatusCode, debugID, err
	}
	grant.Captured = true
	grant.CaptureID = captureID
	grant.PayPalOrderID = orderID
	e.boundOrders[orderID] = sellerScopedKey
	rcpt861 := e.receipts861[po.PONumber]
	authHashHex := grant.ReceiptHashHex
	e.mu.Unlock()

	evalRes.PayPalCaptured = true
	evalRes.PayPalOrderID = orderID
	evalRes.PayPalOrderStatus = "COMPLETED"
	evalRes.PayPalCaptureID = captureID
	evalRes.KeyID = e.keyID
	evalRes.LedgerSeq = capEntry.Seq
	evalRes.LedgerPrevHashHex = capEntry.PrevHashHex
	evalRes.LedgerEntryHashHex = capEntry.EntryHashHex
	raw820, sig820Hex := e.buildEDI820WithLedger(po, rcpt861, inv, authHashHex, orderID, captureID, capEntry.Seq, capEntry.EntryHashHex)
	evalRes.RawEDI820 = raw820
	evalRes.EDI820SignatureHex = sig820Hex
	if idx := strings.LastIndex(evalRes.ReceiptHeader, ";hmac="); idx > 0 {
		postCore := fmt.Sprintf("%s;pp_ord=%s;pp_cap=%s;status=COMPLETED",
			stripLedgerAndPostCaptureReceiptParams(evalRes.ReceiptHeader[:idx]),
			sanitizeReceiptToken(orderID),
			sanitizeReceiptToken(captureID),
		)
		if capEntry.Seq > 0 && len(capEntry.EntryHashHex) >= 16 {
			postCore = fmt.Sprintf("%s;lseq=%d;lhash=%s", postCore, capEntry.Seq, capEntry.EntryHashHex[:16])
		}
		postHMAC := e.shortHMAC(postCore)
		postHeader := fmt.Sprintf("%s;hmac=%s", postCore, postHMAC)
		postSig := hex.EncodeToString(ed25519.Sign(e.edPriv, []byte(postHeader)))
		evalRes.ReceiptHeader = postHeader
		evalRes.Ed25519SignatureHex = postSig
		e.mu.Lock()
		grant.ReceiptHeader = postHeader
		grant.Ed25519SigHex = postSig
		e.mu.Unlock()
	}
	return capResp.StatusCode, debugID, nil
}

// VerifyLivePayPalSandboxE2E executes the 5-step PayPal Orders v2 verification:
//  1. Negative Control: invalid credentials MUST fail with HTTP 401.
//  2. OAuth2 Token acquisition (POST /v1/oauth2/token).
//  3. 3-Way Match (850 + 861 + 810) and Semantic Audit.
//  4. Live Order Creation (POST /v2/checkout/orders) with PayPal-Request-Id = deterministic receipt hash.
//  5. Live Readback Verification (GET /v2/checkout/orders/{id}) asserting exact field equality.
func (e *TinyGAAPEngine) VerifyLivePayPalSandboxE2E(ctx context.Context, raw850, raw861, raw810 string) (*PayPalLiveSandboxProof, error) {
	base := strings.TrimRight(e.cfg.PayPalBaseURL, "/")
	proof := &PayPalLiveSandboxProof{
		ProtocolVersion:  ProtocolVersion,
		TimestampUTC:     time.Now().UTC().Format(time.RFC3339),
		EndpointBase:     base,
		KeyID:            e.keyID,
		Ed25519PubKeyHex: e.PublicKeyHex(),
	}

	// Step 1: Negative Control (must NOT return 200)
	negReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/oauth2/token", strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		return proof, err
	}
	negReq.SetBasicAuth("invalid-client-id-negative-control", "invalid-secret-negative-control")
	negReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	negResp, err := e.httpClient.Do(negReq)
	if err != nil {
		return proof, fmt.Errorf("negative control request failed: %w", err)
	}
	_, _ = io.Copy(io.Discard, negResp.Body)
	negResp.Body.Close()
	proof.NegativeControlBadCredsHTTP = negResp.StatusCode
	if negResp.StatusCode == http.StatusOK {
		return proof, fmt.Errorf("negative control failed: invalid credentials returned HTTP 200")
	}

	// Step 2: Live OAuth2 Token
	accessToken, expiresIn, oauthDebugID, err := e.acquirePayPalAccessToken(ctx)
	if err != nil {
		return proof, err
	}
	proof.OAuth2TokenHTTPCode = http.StatusOK
	proof.OAuth2DebugID = oauthDebugID
	proof.OAuth2ExpiresIn = expiresIn

	// Step 3: Register 850 + 861 and Evaluate 810
	po, err := e.RegisterPO850(raw850)
	if err != nil {
		return proof, err
	}
	if strings.TrimSpace(raw861) != "" {
		if _, err := e.RegisterReceivingAdvice861(raw861); err != nil {
			return proof, err
		}
	}
	inv, _, _, err := ParseEDI810(raw810)
	if err != nil {
		return proof, err
	}
	evalRes, err := e.EvaluateAndSettle810(ctx, raw810, "sandbox-e2e-verifier", po.SellerID)
	if evalRes != nil {
		proof.AIAuditVerdict = evalRes.AIAuditVerdict
		proof.LedgerSeq = evalRes.LedgerSeq
		proof.LedgerPrevHashHex = evalRes.LedgerPrevHashHex
		proof.LedgerEntryHashHex = evalRes.LedgerEntryHashHex
	}
	if err != nil {
		return proof, fmt.Errorf("3-way match evaluation failed: %w", err)
	}

	// Step 4: Create Live PayPal Order v2 bound to full 64-char PO SHA-256 and deterministic Request-Id
	amtStr := FormatCentsDecimal(inv.TotalCents)
	orderPayload := map[string]any{
		"intent": "CAPTURE",
		"purchase_units": []map[string]any{
			{
				"reference_id": po.PONumber,
				"invoice_id":   inv.InvoiceNumber,
				"custom_id":    po.SHA256Hex,
				"description":  fmt.Sprintf("tinyGAAP 3-Way Matched EDI 810 (%s) for PO %s", inv.InvoiceNumber, po.PONumber),
				"amount": map[string]any{
					"currency_code": "USD",
					"value":         amtStr,
				},
			},
		},
	}
	orderBody, err := json.Marshal(orderPayload)
	if err != nil {
		return proof, err
	}
	createReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v2/checkout/orders", bytes.NewReader(orderBody))
	if err != nil {
		return proof, err
	}
	createReq.Header.Set("Authorization", "Bearer "+accessToken)
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("PayPal-Request-Id", evalRes.ReceiptHashHex)

	createResp, err := e.httpClient.Do(createReq)
	if err != nil {
		return proof, fmt.Errorf("create order failed: %w", err)
	}
	defer createResp.Body.Close()
	proof.CreateOrderHTTPCode = createResp.StatusCode
	proof.CreateOrderDebugID = createResp.Header.Get("Paypal-Debug-Id")
	proof.PayPalRequestID = evalRes.ReceiptHashHex

	createBytes, _ := io.ReadAll(createResp.Body)
	if createResp.StatusCode != http.StatusCreated && createResp.StatusCode != http.StatusOK {
		return proof, fmt.Errorf("create order returned HTTP %d (debug_id=%s): %s", createResp.StatusCode, proof.CreateOrderDebugID, string(createBytes))
	}

	var orderRes struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		CreateTime string `json:"create_time"`
	}
	if err := json.Unmarshal(createBytes, &orderRes); err != nil || orderRes.ID == "" {
		return proof, fmt.Errorf("invalid create order JSON response")
	}
	proof.LivePayPalOrderID = orderRes.ID
	proof.LivePayPalOrderStatus = orderRes.Status
	proof.LivePayPalCreateTime = orderRes.CreateTime

	// Step 5: Strict Readback Verification (GET /v2/checkout/orders/{id})
	verifiedOrd, getHTTPCode, getDebugID, err := e.getAndVerifyPayPalOrderWithToken(ctx, accessToken, orderRes.ID, po.SHA256Hex, inv.InvoiceNumber, amtStr)
	if err != nil {
		return proof, err
	}
	proof.GetOrderHTTPCode = getHTTPCode
	proof.GetOrderDebugID = getDebugID
	proof.VerifiedCustomIDEDI850SHA256 = verifiedOrd.PurchaseUnits[0].CustomID
	proof.VerifiedInvoiceID = verifiedOrd.PurchaseUnits[0].InvoiceID
	proof.VerifiedAmountUSD = verifiedOrd.PurchaseUnits[0].Amount.Value
	if verifiedOrd.CreateTime != "" {
		proof.LivePayPalCreateTime = verifiedOrd.CreateTime
	}

	// Honesty Invariant: A newly created v2 checkout order without payer interactive approval
	// is in status CREATED, so PayPalCaptured is strictly false.
	proof.PayPalCaptured = false
	proof.EDI997FunctionalAckCode = evalRes.EDI997AckCode
	coreWithoutHMAC := evalRes.ReceiptHeader
	if idx := strings.LastIndex(evalRes.ReceiptHeader, ";hmac="); idx > 0 {
		coreWithoutHMAC = evalRes.ReceiptHeader[:idx]
	}
	preCapCore := fmt.Sprintf("%s;pp_ord=%s;status=%s", coreWithoutHMAC, sanitizeReceiptToken(orderRes.ID), sanitizeReceiptToken(verifiedOrd.Status))
	proof.ReceiptHeader = fmt.Sprintf("%s;hmac=%s", preCapCore, e.shortHMAC(preCapCore))
	proof.Ed25519SignatureHex = hex.EncodeToString(ed25519.Sign(e.edPriv, []byte(proof.ReceiptHeader)))
	return proof, nil
}

// VerifyAndCaptureApprovedPayPalOrderE2E executes live negative control, OAuth2 token acquisition,
// 3-Way Match (850 + 861 + 810), readback verification of an existing buyer-approved PayPal Order v2,
// live capture (POST /v2/checkout/orders/{id}/capture when APPROVED, or verified COMPLETED readback),
// and Ed25519-signed ANSI X12 820 remittance advice generation.
func (e *TinyGAAPEngine) VerifyAndCaptureApprovedPayPalOrderE2E(ctx context.Context, raw850, raw861, raw810, orderID string) (*PayPalLiveSandboxProof, error) {
	orderID = strings.TrimSpace(orderID)
	base := strings.TrimRight(e.cfg.PayPalBaseURL, "/")
	proof := &PayPalLiveSandboxProof{
		ProtocolVersion:  ProtocolVersion,
		TimestampUTC:     time.Now().UTC().Format(time.RFC3339),
		EndpointBase:     base,
		KeyID:            e.keyID,
		Ed25519PubKeyHex: e.PublicKeyHex(),
	}

	// Step 1: Negative Control (must NOT return 200)
	negReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/oauth2/token", strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		return proof, err
	}
	negReq.SetBasicAuth("invalid-client-id-negative-control", "invalid-secret-negative-control")
	negReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	negResp, err := e.httpClient.Do(negReq)
	if err != nil {
		return proof, fmt.Errorf("negative control request failed: %w", err)
	}
	_, _ = io.Copy(io.Discard, negResp.Body)
	negResp.Body.Close()
	proof.NegativeControlBadCredsHTTP = negResp.StatusCode
	if negResp.StatusCode == http.StatusOK {
		return proof, fmt.Errorf("negative control failed: invalid credentials returned HTTP 200")
	}

	// Step 2: Live OAuth2 Token
	accessToken, expiresIn, oauthDebugID, err := e.acquirePayPalAccessToken(ctx)
	if err != nil {
		return proof, err
	}
	proof.OAuth2TokenHTTPCode = http.StatusOK
	proof.OAuth2DebugID = oauthDebugID
	proof.OAuth2ExpiresIn = expiresIn

	// Step 3: Register 850 + 861 and Evaluate 810 (with VerifyPayPalOrderOnSettle deferred to Step 4 so COMPLETED is also inspectable)
	po, err := e.RegisterPO850(raw850)
	if err != nil {
		return proof, err
	}
	var rcpt861 *EDI861Receipt
	if strings.TrimSpace(raw861) != "" {
		rcpt861, err = e.RegisterReceivingAdvice861(raw861)
		if err != nil {
			return proof, err
		}
	}
	inv, _, _, err := ParseEDI810(raw810)
	if err != nil {
		return proof, err
	}
	evalRes := e.resumeReplayedGrantForCapture(po, rcpt861, inv, orderID)
	if evalRes == nil {
		evalRes, err = e.EvaluateAndSettle810(ctx, raw810, "sandbox-e2e-capturer", po.SellerID)
		if evalRes != nil {
			proof.AIAuditVerdict = evalRes.AIAuditVerdict
			proof.LedgerSeq = evalRes.LedgerSeq
			proof.LedgerPrevHashHex = evalRes.LedgerPrevHashHex
			proof.LedgerEntryHashHex = evalRes.LedgerEntryHashHex
		}
		if err != nil {
			return proof, fmt.Errorf("3-way match evaluation failed: %w", err)
		}
	} else {
		proof.AIAuditVerdict = evalRes.AIAuditVerdict
	}
	proof.PayPalRequestID = evalRes.ReceiptHashHex
	proof.EDI997FunctionalAckCode = evalRes.EDI997AckCode

	// Step 4: Readback Verification of Existing Order (APPROVED or COMPLETED)
	amtStr := FormatCentsDecimal(inv.TotalCents)
	verifiedOrd, getHTTPCode, getDebugID, err := e.getAndVerifyPayPalOrderStatusWithToken(ctx, accessToken, orderID, po.SHA256Hex, inv.InvoiceNumber, amtStr, true)
	if err != nil {
		return proof, err
	}
	proof.GetOrderHTTPCode = getHTTPCode
	proof.GetOrderDebugID = getDebugID
	proof.LivePayPalOrderID = verifiedOrd.ID
	proof.LivePayPalOrderStatus = verifiedOrd.Status
	proof.LivePayPalCreateTime = verifiedOrd.CreateTime
	proof.VerifiedCustomIDEDI850SHA256 = verifiedOrd.PurchaseUnits[0].CustomID
	proof.VerifiedInvoiceID = verifiedOrd.PurchaseUnits[0].InvoiceID
	proof.VerifiedAmountUSD = verifiedOrd.PurchaseUnits[0].Amount.Value

	switch verifiedOrd.Status {
	case "APPROVED":
		capHTTPCode, capDebugID, err := e.captureApprovedPayPalOrderWithTelemetry(ctx, evalRes, po, inv, orderID)
		if capHTTPCode != 0 {
			proof.CaptureOrderHTTPCode = capHTTPCode
		}
		if capDebugID != "" {
			proof.CaptureOrderDebugID = capDebugID
		}
		if err != nil {
			return proof, err
		}
		postOrd, postGetCode, postGetDebugID, err := e.getAndVerifyPayPalOrderStatusWithToken(ctx, accessToken, orderID, po.SHA256Hex, inv.InvoiceNumber, amtStr, true)
		if err != nil {
			return proof, err
		}
		if postOrd.Status != "COMPLETED" {
			return proof, fmt.Errorf("%w: post-capture GET order %s returned status %q (want COMPLETED)", ErrPayPalCaptureNotCompleted, orderID, postOrd.Status)
		}
		proof.GetOrderHTTPCode = postGetCode
		if postGetDebugID != "" {
			proof.GetOrderDebugID = postGetDebugID
		}
		proof.LivePayPalOrderStatus = postOrd.Status
		proof.PayPalCaptured = true
		proof.LivePayPalCaptureID = evalRes.PayPalCaptureID
		proof.EDI820Remittance = evalRes.RawEDI820
		proof.EDI820SignatureHex = evalRes.EDI820SignatureHex
		proof.LedgerSeq = evalRes.LedgerSeq
		proof.LedgerPrevHashHex = evalRes.LedgerPrevHashHex
		proof.LedgerEntryHashHex = evalRes.LedgerEntryHashHex
		proof.ReceiptHeader = evalRes.ReceiptHeader
		proof.Ed25519SignatureHex = evalRes.Ed25519SignatureHex
		return proof, nil
	case "COMPLETED":
		if err := e.finalizeCompletedOrderCapture(po, rcpt861, inv, evalRes, verifiedOrd, orderID, amtStr, proof); err != nil {
			return proof, err
		}
		return proof, nil
	default:
		return proof, fmt.Errorf("%w: order %s is in status %q (requires buyer approval before capture)", ErrPayPalCaptureNotCompleted, orderID, verifiedOrd.Status)
	}
}

func (e *TinyGAAPEngine) resumeReplayedGrantForCapture(po *EDI850PO, rcpt861 *EDI861Receipt, inv *EDI810Invoice, orderID string) *SettlementEvaluationResult {
	if po == nil || inv == nil || strings.TrimSpace(e.cfg.LedgerFile) == "" {
		return nil
	}
	expectedReqID := DeterministicPayPalRequestID(po.SHA256Hex, inv.SHA256Hex, inv.InvoiceNumber)
	sellerScopedKey := strings.ToLower(strings.TrimSpace(po.SellerID)) + "|" + inv.InvoiceNumber
	e.mu.Lock()
	g, ok := e.authGrants[sellerScopedKey]
	if !ok || g == nil || g.Captured || g.ReceiptHeader != "" ||
		g.InvoiceNumber != inv.InvoiceNumber || g.PONumber != po.PONumber ||
		g.TotalCents != inv.TotalCents || g.ReceiptHashHex != expectedReqID ||
		(g.PayPalOrderID != "" && g.PayPalOrderID != strings.TrimSpace(orderID)) ||
		strings.TrimSpace(g.AgentKey) == "" || strings.TrimSpace(g.AuditorMode) == "" || strings.TrimSpace(g.AuditorModel) == "" {
		e.mu.Unlock()
		return nil
	}
	audMode := strings.TrimSpace(g.AuditorMode)
	audModel := strings.TrimSpace(g.AuditorModel)
	e.mu.Unlock()

	r861Token := "none"
	if rcpt861 != nil {
		r861Hash := rcpt861.SHA256Hex
		if len(r861Hash) > 16 {
			r861Hash = r861Hash[:16]
		}
		r861Token = rcpt861.ReceiptNumber + ":" + r861Hash
	}
	raw997 := e.buildEDI997(inv, "A", "", 0, "")
	h997 := sha256.Sum256([]byte(raw997))
	r997Token := "A:" + hex.EncodeToString(h997[:])[:16]
	receiptCore := fmt.Sprintf("tinygaap:v=3;kid=%s;inv=%s;po=%s;seller=%s;r861=%s;r997=%s;aud_mode=%s;aud_model=%s;payto=%s;rail=%s:%s;req_id=%s",
		sanitizeReceiptToken(e.keyID),
		sanitizeReceiptToken(inv.InvoiceNumber),
		sanitizeReceiptToken(po.PONumber),
		sanitizeReceiptToken(po.SellerID),
		sanitizeReceiptToken(r861Token),
		sanitizeReceiptToken(r997Token),
		sanitizeReceiptToken(audMode),
		sanitizeReceiptToken(audModel),
		sanitizeReceiptToken(po.SellerID),
		e.paypalEnvLabel(),
		FormatCentsDecimal(inv.TotalCents),
		expectedReqID,
	)
	receiptHeader := fmt.Sprintf("%s;hmac=%s", receiptCore, e.shortHMAC(receiptCore))
	receiptSig := hex.EncodeToString(ed25519.Sign(e.edPriv, []byte(receiptHeader)))
	return &SettlementEvaluationResult{
		ProtocolVersion:      ProtocolVersion,
		SettlementAuthorized: true,
		InvoiceNumber:        inv.InvoiceNumber,
		PONumber:             po.PONumber,
		TotalCents:           inv.TotalCents,
		EDI997AckCode:        "A",
		RawEDI997:            raw997,
		AIAuditVerdict: &AIAuditVerdict{
			Mode:     audMode,
			ModelID:  audModel,
			Decision: "APPROVE",
		},
		ReceiptHashHex:      expectedReqID,
		ReceiptHeader:       receiptHeader,
		KeyID:               e.keyID,
		Ed25519PubKeyHex:    e.PublicKeyHex(),
		Ed25519SignatureHex: receiptSig,
	}
}

func (e *TinyGAAPEngine) finalizeCompletedOrderCapture(po *EDI850PO, rcpt861 *EDI861Receipt, inv *EDI810Invoice, evalRes *SettlementEvaluationResult, verifiedOrd *paypalOrderReadback, orderID, amtStr string, proof *PayPalLiveSandboxProof) error {
	caps := verifiedOrd.PurchaseUnits[0].Payments.Captures
	if len(caps) == 0 || caps[0].Status != "COMPLETED" || strings.TrimSpace(caps[0].ID) == "" {
		return fmt.Errorf("%w: order %s is COMPLETED without a valid COMPLETED capture object", ErrPayPalCaptureNotCompleted, orderID)
	}
	if caps[0].Amount.CurrencyCode != "USD" || caps[0].Amount.Value != amtStr {
		return fmt.Errorf("%w: capture amount %s %s != USD %s", ErrPayPalCaptureNotCompleted, caps[0].Amount.CurrencyCode, caps[0].Amount.Value, amtStr)
	}
	captureID := strings.TrimSpace(caps[0].ID)
	sellerScopedKey := strings.ToLower(strings.TrimSpace(po.SellerID)) + "|" + inv.InvoiceNumber
	e.mu.Lock()
	g := e.authGrants[sellerScopedKey]
	if g == nil {
		e.mu.Unlock()
		return fmt.Errorf("%w: missing authorization grant for invoice %q", ErrPayPalCaptureNotCompleted, inv.InvoiceNumber)
	}
	if g.Captured {
		e.mu.Unlock()
		return fmt.Errorf("%w: invoice %q already captured", ErrDuplicateInvoiceReplay, inv.InvoiceNumber)
	}
	grantAgent := strings.TrimSpace(g.AgentKey)
	grantAudMode := strings.TrimSpace(g.AuditorMode)
	grantAudModel := strings.TrimSpace(g.AuditorModel)
	if grantAgent == "" || grantAudMode == "" || grantAudModel == "" {
		e.mu.Unlock()
		return fmt.Errorf("%w: authorization grant for %q is missing agent or auditor attribution", ErrPayPalCaptureNotCompleted, inv.InvoiceNumber)
	}
	capEntry := LedgerEntry{
		TimestampUTC:      time.Now().UTC().Format(time.RFC3339),
		EventType:         "PAYPAL_ORDER_CAPTURED",
		AgentKey:          grantAgent,
		SellerID:          po.SellerID,
		InvoiceNumber:     inv.InvoiceNumber,
		PONumber:          po.PONumber,
		TotalCents:        inv.TotalCents,
		PayPalRequestID:   evalRes.ReceiptHashHex,
		PayPalOrderID:     orderID,
		PayPalOrderStatus: "COMPLETED",
		PayPalCaptured:    true,
		PayPalCaptureID:   captureID,
		AuditorMode:       grantAudMode,
		AuditorModelID:    grantAudModel,
	}
	if err := e.appendLedgerLocked(&capEntry); err != nil {
		e.mu.Unlock()
		return err
	}
	g.Captured = true
	g.CaptureID = captureID
	g.PayPalOrderID = orderID
	e.boundOrders[orderID] = sellerScopedKey
	e.mu.Unlock()

	raw820, sig820Hex := e.buildEDI820WithLedger(po, rcpt861, inv, evalRes.ReceiptHashHex, orderID, captureID, capEntry.Seq, capEntry.EntryHashHex)
	coreWithoutHMAC := evalRes.ReceiptHeader
	if idx := strings.LastIndex(evalRes.ReceiptHeader, ";hmac="); idx > 0 {
		coreWithoutHMAC = stripLedgerAndPostCaptureReceiptParams(evalRes.ReceiptHeader[:idx])
	}
	coreWithCapture := fmt.Sprintf("%s;pp_ord=%s;pp_cap=%s;status=COMPLETED", coreWithoutHMAC, sanitizeReceiptToken(orderID), sanitizeReceiptToken(captureID))
	if capEntry.Seq > 0 && len(capEntry.EntryHashHex) >= 16 {
		coreWithCapture = fmt.Sprintf("%s;lseq=%d;lhash=%s", coreWithCapture, capEntry.Seq, capEntry.EntryHashHex[:16])
	}
	postHeader := fmt.Sprintf("%s;hmac=%s", coreWithCapture, e.shortHMAC(coreWithCapture))
	postSigHex := hex.EncodeToString(ed25519.Sign(e.edPriv, []byte(postHeader)))

	evalRes.PayPalOrderID = orderID
	evalRes.PayPalCaptureID = captureID
	evalRes.RawEDI820 = raw820
	evalRes.EDI820SignatureHex = sig820Hex
	evalRes.LedgerSeq = capEntry.Seq
	evalRes.LedgerPrevHashHex = capEntry.PrevHashHex
	evalRes.LedgerEntryHashHex = capEntry.EntryHashHex
	evalRes.ReceiptHeader = postHeader
	evalRes.Ed25519SignatureHex = postSigHex

	proof.LivePayPalOrderStatus = "COMPLETED"
	proof.PayPalCaptured = true
	proof.LivePayPalCaptureID = captureID
	proof.EDI820Remittance = raw820
	proof.EDI820SignatureHex = sig820Hex
	proof.LedgerSeq = capEntry.Seq
	proof.LedgerPrevHashHex = capEntry.PrevHashHex
	proof.LedgerEntryHashHex = capEntry.EntryHashHex
	proof.ReceiptHeader = postHeader
	proof.Ed25519SignatureHex = postSigHex
	return nil
}
