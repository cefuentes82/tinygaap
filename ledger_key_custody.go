// Copyright 2026 Carlos Fuentes. Licensed under the Apache License, Version 2.0.
package tinygaap

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const EphemeralKeyID = "efimera"

var (
	ErrKeyCustodyInvalid = errors.New("tinygaap: persistent Ed25519 key missing, insecure permissions, or invalid format (fail-closed)")
	ErrUntrustedKeyID    = errors.New("tinygaap: ephemeral, missing, or unregistered Ed25519 key ID (fail-closed)")
	ErrLedgerInvalid     = errors.New("tinygaap: persistent ledger missing, locked, corrupt, or tampered (fail-closed)")
)

// LedgerEntry represents a single hash-chained, Ed25519-signed append-only JSONL record.
type LedgerEntry struct {
	Seq               int64      `json:"seq"`
	TimestampUTC      string     `json:"timestamp_utc"`
	EventType         string     `json:"event_type"`
	AgentKey          string     `json:"agent_key"`
	SellerID          string     `json:"seller_id"`
	InvoiceNumber     string     `json:"invoice_number"`
	PONumber          string     `json:"po_number"`
	BilledLines       []LineItem `json:"billed_lines,omitempty"`
	TotalCents        int64      `json:"total_cents"`
	PayPalRequestID   string     `json:"paypal_request_id"`
	PayPalOrderID     string     `json:"paypal_order_id,omitempty"`
	PayPalOrderStatus string     `json:"paypal_order_status,omitempty"`
	PayPalCaptured    bool       `json:"paypal_captured"`
	PayPalCaptureID   string     `json:"paypal_capture_id,omitempty"`
	AuditorMode       string     `json:"auditor_mode"`
	AuditorModelID    string     `json:"auditor_model_id"`
	KID               string     `json:"kid"`
	PrevHashHex       string     `json:"prev_hash_hex"`
	EntryHashHex      string     `json:"entry_hash_hex"`
	EntrySigHex       string     `json:"entry_sig_hex"`
}

type ledgerEntryHashPayload struct {
	Version           string     `json:"v"`
	Seq               int64      `json:"seq"`
	TimestampUTC      string     `json:"timestamp_utc"`
	EventType         string     `json:"event_type"`
	AgentKey          string     `json:"agent_key"`
	SellerID          string     `json:"seller_id"`
	InvoiceNumber     string     `json:"invoice_number"`
	PONumber          string     `json:"po_number"`
	BilledLines       []LineItem `json:"billed_lines,omitempty"`
	TotalCents        int64      `json:"total_cents"`
	PayPalRequestID   string     `json:"paypal_request_id"`
	PayPalOrderID     string     `json:"paypal_order_id,omitempty"`
	PayPalOrderStatus string     `json:"paypal_order_status,omitempty"`
	PayPalCaptured    bool       `json:"paypal_captured"`
	PayPalCaptureID   string     `json:"paypal_capture_id,omitempty"`
	AuditorMode       string     `json:"auditor_mode"`
	AuditorModelID    string     `json:"auditor_model_id"`
	KID               string     `json:"kid"`
	PrevHashHex       string     `json:"prev_hash_hex"`
}

// ComputeKeyID returns the 16-hex-character key identifier derived from the first 8 bytes
// of SHA-256 over the raw 32-byte Ed25519 public key.
func ComputeKeyID(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		return ""
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

func isValidPersistentKID(kid string) bool {
	if len(kid) != 16 || kid == EphemeralKeyID {
		return false
	}
	for i := 0; i < len(kid); i++ {
		c := kid[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func computeLedgerEntryHashChecked(e LedgerEntry) (string, error) {
	canon, err := json.Marshal(ledgerEntryHashPayload{
		Version:           "tinygaap-ledger-v1",
		Seq:               e.Seq,
		TimestampUTC:      e.TimestampUTC,
		EventType:         e.EventType,
		AgentKey:          e.AgentKey,
		SellerID:          e.SellerID,
		InvoiceNumber:     e.InvoiceNumber,
		PONumber:          e.PONumber,
		BilledLines:       e.BilledLines,
		TotalCents:        e.TotalCents,
		PayPalRequestID:   e.PayPalRequestID,
		PayPalOrderID:     e.PayPalOrderID,
		PayPalOrderStatus: e.PayPalOrderStatus,
		PayPalCaptured:    e.PayPalCaptured,
		PayPalCaptureID:   e.PayPalCaptureID,
		AuditorMode:       e.AuditorMode,
		AuditorModelID:    e.AuditorModelID,
		KID:               e.KID,
		PrevHashHex:       e.PrevHashHex,
	})
	if err != nil || len(canon) == 0 {
		return "", fmt.Errorf("%w: canonical ledger marshal failed: %v", ErrLedgerInvalid, err)
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

// ComputeLedgerEntryHash computes the canonical SHA-256 hex digest of a LedgerEntry's payload,
// returning an empty string (never hashing empty/partial bytes) if canonical marshaling fails.
func ComputeLedgerEntryHash(e LedgerEntry) string {
	h, err := computeLedgerEntryHashChecked(e)
	if err != nil {
		return ""
	}
	return h
}

func loadOrInitEd25519Key0600(keyPath string, allowInit bool, keysDir string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	info, err := os.Lstat(keyPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("%w: stat failed", ErrKeyCustodyInvalid)
		}
		if !allowInit {
			return nil, nil, fmt.Errorf("%w: key file does not exist", ErrKeyCustodyInvalid)
		}
		if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
			return nil, nil, fmt.Errorf("%w: mkdir failed", ErrKeyCustodyInvalid)
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: keygen failed", ErrKeyCustodyInvalid)
		}
		f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: exclusive create failed", ErrKeyCustodyInvalid)
		}
		if _, err := f.WriteString(hex.EncodeToString(priv) + "\n"); err != nil {
			_ = f.Close()
			return nil, nil, fmt.Errorf("%w: write failed", ErrKeyCustodyInvalid)
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return nil, nil, fmt.Errorf("%w: fsync failed", ErrKeyCustodyInvalid)
		}
		if err := f.Close(); err != nil {
			return nil, nil, fmt.Errorf("%w: close failed", ErrKeyCustodyInvalid)
		}
		if strings.TrimSpace(keysDir) != "" {
			kid := ComputeKeyID(pub)
			if err := os.MkdirAll(keysDir, 0755); err != nil {
				return nil, nil, fmt.Errorf("%w: mkdir keys dir failed", ErrKeyCustodyInvalid)
			}
			pubPath := filepath.Join(keysDir, kid+".pub")
			if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)+"\n"), 0644); err != nil {
				return nil, nil, fmt.Errorf("%w: write public key failed", ErrKeyCustodyInvalid)
			}
		}
		return priv, pub, nil
	}

	if allowInit {
		return nil, nil, fmt.Errorf("%w: key file already exists while InitEd25519Key is set", ErrKeyCustodyInvalid)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, nil, fmt.Errorf("%w: key file must be a regular 0600 file (got mode %#o)", ErrKeyCustodyInvalid, info.Mode().Perm())
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read failed", ErrKeyCustodyInvalid)
	}
	privBytes, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("%w: invalid 64-byte hex Ed25519 private key", ErrKeyCustodyInvalid)
	}
	derived := ed25519.NewKeyFromSeed(privBytes[:ed25519.SeedSize])
	if !bytes.Equal(derived, privBytes) {
		return nil, nil, fmt.Errorf("%w: private key seed/public half mismatch", ErrKeyCustodyInvalid)
	}
	priv := ed25519.PrivateKey(privBytes)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, nil
}

// LoadPublicKeyFromRegistry loads <keysDir>/<kid>.pub, verifies that kid is a non-ephemeral
// 16-hex SHA-256 prefix (never "efimera"), and confirms sha256(pub)[:16] == kid.
func LoadPublicKeyFromRegistry(keysDir, kid string) (ed25519.PublicKey, error) {
	if !isValidPersistentKID(kid) {
		return nil, fmt.Errorf("%w: invalid or ephemeral kid %q", ErrUntrustedKeyID, kid)
	}
	if strings.TrimSpace(keysDir) == "" {
		return nil, fmt.Errorf("%w: empty keys directory", ErrUntrustedKeyID)
	}
	pubPath := filepath.Join(keysDir, kid+".pub")
	raw, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("%w: unregistered kid %q", ErrUntrustedKeyID, kid)
	}
	trimmed := strings.TrimRight(string(raw), "\r\n")
	if len(trimmed) != ed25519.PublicKeySize*2 {
		return nil, fmt.Errorf("%w: malformed public key length in %s", ErrUntrustedKeyID, filepath.Base(pubPath))
	}
	pubBytes, err := hex.DecodeString(trimmed)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid hex public key in %s", ErrUntrustedKeyID, filepath.Base(pubPath))
	}
	pub := ed25519.PublicKey(pubBytes)
	if ComputeKeyID(pub) != kid {
		return nil, fmt.Errorf("%w: public key content does not match kid %q", ErrUntrustedKeyID, kid)
	}
	return pub, nil
}

func parseStrictReceiptHeader(receiptHeader string) (map[string]string, error) {
	const prefix = "tinygaap:v=3;"
	if !strings.HasPrefix(receiptHeader, prefix) {
		return nil, errors.New("receipt header missing tinygaap:v=3 prefix")
	}
	if strings.ContainsAny(receiptHeader, "\r\n") {
		return nil, errors.New("receipt header contains newline")
	}
	rest := receiptHeader[len(prefix):]
	tokens := strings.Split(rest, ";")
	if len(tokens) < 2 {
		return nil, errors.New("receipt header has too few parameters")
	}
	params := make(map[string]string, len(tokens))
	for i, tok := range tokens {
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 || eq == len(tok)-1 || strings.IndexByte(tok[eq+1:], '=') >= 0 {
			return nil, fmt.Errorf("malformed receipt parameter %q", tok)
		}
		k := tok[:eq]
		v := tok[eq+1:]
		if _, dup := params[k]; dup {
			return nil, fmt.Errorf("duplicate receipt parameter %q", k)
		}
		if i == len(tokens)-1 && k != "hmac" {
			return nil, errors.New("hmac must be the final receipt parameter")
		}
		if k == "hmac" && i != len(tokens)-1 {
			return nil, errors.New("trailing parameters after hmac are forbidden")
		}
		params[k] = v
	}
	return params, nil
}

// VerifyReceiptWithRegistry verifies an Ed25519 receipt signature strictly against a public-key
// registry directory (<keysDir>/<kid>.pub), extracting kid from inside the signed receipt_header
// and rejecting kid="efimera" or any unregistered key (closing N1 and N5).
func VerifyReceiptWithRegistry(keysDir, receiptHeader, sigHex string) error {
	if strings.HasPrefix(receiptHeader, "ISA*") {
		if sigHex == "" || !strings.Contains(receiptHeader, "ED25519:"+sigHex) {
			return fmt.Errorf("%w: mismatched or empty signature for EDI 820", ErrUntrustedKeyID)
		}
		return VerifyEDI820WithRegistry(keysDir, receiptHeader)
	}
	params, err := parseStrictReceiptHeader(receiptHeader)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUntrustedKeyID, err)
	}
	kid := params["kid"]
	pub, err := LoadPublicKeyFromRegistry(keysDir, kid)
	if err != nil {
		return err
	}
	sigBytes, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("%w: invalid Ed25519 signature hex", ErrUntrustedKeyID)
	}
	if !ed25519.Verify(pub, []byte(receiptHeader), sigBytes) {
		return fmt.Errorf("%w: Ed25519 signature verification failed for kid %q", ErrUntrustedKeyID, kid)
	}
	return nil
}

var edi820RefLKRegex = regexp.MustCompile(`(?m)^REF\*LK\*([^~*\r\n]+)(?:\*[^~\r\n]*)?~$`)

// VerifyEDI820WithRegistry extracts the signed REF*LK*<kid> segment from an EDI 820 document,
// rejects ephemeral or unregistered keys, and verifies the canonical Ed25519 signature.
func VerifyEDI820WithRegistry(keysDir, raw820 string) error {
	if strings.Count(raw820, "REF*LK*") != 1 {
		return fmt.Errorf("%w: EDI 820 must contain exactly one REF*LK* key reference", ErrUntrustedKeyID)
	}
	matches := edi820RefLKRegex.FindAllStringSubmatch(raw820, -1)
	if len(matches) != 1 || len(matches[0]) < 2 {
		return fmt.Errorf("%w: malformed REF*LK* segment in EDI 820", ErrUntrustedKeyID)
	}
	kid := matches[0][1]
	pub, err := LoadPublicKeyFromRegistry(keysDir, kid)
	if err != nil {
		return err
	}
	if !VerifyEDI820Signature(hex.EncodeToString(pub), raw820) {
		return fmt.Errorf("%w: canonical EDI 820 Ed25519 signature invalid for kid %q", ErrUntrustedKeyID, kid)
	}
	return nil
}

func validateLedgerEntryStrict(entry LedgerEntry, expectedSeq int64, expectedPrevHash string) (time.Time, error) {
	if entry.Seq != expectedSeq {
		return time.Time{}, fmt.Errorf("%w: ledger sequence mismatch at %d (got %d)", ErrLedgerInvalid, expectedSeq, entry.Seq)
	}
	if entry.PrevHashHex != expectedPrevHash {
		return time.Time{}, fmt.Errorf("%w: broken prev_hash_hex chain at seq %d", ErrLedgerInvalid, expectedSeq)
	}
	ts, err := time.Parse(time.RFC3339, entry.TimestampUTC)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: invalid RFC3339 timestamp at seq %d", ErrLedgerInvalid, expectedSeq)
	}
	if strings.TrimSpace(entry.AgentKey) == "" ||
		strings.TrimSpace(entry.SellerID) == "" ||
		strings.TrimSpace(entry.InvoiceNumber) == "" ||
		strings.TrimSpace(entry.PONumber) == "" ||
		strings.TrimSpace(entry.PayPalRequestID) == "" ||
		strings.TrimSpace(entry.AuditorMode) == "" ||
		strings.TrimSpace(entry.AuditorModelID) == "" ||
		strings.TrimSpace(entry.KID) == "" {
		return time.Time{}, fmt.Errorf("%w: missing required field at seq %d", ErrLedgerInvalid, expectedSeq)
	}
	if entry.TotalCents <= 0 {
		return time.Time{}, fmt.Errorf("%w: non-positive total_cents (%d) at seq %d", ErrLedgerInvalid, entry.TotalCents, expectedSeq)
	}
	switch entry.EventType {
	case "SETTLEMENT_AUTHORIZED":
		if entry.PayPalCaptured {
			return time.Time{}, fmt.Errorf("%w: SETTLEMENT_AUTHORIZED cannot have paypal_captured=true at seq %d", ErrLedgerInvalid, expectedSeq)
		}
		for _, bl := range entry.BilledLines {
			if strings.TrimSpace(bl.VendorSKU) == "" || bl.Quantity <= 0 || bl.UnitPriceCents < 0 {
				return time.Time{}, fmt.Errorf("%w: invalid billed_lines item at seq %d", ErrLedgerInvalid, expectedSeq)
			}
		}
	case "PAYPAL_ORDER_CAPTURED":
		if !entry.PayPalCaptured || strings.TrimSpace(entry.PayPalOrderID) == "" || strings.TrimSpace(entry.PayPalCaptureID) == "" {
			return time.Time{}, fmt.Errorf("%w: PAYPAL_ORDER_CAPTURED missing order_id or capture_id at seq %d", ErrLedgerInvalid, expectedSeq)
		}
	default:
		return time.Time{}, fmt.Errorf("%w: unknown event_type %q at seq %d", ErrLedgerInvalid, entry.EventType, expectedSeq)
	}
	expectedEntryHash, err := computeLedgerEntryHashChecked(entry)
	if err != nil || expectedEntryHash == "" {
		return time.Time{}, fmt.Errorf("%w: canonical hash failed at seq %d: %v", ErrLedgerInvalid, expectedSeq, err)
	}
	if entry.EntryHashHex != expectedEntryHash {
		return time.Time{}, fmt.Errorf("%w: tampered entry_hash_hex at seq %d", ErrLedgerInvalid, expectedSeq)
	}
	return ts.UTC(), nil
}

// VerifyLedgerFile reads an existing ledger file without O_CREATE, requires a non-empty keysDir,
// and validates monotonic seq, hash chaining, strict field presence, duplicate replay invariants,
// and Ed25519 entry signatures.
func VerifyLedgerFile(ledgerPath, keysDir string) ([]LedgerEntry, error) {
	if strings.TrimSpace(keysDir) == "" {
		return nil, fmt.Errorf("%w: keysDir is required to verify ledger entry signatures", ErrLedgerInvalid)
	}
	f, err := os.Open(ledgerPath)
	if err != nil {
		return nil, fmt.Errorf("%w: open ledger failed: %v", ErrLedgerInvalid, err)
	}
	defer f.Close()

	var entries []LedgerEntry
	seenAuth := make(map[string]bool)
	seenCap := make(map[string]bool)
	prevHash := strings.Repeat("0", 64)
	var seq int64

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			return nil, fmt.Errorf("%w: blank line in ledger at seq %d", ErrLedgerInvalid, seq+1)
		}
		var entry LedgerEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("%w: corrupt JSON at seq %d: %v", ErrLedgerInvalid, seq+1, err)
		}
		seq++
		if _, err := validateLedgerEntryStrict(entry, seq, prevHash); err != nil {
			return nil, err
		}
		if strings.TrimSpace(keysDir) != "" {
			pub, err := LoadPublicKeyFromRegistry(keysDir, entry.KID)
			if err != nil {
				return nil, fmt.Errorf("%w: seq %d key check failed: %v", ErrLedgerInvalid, seq, err)
			}
			sigBytes, err := hex.DecodeString(entry.EntrySigHex)
			if err != nil || len(sigBytes) != ed25519.SignatureSize || !ed25519.Verify(pub, []byte(entry.EntryHashHex), sigBytes) {
				return nil, fmt.Errorf("%w: invalid entry_sig_hex at seq %d", ErrLedgerInvalid, seq)
			}
		}
		sellerKey := strings.ToLower(strings.TrimSpace(entry.SellerID)) + "|" + entry.InvoiceNumber
		switch entry.EventType {
		case "SETTLEMENT_AUTHORIZED":
			if seenAuth[sellerKey] {
				return nil, fmt.Errorf("%w: duplicate SETTLEMENT_AUTHORIZED for %s at seq %d", ErrLedgerInvalid, sellerKey, seq)
			}
			seenAuth[sellerKey] = true
		case "PAYPAL_ORDER_CAPTURED":
			if !seenAuth[sellerKey] || seenCap[sellerKey] {
				return nil, fmt.Errorf("%w: invalid or duplicate PAYPAL_ORDER_CAPTURED for %s at seq %d", ErrLedgerInvalid, sellerKey, seq)
			}
			seenCap[sellerKey] = true
		}
		lineSum := sha256.Sum256([]byte(line))
		prevHash = hex.EncodeToString(lineSum[:])
		entries = append(entries, entry)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: scan ledger failed: %v", ErrLedgerInvalid, err)
	}
	return entries, nil
}

// VerifyReceiptAgainstLedger verifies a receipt against both the public-key registry and the
// hash-chained ledger file, catching tail truncation for any verifier holding a later receipt
// whose lseq exceeds the ledger head (the engine itself has no external head anchor on restart).
func VerifyReceiptAgainstLedger(ledgerPath, keysDir, receiptHeader, sigHex string) error {
	if err := VerifyReceiptWithRegistry(keysDir, receiptHeader, sigHex); err != nil {
		return err
	}
	params, err := parseStrictReceiptHeader(receiptHeader)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLedgerInvalid, err)
	}
	lseqStr, okSeq := params["lseq"]
	lhash16, okHash := params["lhash"]
	if !okSeq || !okHash || len(lhash16) != 16 {
		return fmt.Errorf("%w: receipt missing lseq or 16-hex lhash binding", ErrLedgerInvalid)
	}
	lseq, err := strconv.ParseInt(lseqStr, 10, 64)
	if err != nil || lseq <= 0 {
		return fmt.Errorf("%w: invalid lseq %q in receipt", ErrLedgerInvalid, lseqStr)
	}
	entries, err := VerifyLedgerFile(ledgerPath, keysDir)
	if err != nil {
		return err
	}
	if lseq > int64(len(entries)) {
		return fmt.Errorf("%w: receipt references lseq=%d but ledger ends at seq=%d (truncation detected)", ErrLedgerInvalid, lseq, len(entries))
	}
	target := entries[lseq-1]
	if !strings.HasPrefix(target.EntryHashHex, lhash16) {
		return fmt.Errorf("%w: receipt lhash %q does not match ledger seq %d entry hash", ErrLedgerInvalid, lhash16, lseq)
	}
	if sanitizeReceiptToken(target.InvoiceNumber) != params["inv"] || target.KID != params["kid"] {
		return fmt.Errorf("%w: receipt invoice/kid mismatch against ledger seq %d", ErrLedgerInvalid, lseq)
	}
	return nil
}

func (e *TinyGAAPEngine) openLockAndReplayLedger(ledgerPath string, allowInit bool) error {
	var f *os.File
	info, statErr := os.Lstat(ledgerPath)
	if statErr != nil {
		if !os.IsNotExist(statErr) {
			return fmt.Errorf("%w: stat ledger failed", ErrLedgerInvalid)
		}
		if !allowInit {
			return fmt.Errorf("%w: ledger file %s does not exist (pass InitLedger to initialize)", ErrLedgerInvalid, filepath.Base(ledgerPath))
		}
		if err := os.MkdirAll(filepath.Dir(ledgerPath), 0700); err != nil {
			return fmt.Errorf("%w: mkdir ledger dir failed", ErrLedgerInvalid)
		}
		created, err := os.OpenFile(ledgerPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("%w: create ledger failed: %v", ErrLedgerInvalid, err)
		}
		if err := created.Sync(); err != nil {
			_ = created.Close()
			return fmt.Errorf("%w: fsync initial ledger failed", ErrLedgerInvalid)
		}
		f = created
	} else {
		if allowInit {
			return fmt.Errorf("%w: ledger file already exists while InitLedger is set", ErrLedgerInvalid)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("%w: ledger file must be regular 0600 (got %#o)", ErrLedgerInvalid, info.Mode().Perm())
		}
		opened, err := os.OpenFile(ledgerPath, os.O_RDWR, 0600)
		if err != nil {
			return fmt.Errorf("%w: open ledger failed: %v", ErrLedgerInvalid, err)
		}
		f = opened
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return fmt.Errorf("%w: exclusive flock failed (ledger already locked by another engine)", ErrLedgerInvalid)
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
		return fmt.Errorf("%w: seek start failed", ErrLedgerInvalid)
	}

	prevHash := strings.Repeat("0", 64)
	var seq int64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			_ = f.Close()
			return fmt.Errorf("%w: blank line in ledger at seq %d", ErrLedgerInvalid, seq+1)
		}
		var entry LedgerEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			_ = f.Close()
			return fmt.Errorf("%w: corrupt JSON at seq %d", ErrLedgerInvalid, seq+1)
		}
		seq++
		ts, err := validateLedgerEntryStrict(entry, seq, prevHash)
		if err != nil {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			_ = f.Close()
			return err
		}

		// Verify entry signature with engine key (if matching KID) or public-key registry.
		var verifyPub ed25519.PublicKey
		if entry.KID == e.keyID {
			verifyPub = e.edPub
		} else if strings.TrimSpace(e.cfg.KeysDir) != "" {
			regPub, err := LoadPublicKeyFromRegistry(e.cfg.KeysDir, entry.KID)
			if err != nil {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
				return fmt.Errorf("%w: seq %d unknown kid %q", ErrLedgerInvalid, seq, entry.KID)
			}
			verifyPub = regPub
		} else {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			_ = f.Close()
			return fmt.Errorf("%w: seq %d signed by kid %q without KeysDir configured", ErrLedgerInvalid, seq, entry.KID)
		}
		sigBytes, err := hex.DecodeString(entry.EntrySigHex)
		if err != nil || len(sigBytes) != ed25519.SignatureSize || !ed25519.Verify(verifyPub, []byte(entry.EntryHashHex), sigBytes) {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			_ = f.Close()
			return fmt.Errorf("%w: invalid entry signature at seq %d", ErrLedgerInvalid, seq)
		}

		sellerKey := strings.ToLower(strings.TrimSpace(entry.SellerID)) + "|" + entry.InvoiceNumber
		switch entry.EventType {
		case "SETTLEMENT_AUTHORIZED":
			if _, exists := e.settledSellerInv[sellerKey]; exists {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
				return fmt.Errorf("%w: duplicate invoice authorization %s in ledger at seq %d", ErrLedgerInvalid, sellerKey, seq)
			}
			if entry.PayPalOrderID != "" {
				if boundKey, bound := e.boundOrders[entry.PayPalOrderID]; bound && boundKey != sellerKey {
					_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
					_ = f.Close()
					return fmt.Errorf("%w: conflicting PayPalOrderID binding at seq %d", ErrLedgerInvalid, seq)
				}
				e.boundOrders[entry.PayPalOrderID] = sellerKey
			}
			e.settledInv[entry.InvoiceNumber] = entry.PayPalRequestID
			e.settledSellerInv[sellerKey] = entry.PayPalRequestID
			if e.billedLines[entry.PONumber] == nil {
				e.billedLines[entry.PONumber] = make(map[string]int64)
			}
			for _, bl := range entry.BilledLines {
				e.billedLines[entry.PONumber][bl.VendorSKU] += bl.Quantity
			}
			rec := spendRecord{Timestamp: ts, Cents: entry.TotalCents}
			e.agentSpend[entry.AgentKey] = append(e.agentSpend[entry.AgentKey], rec)
			e.globalSpend = append(e.globalSpend, rec)
			e.authGrants[sellerKey] = &authGrant{
				AgentKey:       entry.AgentKey,
				SellerID:       entry.SellerID,
				InvoiceNumber:  entry.InvoiceNumber,
				PONumber:       entry.PONumber,
				PayPalOrderID:  entry.PayPalOrderID,
				TotalCents:     entry.TotalCents,
				ReceiptHashHex: entry.PayPalRequestID,
				AuditorMode:    entry.AuditorMode,
				AuditorModel:   entry.AuditorModelID,
				Captured:       false,
			}
		case "PAYPAL_ORDER_CAPTURED":
			grant, ok := e.authGrants[sellerKey]
			if !ok || grant == nil || grant.Captured {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
				return fmt.Errorf("%w: orphan or duplicate capture in ledger at seq %d", ErrLedgerInvalid, seq)
			}
			if boundKey, bound := e.boundOrders[entry.PayPalOrderID]; bound && boundKey != sellerKey {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
				return fmt.Errorf("%w: conflicting capture PayPalOrderID at seq %d", ErrLedgerInvalid, seq)
			}
			grant.Captured = true
			grant.CaptureID = entry.PayPalCaptureID
			grant.PayPalOrderID = entry.PayPalOrderID
			e.boundOrders[entry.PayPalOrderID] = sellerKey
		}

		lineSum := sha256.Sum256([]byte(line))
		prevHash = hex.EncodeToString(lineSum[:])
	}
	if err := sc.Err(); err != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
		return fmt.Errorf("%w: scan ledger failed: %v", ErrLedgerInvalid, err)
	}

	e.ledgerFile = f
	e.ledgerSeq = seq
	e.ledgerLastHash = prevHash
	return nil
}

// Close syncs, unlocks, and closes the engine's persistent ledger file if open.
func (e *TinyGAAPEngine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ledgerFile == nil {
		return nil
	}
	f := e.ledgerFile
	e.ledgerFile = nil
	syncErr := f.Sync()
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	closeErr := f.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

// KeyID returns the engine's Ed25519 key identifier (16-hex SHA-256 prefix, or "efimera" in ephemeral mode).
func (e *TinyGAAPEngine) KeyID() string {
	return e.keyID
}

func (e *TinyGAAPEngine) appendLedgerLocked(entry *LedgerEntry) error {
	if e.ledgerFile == nil {
		if strings.TrimSpace(e.cfg.LedgerFile) != "" {
			return fmt.Errorf("%w: persistent ledger is closed", ErrLedgerInvalid)
		}
		entry.Seq = 0
		entry.PrevHashHex = ""
		entry.EntryHashHex = ""
		return nil
	}
	entry.Seq = e.ledgerSeq + 1
	entry.PrevHashHex = e.ledgerLastHash
	entry.KID = e.keyID
	if _, err := validateLedgerEntryStrictForWrite(*entry); err != nil {
		return err
	}
	entryHash, err := computeLedgerEntryHashChecked(*entry)
	if err != nil {
		return err
	}
	entry.EntryHashHex = entryHash
	entry.EntrySigHex = hex.EncodeToString(ed25519.Sign(e.edPriv, []byte(entry.EntryHashHex)))

	lineBytes, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("%w: marshal ledger entry: %v", ErrLedgerInvalid, err)
	}
	if _, err := e.ledgerFile.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("%w: seek ledger end: %v", ErrLedgerInvalid, err)
	}
	if _, err := e.ledgerFile.Write(append(lineBytes, '\n')); err != nil {
		return fmt.Errorf("%w: write ledger entry: %v", ErrLedgerInvalid, err)
	}
	if err := e.ledgerFile.Sync(); err != nil {
		return fmt.Errorf("%w: fsync ledger entry: %v", ErrLedgerInvalid, err)
	}
	lineSum := sha256.Sum256(lineBytes)
	e.ledgerSeq = entry.Seq
	e.ledgerLastHash = hex.EncodeToString(lineSum[:])
	return nil
}

func validateLedgerEntryStrictForWrite(entry LedgerEntry) (time.Time, error) {
	entry.EntryHashHex = ComputeLedgerEntryHash(entry)
	return validateLedgerEntryStrict(entry, entry.Seq, entry.PrevHashHex)
}

func stripLedgerAndPostCaptureReceiptParams(core string) string {
	const prefix = "tinygaap:v=3;"
	if !strings.HasPrefix(core, prefix) {
		return core
	}
	parts := strings.Split(core[len(prefix):], ";")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.HasPrefix(p, "lseq=") || strings.HasPrefix(p, "lhash=") ||
			strings.HasPrefix(p, "pp_ord=") || strings.HasPrefix(p, "pp_cap=") || strings.HasPrefix(p, "status=") {
			continue
		}
		kept = append(kept, p)
	}
	return prefix + strings.Join(kept, ";")
}

// VerifyWaitApprovalAndCapturePayPalOrderE2E creates a PayPal Order v2 (intent=CAPTURE) bound to
// the 3-Way Matched EDI 850/861/810, invokes onApproveURL with the Sandbox buyer approval link
// (rel="approve" or "payer-action"), polls GET /v2/checkout/orders/{id} every pollInterval up to
// waitTimeout until status becomes APPROVED, executes POST /v2/checkout/orders/{id}/capture,
// confirms COMPLETED via a post-capture GET readback, records the capture in the persistent ledger,
// and emits a signed EDI 820 remittance advice and signed PayPalLiveSandboxProof.
// If waitTimeout expires before buyer approval, returns a signed CREATED proof with PayPalCaptured=false
// alongside ErrPayPalCaptureNotCompleted.
func (e *TinyGAAPEngine) VerifyWaitApprovalAndCapturePayPalOrderE2E(
	ctx context.Context,
	raw850, raw861, raw810 string,
	waitTimeout, pollInterval time.Duration,
	onApproveURL func(string),
) (*PayPalLiveSandboxProof, error) {
	if waitTimeout <= 0 {
		waitTimeout = 10 * time.Minute
	}
	if pollInterval <= 0 {
		pollInterval = 10 * time.Second
	}

	base := strings.TrimRight(e.cfg.PayPalBaseURL, "/")
	proof := &PayPalLiveSandboxProof{
		ProtocolVersion:  ProtocolVersion,
		TimestampUTC:     time.Now().UTC().Format(time.RFC3339),
		EndpointBase:     base,
		KeyID:            e.KeyID(),
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
	evalRes, err := e.EvaluateAndSettle810(ctx, raw810, "sandbox-e2e-wait-approval", po.SellerID)
	if evalRes != nil {
		proof.AIAuditVerdict = evalRes.AIAuditVerdict
		proof.LedgerSeq = evalRes.LedgerSeq
		proof.LedgerPrevHashHex = evalRes.LedgerPrevHashHex
		proof.LedgerEntryHashHex = evalRes.LedgerEntryHashHex
	}
	if err != nil {
		return proof, fmt.Errorf("3-way match evaluation failed: %w", err)
	}
	proof.PayPalRequestID = evalRes.ReceiptHashHex
	proof.EDI997FunctionalAckCode = evalRes.EDI997AckCode

	// Step 4: Create Live PayPal Order v2
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

	createBytes, _ := io.ReadAll(createResp.Body)
	if createResp.StatusCode != http.StatusCreated && createResp.StatusCode != http.StatusOK {
		return proof, fmt.Errorf("create order returned HTTP %d (debug_id=%s): %s", createResp.StatusCode, proof.CreateOrderDebugID, string(createBytes))
	}

	var orderRes struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		CreateTime string `json:"create_time"`
		Links      []struct {
			Href string `json:"href"`
			Rel  string `json:"rel"`
		} `json:"links"`
	}
	if err := json.Unmarshal(createBytes, &orderRes); err != nil || orderRes.ID == "" {
		return proof, errors.New("invalid create order JSON response")
	}
	approveURL := ""
	for _, lnk := range orderRes.Links {
		if strings.EqualFold(lnk.Rel, "approve") && strings.TrimSpace(lnk.Href) != "" {
			approveURL = strings.TrimSpace(lnk.Href)
			break
		}
	}
	if approveURL == "" {
		for _, lnk := range orderRes.Links {
			if strings.EqualFold(lnk.Rel, "payer-action") && strings.TrimSpace(lnk.Href) != "" {
				approveURL = strings.TrimSpace(lnk.Href)
				break
			}
		}
	}
	if approveURL == "" {
		return proof, fmt.Errorf("%w: create order response for %s did not include a rel=approve link", ErrPayPalCaptureNotCompleted, orderRes.ID)
	}

	// Step 5: Initial GET Readback + Emit Approval URL
	verifiedOrd, getHTTPCode, getDebugID, err := e.getAndVerifyPayPalOrderStatusWithToken(ctx, accessToken, orderRes.ID, po.SHA256Hex, inv.InvoiceNumber, amtStr, true)
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

	if onApproveURL != nil {
		onApproveURL(approveURL)
	}

	// Step 6: Poll until status == APPROVED (or timeout)
	waitCtx, cancelWait := context.WithTimeout(ctx, waitTimeout)
	defer cancelWait()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for verifiedOrd.Status != "APPROVED" && verifiedOrd.Status != "COMPLETED" {
		select {
		case <-waitCtx.Done():
			proof.PayPalCaptured = false
			coreWithoutHMAC := evalRes.ReceiptHeader
			if idx := strings.LastIndex(evalRes.ReceiptHeader, ";hmac="); idx > 0 {
				coreWithoutHMAC = evalRes.ReceiptHeader[:idx]
			}
			timeoutCore := fmt.Sprintf("%s;pp_ord=%s;status=%s", coreWithoutHMAC, sanitizeReceiptToken(orderRes.ID), sanitizeReceiptToken(verifiedOrd.Status))
			proof.ReceiptHeader = fmt.Sprintf("%s;hmac=%s", timeoutCore, e.shortHMAC(timeoutCore))
			proof.Ed25519SignatureHex = hex.EncodeToString(ed25519.Sign(e.edPriv, []byte(proof.ReceiptHeader)))
			return proof, fmt.Errorf("%w: timed out after %s waiting for buyer approval on order %s (status=%s)", ErrPayPalCaptureNotCompleted, waitTimeout, orderRes.ID, verifiedOrd.Status)
		case <-ticker.C:
			polledOrd, pollCode, pollDebugID, pollErr := e.getAndVerifyPayPalOrderStatusWithToken(waitCtx, accessToken, orderRes.ID, po.SHA256Hex, inv.InvoiceNumber, amtStr, true)
			if pollErr != nil {
				if waitCtx.Err() != nil {
					continue
				}
				return proof, pollErr
			}
			verifiedOrd = polledOrd
			proof.GetOrderHTTPCode = pollCode
			if pollDebugID != "" {
				proof.GetOrderDebugID = pollDebugID
			}
			proof.LivePayPalOrderStatus = polledOrd.Status
		}
	}

	// Step 7: Capture Approved Order (or Verify Already-Completed Capture) + Post-Capture GET Readback
	if verifiedOrd.Status == "APPROVED" {
		capHTTPCode, capDebugID, err := e.captureApprovedPayPalOrderWithTelemetry(ctx, evalRes, po, inv, orderRes.ID)
		if capHTTPCode != 0 {
			proof.CaptureOrderHTTPCode = capHTTPCode
		}
		if capDebugID != "" {
			proof.CaptureOrderDebugID = capDebugID
		}
		if err != nil {
			return proof, err
		}
		postOrd, postGetCode, postGetDebugID, err := e.getAndVerifyPayPalOrderStatusWithToken(ctx, accessToken, orderRes.ID, po.SHA256Hex, inv.InvoiceNumber, amtStr, true)
		if err != nil {
			return proof, err
		}
		if postOrd.Status != "COMPLETED" {
			return proof, fmt.Errorf("%w: post-capture GET order %s returned status %q (want COMPLETED)", ErrPayPalCaptureNotCompleted, orderRes.ID, postOrd.Status)
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
	}
	if verifiedOrd.Status == "COMPLETED" {
		if err := e.finalizeCompletedOrderCapture(po, rcpt861, inv, evalRes, verifiedOrd, orderRes.ID, amtStr, proof); err != nil {
			return proof, err
		}
		return proof, nil
	}
	return proof, fmt.Errorf("%w: unexpected order %s status %q after approval wait", ErrPayPalCaptureNotCompleted, orderRes.ID, verifiedOrd.Status)
}
