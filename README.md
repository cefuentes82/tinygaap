# tinyGAAP (`tinygaap.io/paypal-edi`)

**Fail-Closed Procurement Auditor, Commercial EDI 3-Way Match (`850`/`861`/`810`/`997`/`820`), Cryptographic `x402-style` HTTP 402 Gate & PayPal Orders v2 Settlement Engine**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8.svg)](./go.mod)

## Overview

Autonomous procurement agents need to pay commercial suppliers without falling prey to prompt injection in invoice notes (`NTE`), beneficiary hijacking (`CAD`/`N1*SE`), partial-shipment billing discrepancies, cumulative PO overbilling, or runaway hourly spend.

**`tinyGAAP`** combines **deterministic procurement rules and optional LLM veto auditing** with **integer-cent 3-Way Match** and **PayPal Orders v2** settlement:

1. **Cryptographic `x402-style` HTTP 402 Gate (`SignX402PaymentHeader` / `VerifyX402PaymentHeader` — not wire-compatible with the x402 spec):**
   - Requests to `/v1/edi/810/settle` must present a valid `Payment-Signature` header (or the same value in `X-Payment`), `exact:x402:paypal-order-v2:sig=<hmac-sha256>`, binding the `HMAC-SHA256` signature to the exact `SHA-256` digest of the raw `EDI 810` payload. Missing or forged signatures fail closed with `HTTP 402 Payment Required` and a `WWW-Authenticate: x402` challenge.
2. **Fail-Closed Semantic Procurement Auditor (`agent_auditor.go`):**
   - Inspects `NTE` notes with a deterministic rule guard (which uses no LLM) for known injection phrases, off-domain payee handles and third-party notes, followed by an optional OpenAI-compatible `/v1/chat/completions` JSON endpoint when `TINYGAAP_LLM_ENDPOINT` is explicitly configured (`TINYGAAP_LLM_ENDPOINT`, `TINYGAAP_LLM_API_KEY`, `TINYGAAP_LLM_MODEL`); the engine separately requires the `CAD` pay-to and `N1*SE` seller ID to match the PO seller.
   - Operates under **epistemic separation** and **fail-closed semantics**: the auditor can **veto** suspicious invoices (`HTTP 403`), and any configured LLM endpoint failure or malformed JSON response fails closed (`REJECT`), while an LLM `APPROVE` can **never override** the deterministic 3-Way Match or allowlist.
3. **True 3-Way Match by Default (`EDI 850` PO ↔ `861` Receiving Advice ↔ `810` Invoice):**
   - Enforces `Require861Receipt = true` by default (unless `AllowTwoWayMatch: true` is explicitly set).
   - Matches line items by `VendorSKU` (`VP`/`BP` in `RCD` or `LIN`) across any line ordering, verifying Unit of Measure, integer-cent unit price, ordered quantity (`PO1`), warehouse-accepted quantity (`RCD`) and condition code (`BRA04`), document totals (`AMT*TT` vs `TDS`), seller-scoped invoice replay, and **a per-PO, per-SKU billed-quantity tally**, so the same PO can't be billed twice under different invoice numbers.
   - Emits `EDI 997` Functional Acknowledgments (`AK9*A` or `AK9*R`) echoing the incoming `GS01`/`GS06` and `ST01`/`ST02` control numbers, with an `AK3` naming the segment type tied to the failing rule and its 1-based position (exact for `IT1` lines; first occurrence for other segment types).
4. **PayPal Orders v2 Readback & Capture (`POST /v2/checkout/orders`, `GET /v2/checkout/orders/{id}`, `POST /v2/checkout/orders/{id}/capture`):**
   - Binds `purchase_units[0].custom_id` to the full 64-character `SHA-256` digest of the originating `EDI 850` Purchase Order.
   - Enforces distinct deterministic `PayPal-Request-Id` idempotency keys for order creation (`DeterministicPayPalRequestID`) and order capture (`DeterministicPayPalCaptureRequestID`, prefixed with `cap-`); cross-invoice order reuse is blocked by the engine's order bindings and the `invoice_id` readback.
   - Binds capture authorization strictly to the evaluated invoice in the engine's authorization grants (`authGrants`) and emits an Ed25519-signed canonical `EDI 820` Remittance Advice (`CanonicalEDI820ForSigning` / `VerifyEDI820Signature`) **only** when PayPal capture returns `COMPLETED` (or a verified order readback confirms a `COMPLETED` capture) with `captures[0].status == "COMPLETED"`, matching order ID, a non-empty capture ID, and matching USD amount.

5. **Persistent `0600` Ed25519 Key Custody & Hash-Chained Append-Only Ledger (`ledger_key_custody.go`):**
   - Loads a `0600` Ed25519 signing key (`TINYGAAP_ED25519_KEY_FILE` / `-key-file`, never created implicitly unless `-init-key` is passed) with key identifier `kid = sha256(pub)[:16]` verifiable offline against `keys/<kid>.pub` (`VerifyReceiptWithRegistry`, `VerifyEDI820WithRegistry`), rejecting `kid=efimera` and unregistered keys.
   - Maintains an exclusively `flock`-locked, `fsync` write-ahead, SHA-256 hash-chained and Ed25519-signed JSONL ledger (`TINYGAAP_LEDGER_FILE` / `-ledger-file`, initialized explicitly via `-init-ledger`), replaying settled `(seller, BIG02)` invoices, `PayPalOrderID` bindings, cumulative PO SKU quantities, and rolling hourly spend across restarts, and binding `lseq` + `lhash` into signed receipts (`VerifyReceiptAgainstLedger`).

---

## Quick Start & Running Tests (Offline, Go Standard Library Only; Linux and macOS)

```bash
test -z "$(gofmt -l .)"
go vet ./...
# -race needs cgo and a C compiler on Linux
go test -v -race -count=1 ./...
CGO_ENABLED=0 go test -count=1 ./...
```

### Running the Standalone `x402-style` HTTP 402 + EDI Gate Server

```bash
export TINYGAAP_HMAC_SECRET="replace-with-at-least-16-random-bytes"
# First-time explicit key + ledger initialization (0600, O_CREATE|O_EXCL):
go run ./cmd/serve_tinygaap -key-file ./state/ed25519_priv.hex -init-key -keys-dir ./keys -ledger-file ./state/ledger.jsonl -init-ledger -addr 127.0.0.1:8090
# Subsequent runs load the existing 0600 key and replay the hash-chained ledger (or pass -demo-ephemeral for ephemeral in-memory testing):
go run ./cmd/serve_tinygaap -key-file ./state/ed25519_priv.hex -keys-dir ./keys -ledger-file ./state/ledger.jsonl -addr 127.0.0.1:8090
```

---

## Reproducing the Live PayPal Sandbox Proof

Judges can verify live execution against PayPal's Sandbox API (`https://api-m.sandbox.paypal.com`) using their own PayPal Developer Sandbox credentials (new runs invoked with `-key-file`, `-keys-dir ./keys`, and `-ledger-file` produce proofs that verify offline against `keys/<kid>.pub`; see Known limitations #1 regarding the committed proof artifact):

```bash
export PAYPAL_CLIENT_ID="your-sandbox-client-id"
export PAYPAL_CLIENT_SECRET="your-sandbox-client-secret"
# Optional: pass file paths instead of inline environment values:
# export PAYPAL_CLIENT_ID_FILE="/path/to/sandbox_client_id"
# export PAYPAL_CLIENT_SECRET_FILE="/path/to/sandbox_client_secret"

# Optional: configure an OpenAI-compatible /v1/chat/completions LLM Auditor endpoint
# (defaults to deterministic rule guard with no network call if unset):
# export TINYGAAP_LLM_ENDPOINT="http://127.0.0.1:11434/v1/chat/completions"
# export TINYGAAP_LLM_MODEL="llama3.2:3b"

# Persistent interactive Sandbox flow (creates order, prints ONLY the buyer approval URL to stdout,
# polls until approved, captures into COMPLETED + signed EDI 820 verifiable against ./keys, and writes proof JSON):
go run ./cmd/verify_paypal_sandbox -key-file ./state/ed25519_priv.hex -init-key -keys-dir ./keys -ledger-file ./state/ledger.jsonl -init-ledger -wait-approval 20m -out ./my_proof.json

# Demo only: throwaway key (kid=efimera, rejected by the registry verifiers), no ledger:
go run ./cmd/verify_paypal_sandbox -demo-ephemeral -wait-approval 20m -out ./my_proof.json
go run ./cmd/verify_paypal_sandbox -demo-ephemeral -out ./my_proof.json
go run ./cmd/verify_paypal_sandbox -demo-ephemeral -capture-order <APPROVED_ORDER_ID> -invoice-id <INVOICE_ID> -out ./my_proof.json
```

---

## Built With

tinyGAAP was built by one human working with a team of AI agents, under one rule: nobody grades their own homework.

- **Carlos Fuentes**: design, requirements, acceptance criteria, and every release decision.
- **Gemini (Google)**, through Google Antigravity: most of the Go implementation and its tests.
- **Claude (Anthropic)**, through Claude Code: independent verification. That covers a six-lens review that raised 25 findings (on this tree, 22 are verified closed; the rest are covered under Known limitations), a mutation-testing harness, an EDI cross-check against public sources, a license and attribution check, and a secret and privacy scan of everything reachable in the public repository. Each release candidate was rebuilt and tested by a second agent, which reported before anything moved forward. The repository also ships a 12-case adversarial corpus (injection, payee hijacking, a forged signature, arithmetic and envelope tampering) that the test suite replays.

The deterministic path (3-way match, x402-style HTTP 402 gate (not wire-compatible with the x402 spec), PayPal readback and capture checks) uses no LLM. The optional LLM auditor can only veto; it can never approve a payment on its own.

**Scope and dependencies.** tinyGAAP is an independent, open-source implementation that reads and writes a minimal subset of ASC X12 005010 transaction sets (850, 861, 810, 997, 820). It uses only the Go standard library; there are no external modules. It is not affiliated with, endorsed by, or certified by ASC X12, PayPal, Inc., or the x402 project.

## Known limitations

A second agent re-checked the 25 findings of the six-lens review on this tree: 22 are verified closed. What remains open is listed here, together with other limits we know of.

1. The committed PayPal proof comes from one interactive Sandbox run (a person approved the order, then the engine captured it) and verifies offline against `keys/dcaa4e385c20a8af.pub`; it is Sandbox, not production.
2. Persistent `0600` Ed25519 key custody (`keys/<kid>.pub`) requires a paired `0600` `flock`-locked hash-chained JSONL ledger (`-key-file` requires `-ledger-file`), persisting settled invoices, PO line consumption, and hourly spend across restarts on a single host (`-demo-ephemeral` remains per-process, and multi-node consensus is out of scope). Write-ahead `SETTLEMENT_AUTHORIZED` entries cannot be voided in place, and deleting entries from the end of the ledger file is detected by receipt holders via `VerifyReceiptAgainstLedger`, not by an engine restarting without an external head anchor.
3. There are no bounded retries: a transient PayPal failure aborts the settlement.
4. X12 envelope validation is minimal: the ISA must be 106 characters and supplies the element and segment delimiters, and segment counts and matching control numbers are checked; the version, the other ISA fields and the presence of GE/IEA are not, and component and repetition separators are not interpreted.
5. Receipts bind the 861, the 997 and the ledger entry (`lhash`) by 16-hex-character SHA-256 prefixes.
6. Offline test runs exercise mock HTTP and deterministic auditor paths; the live OpenAI-compatible LLM auditor integration test is skipped unless `TINYGAAP_LLM_ENDPOINT` is configured (`TINYGAAP_LLM_MODEL` defaults to `llama3.2:3b`).
7. The public repository starts at a single commit; the earlier development history is kept private.
8. The PayPal order sets no payee: funds go to the PayPal account whose API credentials are configured, and the supplier ID in the 820 comes from the EDI, not from PayPal.
9. Unit prices are not overflow-checked: a price above about $92 quadrillion wraps around (4611686018427387929.00 reads as 25.00). The amount paid still comes from TDS, which must equal the PO total.
10. `serve_tinygaap`'s `/v1/edi/850/register` and `/v1/edi/861/register` endpoints are unauthenticated and replace a PO or 861 that has the same PO number; keep the server on loopback (the default).

---

## Standards & Non-Affiliation Notice

See [NOTICE](./NOTICE). tinyGAAP is an independent, open-source implementation that reads and writes a minimal subset of ASC X12 005010 transaction sets (`850`, `861`, `810`, `997`, `820`) with an x402-style HTTP 402 gate (not wire-compatible with the x402 spec), and is not affiliated with, endorsed by, or certified by ASC X12, PayPal, Inc., or the x402 project.

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
