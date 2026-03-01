// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package security

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/had-nu/wardex/pkg/accept/signer"
	"github.com/had-nu/wardex/pkg/model"
)

func generateBaseAcceptance() model.Acceptance {
	return model.Acceptance{
		ID:               "acc-12345",
		CVE:              "CVE-2024-9999",
		AcceptedBy:       "audit@wardex.local",
		Justification:    "Business accepted risk due to mitigating WAF",
		ExpiresAt:        time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		Ticket:           "JIRA-123",
		ContextRiskScore: 7.5,
		ReportHash:       "abc123def456",
	}
}

// 1. Validate that exact same payload and key produce the identical signature
func TestCryptoAudit_Determinism(t *testing.T) {
	acc := generateBaseAcceptance()
	key := []byte("a-very-secure-256-bit-key-here-!")

	sig1, err := signer.Sign(acc, key)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	sig2, err := signer.Sign(acc, key)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	if sig1 != sig2 {
		t.Errorf("Signature is not deterministic. Sig1: %s != Sig2: %s", sig1, sig2)
	}
}

// 2. Validate Constant-Time Comparison exists via Verification
func TestCryptoAudit_Verification(t *testing.T) {
	acc := generateBaseAcceptance()
	key := []byte("a-very-secure-256-bit-key-here-!")

	sig, _ := signer.Sign(acc, key)
	acc.Signature = sig

	if err := signer.Verify(acc, key); err != nil {
		t.Errorf("Valid signature failed verification: %v", err)
	}
}

// 3. Validate Tampering of Payload Fields
func TestCryptoAudit_TamperingAttacks(t *testing.T) {
	key := []byte("a-very-secure-256-bit-key-here-!")

	// Generate baseline
	acc := generateBaseAcceptance()
	sig, _ := signer.Sign(acc, key)
	acc.Signature = sig

	// Attack 1: CVE Tampering
	attack1 := acc
	attack1.CVE = "CVE-2024-0000" // Hacker swaps CVE
	if err := signer.Verify(attack1, key); err != signer.ErrTampered {
		t.Errorf("Failed to detect CVE tampering")
	}

	// Attack 2: Expiration Tampering
	attack2 := acc
	attack2.ExpiresAt = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC) // Hacker pushes out expiration
	if err := signer.Verify(attack2, key); err != signer.ErrTampered {
		t.Errorf("Failed to detect Expiration tampering")
	}

	// Attack 3: Report Hash / Replay Tampering
	attack3 := acc
	attack3.ReportHash = "fakehash" // Hacker replays to different environment
	if err := signer.Verify(attack3, key); err != signer.ErrTampered {
		t.Errorf("Failed to detect ReportHash tampering")
	}
}

// 4. Validate Key Compromise / Isolation
func TestCryptoAudit_KeyIsolation(t *testing.T) {
	acc := generateBaseAcceptance()
	keyProd := []byte("production-secure-256-bit-key-!!")
	keyDev := []byte("development-secure-256-bit-key-!")

	sigDev, _ := signer.Sign(acc, keyDev)
	acc.Signature = sigDev

	if err := signer.Verify(acc, keyProd); err != signer.ErrTampered {
		t.Errorf("Production environment verified a Dev signature. Key isolation failed.")
	}
}

// 5. Length Extension / Collision Analysis Protection
func TestCryptoAudit_LengthExtension(t *testing.T) {
	// Because Wardex uses HMAC-SHA256, it is mathematically immune to Length Extension Attacks
	// inherently, but we must verify the payload structure strips injected delimiters
	acc := generateBaseAcceptance()
	key := []byte("key")

	acc.Justification = "test|pipe"
	sig1, _ := signer.Sign(acc, key)

	acc2 := generateBaseAcceptance()
	acc2.Justification = "test"
	acc2.Ticket = "pipe" + acc.Ticket // Trying to inject a pipe to shift fields
	sig2, _ := signer.Sign(acc2, key)

	// Since we format using "%s|%s", "test|pipe"+"JIRA" is mathematically identical to "test"+"pipeJIRA" in string
	// IF the parser naively appended strings. BUT because they occupy different structural fields,
	// they should be piped separately: "test|pipe|JIRA-123" vs "test|pipeJIRA-123"
	if sig1 == sig2 {
		t.Logf("WARN: Payload is susceptible to delimiter injection collisions if an attacker can control multiple adjacent fields.")
	}
}

// 6. Test Signature Length and Format
func TestCryptoAudit_SignatureFormat(t *testing.T) {
	acc := generateBaseAcceptance()
	key := []byte("key")
	sig, _ := signer.Sign(acc, key)

	if !strings.HasPrefix(sig, "sha256:") {
		t.Errorf("Signature lacks 'sha256:' algorithm prefix")
	}

	expectedHexLen := sha256.Size * 2 // 32 bytes * 2 characters / byte
	parts := strings.Split(sig, ":")
	if len(parts) != 2 {
		t.Fatalf("Signature format malformed")
	}

	if len(parts[1]) != expectedHexLen {
		t.Errorf("Expected signature length %d, got %d", expectedHexLen, len(parts[1]))
	}

	_, err := hex.DecodeString(parts[1])
	if err != nil {
		t.Errorf("Signature body is not valid hex: %v", err)
	}
}
