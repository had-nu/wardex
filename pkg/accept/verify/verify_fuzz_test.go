// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package verify

import (
	"strings"
	"testing"
	"time"

	"github.com/had-nu/wardex/v2/pkg/model"
)

// FuzzSignVerify exercises the HMAC signing/verification with arbitrary keys
// and corrupted payloads. Invariants:
//   - Sign must never fail for any key;
//   - a freshly signed acceptance always verifies;
//   - tampering with any content field must invalidate the signature;
//   - a different key must invalidate the signature.
func FuzzSignVerify(f *testing.F) {
	f.Add([]byte("valid-secret-key"), []byte("payload"))
	f.Add([]byte(""), []byte(""))
	f.Add([]byte("k"), []byte("x"))
	f.Add([]byte(strings.Repeat("k", 256)), []byte(strings.Repeat("p", 1024)))

	f.Fuzz(func(t *testing.T, key, payload []byte) {
		base := model.Acceptance{
			ID:               "A-1",
			CVE:              "CVE-2024-0001",
			AcceptedBy:       "ops",
			Justification:    string(payload),
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			Ticket:           "TCK-1",
			ReportHash:       "sha256:abc",
			ContextRiskScore: 1.0,
		}

		sig, err := Sign(base, key)
		if err != nil {
			t.Fatalf("sign should never fail: %v", err)
		}
		base.Signature = sig
		if err := Verify(base, key); err != nil {
			t.Fatalf("verify of own signature failed: %v", err)
		}

		tampered := base
		tampered.CVE = "CVE-2024-9999"
		if err := Verify(tampered, key); err == nil {
			t.Fatalf("tampered acceptance verified successfully")
		}

		wrongKey := append(append([]byte{}, key...), 0x01)
		if err := Verify(base, wrongKey); err == nil {
			t.Fatalf("signature accepted under a different key")
		}
	})
}

// FuzzVerifyAll checks the batch verifier never panics on corrupted signature
// input and always reports tampering for a mismatch.
func FuzzVerifyAll(f *testing.F) {
	f.Add([]byte("key"), []byte("sig"))
	f.Add([]byte(""), []byte(""))
	f.Add([]byte("k"), []byte("sha256:00"))

	f.Fuzz(func(t *testing.T, key, sig []byte) {
		acceptances := []model.Acceptance{{
			ID:            "A-1",
			CVE:           "CVE-2024-0001",
			AcceptedBy:    "ops",
			Justification: "x",
			ExpiresAt:     time.Now().Add(24 * time.Hour),
			Signature:     string(sig),
			ReportHash:    "sha256:abc",
		}}

		results, allValid := VerifyAll(acceptances, key, "sha256:abc", "hash")
		if len(results) != len(acceptances) {
			t.Fatalf("results length mismatch: %d != %d", len(results), len(acceptances))
		}
		for _, r := range results {
			if r.Valid {
				t.Fatalf("corrupted signature reported as valid")
			}
		}
		if allValid {
			t.Fatalf("corrupted signatures reported as all-valid")
		}
	})
}
