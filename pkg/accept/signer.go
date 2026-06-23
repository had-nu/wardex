// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package accept

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/model"
)

var (
	// ErrTampered indicates the acceptance HMAC signature does not match,
	// meaning the content has been modified since signing.
	ErrTampered = errors.New("acceptance signature invalid: content may have been tampered")
	// ErrLiteralSecret is returned when the signing secret is provided as
	// a literal value in config instead of via environment variable or file.
	ErrLiteralSecret = errors.New("signing secret must not be a literal value in config; use WARDEX_ACCEPT_SECRET env var or signing_secret_file")
)

// hashPayload generates a canonical string for the HMAC payload
func hashPayload(a model.Acceptance) string {
	// Canonical concatenation separated by pipe
	// ID|CVEID|AcceptedBy|Justification|ExpiresAt(RFC3339)|Ticket|Revoked|RevokedBy|RevokeReason|ReportHash
	revoked := "false"
	if a.Revoked {
		revoked = "true"
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%.2f|%s",
		a.ID,
		a.CVE,
		a.AcceptedBy,
		a.Justification,
		a.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		a.Ticket,
		revoked,
		a.RevokedBy,
		a.RevokeReason,
		a.ContextRiskScore,
		a.ReportHash,
	)
}

// Sign generates an HMAC-SHA256 signature for the Acceptance content.
func Sign(a model.Acceptance, key []byte) (string, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(hashPayload(a)))
	sig := mac.Sum(nil)
	return "sha256:" + hex.EncodeToString(sig), nil
}

// Verify confirms that the signature is valid.
func Verify(a model.Acceptance, key []byte) error {
	expectedSig, err := Sign(a, key)
	if err != nil {
		return err
	}

	if !hmac.Equal([]byte(a.Signature), []byte(expectedSig)) {
		return ErrTampered
	}
	return nil
}

// ResolveSecret resolves the signing secret by order of precedence:
// 1. WARDEX_ACCEPT_SECRET env var
// 2. File referenced by signing_secret_file in config (TBD)
// 3. ErrLiteralSecret if config contains a literal value
func ResolveSecret(cfg config.Config) ([]byte, error) {
	if secret := os.Getenv("WARDEX_ACCEPT_SECRET"); secret != "" {
		return []byte(strings.TrimSpace(secret)), nil
	}

	return nil, errors.New("missing WARDEX_ACCEPT_SECRET environment variable. [HINT] Gere uma chave com: openssl rand -base64 32. Depois exporte: export WARDEX_ACCEPT_SECRET=\"$(openssl rand -base64 32)\"")
}
