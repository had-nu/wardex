package signer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/had-nu/wardex/pkg/model"
)

var ErrTampered = errors.New("acceptance signature invalid: content may have been tampered")

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
