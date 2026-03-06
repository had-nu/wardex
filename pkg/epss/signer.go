// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package epss

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/had-nu/wardex/pkg/model"
)

var ErrTampered = errors.New("epss enrichment signature invalid: content may have been tampered")

// hashPayload generates a canonical string for the HMAC payload
func hashPayload(f model.EPSSEnrichmentFile) string {
	// Canonical concatenation:
	// Date | CVE=Score | CVE=Score
	var parts []string
	parts = append(parts, f.GeneratedAt)

	// Since maps or JSON could shift order, we must sort the enrichments
	var enrichs []string
	for _, e := range f.Enrichments {
		enrichs = append(enrichs, fmt.Sprintf("%s:%.6f", e.CVE, e.Score))
	}
	sort.Strings(enrichs)

	parts = append(parts, enrichs...)

	return strings.Join(parts, "|")
}

// Sign generates an HMAC-SHA256 signature for the EPSS Enrichment content.
func Sign(f model.EPSSEnrichmentFile, key []byte) (string, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(hashPayload(f)))
	sig := mac.Sum(nil)
	return "sha256:" + hex.EncodeToString(sig), nil
}

// Verify confirms that the signature is valid.
func Verify(f model.EPSSEnrichmentFile, key []byte) error {
	expectedSig, err := Sign(f, key)
	if err != nil {
		return err
	}

	if !hmac.Equal([]byte(f.Signature), []byte(expectedSig)) {
		return ErrTampered
	}
	return nil
}
