// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package verify provides signature, expiry, and state verification for
// acceptance records.
package verify

import (
	"time"

	"github.com/had-nu/wardex/v2/pkg/model"
)

// Result represents the verification result of an Acceptance.
type Result struct {
	Acceptance     model.Acceptance
	Valid          bool
	Expired        bool
	Tampered       bool
	Stale          bool // config mudou desde a aceitação
	ReportMismatch bool // GateReport actual diverge do original
	ExpiresIn      time.Duration
	Errors         []string
}

// VerifyAll verifies the signature, expiry, and hashes for multiple acceptances.
func VerifyAll(acceptances []model.Acceptance, key []byte, currentReportHash string, currentConfigHash string) ([]Result, bool) {
	var results []Result
	allValid := true

	for _, a := range acceptances {
		res := Result{Acceptance: a}

		if err := Verify(a, key); err != nil {
			res.Tampered = true
			res.Errors = append(res.Errors, err.Error())
			allValid = false
		}

		if !a.ExpiresAt.IsZero() && time.Now().After(a.ExpiresAt) {
			res.Expired = true
			res.Errors = append(res.Errors, "acceptance has expired")
			allValid = false
		} else {
			res.ExpiresIn = time.Until(a.ExpiresAt)
		}

		// Check ReportHash - required for new acceptances
		if a.ReportHash == "" {
			res.ReportMismatch = true
			res.Errors = append(res.Errors, "acceptance missing ReportHash — cannot verify binding to report")
			allValid = false
		} else if currentReportHash == "" {
			res.ReportMismatch = true
			res.Errors = append(res.Errors, "current report hash not provided — cannot verify ReportHash")
			allValid = false
		} else if a.ReportHash != currentReportHash {
			res.ReportMismatch = true
			res.Errors = append(res.Errors, "acceptance ReportHash does not match current report")
			allValid = false
		}

		// Check ConfigHash - required for new acceptances
		if a.ConfigHash == "" {
			res.Stale = true
			res.Errors = append(res.Errors, "acceptance missing ConfigHash — cannot verify binding to config")
			allValid = false
		} else if currentConfigHash == "" {
			res.Stale = true
			res.Errors = append(res.Errors, "current config hash not provided — cannot verify ConfigHash")
			allValid = false
		} else if a.ConfigHash != currentConfigHash {
			res.Stale = true
			res.Errors = append(res.Errors, "acceptance ConfigHash does not match current config")
			allValid = false
		}

		// Validation succeeds if its non tampered, non expired, and hashes match
		if !res.Tampered && !res.Expired && !res.ReportMismatch && !res.Stale {
			res.Valid = true
		}
		results = append(results, res)
	}

	return results, allValid
}
