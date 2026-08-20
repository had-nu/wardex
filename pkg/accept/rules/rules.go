// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package rules enforces business constraints on acceptance records.
package rules

import (
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/model"
)

var (
	// ErrInvalidEmail indicates the accepted_by field is not a valid email.
	ErrInvalidEmail = fmt.Errorf("accepted_by must be a valid email address")
	// ErrJustificationShort indicates the justification does not meet the
	// minimum length requirement.
	ErrJustificationShort = fmt.Errorf("justification is too short")
	// ErrBannedPhrase indicates the justification contains a prohibited
	// phrase from the blocklist.
	ErrBannedPhrase = fmt.Errorf("justification contains banned phrases")
	// ErrExpiryTooLong indicates the requested expiration exceeds the
	// configured maximum TTL.
	ErrExpiryTooLong = fmt.Errorf("expiration date exceeds maximum allowed limit")
)

// ValidateBusinessRules enforces acceptance constraints against the config limits.
func ValidateBusinessRules(a model.Acceptance, cfg config.AcceptanceConfig) error {
	// 1. Email constraint
	if _, err := mail.ParseAddress(a.AcceptedBy); err != nil {
		return ErrInvalidEmail
	}

	// 2. Justification minimum characters
	minChars := cfg.Limits.MinJustificationChars
	if minChars == 0 {
		minChars = 80 // Sensible default according to specs
	}
	if len(strings.TrimSpace(a.Justification)) < minChars {
		return fmt.Errorf("%w: minimum %d characters required", ErrJustificationShort, minChars)
	}

	// 3. Banned phrases check
	lowerJustification := strings.ToLower(a.Justification)
	for _, phrase := range cfg.BannedJustificationPhrases {
		if phrase != "" && strings.Contains(lowerJustification, strings.ToLower(phrase)) {
			return fmt.Errorf("%w: '%s'", ErrBannedPhrase, phrase)
		}
	}

	// 4. Maximum Expiry Check
	maxDays := cfg.Limits.MaxAcceptanceDays
	if maxDays == 0 {
		maxDays = 30 // Sensible default
	}

	maxDuration := time.Duration(maxDays) * 24 * time.Hour
	// To prevent slight drifts causing errors, we allow a tiny buffer
	if time.Until(a.ExpiresAt) > maxDuration+(1*time.Hour) {
		return fmt.Errorf("%w: maximum allowed is %d days", ErrExpiryTooLong, maxDays)
	}

	return nil
}
