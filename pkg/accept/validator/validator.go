package validator

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/had-nu/wardex/config"
	"github.com/had-nu/wardex/pkg/model"
)

var (
	ErrInvalidEmail       = errors.New("accepted_by must be a valid email address")
	ErrJustificationShort = errors.New("justification is too short")
	ErrBannedPhrase       = errors.New("justification contains banned phrases")
	ErrExpiryTooLong      = errors.New("expiration date exceeds maximum allowed limit")
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
