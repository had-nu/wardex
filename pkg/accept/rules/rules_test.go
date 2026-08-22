// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package rules

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/model"
)

// testAcceptance creates a valid acceptance for testing.
func testAcceptance(t *testing.T, id string) model.Acceptance {
	return model.Acceptance{
		ID:              id,
		CVE:             "CVE-2024-1234",
		AcceptedBy:      "tester@example.com",
		Justification:   "This is a detailed justification that meets the minimum character requirement for acceptance records.",
		CreatedAt:       time.Now().UTC().Truncate(time.Second),
		ExpiresAt:       time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second),
		Ticket:          "TICKET-123",
		ContextRiskScore: 0.5,
	}
}

func defaultConfig() config.AcceptanceConfig {
	return config.AcceptanceConfig{
		Limits: config.Limits{
			MaxAcceptanceDays:      30,
			MinJustificationChars:  50,
			MaxReportAgeHours:      72,
		},
		BannedJustificationPhrases: []string{"risk accepted without review", "business decision", "temporary fix"},
	}
}

func TestValidateBusinessRules_ValidAcceptance(t *testing.T) {
	acc := testAcceptance(t, "acc-001")
	cfg := defaultConfig()

	err := ValidateBusinessRules(acc, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateBusinessRules_InvalidEmail(t *testing.T) {
	acc := testAcceptance(t, "acc-001")
	acc.AcceptedBy = "not-an-email"
	cfg := defaultConfig()

	err := ValidateBusinessRules(acc, cfg)
	if err == nil {
		t.Fatal("expected error for invalid email")
	}
	if err != ErrInvalidEmail {
		t.Fatalf("expected ErrInvalidEmail, got: %v", err)
	}
}

func TestValidateBusinessRules_EmailWithSpaces(t *testing.T) {
	acc := testAcceptance(t, "acc-001")
	acc.AcceptedBy = "  tester@example.com  "
	cfg := defaultConfig()

	err := ValidateBusinessRules(acc, cfg)
	if err != nil {
		t.Fatalf("unexpected error for email with spaces: %v", err)
	}
}

func TestValidateBusinessRules_JustificationTooShort(t *testing.T) {
	acc := testAcceptance(t, "acc-001")
	acc.Justification = "too short"
	cfg := defaultConfig()

	err := ValidateBusinessRules(acc, cfg)
	if err == nil {
		t.Fatal("expected error for short justification")
	}
	if !errors.Is(err, ErrJustificationShort) {
		t.Fatalf("expected ErrJustificationShort, got: %v", err)
	}
}

func TestValidateBusinessRules_JustificationMinCharsConfigurable(t *testing.T) {
	acc := testAcceptance(t, "acc-001")
	acc.Justification = "Short text."
	cfg := defaultConfig()
	cfg.Limits.MinJustificationChars = 10 // 10 chars

	err := ValidateBusinessRules(acc, cfg)
	if err != nil {
		t.Fatalf("unexpected error for 11 chars with min 10: %v", err)
	}

	cfg.Limits.MinJustificationChars = 15 // 15 chars required, but only 11 in string
	err = ValidateBusinessRules(acc, cfg)
	if err == nil {
		t.Fatal("expected error for short justification")
	}
	if !errors.Is(err, ErrJustificationShort) {
		t.Fatalf("expected ErrJustificationShort, got: %v", err)
	}
}

func TestValidateBusinessRules_JustificationDefaultMinChars(t *testing.T) {
	acc := testAcceptance(t, "acc-001")
	acc.Justification = strings.Repeat("x", 79) // 79 chars
	cfg := defaultConfig()
	cfg.Limits.MinJustificationChars = 0 // Should default to 80

	err := ValidateBusinessRules(acc, cfg)
	if err == nil {
		t.Fatal("expected error for 79 chars with default min 80")
	}
	if !errors.Is(err, ErrJustificationShort) {
		t.Fatalf("expected ErrJustificationShort, got: %v", err)
	}
}

func TestValidateBusinessRules_BannedPhraseExact(t *testing.T) {
	acc := testAcceptance(t, "acc-001")
	acc.Justification = "We decided to risk accepted without review for this issue."
	cfg := defaultConfig()

	err := ValidateBusinessRules(acc, cfg)
	if err == nil {
		t.Fatal("expected error for banned phrase")
	}
	if !errors.Is(err, ErrBannedPhrase) {
		t.Fatalf("expected ErrBannedPhrase, got: %v", err)
	}
}

func TestValidateBusinessRules_BannedPhraseCaseInsensitive(t *testing.T) {
	acc := testAcceptance(t, "acc-001")
	acc.Justification = "RISK ACCEPTED WITHOUT REVIEW was the decision, this is a longer justification."
	cfg := defaultConfig()

	err := ValidateBusinessRules(acc, cfg)
	if err == nil {
		t.Fatal("expected error for banned phrase (case insensitive)")
	}
	if !errors.Is(err, ErrBannedPhrase) {
		t.Fatalf("expected ErrBannedPhrase, got: %v", err)
	}
}

func TestValidateBusinessRules_BannedPhrasePartial(t *testing.T) {
	acc := testAcceptance(t, "acc-001")
	acc.Justification = "This is a temporary fix for the issue, with a longer justification text."
	cfg := defaultConfig()

	err := ValidateBusinessRules(acc, cfg)
	if err == nil {
		t.Fatal("expected error for banned phrase 'temporary fix'")
	}
	if !errors.Is(err, ErrBannedPhrase) {
		t.Fatalf("expected ErrBannedPhrase, got: %v", err)
	}
}

func TestValidateBusinessRules_BannedPhraseEmptyList(t *testing.T) {
	acc := testAcceptance(t, "acc-001")
	acc.Justification = "risk accepted without review is fine here."
	cfg := defaultConfig()
	cfg.BannedJustificationPhrases = []string{}

	err := ValidateBusinessRules(acc, cfg)
	if err != nil {
		if !errors.Is(err, ErrJustificationShort) {
			t.Fatalf("unexpected error with empty banned list: %v", err)
		}
	}
}

func TestValidateBusinessRules_ExpiryTooLong(t *testing.T) {
	acc := testAcceptance(t, "acc-001")
	acc.ExpiresAt = time.Now().Add(31 * 24 * time.Hour).UTC().Truncate(time.Second) // 31 days
	cfg := defaultConfig()

	err := ValidateBusinessRules(acc, cfg)
	if err == nil {
		t.Fatal("expected error for expiry > 30 days")
	}
	if !errors.Is(err, ErrExpiryTooLong) {
		t.Fatalf("expected ErrExpiryTooLong, got: %v", err)
	}
}

func TestValidateBusinessRules_ExpiryWithinLimit(t *testing.T) {
	acc := testAcceptance(t, "acc-001")
	acc.ExpiresAt = time.Now().Add(29 * 24 * time.Hour).UTC().Truncate(time.Second)
	cfg := defaultConfig()

	err := ValidateBusinessRules(acc, cfg)
	if err != nil {
		t.Fatalf("unexpected error for expiry within limit: %v", err)
	}
}

func TestValidateBusinessRules_ExpiryDefaultMaxDays(t *testing.T) {
	acc := testAcceptance(t, "acc-001")
	acc.ExpiresAt = time.Now().Add(35 * 24 * time.Hour).UTC().Truncate(time.Second)
	cfg := defaultConfig()
	cfg.Limits.MaxAcceptanceDays = 0 // Should default to 30

	err := ValidateBusinessRules(acc, cfg)
	if err == nil {
		t.Fatal("expected error for expiry > default 30 days")
	}
	if !errors.Is(err, ErrExpiryTooLong) {
		t.Fatalf("expected ErrExpiryTooLong, got: %v", err)
	}
}

func TestValidateBusinessRules_ExpiryBoundary(t *testing.T) {
	acc := testAcceptance(t, "acc-001")
	baseTime := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	acc.ExpiresAt = baseTime.Add(30 * time.Minute) // 30 days + 30 min
	cfg := defaultConfig()

	err := ValidateBusinessRules(acc, cfg)
	// Should allow 1 hour buffer
	if err != nil {
		t.Fatalf("unexpected error for 30 days + 30 min: %v", err)
	}

	acc.ExpiresAt = baseTime.Add(2 * time.Hour) // 30 days + 2 hours
	err = ValidateBusinessRules(acc, cfg)
	if err == nil {
		t.Fatal("expected error for 30 days + 2 hours")
	}
}

func TestValidateBusinessRules_EmptyJustification(t *testing.T) {
	acc := testAcceptance(t, "acc-001")
	acc.Justification = ""
	cfg := defaultConfig()

	err := ValidateBusinessRules(acc, cfg)
	if err == nil {
		t.Fatal("expected error for empty justification")
	}
}

func TestValidateBusinessRules_WhitespaceJustification(t *testing.T) {
	acc := testAcceptance(t, "acc-001")
	acc.Justification = "   \t\n  "
	cfg := defaultConfig()

	err := ValidateBusinessRules(acc, cfg)
	if err == nil {
		t.Fatal("expected error for whitespace-only justification")
	}
}

func TestValidateBusinessRules_ExpiryInPast(t *testing.T) {
	acc := testAcceptance(t, "acc-001")
	acc.ExpiresAt = time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Second)
	cfg := defaultConfig()

	err := ValidateBusinessRules(acc, cfg)
	// Past expiry should be caught by expiry check
	if err == nil {
		t.Fatal("expected error for past expiry")
	}
}

// Fuzz tests

func FuzzValidateBusinessRules(f *testing.F) {
	f.Add("tester@example.com", "This is a valid justification with enough characters", "2025-01-01T00:00:00Z")
	f.Add("tester@example.com", "Short", "2025-01-01T00:00:00Z")

	f.Fuzz(func(t *testing.T, email, justification, expiresAt string) {
		acc := model.Acceptance{
			ID:              "test",
			CVE:             "CVE-2024-1234",
			AcceptedBy:      email,
			Justification:   justification,
			CreatedAt:       time.Now().UTC(),
			ExpiresAt:       time.Now().Add(24 * time.Hour).UTC(),
		}
		// Parse expiresAt if provided
		if t, err := time.Parse(time.RFC3339, expiresAt); err == nil {
			acc.ExpiresAt = t
		}
		cfg := defaultConfig()
		ValidateBusinessRules(acc, cfg)
	})
}