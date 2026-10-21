// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package config

import (
	"strings"
	"testing"
)

func TestValidateSupportPeriod(t *testing.T) {
	tests := []struct {
		name    string
		cfg     SupportPeriodConfig
		wantAny []string // a substring each warning must contain
		clean   bool
	}{
		{
			name:  "a complete record",
			clean: true,
			cfg: SupportPeriodConfig{
				Years:         7,
				Justification: "Expected in use at least seven years; user contracts run on that term.",
				VDPReference:  "https://example.invalid/vdp",
			},
		},
		{
			name:    "no support period recorded",
			cfg:     SupportPeriodConfig{},
			wantAny: []string{"is not set", "Article 13(8)"},
		},
		{
			name: "below the floor without the exception",
			cfg: SupportPeriodConfig{
				Years: 3, Justification: "Short-lived appliance.", VDPReference: "https://example.invalid/vdp",
			},
			wantAny: []string{"at least 5 years", "expected_use_shorter_than_five_years"},
		},
		{
			name: "below the floor with the exception recorded",
			// This is the case Article 13(8) expressly permits. It must not warn.
			clean: true,
			cfg: SupportPeriodConfig{
				Years:                             3,
				Justification:                     "Single-season device; not expected to remain in use.",
				VDPReference:                      "https://example.invalid/vdp",
				ExpectedUseIsShorterThanFiveYears: true,
			},
		},
		{
			name:  "at the floor",
			clean: true,
			cfg: SupportPeriodConfig{
				Years: 5, Justification: "Default floor.", VDPReference: "https://example.invalid/vdp",
			},
		},
		{
			name: "justification missing",
			cfg: SupportPeriodConfig{
				Years: 7, VDPReference: "https://example.invalid/vdp",
			},
			wantAny: []string{"justification is empty", "Annex VII point 4"},
		},
		{
			name: "justification is whitespace",
			cfg: SupportPeriodConfig{
				Years: 7, Justification: "   ", VDPReference: "https://example.invalid/vdp",
			},
			wantAny: []string{"justification is empty"},
		},
		{
			name: "disclosure policy reference missing",
			cfg: SupportPeriodConfig{
				Years: 7, Justification: "Seven years.",
			},
			wantAny: []string{"vdp_reference is empty", "coordinated vulnerability disclosure"},
		},
		{
			name:    "negative",
			cfg:     SupportPeriodConfig{Years: -1},
			wantAny: []string{"not a duration"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CRAConfig{SupportPeriod: tt.cfg}.ValidateSupportPeriod()

			if tt.clean {
				if len(got) != 0 {
					t.Fatalf("expected no warnings, got %v", got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatal("expected at least one warning, got none")
			}
			joined := strings.Join(got, "\n")
			for _, want := range tt.wantAny {
				if !strings.Contains(joined, want) {
					t.Errorf("warnings %q do not mention %q", joined, want)
				}
			}
		})
	}
}

// TestSupportPeriodRuleMatchesArticle138 records the shape of the rule, because
// the exception is the part that is easy to get wrong in the other direction.
//
// Article 13(8): "Without prejudice to the second subparagraph, the support
// period shall be at least five years. Where the product with digital elements is
// expected to be in use for less than five years, the support period shall
// correspond to the expected use time."
func TestSupportPeriodRuleMatchesArticle138(t *testing.T) {
	if MinimumSupportPeriodYears != 5 {
		t.Fatalf("MinimumSupportPeriodYears = %d, the Regulation says five", MinimumSupportPeriodYears)
	}

	// Enforcing the floor unconditionally would report a permitted short period
	// as a defect, which is the failure the exception exists to prevent.
	short := CRAConfig{SupportPeriod: SupportPeriodConfig{
		Years: 2, Justification: "x", VDPReference: "y",
	}}
	if w := short.ValidateSupportPeriod(); len(w) == 0 {
		t.Error("a two-year period warned about nothing; the floor must be enforced")
	}

	shortAndPermitted := CRAConfig{SupportPeriod: SupportPeriodConfig{
		Years: 2, Justification: "x", VDPReference: "y",
		ExpectedUseIsShorterThanFiveYears: true,
	}}
	if w := shortAndPermitted.ValidateSupportPeriod(); len(w) != 0 {
		t.Errorf("a permitted two-year period produced warnings: %v", w)
	}
}
