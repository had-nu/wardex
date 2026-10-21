// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package main

import "testing"

func TestIsGoldenFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want bool
	}{
		{"test/golden/cases/G1/assess-iso27001-both-layers/want/stdout.txt", true},
		{"test/golden/cases/G1/assess-iso27001-both-layers/want/exit", true},
		{"test/golden/cases/G1/assess-iso27001-both-layers/want/files/report.csv", true},
		{"test/golden/cases/G1/assess-iso27001-both-layers/case.yaml", false},
		{"test/golden/cases/G1/assess-iso27001-both-layers/in/documented.yaml", false},
		{"test/golden/normalise.go", false},
		{"doc/specs/SPEC-M0-baseline.md", false},
	}
	for _, test := range tests {
		if got := isGoldenFile(test.path); got != test.want {
			t.Errorf("isGoldenFile(%q) = %t, want %t", test.path, got, test.want)
		}
	}
}

func TestGoldenChangeValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		msg   string
		want  string
		found bool
	}{
		{
			name:  "trailer in the final paragraph",
			msg:   "test: update the ISO golden\n\nRewrites the report expectation.\n\nGolden-Change: ADR-0007\n",
			want:  "ADR-0007",
			found: true,
		},
		{
			name:  "key is case-insensitive",
			msg:   "test: update\n\ngolden-change: #123",
			want:  "#123",
			found: true,
		},
		{
			name:  "message that is only trailers",
			msg:   "Golden-Change: ISSUE-9",
			want:  "ISSUE-9",
			found: true,
		},
		{
			name:  "trailer beside another trailer",
			msg:   "test: update\n\nSigned-off-by: Someone <someone@example.com>\nGolden-Change: ADR-0007",
			want:  "ADR-0007",
			found: true,
		},
		{
			name:  "prose in the final paragraph is not a trailer",
			msg:   "test: update\n\nGolden-Change: ADR-0007\nbut this line is prose.",
			found: false,
		},
		{
			name:  "empty value does not count",
			msg:   "test: update\n\nGolden-Change:",
			found: false,
		},
		{
			name:  "no trailer",
			msg:   "test: update the golden files",
			found: false,
		},
		{
			name:  "CRLF message",
			msg:   "test: update\r\n\r\nGolden-Change: ADR-0007\r\n",
			want:  "ADR-0007",
			found: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, found := goldenChangeValue(test.msg)
			if found != test.found || got != test.want {
				t.Fatalf("goldenChangeValue(%q) = %q, %t; want %q, %t", test.msg, got, found, test.want, test.found)
			}
		})
	}
}

func TestCheckRevisionRejectsOptions(t *testing.T) {
	t.Parallel()

	if err := checkRevision("-tip", "--upload-pack=evil"); err == nil {
		t.Fatal("checkRevision accepted a revision that starts with a dash")
	}
	if err := checkRevision("-tip", "main"); err != nil {
		t.Fatalf("checkRevision rejected a valid revision: %v", err)
	}
}
