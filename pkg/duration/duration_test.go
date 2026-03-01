// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package duration

import (
	"testing"
	"time"
)

func TestParseExtended(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{
			name:  "30 days",
			input: "30d",
			want:  30 * 24 * time.Hour,
		},
		{
			name:  "3 days",
			input: "3d",
			want:  3 * 24 * time.Hour,
		},
		{
			name:  "1 day",
			input: "1d",
			want:  24 * time.Hour,
		},
		{
			name:  "0 days",
			input: "0d",
			want:  0,
		},
		{
			name:  "standard hours",
			input: "72h",
			want:  72 * time.Hour,
		},
		{
			name:  "standard composite",
			input: "1h30m",
			want:  1*time.Hour + 30*time.Minute,
		},
		{
			name:  "standard seconds",
			input: "30s",
			want:  30 * time.Second,
		},
		{
			name:  "standard milliseconds",
			input: "500ms",
			want:  500 * time.Millisecond,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "negative days",
			input:   "-5d",
			wantErr: true,
		},
		{
			name:    "non-numeric day prefix",
			input:   "abcd",
			wantErr: true,
		},
		{
			name:    "float days not supported",
			input:   "1.5d",
			wantErr: true,
		},
		{
			name:  "whitespace trimmed",
			input: "  7d  ",
			want:  7 * 24 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseExtended(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseExtended(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseExtended(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
