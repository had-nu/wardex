// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package auditlog

import (
	"errors"
	"strings"
	"testing"
)

func TestScanLines(t *testing.T) {
	input := "line one\n\n  line two  \r\nline three\n"
	var got []string
	err := Scan(strings.NewReader(input), 0, func(line []byte) error {
		got = append(got, string(line))
		return nil
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	want := []string{"line one", "line two", "line three"}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestScanHandlerErrorPropagates(t *testing.T) {
	sentinel := errors.New("stop")
	err := Scan(strings.NewReader("a\nb\n"), 0, func(line []byte) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("handler error not propagated: %v", err)
	}
}

func TestScanLineTooLong(t *testing.T) {
	long := strings.Repeat("x", DefaultMaxLineBytes+1)
	err := Scan(strings.NewReader(long+"\n"), DefaultMaxLineBytes, func(line []byte) error {
		return nil
	})
	if !errors.Is(err, ErrLineTooLong) {
		t.Errorf("expected ErrLineTooLong, got %v", err)
	}
}

func TestScanEmptyInput(t *testing.T) {
	var called bool
	err := Scan(strings.NewReader("\n\n"), 0, func(line []byte) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if called {
		t.Error("handler called for empty input")
	}
}
