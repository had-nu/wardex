// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import "testing"

func TestDetectProfileForBufferIsNonInteractive(t *testing.T) {
	p := DetectProfile(testWriter{})
	if p.Interactive {
		t.Fatal("buffer must not be considered interactive")
	}
	if p.ColorDepth != ColorNone {
		t.Fatalf("buffer profile should disable colour, got %v", p.ColorDepth)
	}
	if p.Width != DefaultWidth {
		t.Fatalf("buffer profile should use default width, got %d", p.Width)
	}
}

func TestNormalizeProfileBoundsWidthAndColour(t *testing.T) {
	p := normalizeProfile(Profile{Width: 5, ColorDepth: ColorDepth(99)})
	if p.Width != MinWidth {
		t.Fatalf("minimum width not applied: %d", p.Width)
	}
	if p.ColorDepth != ColorNone {
		t.Fatalf("invalid colour depth not disabled: %v", p.ColorDepth)
	}

	p = normalizeProfile(Profile{Width: 1000, ColorDepth: ColorANSI})
	if p.Width != MaxWidth {
		t.Fatalf("maximum width not applied: %d", p.Width)
	}
}

type testWriter struct{}

func (testWriter) Write(p []byte) (int, error) { return len(p), nil }
