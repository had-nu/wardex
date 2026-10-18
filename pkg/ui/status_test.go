// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"sort"
	"strings"
	"testing"
)

// statusExpectation is the complete status vocabulary the renderer accepts,
// with the semantic each string must resolve to. It is deliberately
// hand-written: the point of the table is to fail when a string is dropped
// from a switch arm in dashboard.go, which a count-based assertion cannot do.
var statusExpectation = map[string]StatusKind{
	// Running.
	"RUNNING": StatusRunning,
	"ACTIVE":  StatusRunning,
	"PENDING": StatusRunning,

	// Success.
	"DONE":             StatusSuccess,
	"COMPLETE":         StatusSuccess,
	"COMPLETED":        StatusSuccess,
	"PASS":             StatusSuccess,
	"ALLOW":            StatusSuccess,
	"ALLOWED":          StatusSuccess,
	"SUCCESS":          StatusSuccess,
	"READY":            StatusSuccess,
	"GENERATED":        StatusSuccess,
	"SEALED":           StatusSuccess,
	"ADDED":            StatusSuccess,
	"INITIALISED":      StatusSuccess,
	"INITIALIZED":      StatusSuccess,
	"UPDATED":          StatusSuccess,
	"VALID":            StatusSuccess,
	"VERIFIED":         StatusSuccess,
	"COMPUTED":         StatusSuccess,
	"CONVERTED":        StatusSuccess,
	"LOADED":           StatusSuccess,
	"CREATED":          StatusSuccess,
	"ACKNOWLEDGED":     StatusSuccess,
	"RECORDED":         StatusSuccess,
	"CLEAR":            StatusSuccess,
	"FORWARDING READY": StatusSuccess,

	// Warning.
	"WARN":            StatusWarning,
	"WARNING":         StatusWarning,
	"MEDIUM":          StatusWarning,
	"PARTIAL":         StatusWarning,
	"REVIEW":          StatusWarning,
	"NOT_INITIALIZED": StatusWarning,
	"EMPTY":           StatusWarning,
	"NO EVENTS":       StatusWarning,

	// Danger.
	"FAIL":      StatusDanger,
	"FAILED":    StatusDanger,
	"ERROR":     StatusDanger,
	"BLOCK":     StatusDanger,
	"BLOCKED":   StatusDanger,
	"HIGH":      StatusDanger,
	"DANGER":    StatusDanger,
	"REVOKED":   StatusDanger,
	"INVALID":   StatusDanger,
	"BROKEN":    StatusDanger,
	"EXPIRED":   StatusDanger,
	"MISMATCH":  StatusDanger,
	"DUPLICATE": StatusDanger,
}

// TestStatusKindResolvesWholeVocabulary checks every accepted status string,
// not a sample. Removing a string from a switch arm fails here.
func TestStatusKindResolvesWholeVocabulary(t *testing.T) {
	for status, want := range statusExpectation {
		if got := statusKind(status); got != want {
			t.Errorf("statusKind(%q) = %v, want %v", status, got, want)
		}
	}
}

// TestStatusKindNormalisesInput confirms the lookup is case and space
// insensitive, because every call site passes free-form pipeline strings.
func TestStatusKindNormalisesInput(t *testing.T) {
	for _, form := range []string{"revoked", "REVOKED", "  Revoked  ", "\trevoked\n"} {
		if got := statusKind(form); got != StatusDanger {
			t.Errorf("statusKind(%q) = %v, want %v", form, got, StatusDanger)
		}
	}
}

// TestStatusKindUnknownIsNeutral confirms unrecognised input degrades to a
// neutral style rather than to danger or success.
func TestStatusKindUnknownIsNeutral(t *testing.T) {
	for _, unknown := range []string{
		"", "   ", "COMPLTE", "REVOEKED", "PASSED", "OK", "WARNINGS",
		"BLOCKED_BY_POLICY", "INITIALISE", "COLOURS",
	} {
		if got := statusKind(unknown); got != StatusNeutral {
			t.Errorf("statusKind(%q) = %v, want %v", unknown, got, StatusNeutral)
		}
	}
}

// TestStatusKindDistinctSpellingsDisagree is a regression guard for the two
// spellings of the same concept. INITIALISED and INITIALIZED are both accepted
// for backward compatibility; removing either one silently changes the colour
// of any caller still using it, so the duplication is pinned here instead of
// left to chance.
func TestStatusKindDistinctSpellingsDisagree(t *testing.T) {
	for _, spelling := range []string{"INITIALISED", "INITIALIZED"} {
		if got := statusKind(spelling); got != StatusSuccess {
			t.Errorf("statusKind(%q) = %v, want %v", spelling, got, StatusSuccess)
		}
	}
}

// TestPhaseMarkerCoversStatusVocabulary checks the phase marker resolves a
// distinct glyph per phase outcome, and that unknown phases stay neutral.
func TestPhaseMarkerCoversStatusVocabulary(t *testing.T) {
	cases := map[string]string{
		"DONE":     "✓",
		"COMPLETE": "✓",
		"FAILED":   "✗",
		"RUNNING":  "▶",
		"SKIPPED":  "−",
	}
	for status, wantUnicode := range cases {
		if got := phaseMarker(status, true); got != wantUnicode {
			t.Errorf("phaseMarker(%q, unicode) = %q, want %q", status, got, wantUnicode)
		}
	}

	wantASCII := map[string]string{
		"DONE":    "+",
		"FAILED":  "x",
		"RUNNING": ">",
		"SKIPPED": "-",
	}
	for status, wantASCIIGlyph := range wantASCII {
		if got := phaseMarker(status, false); got != wantASCIIGlyph {
			t.Errorf("phaseMarker(%q, ascii) = %q, want %q", status, got, wantASCIIGlyph)
		}
	}

	if got := phaseMarker("SOMETHING_NEW", true); got != "·" {
		t.Errorf("unknown phase marker = %q, want the neutral dot", got)
	}
	if got := phaseMarker("SOMETHING_NEW", false); got != "." {
		t.Errorf("unknown ascii phase marker = %q, want a dot", got)
	}

	// PENDING is classified as running by statusKind but has no dedicated
	// glyph, so it falls through to the neutral dot. The two tables disagree by
	// design; this pins the current behaviour.
	if got := phaseMarker("PENDING", true); got != "·" {
		t.Errorf("phaseMarker(\"PENDING\", unicode) = %q, want the neutral dot", got)
	}
	if got := statusKind("PENDING"); got != StatusRunning {
		t.Errorf("statusKind(\"PENDING\") = %v, want %v", got, StatusRunning)
	}
}

// neutralByDesign lists statuses the renderer accepts that deliberately carry
// no semantic colour. A skipped phase is informational, not a warning, so it
// must not read as a problem. statusKind omits these arms on purpose; this
// table records the decision so a future change has to be deliberate.
var neutralByDesign = map[string]string{
	"SKIPPED": "a skipped phase is informational, not a warning",
	"SKIP":    "short form of SKIPPED",
}

// TestStatusNeutralByDesignIsStillNeutral pins the deliberate omissions above.
func TestStatusNeutralByDesignIsStillNeutral(t *testing.T) {
	for status, reason := range neutralByDesign {
		if got := statusKind(status); got != StatusNeutral {
			t.Errorf("statusKind(%q) = %v, want %v (%s)", status, got, StatusNeutral, reason)
		}
	}
}

// TestPhaseVocabularyIsClassified checks every phase status the orchestrator
// emits is either classified or explicitly listed as neutral by design. This is
// what caught SKIPPED and SKIP resolving to neutral by omission.
func TestPhaseVocabularyIsClassified(t *testing.T) {
	phaseStatuses := []string{
		"DONE", "COMPLETE", "COMPLETED",
		"RUNNING", "ACTIVE", "PENDING",
		"FAILED", "FAIL", "ERROR",
		"SKIPPED", "SKIP",
	}

	for _, status := range phaseStatuses {
		_, classified := statusExpectation[status]
		_, deliberate := neutralByDesign[status]
		if !classified && !deliberate {
			t.Errorf("phase status %q is neither classified nor listed as neutral by design", status)
		}
	}
}

// TestStatusExpectationIsReachable guards the table against its own drift: a
// status declared non-neutral must actually resolve non-neutral.
func TestStatusExpectationIsReachable(t *testing.T) {
	var neutral []string
	for status := range statusExpectation {
		if statusKind(status) == StatusNeutral {
			neutral = append(neutral, status)
		}
	}
	if len(neutral) > 0 {
		sort.Strings(neutral)
		t.Errorf("statuses declared non-neutral but resolving to neutral: %s", strings.Join(neutral, ", "))
	}
}
