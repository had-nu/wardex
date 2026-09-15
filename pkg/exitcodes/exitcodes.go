// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package exitcodes defines named exit codes for the Wardex CLI.
// These avoid magic numbers and prevent collisions with reserved POSIX codes.
//
// POSIX reserves:
//   - 0: success
//   - 1: general errors
//   - 2: misuse of shell builtins
//   - 126: command invoked cannot execute
//   - 127: command not found
//   - 128+N: fatal signal N
//
// Wardex uses codes >= 3 for specific conditions, and >= 10 for gate/compliance.
package exitcodes

const (
	// OK indicates successful execution.
	OK = 0

	// GenericError indicates a general application error.
	GenericError = 1

	// IntegrityFailure indicates a cryptographic integrity violation.
	// This covers both acceptance HMAC tampering and wexstate seal
	// verification failures (revoked key, trust store drift, invalid sig).
	IntegrityFailure = 3

	// StoreInconsistent indicates a mismatch between the store
	// file and the audit log (entries missing from the YAML file).
	StoreInconsistent = 4

	// ExpiringSoon indicates that one or more acceptances are
	// approaching their expiration date within the warn-before window.
	ExpiringSoon = 5

	// FreshnessAdvisory indicates the gate class treats freshness gaps
	// (e.g. missing EPSS/KEV scores) as an advisory instead of a hard stop.
	// The pipeline is NOT blocked — consumers are told to refresh evidence.
	// README warns: do not treat 6 as "release blocked"; it is a nudge.
	// NEW in v2.6 — L3 gate classes (pr/nightly).
	FreshnessAdvisory = 6

	// GateBlocked indicates the release gate evaluated to "block".
	// The deployment should not proceed.
	GateBlocked = 10

	// ComplianceFail indicates a gap score exceeded the --fail-above threshold.
	ComplianceFail = 11

	// ActivelyExploited indicates one or more CVEs in the evidence envelope are
	// classified as actively exploited (e.g. present in the CISA KEV catalogue).
	// This is a hard stop: unlike GateBlocked (10), it cannot be overridden by
	// a risk acceptance. CI pipelines must treat exit code 12 explicitly.
	// NEW in v2.0 — CRA Article 14 compliance.
	ActivelyExploited = 12

	// DuplicateRelease indicates that the release version passed to
	// `wardex gate check-version` has already been sealed in the audit chain.
	// CI pipelines must treat exit code 13 explicitly as an idempotency guard:
	// a version must be sealed exactly once.
	// NEW in v2.6 — L4 anti-regression version guard.
	DuplicateRelease = 13
)
