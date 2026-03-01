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

	// Tampered indicates an HMAC signature validation failure.
	// An acceptance record may have been modified outside Wardex.
	Tampered = 3

	// StoreInconsistent indicates a mismatch between the store
	// file and the audit log (entries missing from the YAML file).
	StoreInconsistent = 4

	// ExpiringSoon indicates that one or more acceptances are
	// approaching their expiration date within the warn-before window.
	ExpiringSoon = 5

	// GateBlocked indicates the release gate evaluated to "block".
	// The deployment should not proceed.
	GateBlocked = 10

	// ComplianceFail indicates a gap score exceeded the --fail-above threshold.
	ComplianceFail = 11
)
