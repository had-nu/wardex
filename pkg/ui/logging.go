// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"fmt"
	"io"
)

// Log writes a bracket-prefixed message to w with colour when TTY.
// Pattern: [PREFIX] message
//
// Deprecated: the sink parameter is ignored. Logging is centralised on the
// process-wide slog logger (see Default/SetLogger). Use Info/Warn/Error instead.
func Log(_ io.Writer, prefix, msg string, args ...any) {
	formatted := fmt.Sprintf(msg, args...)
	switch prefix {
	case "REJECT", "BLOCK", "FAIL":
		Error(formatted)
	case "WARN":
		Warn(formatted)
	default:
		Info(formatted)
	}
}

// LogReject writes a [REJECT] message (red+bold) — for denied acceptances, tampered data.
//
// Deprecated: use Error.
func LogReject(_ io.Writer, msg string, args ...any) {
	Error(fmt.Sprintf(msg, args...))
}

// LogWarn writes a [WARN] message (yellow) — for discarded data that affects results.
//
// Deprecated: use Warn.
func LogWarn(_ io.Writer, msg string, args ...any) {
	Warn(fmt.Sprintf(msg, args...))
}

// LogInfo writes a [INFO] message (cyan) — for informational notices.
//
// Deprecated: use Info.
func LogInfo(_ io.Writer, msg string, args ...any) {
	Info(fmt.Sprintf(msg, args...))
}

// LogHint writes a [HINT] message (cyan) — for actionable suggestions.
//
// Deprecated: use Info.
func LogHint(_ io.Writer, msg string, args ...any) {
	Info(fmt.Sprintf(msg, args...))
}
