// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"fmt"
	"io"
)

// Log writes a bracket-prefixed message to w with colour when TTY.
// Pattern: [PREFIX] message
func Log(w io.Writer, prefix, msg string, args ...any) {
	formatted := fmt.Sprintf(msg, args...)
	if IsTerminal(w) {
		var colour string
		switch prefix {
		case "REJECT", "BLOCK", "FAIL":
			colour = Red + Bold
		case "WARN":
			colour = Yellow
		case "INFO", "HINT":
			colour = Cyan
		case "PASS", "OK":
			colour = Green
		default:
			colour = Gray
		}
		fmt.Fprintf(w, "%s[%s]%s %s\n", colour, prefix, Reset, formatted)
	} else {
		fmt.Fprintf(w, "[%s] %s\n", prefix, formatted)
	}
}

// LogReject writes a [REJECT] message (red+bold) — for denied acceptances, tampered data.
func LogReject(w io.Writer, msg string, args ...any) {
	Log(w, "REJECT", msg, args...)
}

// LogWarn writes a [WARN] message (yellow) — for discarded data that affects results.
func LogWarn(w io.Writer, msg string, args ...any) {
	Log(w, "WARN", msg, args...)
}

// LogInfo writes a [INFO] message (cyan) — for informational notices.
func LogInfo(w io.Writer, msg string, args ...any) {
	Log(w, "INFO", msg, args...)
}

// LogHint writes a [HINT] message (cyan) — for actionable suggestions.
func LogHint(w io.Writer, msg string, args ...any) {
	Log(w, "HINT", msg, args...)
}
