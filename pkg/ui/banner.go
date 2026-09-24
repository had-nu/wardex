// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"io"
	"os"
)

// PrintBanner outputs the compact Wardex branding using stdout's detected
// capabilities. It is kept for callers that explicitly request a banner;
// command entry points should use PrintBannerTo to avoid decorating pipes.
func PrintBanner(version string) {
	NewDefaultRenderer(os.Stdout).Header(version)
}

// PrintBannerTo is the writer-injectable counterpart used by commands that
// need to keep human UI separate from structured output. It is a no-op for
// non-interactive writers.
func PrintBannerTo(w io.Writer, version string) bool {
	return PrintHeaderTo(w, version)
}
