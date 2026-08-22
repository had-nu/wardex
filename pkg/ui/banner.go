// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"fmt"
)

const (
	clrPurple = "\033[38;2;111;66;193m"
	clrMuted  = "\033[38;2;110;118;129m"
	clrWhite  = "\033[37m"
	clrBold   = "\033[1m"
	clrReset  = "\033[0m"
)

// PrintBanner outputs the professional branding for Wardex.
func PrintBanner(version string) {
	fmt.Printf("\n %s(⬡───────────────────────)%s  %s%sWARDEX%s  %s·%s  %srisk-based release gate%s  %sv%s%s\n\n",
		clrPurple, clrReset,
		clrBold, clrWhite, clrReset,
		clrMuted, clrReset,
		clrPurple, clrReset,
		clrWhite, version, clrReset)
}

