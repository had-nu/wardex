// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"fmt"
	"time"
)

// ANSI color codes for the aesthetic
const (
	dim       = "\033[38;5;236m"
	dimLine   = "\033[38;5;235m" // Very dark gray for separator lines
	dimPurple = "\033[38;5;55m"
	purple    = "\033[38;2;170;0;255m"
	grey      = "\033[38;2;170;170;170m"
	pink      = "\033[38;2;255;0;127m"
	cyan      = "\033[38;5;51m"
	green     = "\033[38;5;46m"
	yellow    = "\033[38;5;226m"
	white     = "\033[38;5;255m"
	reset     = "\033[0m"
)


// PrintBanner outputs a professional, minimalist Wardex header.
func PrintBanner(version string) {
	now := time.Now().Format("2006-01-02 15:04:05")

	// Colors
	p := pink
	c := cyan
	g := green
	r := reset
	d := dim

	line := fmt.Sprintf("%s────────────────────────────────────────────────────────────────────────────────%s", d, r)

	fmt.Printf("\n%s\n", line)
	fmt.Printf("  %s◈ WARDEX%s v%s  %s|%s  Status: %sACTIVE%s  %s|%s  Threshold: %s0.72%s  %s|%s  %s%s%s\n",
		p, r, version, d, r, g, r, d, r, c, r, d, r, d, now, r)
	fmt.Printf("%s\n\n", line)
}
