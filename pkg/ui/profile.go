// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

const (
	// DefaultWidth is used when the terminal width cannot be detected.
	DefaultWidth = 80
	// MinWidth leaves enough room for a compact two-column layout.
	MinWidth = 20
	// MaxWidth prevents a very wide terminal from producing unreadable lines.
	MaxWidth = 240
)

// ColorDepth describes the ANSI colour capabilities available to a renderer.
type ColorDepth uint8

const (
	ColorNone ColorDepth = iota
	ColorANSI
	ColorTrueColor
)

// Profile is the rendering capability set used by the terminal UI.
//
// It is intentionally a value type so tests and non-interactive callers can
// provide a deterministic profile without changing process-wide environment.
type Profile struct {
	Interactive bool
	ColorDepth  ColorDepth
	Unicode     bool
	Width       int
}

// DetectProfile inspects w and the current process environment.
//
// Human-facing decoration is disabled for pipes, files and CI. The output
// itself is not changed; callers decide which renderer to use.
func DetectProfile(w io.Writer) Profile {
	return detectProfile(w, os.Getenv)
}

type envLookup func(string) string

func detectProfile(w io.Writer, getenv envLookup) Profile {
	p := Profile{
		ColorDepth: ColorNone,
		Unicode:    false,
		Width:      DefaultWidth,
	}

	fd, ok := terminalFD(w)
	if !ok || !term.IsTerminal(fd) {
		return p
	}

	p.Interactive = true
	p.Unicode = unicodeSupported(getenv)
	p.Width = terminalWidth(fd, getenv)

	return applyEnvironment(p, getenv)
}

func applyEnvironment(p Profile, getenv envLookup) Profile {
	if isCI(getenv) {
		return normalizeProfile(Profile{ColorDepth: ColorNone, Unicode: false, Width: DefaultWidth})
	}
	if getenv("NO_COLOR") != "" || strings.EqualFold(getenv("TERM"), "dumb") {
		p.ColorDepth = ColorNone
		return normalizeProfile(p)
	}

	p.ColorDepth = ColorANSI
	colorTerm := strings.ToLower(getenv("COLORTERM"))
	if colorTerm == "truecolor" || colorTerm == "24bit" {
		p.ColorDepth = ColorTrueColor
	}

	return normalizeProfile(p)
}

func terminalFD(w io.Writer) (int, bool) {
	f, ok := w.(*os.File)
	if !ok {
		return 0, false
	}
	return int(f.Fd()), true
}

func terminalWidth(fd int, getenv envLookup) int {
	if width, _, err := term.GetSize(fd); err == nil && width > 0 {
		return width
	}
	if raw := getenv("COLUMNS"); raw != "" {
		if width, err := strconv.Atoi(raw); err == nil && width > 0 {
			return width
		}
	}
	return DefaultWidth
}

func unicodeSupported(getenv envLookup) bool {
	if strings.EqualFold(getenv("TERM"), "dumb") {
		return false
	}
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		value := getenv(key)
		if value == "" {
			continue
		}
		value = strings.ToUpper(value)
		return strings.Contains(value, "UTF-8") || strings.Contains(value, "UTF8")
	}
	return true
}

func isCI(getenv envLookup) bool {
	for _, key := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI"} {
		value := strings.TrimSpace(getenv(key))
		if value != "" && !strings.EqualFold(value, "0") && !strings.EqualFold(value, "false") {
			return true
		}
	}
	return false
}

func normalizeProfile(p Profile) Profile {
	if p.Width <= 0 {
		p.Width = DefaultWidth
	}
	if p.Width < MinWidth {
		p.Width = MinWidth
	}
	if p.Width > MaxWidth {
		p.Width = MaxWidth
	}
	if p.ColorDepth > ColorTrueColor {
		p.ColorDepth = ColorNone
	}
	return p
}
