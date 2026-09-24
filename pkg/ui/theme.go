// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import "strings"

// Theme contains semantic colours for Wardex terminal output. Wardex keeps
// its purple brand accent while using cyan and the status colours for meaning.
type Theme struct {
	depth ColorDepth
}

// NewTheme creates a theme for the requested colour depth.
func NewTheme(depth ColorDepth) Theme {
	return Theme{depth: depth}
}

// StatusKind identifies a semantic state rendered by the UI.
type StatusKind uint8

const (
	StatusNeutral StatusKind = iota
	StatusRunning
	StatusSuccess
	StatusWarning
	StatusDanger
)

// Brand renders the primary Wardex accent.
func (t Theme) Brand(s string) string {
	return t.paint(s, "\033[35m", "\033[38;2;111;66;193m", false)
}

// Structure renders borders, rules and active structural elements.
func (t Theme) Structure(s string) string {
	return t.paint(s, "\033[36m", "\033[38;2;42;181;220m", false)
}

// Heading renders a primary section or product label.
func (t Theme) Heading(s string) string {
	return t.paint(s, "\033[97m", "\033[38;2;231;237;247m", true)
}

// Text renders primary text.
func (t Theme) Text(s string) string {
	return t.paint(s, "\033[97m", "\033[38;2;231;237;247m", false)
}

// Muted renders supporting metadata.
func (t Theme) Muted(s string) string {
	return t.paint(s, "\033[90m", "\033[38;2;113;131;160m", false)
}

// Status renders a semantic status token.
func (t Theme) Status(s string, kind StatusKind) string {
	switch kind {
	case StatusRunning:
		return t.paint(s, "\033[36m", "\033[38;2;59;148;208m", false)
	case StatusSuccess:
		return t.paint(s, "\033[32m", "\033[38;2;66;229;161m", false)
	case StatusWarning:
		return t.paint(s, "\033[33m", "\033[38;2;242;211;77m", false)
	case StatusDanger:
		return t.paint(s, "\033[31m", "\033[38;2;240;79;109m", false)
	default:
		return t.Muted(s)
	}
}

func (t Theme) paint(s, ansi, trueColor string, bold bool) string {
	if s == "" || t.depth == ColorNone {
		return s
	}

	code := ansi
	if t.depth == ColorTrueColor {
		code = trueColor
	}
	code = strings.TrimSuffix(code, "m")
	if bold {
		code += ";1"
	}
	return code + "m" + s + Reset
}
