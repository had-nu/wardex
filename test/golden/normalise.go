// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package golden contains the black-box golden harness and the normalisation
// rules that make its output comparable across runs and machines.
package golden

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Rules accepted in the normalise list of a case. Each rule removes one
// documented instability; widening the normalisation is not how a flaky case
// is fixed, it is how the case stops testing anything.
const (
	// RuleTimestamps replaces RFC 3339 timestamps with <TS>.
	RuleTimestamps = "timestamps"
	// RuleTmpDir replaces the temporary directory root with <TMP>.
	RuleTmpDir = "tmpdir"
	// RuleVersion replaces the built version string with <VERSION>.
	RuleVersion = "version"
)

// timestampPattern matches RFC 3339 with an optional fractional second and
// either Z or a numeric offset. That is the format the reports emit.
var timestampPattern = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})`)

// Normaliser applies the normalisation rules declared by a case.
type Normaliser struct {
	// TempDir is the temporary root of the run that produced the content.
	TempDir string
	// Version is the version the binary was built with.
	Version string
	// Rules is the ordered list of rules to apply.
	Rules []string
}

// Normalise returns content with the configured rules applied. Line endings
// become LF, the declared substitutions run in order, and content that is
// valid JSON is re-encoded with a fixed two-space indentation, so that two
// equal documents cannot compare unequal because of formatting alone.
func (n Normaliser) Normalise(content string) (string, error) {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	for _, rule := range n.Rules {
		switch rule {
		case RuleTimestamps:
			content = timestampPattern.ReplaceAllString(content, "<TS>")
		case RuleTmpDir:
			if n.TempDir == "" {
				return "", fmt.Errorf("normalise: rule %q needs a temporary directory", rule)
			}
			content = strings.ReplaceAll(content, n.TempDir, "<TMP>")
		case RuleVersion:
			if n.Version == "" {
				return "", fmt.Errorf("normalise: rule %q needs a version", rule)
			}
			content = strings.ReplaceAll(content, n.Version, "<VERSION>")
		default:
			return "", fmt.Errorf("normalise: unknown rule %q", rule)
		}
	}

	if strings.TrimSpace(content) == "" {
		return "", nil
	}

	if trimmed := strings.TrimSpace(content); json.Valid([]byte(trimmed)) {
		var buf bytes.Buffer
		if err := json.Indent(&buf, []byte(trimmed), "", "  "); err == nil {
			content = buf.String()
		}
	}

	return strings.TrimRight(content, "\n") + "\n", nil
}
