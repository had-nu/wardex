// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package auditlog provides a streaming reader for wardex JSONL audit logs.
// It bounds memory usage per line and avoids unbounded whole-file loads,
// following the LIMIT+1 / cursor discipline used by wardex consumers.
package auditlog

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

// DefaultMaxLineBytes bounds a single audit log line. A line larger than this
// cap is treated as a structural error rather than being fully buffered.
const DefaultMaxLineBytes = 1 << 20 // 1 MiB

// ErrLineTooLong is returned when a scanned line exceeds the configured cap.
// It maps to the bufio.ErrTooLong scanner error.
var ErrLineTooLong = errors.New("auditlog: line exceeds maximum size")

// Handler is invoked for each non-empty, trimmed JSONL line (without the
// trailing newline). The line slice is only valid for the duration of the call;
// handlers must copy it if they retain the data.
type Handler func(line []byte) error

// Scan streams an io.Reader line by line, invoking handler for each non-empty
// line. Lines are trimmed of leading/trailing whitespace. The scanner buffer
// is sized to the configured cap so oversized lines are reported instead of
// silently truncated. A maxLineBytes <= 0 selects DefaultMaxLineBytes.
func Scan(r io.Reader, maxLineBytes int, handler Handler) error {
	if maxLineBytes <= 0 {
		maxLineBytes = DefaultMaxLineBytes
	}

	scanner := bufio.NewScanner(r)
	buf := make([]byte, 64*1024)
	if maxLineBytes < len(buf) {
		buf = make([]byte, maxLineBytes)
	}
	scanner.Buffer(buf, maxLineBytes)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if err := handler(line); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return ErrLineTooLong
		}
		return err
	}
	return nil
}
