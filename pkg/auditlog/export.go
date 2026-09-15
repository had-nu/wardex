// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package auditlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// defaultLimit is the page size used when Export gets Limit <= 0.
const defaultLimit = 100

// ErrChainTampered is returned when resuming from a cursor detects that the
// entry following the cursor does not chain to it via previous_entry_hash.
var ErrChainTampered = errors.New("auditlog: chain tampered at resume cursor")

// ExportEntry is a single audit log record seen by Export. Raw is the trimmed
// JSONL line; Hash is the chain hash (sha256 of the raw line); PrevHash is the
// entry's previous_entry_hash (empty for a genesis entry).
type ExportEntry struct {
	Hash     string
	PrevHash string
	Raw      []byte
}

// ExportOptions controls bounded paginated reading of an audit stream.
//   - Limit <= 0 selects defaultLimit.
//   - Cursor == "" starts at the genesis entry. Otherwise the export resumes
//     AFTER the entry whose chain hash equals Cursor, cross-checking that the
//     next entry chains to it (integrity on resume).
//   - Tail selects the trailing Limit entries (newest) instead of the leading
//     ones. NextCursor is still the hash of the last delivered entry, so a
//     subsequent request with --cursor resumes forward from the tail.
type ExportOptions struct {
	Limit  int
	Cursor string
	Tail   bool
}

// ExportResult is a single export page.
type ExportResult struct {
	Entries    []ExportEntry
	HasMore    bool
	NextCursor string
}

// Export streams an io.Reader implementing LIMIT+1 semantics: at most Limit
// entries are delivered and HasMore reports whether a page would be non-empty.
// For Tail pages HasMore is always false; the newest entries were delivered.
func Export(r io.Reader, opts ExportOptions) (ExportResult, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = defaultLimit
	}

	res := ExportResult{}
	if opts.Tail {
		return exportTail(r, limit, res)
	}

	var ring []ExportEntry
	hasMore := false
	delivered := 0
	resuming := opts.Cursor == ""
	expectPrev := opts.Cursor

	err := Scan(r, DefaultMaxLineBytes, func(line []byte) error {
		e, err := entryFromLine(line)
		if err != nil {
			return err
		}

		if !resuming {
			if e.Hash == opts.Cursor {
				resuming = true
				expectPrev = e.Hash
				return nil
			}
			return nil
		}

		// First entry after the cursor must chain to it.
		if expectPrev != "" && e.PrevHash != expectPrev {
			return fmt.Errorf("%w: expected previous_entry_hash %s, got %s", ErrChainTampered, expectPrev, e.PrevHash)
		}
		expectPrev = ""

		if delivered >= limit {
			hasMore = true
			return nil
		}
		delivered++
		ring = append(ring, e)
		return nil
	})
	if err != nil {
		return ExportResult{}, err
	}

	if opts.Cursor != "" && !resuming {
		return ExportResult{}, fmt.Errorf("auditlog: cursor %s not found in chain", opts.Cursor)
	}

	res.Entries = ring
	res.HasMore = hasMore
	if len(ring) > 0 {
		res.NextCursor = ring[len(ring)-1].Hash
	}
	return res, nil
}

// exportTail keeps a bounded window of the trailing Limit entries.
func exportTail(r io.Reader, limit int, res ExportResult) (ExportResult, error) {
	window := make([]ExportEntry, 0, limit+1)
	err := Scan(r, DefaultMaxLineBytes, func(line []byte) error {
		e, err := entryFromLine(line)
		if err != nil {
			return err
		}
		window = append(window, e)
		if len(window) > limit {
			window = window[1:]
		}
		return nil
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.Entries = window
	res.HasMore = false
	if len(window) > 0 {
		res.NextCursor = window[len(window)-1].Hash
	}
	return res, nil
}

func entryFromLine(line []byte) (ExportEntry, error) {
	var probe struct {
		PrevHash string `json:"previous_entry_hash"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		return ExportEntry{}, fmt.Errorf("auditlog: parse entry: %w", err)
	}
	return ExportEntry{
		Hash:     hashLine(line),
		PrevHash: probe.PrevHash,
		Raw:      append([]byte(nil), line...),
	}, nil
}

func hashLine(line []byte) string {
	h := sha256.Sum256(line)
	return hex.EncodeToString(h[:])
}
