// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package accept

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/utils"
)

// ChainGap represents a verification failure in the audit log chain.
type ChainGap struct {
	Index   int
	Message string
}

// LastEntryHash reads the last non-empty line of the JSONL log file at logPath
// and returns the SHA-256 hash of its raw bytes (excluding trailing newline).
// If the file does not exist or has no entries, it returns an empty string.
func LastEntryHash(logPath string) (string, error) {
	auditMu.Lock()
	defer auditMu.Unlock()
	return lastEntryHashLocked(logPath)
}

// lastEntryHashLocked is the lock-free helper for LastEntryHash.
func lastEntryHashLocked(logPath string) (string, error) {
	cwd, _ := os.Getwd()
	safePathStr, err := utils.SafePath(cwd, logPath)
	if err != nil {
		return "", err
	}

	f, err := os.Open(safePathStr) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer func() { _ = f.Close() }()

	var lastLine string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lastLine = line
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	if lastLine == "" {
		return "", nil
	}

	h := sha256.Sum256([]byte(lastLine))
	return hex.EncodeToString(h[:]), nil
}

// ChainedAuditLog sets the PreviousEntryHash on entry to the hash of the last
// line of the log, and then appends the entry to the log.
func ChainedAuditLog(logPath string, entry model.AuditEntry) error {
	auditMu.Lock()
	defer auditMu.Unlock()

	prevHash, err := lastEntryHashLocked(logPath)
	if err != nil {
		return fmt.Errorf("audit chain: failed to get last entry hash: %w", err)
	}
	entry.PreviousEntryHash = prevHash

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	} else {
		entry.Timestamp = entry.Timestamp.UTC()
	}

	cwd, _ := os.Getwd()
	safePathStr, err := utils.SafePath(cwd, logPath)
	if err != nil {
		return err
	}

	dir := filepath.Dir(safePathStr)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	f, err := os.OpenFile(safePathStr, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	_, err = f.Write(data)
	return err
}

// VerifyChain checks the integrity of the audit log chain.
// It verifies that each entry's previous_entry_hash matches the SHA-256 hash of the preceding entry.
func VerifyChain(logPath string) ([]ChainGap, error) {
	auditMu.Lock()
	defer auditMu.Unlock()

	cwd, _ := os.Getwd()
	safePathStr, err := utils.SafePath(cwd, logPath)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(safePathStr) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var gaps []ChainGap
	var expectedPrevHash string
	var index int

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		var entry model.AuditEntry
		if err := json.Unmarshal([]byte(trimmed), &entry); err != nil {
			gaps = append(gaps, ChainGap{
				Index:   index,
				Message: fmt.Sprintf("malformed JSON at entry %d: %v", index, err),
			})
			expectedPrevHash = ""
			index++
			continue
		}

		if entry.PreviousEntryHash != expectedPrevHash {
			gaps = append(gaps, ChainGap{
				Index:   index,
				Message: fmt.Sprintf("hash mismatch at entry %d: expected %q, got %q", index, expectedPrevHash, entry.PreviousEntryHash),
			})
		}

		h := sha256.Sum256([]byte(line))
		expectedPrevHash = hex.EncodeToString(h[:])
		index++
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return gaps, nil
}
