// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package statestore

import (
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"lukechampine.com/blake3"
)

// ChainEntry is one link in the BLAKE3 hash chain.
type ChainEntry struct {
	Index     int       `json:"index"`
	Timestamp time.Time `json:"timestamp"`
	DataHash  string    `json:"data_hash"`  // BLAKE3 hash of the state data
	PrevHash  string    `json:"prev_hash"`  // BLAKE3 hash of the previous entry
	ChainHash string    `json:"chain_hash"` // BLAKE3(DataHash || PrevHash)
}

// ComputeChainHash computes the BLAKE3 hash for a chain entry.
func ComputeChainHash(dataHash, prevHash string) string {
	h := blake3.New(32, nil)
	h.Write([]byte(dataHash))
	h.Write([]byte(prevHash))
	return hex.EncodeToString(h.Sum(nil))
}

// HashBytes computes BLAKE3 hash of raw bytes.
func HashBytes(data []byte) string {
	h := blake3.New(32, nil)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// ChainFile is the on-disk format for the BLAKE3 chain.
type ChainFile struct {
	Entries []ChainEntry `json:"entries"`
}

// LoadChain reads the chain file from disk.
func LoadChain(path string) (*ChainFile, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			return &ChainFile{Entries: make([]ChainEntry, 0)}, nil
		}
		return nil, fmt.Errorf("statestore: read chain: %w", err)
	}

	var chain ChainFile
	if err := unmarshalJSON(data, &chain); err != nil {
		return nil, fmt.Errorf("statestore: parse chain: %w", err)
	}
	return &chain, nil
}

// SaveChain writes the chain file atomically.
func SaveChain(path string, chain *ChainFile) error {
	data, err := marshalJSON(chain)
	if err != nil {
		return fmt.Errorf("statestore: marshal chain: %w", err)
	}
	return atomicWrite(path, data)
}

// VerifyChain checks the integrity of the entire chain.
func VerifyChain(chain *ChainFile) error {
	for i, entry := range chain.Entries {
		if i == 0 {
			// Genesis entry: PrevHash must be empty
			if entry.PrevHash != "" {
				return fmt.Errorf("statestore: genesis entry has non-empty prev_hash")
			}
			// Recompute chain hash
			expected := ComputeChainHash(entry.DataHash, entry.PrevHash)
			if entry.ChainHash != expected {
				return fmt.Errorf("statestore: chain entry %d hash mismatch: expected %s, got %s", i, expected, entry.ChainHash)
			}
			continue
		}

		// Verify PrevHash matches previous entry's ChainHash
		prev := chain.Entries[i-1]
		if entry.PrevHash != prev.ChainHash {
			return fmt.Errorf("statestore: chain entry %d prev_hash mismatch: expected %s, got %s", i, prev.ChainHash, entry.PrevHash)
		}

		// Recompute chain hash
		expected := ComputeChainHash(entry.DataHash, entry.PrevHash)
		if entry.ChainHash != expected {
			return fmt.Errorf("statestore: chain entry %d hash mismatch: expected %s, got %s", i, expected, entry.ChainHash)
		}
	}
	return nil
}

// AppendEntry adds a new entry to the chain.
func AppendEntry(chain *ChainFile, dataHash string) ChainEntry {
	var prevHash string
	if len(chain.Entries) > 0 {
		prevHash = chain.Entries[len(chain.Entries)-1].ChainHash
	}

	entry := ChainEntry{
		Index:     len(chain.Entries),
		Timestamp: time.Now().UTC(),
		DataHash:  dataHash,
		PrevHash:  prevHash,
		ChainHash: ComputeChainHash(dataHash, prevHash),
	}

	chain.Entries = append(chain.Entries, entry)
	return entry
}
