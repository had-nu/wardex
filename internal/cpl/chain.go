package cpl

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// genesisMarker is the legacy prev_hash value used by the first entry of a
// legacy-format chain. The canonical format uses an absent/empty
// previous_entry_hash instead; the marker is only accepted during the
// backward-compatibility window.
const genesisMarker = "genesis"

// ChainLink is the resolved previous-entry link for a raw JSONL audit entry.
// Hash is empty for a genesis entry. Legacy reports whether the link was
// resolved from the deprecated prev_hash field instead of the canonical
// previous_entry_hash.
type ChainLink struct {
	Hash   string
	Legacy bool
}

// ParseChainLink resolves the previous-entry link from a raw JSONL line.
//
// Canonical field: previous_entry_hash (absent or empty = genesis).
// Legacy fallback: prev_hash ("genesis" = genesis, otherwise a hash link).
// Canonical always wins when both fields are present.
func ParseChainLink(line []byte) (ChainLink, error) {
	var entry struct {
		PreviousEntryHash string `json:"previous_entry_hash"`
		PrevHash          string `json:"prev_hash"`
	}
	if err := json.Unmarshal(line, &entry); err != nil {
		return ChainLink{}, fmt.Errorf("cpl: parse entry: %w", err)
	}

	if entry.PreviousEntryHash != "" {
		return ChainLink{Hash: entry.PreviousEntryHash}, nil
	}

	if entry.PrevHash != "" {
		if entry.PrevHash == genesisMarker {
			return ChainLink{Legacy: true}, nil
		}
		return ChainLink{Hash: entry.PrevHash, Legacy: true}, nil
	}

	return ChainLink{}, nil // canonical genesis: no previous_entry_hash
}

// IsGenesis reports whether the raw JSONL line is a chain genesis entry
// (no previous link). It accepts both the canonical format (absent or empty
// previous_entry_hash) and the legacy format (prev_hash set to "genesis").
func IsGenesis(line []byte) (bool, error) {
	link, err := ParseChainLink(line)
	if err != nil {
		return false, err
	}
	return link.Hash == "", nil
}

// VerifyChain checks the integrity of a chained audit log segment.
//
// The canonical format links entries through previous_entry_hash, with an
// absent/empty field on the first (genesis) entry. Legacy entries linked
// through prev_hash are accepted during the compatibility window, with the
// literal value "genesis" marking the first entry. Each entry must reference
// the SHA-256 digest of the raw bytes of the preceding line.
//
// Returns (false, nil) when a tampered or invalid link is detected and
// (false, error) on structural failures such as a malformed JSON line.
func VerifyChain(log []byte) (bool, error) {
	report, err := VerifyStream(bytes.NewReader(log), "")
	if err != nil {
		return false, err
	}
	return report.Valid, nil
}
