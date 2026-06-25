package cpl

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

const genesisMarker = "genesis"

func VerifyChain(log []byte) (bool, error) {
	lines := bytes.Split(bytes.TrimSpace(log), []byte("\n"))
	if len(lines) == 0 {
		return false, fmt.Errorf("cpl: empty audit log")
	}

	var expectedPrevHash string
	for i, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var entry struct {
			PrevHash string `json:"prev_hash"`
		}
		if err := json.Unmarshal(line, &entry); err != nil {
			return false, fmt.Errorf("cpl: line %d: parse error: %w", i+1, err)
		}

		if i == 0 {
			if entry.PrevHash != genesisMarker {
				return false, nil
			}
		} else {
			if entry.PrevHash != expectedPrevHash {
				return false, nil
			}
		}

		h := sha256.Sum256(line)
		expectedPrevHash = fmt.Sprintf("%x", h)
	}
	return true, nil
}
