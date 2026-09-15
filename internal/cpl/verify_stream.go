package cpl

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"github.com/had-nu/wardex/v2/pkg/auditlog"
)

// SegmentResult reports the verification outcome of a single chain segment
// (one session). Valid is false when any entry in the segment breaks the
// hash-link chain.
type SegmentResult struct {
	Valid   bool
	Entries int
}

// VerifyReport summarizes a streamed chain verification.
type VerifyReport struct {
	Segments []SegmentResult
	Entries  int
	Valid    bool
}

// VerifyStream verifies a chained audit log in a single streaming pass,
// without loading the whole log into memory. Optional sessionFilter limits
// the verified entries to one session (matches the pre-existing CLI filter
// semantics: exact session_id match, or substring match on the raw line).
//
// It returns a structural error for malformed JSON or an empty log; integrity
// violations are reported as Valid=false with a nil error.
func VerifyStream(r io.Reader, sessionFilter string) (VerifyReport, error) {
	report, err := streamVerify(r, sessionFilter)
	if err != nil {
		return VerifyReport{}, err
	}
	if len(report.Segments) == 0 {
		return VerifyReport{}, fmt.Errorf("cpl: empty audit log")
	}
	report.Valid = true
	for _, s := range report.Segments {
		if !s.Valid {
			report.Valid = false
			break
		}
	}
	return report, nil
}

func streamVerify(r io.Reader, sessionFilter string) (VerifyReport, error) {
	var report VerifyReport
	current := SegmentResult{Valid: true}
	var expectedPrevHash string
	index := 0

	err := auditlog.Scan(r, 0, func(line []byte) error {
		if sessionFilter != "" && !matchesSession(line, sessionFilter) {
			return nil
		}

		link, err := ParseChainLink(line)
		if err != nil {
			return fmt.Errorf("cpl: entry %d: %w", index+1, err)
		}

		if link.Hash == "" && index > 0 {
			report.Segments = append(report.Segments, current)
			current = SegmentResult{Valid: true}
			index = 0
		}

		if index == 0 {
			if link.Hash != "" {
				current.Valid = false
			}
		} else if link.Hash != expectedPrevHash {
			current.Valid = false
		}

		h := sha256.Sum256(line)
		expectedPrevHash = fmt.Sprintf("%x", h)
		index++
		report.Entries++
		return nil
	})
	if err != nil {
		return report, err
	}

	if index > 0 {
		report.Segments = append(report.Segments, current)
	}
	return report, nil
}

// matchesSession implements the legacy --session-id filter semantics:
// it matches on the exact session_id field, and falls back to a raw-line
// substring match for entries without a session_id.
func matchesSession(line []byte, sid string) bool {
	var entry struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(line, &entry); err == nil {
		if entry.SessionID == sid || (entry.SessionID == "" && bytes.Contains(line, []byte(sid))) {
			return true
		}
		return false
	}
	return bytes.Contains(line, []byte(sid))
}
