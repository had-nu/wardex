package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/had-nu/wardex/v2/internal/cpl"
	"github.com/spf13/cobra"
)

var (
	sessionID string
)

var VerifyChainCmd = &cobra.Command{
	Use:   "verify-chain",
	Short: "Verify the integrity of the audit log hash chain",
	Long: `Verify that each entry in the audit log correctly references the hash
of the previous entry, ensuring no retroactive tampering has occurred.

The first entry must have prev_hash set to "genesis". Each subsequent
entry must reference the SHA-256 digest of the preceding line.

Multiple sessions (each starting with prev_hash "genesis") are detected
and verified as independent segments.

Returns exit code 0 if the chain is intact, 1 if tampering is detected,
and 2 on operational errors.`,
	RunE: runVerifyChain,
}

func init() {
	VerifyChainCmd.Flags().StringVar(&auditLogPath, "audit-log", "", "Path to the wardex audit log JSONL file (required)")
	VerifyChainCmd.Flags().StringVar(&sessionID, "session-id", "", "Filter entries by session ID (optional)")
	_ = VerifyChainCmd.MarkFlagRequired("audit-log")
}

func runVerifyChain(cmd *cobra.Command, args []string) error {
	logData, err := os.ReadFile(auditLogPath) // #nosec G304 — user-provided path via --audit-log flag
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: reading audit log: %v\n", err)
		os.Exit(2)
		return nil
	}

	// If session-id filter is provided, extract only matching entries
	if sessionID != "" {
		logData = filterBySessionID(logData, sessionID)
	}

	// Split into segments at genesis markers
	segments := splitSegments(logData)
	if len(segments) == 0 {
		fmt.Fprintln(cmd.ErrOrStderr(), "Audit log hash chain: EMPTY")
		os.Exit(2)
		return nil
	}

	allValid := true
	for i, seg := range segments {
		ok, err := cpl.VerifyChain(seg)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "  Segment %d: ERROR - %v\n", i+1, err)
			allValid = false
			continue
		}
		if !ok {
			fmt.Fprintf(cmd.ErrOrStderr(), "  Segment %d: TAMPERED\n", i+1)
			allValid = false
		}
	}

	totalEntries := countEntries(logData)

	if !allValid {
		fmt.Fprintf(cmd.ErrOrStderr(), "\nAudit log hash chain: TAMPERED (%d segments, %d entries)\n", len(segments), totalEntries)
		os.Exit(1)
		return nil
	}

	if len(segments) == 1 {
		fmt.Fprintf(cmd.OutOrStdout(), "Audit log hash chain: INTACT (%d entries)\n", totalEntries)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Audit log hash chain: INTACT (%d segments, %d entries)\n", len(segments), totalEntries)
	}
	return nil
}

// splitSegments splits a multi-session audit log into independent chain segments.
// Each segment starts where prev_hash is "genesis".
func splitSegments(data []byte) [][]byte {
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	var segments [][]byte
	var current []byte

	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var entry struct {
			PrevHash string `json:"prev_hash"`
		}
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}

		if entry.PrevHash == "genesis" && len(current) > 0 {
			segments = append(segments, current)
			current = nil
		}
		current = append(current, line...)
		current = append(current, '\n')
	}

	if len(current) > 0 {
		segments = append(segments, current)
	}
	return segments
}

// filterBySessionID filters log entries by a session_id field.
func filterBySessionID(data []byte, sid string) []byte {
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	var filtered []byte

	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var entry struct {
			SessionID string `json:"session_id"`
		}
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}

		if entry.SessionID == sid || (entry.SessionID == "" && strings.Contains(string(line), sid)) {
			filtered = append(filtered, line...)
			filtered = append(filtered, '\n')
		}
	}
	return filtered
}

func countEntries(data []byte) int {
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	count := 0
	for _, line := range lines {
		if len(bytes.TrimSpace(line)) > 0 {
			count++
		}
	}
	return count
}
