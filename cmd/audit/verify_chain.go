package audit

import (
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/internal/cpl"
	"github.com/had-nu/wardex/v2/pkg/cli"
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

Each segment starts with a genesis entry: no previous link in the canonical
format (absent previous_entry_hash), or prev_hash set to "genesis" in the
legacy format. Each subsequent entry must reference the SHA-256 digest of
the preceding line.

Multiple sessions (each starting with a genesis entry) are detected and
verified as independent segments.

The log is streamed line by line, so arbitrarily large logs verify without
loading into memory.

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
	f, err := cli.SafeOpenFile(auditLogPath)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: reading audit log: %v\n", err)
		os.Exit(2)
		return nil
	}
	defer func() { _ = f.Close() }()

	report, err := cpl.VerifyStream(f, sessionID)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Audit log hash chain: OPERATIONAL ERROR - %v\n", err)
		os.Exit(2)
		return nil
	}

	for i, seg := range report.Segments {
		if !seg.Valid {
			fmt.Fprintf(cmd.ErrOrStderr(), "  Segment %d: TAMPERED\n", i+1)
		}
	}

	if !report.Valid {
		fmt.Fprintf(cmd.ErrOrStderr(), "\nAudit log hash chain: TAMPERED (%d segments, %d entries)\n", len(report.Segments), report.Entries)
		os.Exit(1)
		return nil
	}

	if len(report.Segments) == 1 {
		fmt.Fprintf(cmd.OutOrStdout(), "Audit log hash chain: INTACT (%d entries)\n", report.Entries)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Audit log hash chain: INTACT (%d segments, %d entries)\n", len(report.Segments), report.Entries)
	}
	return nil
}
