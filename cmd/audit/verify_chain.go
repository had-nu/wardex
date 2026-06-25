package audit

import (
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/internal/cpl"
	"github.com/spf13/cobra"
)

var VerifyChainCmd = &cobra.Command{
	Use:   "verify-chain",
	Short: "Verify the integrity of the audit log hash chain",
	Long: `Verify that each entry in the audit log correctly references the hash
of the previous entry, ensuring no retroactive tampering has occurred.

The first entry must have prev_hash set to "genesis". Each subsequent
entry must reference the SHA-256 digest of the preceding line.

Returns exit code 0 if the chain is intact, 1 if tampering is detected,
and 2 on operational errors.`,
	RunE: runVerifyChain,
}

func init() {
	VerifyChainCmd.Flags().StringVar(&auditLogPath, "audit-log", "", "Path to the wardex audit log JSONL file (required)")
	_ = VerifyChainCmd.MarkFlagRequired("audit-log")
}

func runVerifyChain(cmd *cobra.Command, args []string) error {
	logData, err := os.ReadFile(auditLogPath) // #nosec G304 — user-provided path via --audit-log flag
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: reading audit log: %v\n", err)
		os.Exit(2)
		return nil
	}

	ok, err := cpl.VerifyChain(logData)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: verify-chain failed: %v\n", err)
		os.Exit(2)
		return nil
	}

	if !ok {
		fmt.Fprintln(cmd.ErrOrStderr(), "Audit log hash chain: TAMPERED")
		os.Exit(1)
		return nil
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Audit log hash chain: INTACT")
	return nil
}
