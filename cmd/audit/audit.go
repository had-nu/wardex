package audit

import (
	"github.com/spf13/cobra"
)

var AuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit and verify Wardex configuration provenance and log integrity",
	Long: `Commands for auditing Wardex operations, verifying configuration
provenance links, and validating audit log integrity.

Use 'wardex audit verify-link' to check config hashes against archives.
Use 'wardex audit verify-chain' to validate the audit log hash chain.`,
}

func init() {
	AuditCmd.AddCommand(VerifyLinkCmd)
	AuditCmd.AddCommand(VerifyChainCmd)
}
