package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/had-nu/wardex/v2/internal/cpl"
	"github.com/had-nu/wardex/v2/internal/notification"
	"github.com/spf13/cobra"
)

var (
	auditLogPath    string
	configArchive   string
	singleConfig    string
	webhookURL      string
	webhookTokenEnv string
)

var VerifyLinkCmd = &cobra.Command{
	Use:   "verify-link",
	Short: "Verify config hashes in an audit log against archived configurations",
	Long: `Verify that the config_hash entries in a wardex audit log match the
corresponding archived configuration files.

Returns exit code 0 if all entries match, 1 if any MISMATCH or MISSING
entries are found, and 2 on operational errors.

Examples:
  wardex audit verify-link --audit-log wardex-audit.log --config-archive ./configs/
  wardex audit verify-link --audit-log wardex-audit.log --config config.yaml`,
	RunE: runVerifyLink,
}

func init() {
	VerifyLinkCmd.Flags().StringVar(&auditLogPath, "audit-log", "", "Path to the wardex audit log JSONL file (required)")
	VerifyLinkCmd.Flags().StringVar(&configArchive, "config-archive", "", "Directory of archived configuration files")
	VerifyLinkCmd.Flags().StringVar(&singleConfig, "config", "", "Single configuration file to verify against all entries")
	VerifyLinkCmd.Flags().StringVar(&webhookURL, "webhook-url", "", "URL for divergence notification webhook (fire-and-forget)")
	VerifyLinkCmd.Flags().StringVar(&webhookTokenEnv, "webhook-token-env", "", "Environment variable name containing the webhook Bearer token")
	_ = VerifyLinkCmd.MarkFlagRequired("audit-log")
	VerifyLinkCmd.MarkFlagsOneRequired("config-archive", "config")
}

func runVerifyLink(cmd *cobra.Command, args []string) error {
	logData, err := os.ReadFile(auditLogPath) // #nosec G304 — user-provided path via --audit-log flag
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: reading audit log: %v\n", err)
		os.Exit(2)
		return nil
	}

	var results []cpl.LinkResult
	if singleConfig != "" {
		results, err = cpl.VerifyLinkSingle(logData, singleConfig)
	} else {
		results, err = cpl.VerifyLink(logData, configArchive)
	}
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: verify-link failed: %v\n", err)
		os.Exit(2)
		return nil
	}

	summary := struct {
		Total   int `json:"total"`
		OK      int `json:"ok"`
		Mismatch int `json:"mismatch"`
		Missing int `json:"missing"`
	}{Total: len(results)}

	for _, r := range results {
		switch r.Status {
		case cpl.StatusOK:
			summary.OK++
		case cpl.StatusMismatch:
			summary.Mismatch++
		case cpl.StatusMissing:
			summary.Missing++
		}
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	_ = enc.Encode(struct {
		Summary interface{}    `json:"summary"`
		Results []cpl.LinkResult `json:"results"`
	}{Summary: summary, Results: results})

	if summary.Mismatch > 0 || summary.Missing > 0 {
		if webhookURL != "" {
			dispatchNotification(auditLogPath, summary.Total, summary.OK, summary.Mismatch, summary.Missing, results)
		}
		os.Exit(1)
	}

	return nil
}

func dispatchNotification(auditLog string, total, ok, mismatch, missing int, results []cpl.LinkResult) {
	payload := notification.DivergencePayload{
		Source:    "wardex",
		EventType: "cpl.verify_link.mismatch",
		AuditLog:  auditLog,
		Summary: notification.Summary{
			TotalEntries: total,
			OK:           ok,
			Mismatch:     mismatch,
			Missing:      missing,
		},
	}

	for _, r := range results {
		if r.Status != cpl.StatusOK {
			payload.Divergences = append(payload.Divergences, notification.Divergence{
				EntryTimestamp: r.EntryTimestamp,
				Status:         string(r.Status),
				RecordedHash:   r.RecordedHash,
				ComputedHash:   r.ComputedHash,
				ConfigFile:     r.ConfigFile,
			})
		}
	}

	token := ""
	if webhookTokenEnv != "" {
		token = os.Getenv(webhookTokenEnv)
	}

	cfg := notification.WebhookConfig{
		URL:            webhookURL,
		Token:          token,
		TimeoutSeconds: 5,
		Headers: map[string]string{
			"X-Audit-Log": filepath.Base(auditLog),
		},
	}

	if err := notification.Send(cfg, payload); err != nil {
		fmt.Fprintf(os.Stderr, "[wardex] notification: webhook failed: %v\n", err)
	}
}
