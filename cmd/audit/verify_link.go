package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/had-nu/wardex/v2/internal/cpl"
	"github.com/had-nu/wardex/v2/internal/notification"
	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/spf13/cobra"
)

var (
	auditLogPath          string
	configArchive         string
	singleConfig          string
	webhookURL            string
	webhookTokenEnv       string
	expectedSchemaVersion int
)

var VerifyLinkCmd = &cobra.Command{
	Use:   "verify-link",
	Short: "Verify config hashes in an audit log against archived configurations",
	Long: `Verify that the config_hash entries in a wardex audit log match the
corresponding archived configuration files.

When --expected-schema-version is set, entries whose recorded
cpl_schema_version (or legacy schema v1) differs are reported as
SCHEMA_VERSION divergences, proving the sealed decisions were made against
the intended configuration generation.

Returns exit code 0 if all entries match, 1 if any MISMATCH, MISSING or
SCHEMA_VERSION entries are found, and 2 on operational errors.

Examples:
  wardex audit verify-link --audit-log wardex-audit.log --config-archive ./configs/
  wardex audit verify-link --audit-log wardex-audit.log --config config.yaml --expected-schema-version 2`,
	RunE: runVerifyLink,
}

func init() {
	VerifyLinkCmd.Flags().StringVar(&auditLogPath, "audit-log", "", "Path to the wardex audit log JSONL file (required)")
	VerifyLinkCmd.Flags().StringVar(&configArchive, "config-archive", "", "Directory of archived configuration files")
	VerifyLinkCmd.Flags().StringVar(&singleConfig, "config", "", "Single configuration file to verify against all entries")
	VerifyLinkCmd.Flags().IntVar(&expectedSchemaVersion, "expected-schema-version", 0, "Expected CPL config schema version (legacy entries count as v1)")
	VerifyLinkCmd.Flags().StringVar(&webhookURL, "webhook-url", "", "URL for divergence notification webhook (fire-and-forget)")
	VerifyLinkCmd.Flags().StringVar(&webhookTokenEnv, "webhook-token-env", "", "Environment variable name containing the webhook Bearer token")
	_ = VerifyLinkCmd.MarkFlagRequired("audit-log")
	VerifyLinkCmd.MarkFlagsOneRequired("config-archive", "config")
}

func runVerifyLink(cmd *cobra.Command, args []string) error {
	u := beginAuditUI(cmd, "verify-link", auditLogPath)
	u.report(1, "Reading audit log", "RUNNING", auditLogPath)
	logData, err := cli.SafeReadFile(auditLogPath)
	if err != nil {
		u.report(1, "Reading audit log", "FAILED", err.Error())
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: reading audit log: %v\n", err)
		os.Exit(2)
		return nil
	}
	u.report(1, "Reading audit log", "DONE", fmt.Sprintf("%d bytes", len(logData)))

	u.report(2, "Verifying config links", "RUNNING", "")
	var results []cpl.LinkResult
	if singleConfig != "" {
		results, err = cpl.VerifyLinkSingleWithSchemaVersion(logData, singleConfig, expectedSchemaVersion)
	} else {
		results, err = cpl.VerifyLinkWithSchemaVersion(logData, configArchive, expectedSchemaVersion)
	}
	if err != nil {
		u.report(2, "Verifying config links", "FAILED", err.Error())
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: verify-link failed: %v\n", err)
		os.Exit(2)
		return nil
	}
	u.report(2, "Verifying config links", "DONE", fmt.Sprintf("%d result(s)", len(results)))

	summary := struct {
		Total    int `json:"total"`
		OK       int `json:"ok"`
		Mismatch int `json:"mismatch"`
		Missing  int `json:"missing"`
		Schema   int `json:"schema_version"`
	}{Total: len(results)}
	for _, r := range results {
		switch r.Status {
		case cpl.StatusOK:
			summary.OK++
		case cpl.StatusMismatch:
			summary.Mismatch++
		case cpl.StatusMissing:
			summary.Missing++
		case cpl.StatusSchemaVersion:
			summary.Schema++
		}
	}

	u.report(3, "Preparing link report", "RUNNING", "")
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	_ = enc.Encode(struct {
		Summary any              `json:"summary"`
		Results []cpl.LinkResult `json:"results"`
	}{Summary: summary, Results: results})
	u.report(3, "Preparing link report", "DONE", "report emitted")
	if u.progress.Enabled() {
		u.render(buildLinkVerifyDashboard(auditLogPath, summary.Total, summary.OK, summary.Mismatch, summary.Missing, summary.Schema, results))
	}

	if summary.Mismatch > 0 || summary.Missing > 0 || summary.Schema > 0 {
		if webhookURL != "" {
			dispatchNotification(cmd.Context(), auditLogPath, summary.Total, summary.OK, summary.Mismatch, summary.Missing, summary.Schema, results)
		}
		os.Exit(1)
	}
	return nil
}

func dispatchNotification(ctx context.Context, auditLog string, total, ok, mismatch, missing, schema int, results []cpl.LinkResult) {
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

	if err := notification.Send(ctx, cfg, payload); err != nil {
		fmt.Fprintf(os.Stderr, "[wardex] notification: webhook failed: %v\n", err)
	}
}
