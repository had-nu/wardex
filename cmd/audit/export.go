// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package audit

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/had-nu/wardex/v2/pkg/auditlog"
	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/exitcodes"
	"github.com/spf13/cobra"
)

var (
	exportAuditLog string
	exportFormat   string
	exportLimit    int
	exportCursor   string
	exportTail     bool
)

var ExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export audit log entries with cursor pagination (SIEM)",
	Long: `Stream audit log entries in bounded pages for SIEM ingestion.

Semantics:
  --limit N   deliver at most N entries per page (LIMIT+1 internally);
              an extra entry is consumed to set has_more without buffering.
  --cursor    resume AFTER the entry whose chain hash equals the cursor.
              The next entry must chain to the cursor via previous_entry_hash,
              otherwise the export fails as tampered.
  --tail      deliver the trailing N entries (newest) instead of the leading
              ones; the returned cursor lets you poll for newer entries.

Pagination metadata is written to stderr as x-key=value lines:
  x-wardex-entries=<n>
  x-wardex-next-cursor=<sha256>
  x-wardex-has-more=<true|false>

Examples:
  wardex audit export --audit-log wardex-gate-audit.log --format jsonl --limit 500
  wardex audit export --audit-log wardex-gate-audit.log --cursor <sha256> --limit 500
  wardex audit export --audit-log wardex-gate-audit.log --format csv --tail --limit 100

Exit codes:
   0 — export complete
   1 — operational error (read failure, tampered resume, cursor not found)`,
	Args: cobra.NoArgs,
	RunE: runExport,
}

func init() {
	ExportCmd.Flags().StringVar(&exportAuditLog, "audit-log", "", "Path to the wardex audit log JSONL file (required)")
	ExportCmd.Flags().StringVar(&exportFormat, "format", "jsonl", "Output format: jsonl|csv")
	ExportCmd.Flags().IntVar(&exportLimit, "limit", 100, "Page size (delivered entries per page)")
	ExportCmd.Flags().StringVar(&exportCursor, "cursor", "", "SHA-256 chain cursor; resume after this entry")
	ExportCmd.Flags().BoolVar(&exportTail, "tail", false, "Deliver the trailing entries instead of the leading ones")
	_ = ExportCmd.MarkFlagRequired("audit-log")
}

func runExport(cmd *cobra.Command, _ []string) error {
	f, err := cli.SafeOpenFile(exportAuditLog)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: open audit log: %v\n", err)
		os.Exit(exitcodes.GenericError)
		return nil
	}
	defer func() { _ = f.Close() }()

	format := strings.ToLower(exportFormat)
	if format != "jsonl" && format != "csv" {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: unsupported format %q (use jsonl|csv)\n", exportFormat)
		os.Exit(exitcodes.GenericError)
		return nil
	}

	res, err := auditlog.Export(f, auditlog.ExportOptions{
		Limit:  exportLimit,
		Cursor: exportCursor,
		Tail:   exportTail,
	})
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: export: %v\n", err)
		os.Exit(exitcodes.GenericError)
		return nil
	}

	out := cmd.OutOrStdout()
	if format == "csv" {
		if err := writeCSV(out, res.Entries); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: write csv: %v\n", err)
			os.Exit(exitcodes.GenericError)
			return nil
		}
	} else {
		for _, e := range res.Entries {
			if _, err := out.Write(append(append([]byte(nil), e.Raw...), '\n')); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Error: write export: %v\n", err)
				os.Exit(exitcodes.GenericError)
				return nil
			}
		}
	}

	errW := cmd.ErrOrStderr()
	fmt.Fprintf(errW, "x-wardex-entries=%d\n", len(res.Entries))
	fmt.Fprintf(errW, "x-wardex-has-more=%t\n", res.HasMore)
	fmt.Fprintf(errW, "x-wardex-next-cursor=%s\n", res.NextCursor)
	return nil
}

// csvColumns is the fixed CSV export schema. The raw value bytes of each known
// field are emitted; JSON strings are unquoted. Unknown record fields are
// dropped; the raw JSONL export remains lossless.
var csvColumns = []string{"ts", "event", "status", "risk", "config_hash", "previous_entry_hash", "release_version", "policy_ref", "evidence_hash", "detail"}

func writeCSV(w io.Writer, entries []auditlog.ExportEntry) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvColumns); err != nil {
		return err
	}
	for _, e := range entries {
		var rec map[string]json.RawMessage
		if err := json.Unmarshal(e.Raw, &rec); err != nil {
			return err
		}
		row := make([]string, len(csvColumns))
		for i, col := range csvColumns {
			raw, ok := rec[col]
			if !ok {
				row[i] = ""
				continue
			}
			row[i] = strings.Trim(string(raw), `"`)
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
