package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"time"

	"github.com/had-nu/wardex/internal/policy"
	"github.com/had-nu/wardex/pkg/exitcodes"
	"github.com/had-nu/wardex/pkg/utils"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// policyCmd is the root of the `wardex policy` subcommand tree.
var PolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage compliance policy files",
	Long: `Create, validate, and inspect Wardex compliance policy files.

Policy files are YAML documents organised by framework and domain:

  frameworks/
    iso27001/
      technological_controls.yml
      organizational_controls.yml
    nist_csf/
      identify.yml
      protect.yml

Use 'wardex policy validate' to check all files in a framework directory.
Use 'wardex policy add' to add or update a control without editing YAML manually.
Use 'wardex policy list' to inspect control statuses at a glance.`,
}

// ── validate ────────────────────────────────────────────────────────────────

var policyValidateCmd = &cobra.Command{
	Use:   "validate <framework-dir>",
	Short: "Validate all domain YAML files in a framework directory",
	Args:  cobra.ExactArgs(1),
	RunE:  runPolicyValidate,
}

func runPolicyValidate(cmd *cobra.Command, args []string) error {
	domains, err := policy.LoadFramework(args[0])
	if err != nil {
		return err
	}

	total := 0
	for _, d := range domains {
		total += len(d.Controls)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(),
		"✓ %d domain file(s), %d control(s) — all valid in %q\n",
		len(domains), total, args[0],
	)
	return nil
}

// ── list ─────────────────────────────────────────────────────────────────────

var policyListCmd = &cobra.Command{
	Use:   "list <framework-dir>",
	Short: "List all controls and their compliance status",
	Args:  cobra.ExactArgs(1),
	RunE:  runPolicyList,
}

func runPolicyList(cmd *cobra.Command, args []string) error {
	domains, err := policy.LoadFramework(args[0])
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tTITLE\tSTATUS\tOWNER\tLAST ASSESSED")
	_, _ = fmt.Fprintln(w, "--\t-----\t------\t-----\t-------------")

	for _, d := range domains {
		for _, c := range d.Controls {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				c.ID, c.Title, c.Status, c.Owner, c.LastAssessed,
			)
		}
	}
	return w.Flush()
}
// ── check-expiry ─────────────────────────────────────────────────────────────

var policyCheckExpiryCmd = &cobra.Command{
	Use:   "check-expiry <framework-dir>",
	Short: "Check for expired policy exceptions in a framework directory",
	Args:  cobra.ExactArgs(1),
	RunE:  runPolicyCheckExpiry,
}

func runPolicyCheckExpiry(cmd *cobra.Command, args []string) error {
	domains, err := policy.LoadFramework(args[0])
	if err != nil {
		return err
	}

	now := time.Now()
	expiredCount := 0

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tDOMAIN\tEXPIRY\tREASON")
	_, _ = fmt.Fprintln(w, "--\t------\t------\t------")

	for _, d := range domains {
		for _, c := range d.Controls {
			for _, e := range c.Exceptions {
				if e.Expiry == "" {
					continue
				}
				expiry, err := time.Parse("2006-01-02", e.Expiry)
				if err != nil {
					continue
				}
				if expiry.Before(now) {
					_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
						c.ID, d.Domain, e.Expiry, e.Reason,
					)
					expiredCount++
				}
			}
		}
	}

	if expiredCount > 0 {
		_ = w.Flush()
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\n[FAIL] Found %d expired exception(s) in %q\n", expiredCount, args[0])
		os.Exit(exitcodes.ComplianceFail)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "✓ No expired exceptions found in %q\n", args[0])
	return nil
}

// ── add ──────────────────────────────────────────────────────────────────────

var policyAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add or update a control in a domain YAML file",
	Long: `Add a new control or update an existing one (matched by --id) in a
domain YAML file. If the file does not exist it will be created.

Example:
  wardex policy add \
    --file frameworks/iso27001/technological_controls.yml \
    --id A.8.5 \
    --title "Secure authentication" \
    --status partial \
    --owner "Security Team" \
    --note "MFA enforced; hardware tokens pending rollout"`,
	RunE: runPolicyAdd,
}

func init() {
	policyAddCmd.Flags().String("file", "", "path to domain YAML file (required)")
	policyAddCmd.Flags().String("id", "", "control ID, e.g. A.8.1 (required)")
	policyAddCmd.Flags().String("title", "", "human-readable control title (required)")
	policyAddCmd.Flags().String("status", "non_compliant",
		"compliance status: compliant | partial | non_compliant | not_applicable")
	policyAddCmd.Flags().String("owner", "", "team or role responsible for this control")
	policyAddCmd.Flags().String("note", "", "short implementation note")

	_ = policyAddCmd.MarkFlagRequired("title")

	PolicyCmd.AddCommand(policyValidateCmd, policyListCmd, policyAddCmd, policyCheckExpiryCmd)
	// wired into root inside main.go
}

func runPolicyAdd(cmd *cobra.Command, args []string) error {
	file, _ := cmd.Flags().GetString("file")
	id, _ := cmd.Flags().GetString("id")
	title, _ := cmd.Flags().GetString("title")
	status, _ := cmd.Flags().GetString("status")
	owner, _ := cmd.Flags().GetString("owner")
	note, _ := cmd.Flags().GetString("note")

	// Resolve and clean the path before any I/O.
	abs, err := utils.SafePath(".", filepath.Clean(file))
	if err != nil {
		return fmt.Errorf("policy add: resolve path: %w", err)
	}

	var d policy.DomainFile

	// Load existing file if it exists; silently init a new struct otherwise.
	data, err := os.ReadFile(abs) // #nosec G304
	switch {
	case err == nil:
		if err := yaml.Unmarshal(data, &d); err != nil {
			return fmt.Errorf("policy add: parse existing file: %w", err)
		}
	case os.IsNotExist(err):
		// New file: the caller is responsible for setting framework/domain
		// metadata separately (or we could add --framework / --domain flags
		// to this command in a future iteration).
	default:
		return fmt.Errorf("policy add: read: %w", err)
	}

	newControl := policy.Control{
		ID:                 id,
		Title:              title,
		Status:             policy.Status(status),
		Owner:              owner,
		ImplementationNote: note,
		EvidenceRefs:       []string{},
		Exceptions:         []policy.Exception{},
	}

	// Upsert: replace in-place if control ID already exists.
	updated := false
	for i, c := range d.Controls {
		if c.ID == id {
			d.Controls[i] = newControl
			updated = true
			break
		}
	}
	if !updated {
		d.Controls = append(d.Controls, newControl)
	}

	out, err := yaml.Marshal(&d)
	if err != nil {
		return fmt.Errorf("policy add: marshal: %w", err)
	}

	// 0o600: policy files contain compliance state — no need for group/other read.
	if err := os.WriteFile(abs, out, 0o600); err != nil {
		return fmt.Errorf("policy add: write: %w", err)
	}

	verb := "Added"
	if updated {
		verb = "Updated"
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s control %q in %q\n", verb, id, file)
	return nil
}
