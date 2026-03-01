package cli

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/had-nu/wardex/config"
	"github.com/had-nu/wardex/pkg/accept/audit"
	"github.com/had-nu/wardex/pkg/accept/configaudit"
	"github.com/had-nu/wardex/pkg/accept/reporter"
	"github.com/had-nu/wardex/pkg/accept/signer"
	"github.com/had-nu/wardex/pkg/accept/store"
	"github.com/had-nu/wardex/pkg/accept/validator"
	"github.com/had-nu/wardex/pkg/duration"
	"github.com/had-nu/wardex/pkg/exitcodes"
	"github.com/had-nu/wardex/pkg/model"
	"github.com/spf13/cobra"
)

var (
	reqReport   string
	reqCVEs     []string
	reqAcceptBy string
	reqJustif   string
	reqExpires  string
	reqTicket   string
	reqYes      bool

	listActive  bool
	listExpired bool
	listStale   bool
	listCVE     string
	listOutput  string

	verifySince   string
	verifyBackend string

	revokeID       string
	revokeRevokeBy string
	revokeReason   string

	expiryWarnBefore string
)

func AddCommands(rootCmd *cobra.Command, configPathPtr *string) {
	acceptCmd := &cobra.Command{
		Use:   "accept",
		Short: "Manage risk acceptances for vulnerabilities blocking the release gate",
	}

	requestCmd := &cobra.Command{
		Use:   "request",
		Short: "Request a new risk acceptance",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.Load(*configPathPtr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
				os.Exit(1)
			}

			key, err := signer.ResolveSecret(*cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Secret error: %v\n", err)
				os.Exit(1)
			}

			// Validate GateReport
			blockedCVEs, reportHash, err := reporter.Read(reqReport, cfg.AcceptanceConfig.Limits.MaxReportAgeHours)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Report error: %v\n", err)
				os.Exit(1)
			}

			// In a real flow, we check if the requested CVE is in blockedCVEs
			validCVEs := make(map[string]bool)
			for _, v := range blockedCVEs {
				validCVEs[v.CVEID] = true
			}

			for _, reqCVE := range reqCVEs {
				if !validCVEs[reqCVE] {
					fmt.Fprintf(os.Stderr, "CVE %s not found in blocked report\n", reqCVE)
					os.Exit(1)
				}
			}

			// Calculate expirations
			var expiresAt time.Time
			if reqExpires != "" {
				dur, err := duration.ParseExtended(reqExpires)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Invalid expiration format %q: %v\n", reqExpires, err)
					os.Exit(1)
				}
				expiresAt = time.Now().Add(dur)
			}

			currentConfigHash, _ := configaudit.Hash(*configPathPtr)
			baseID := fmt.Sprintf("acc-%s-%d", time.Now().Format("20060102"), time.Now().Unix())

			var createdIDs []string
			for i, cve := range reqCVEs {
				id := baseID
				if len(reqCVEs) > 1 {
					id = fmt.Sprintf("%s-%d", baseID, i)
				}

				acceptance := model.Acceptance{
					ID:            id,
					CVE:           cve,
					AcceptedBy:    reqAcceptBy,
					Justification: reqJustif,
					ExpiresAt:     expiresAt,
					Ticket:        reqTicket,
					ReportHash:    reportHash,
				}

				if err := validator.ValidateBusinessRules(acceptance, cfg.AcceptanceConfig); err != nil {
					fmt.Fprintf(os.Stderr, "Validation error for %s: %v\n", cve, err)
					os.Exit(1)
				}

				_ = audit.Log("wardex-accept-audit.log", model.AuditEntry{
					Event:       "acceptance.created",
					ID:          id,
					CVEID:       cve,
					Actor:       reqAcceptBy,
					Interactive: !reqYes,
					ConfigHash:  currentConfigHash,
				})

				sig, _ := signer.Sign(acceptance, key)
				acceptance.Signature = sig

				if err := store.Append("wardex-acceptances.yaml", acceptance); err != nil {
					fmt.Fprintf(os.Stderr, "Storage error for %s: %v\n", cve, err)
					os.Exit(1)
				}

				createdIDs = append(createdIDs, id)
				fmt.Printf("Created acceptance %s for %s\n", id, cve)
			}
			fmt.Printf("\nTotal: %d acceptance(s) created.\n", len(createdIDs))
		},
	}
	requestCmd.Flags().StringVar(&reqReport, "report", "", "GateReport JSON gerado pelo wardex (obrigatório)")
	requestCmd.Flags().StringSliceVar(&reqCVEs, "cve", []string{}, "CVE ID; repetível para múltiplos CVEs")
	requestCmd.Flags().StringVar(&reqAcceptBy, "accepted-by", "", "Email do responsável (obrigatório)")
	requestCmd.Flags().StringVar(&reqJustif, "justification", "", "Justificativa substantiva (mínimo configurável)")
	requestCmd.Flags().StringVar(&reqExpires, "expires", "", "Data de expiração: ISO 8601 ou relativa (ex: 30d)")
	requestCmd.Flags().StringVar(&reqTicket, "ticket", "", "Referência externa opcional")
	requestCmd.Flags().BoolVar(&reqYes, "yes", false, "Salta confirmação interactiva")
	if err := requestCmd.MarkFlagRequired("report"); err != nil {
		panic(err)
	}
	if err := requestCmd.MarkFlagRequired("accepted-by"); err != nil {
		panic(err)
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List risk acceptances",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.Load(*configPathPtr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
				os.Exit(1)
			}

			key, err := signer.ResolveSecret(*cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Secret error: %v\n", err)
				os.Exit(1)
			}

			currentConfigHash, _ := configaudit.Hash(*configPathPtr)

			// Load checks validity under the hood
			acceptances, err := store.Load("wardex-acceptances.yaml", key, "wardex-accept-audit.log", "", currentConfigHash)
			if err != nil {
				if errors.Is(err, store.ErrTampered) {
					fmt.Fprintf(os.Stderr, "Tampered acceptance detected: %v\n", err)
					os.Exit(exitcodes.Tampered)
				}
				if errors.Is(err, store.ErrStoreInconsistent) {
					fmt.Fprintf(os.Stderr, "Store inconsistent: %v\n", err)
					os.Exit(exitcodes.StoreInconsistent)
				}
				fmt.Fprintf(os.Stderr, "Failed to load acceptances: %v\n", err)
				os.Exit(1)
			}

			// Provide table output
			// Minimal printing logic for now
			fmt.Println("ID\tCVE\tAccepted By\tExpires At\tLogic Status")
			for _, a := range acceptances {
				if listCVE != "" && a.CVE != listCVE {
					continue
				}
				// Additional filtering by active/expired/stale would go here
				fmt.Printf("%s\t%s\t%s\t%s\t[VÁLIDA]\n", a.ID, a.CVE, a.AcceptedBy, a.ExpiresAt.Format("2006-01-02"))
			}
		},
	}
	listCmd.Flags().BoolVar(&listActive, "active", false, "Apenas aceitações activas")
	listCmd.Flags().BoolVar(&listExpired, "expired", false, "Apenas aceitações expiradas")
	listCmd.Flags().BoolVar(&listStale, "stale", false, "Apenas aceitações stale (config mudou)")
	listCmd.Flags().StringVar(&listCVE, "cve", "", "Filtra por CVE ID")
	listCmd.Flags().StringVar(&listOutput, "output", "table", "table|json|csv")

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify logic integrity of risk acceptances",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.Load(*configPathPtr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
				os.Exit(1)
			}

			key, err := signer.ResolveSecret(*cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Secret error: %v\n", err)
				os.Exit(1)
			}

			currentConfigHash, _ := configaudit.Hash(*configPathPtr)

			_, err = store.Load("wardex-acceptances.yaml", key, "wardex-accept-audit.log", "", currentConfigHash)
			if err != nil {
				if errors.Is(err, store.ErrTampered) {
					fmt.Fprintf(os.Stderr, "Tampered validation check failed: %v\n", err)
					os.Exit(exitcodes.Tampered)
				}
				if errors.Is(err, store.ErrStoreInconsistent) {
					fmt.Fprintf(os.Stderr, "Store trace validation failed: %v\n", err)
					os.Exit(exitcodes.StoreInconsistent)
				}
				fmt.Fprintf(os.Stderr, "Standard validation error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("All acceptances passed integrity checks.")
			os.Exit(exitcodes.OK)
		},
	}

	verifyFwdCmd := &cobra.Command{
		Use:   "verify-forwarding",
		Short: "Verify log forwarding status",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Implementation pending for: accept verify-forwarding")
		},
	}
	verifyFwdCmd.Flags().StringVar(&verifySince, "since", "", "Período: ISO 8601 ou relativo (ex: 30d)")
	verifyFwdCmd.Flags().StringVar(&verifyBackend, "backend", "", "Backend a verificar (default: todos)")

	revokeCmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke an existing risk acceptance",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.Load(*configPathPtr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
				os.Exit(1)
			}

			key, err := signer.ResolveSecret(*cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Secret error: %v\n", err)
				os.Exit(1)
			}

			revocation := &model.RevocationRecord{
				RevokedBy: revokeRevokeBy,
				RevokedAt: time.Now(),
				Reason:    revokeReason,
			}

			if err := store.UpdateStatus("wardex-acceptances.yaml", revokeID, "revoked", revocation, key); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to revoke: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Successfully revoked acceptance %s\n", revokeID)
		},
	}
	revokeCmd.Flags().StringVar(&revokeID, "id", "", "ID da aceitação (obrigatório)")
	revokeCmd.Flags().StringVar(&revokeRevokeBy, "revoked-by", "", "Email do responsável (obrigatório)")
	revokeCmd.Flags().StringVar(&revokeReason, "reason", "", "Motivo da revogação (obrigatório)")
	if err := revokeCmd.MarkFlagRequired("id"); err != nil {
		panic(err)
	}
	if err := revokeCmd.MarkFlagRequired("revoked-by"); err != nil {
		panic(err)
	}
	if err := revokeCmd.MarkFlagRequired("reason"); err != nil {
		panic(err)
	}

	checkExpiryCmd := &cobra.Command{
		Use:   "check-expiry",
		Short: "Check for pending expirations",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.Load(*configPathPtr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
				os.Exit(1)
			}

			key, err := signer.ResolveSecret(*cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Secret error: %v\n", err)
				os.Exit(1)
			}

			currentConfigHash, _ := configaudit.Hash(*configPathPtr)
			acceptances, err := store.Load("wardex-acceptances.yaml", key, "wardex-accept-audit.log", "", currentConfigHash)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Load error: %v\n", err)
				os.Exit(1)
			}

			dur, err := duration.ParseExtended(expiryWarnBefore)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Invalid duration format %q: %v\n", expiryWarnBefore, err)
				os.Exit(1)
			}

			warnTime := time.Now().Add(dur)
			expiringCount := 0

			for _, a := range acceptances {
				if a.ExpiresAt.Before(warnTime) {
					fmt.Printf("WARNING: Acceptance %s for CVE %s expires at %v\n", a.ID, a.CVE, a.ExpiresAt.Format(time.RFC3339))
					expiringCount++
				}
			}

			if expiringCount > 0 {
				os.Exit(exitcodes.ExpiringSoon)
			}

			fmt.Println("No acceptances expiring soon.")
			os.Exit(exitcodes.OK)
		},
	}
	checkExpiryCmd.Flags().StringVar(&expiryWarnBefore, "warn-before", "72h", "Período de aviso: ex. 3d, 72h")

	acceptCmd.AddCommand(requestCmd, listCmd, verifyCmd, verifyFwdCmd, revokeCmd, checkExpiryCmd)
	rootCmd.AddCommand(acceptCmd)
}
