// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package cli

import (
	"io"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Allow mocking in tests
	exitFunc           = os.Exit
	stderr   io.Writer = os.Stderr

	acceptCfgPath *string

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
	verifyOutput  string

	revokeID       string
	revokeRevokeBy string
	revokeReason   string

	expiryWarnBefore string

	aeCVE          string
	aeJustif       string
	aeArtefactPath string
)

// AddCommands registers all risk acceptance subcommands (request, list,
// verify, revoke, active-exploit) on the given cobra root command.
func AddCommands(rootCmd *cobra.Command, configPathPtr *string) {
	acceptCfgPath = configPathPtr
	acceptCmd := &cobra.Command{
		Use:   "accept",
		Short: "Manage risk acceptances for vulnerabilities blocking the release gate",
	}

	requestCmd := &cobra.Command{
		Use:   "request",
		Short: "Request a new risk acceptance",
		Run:   runRequest,
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
		Run:   runList,
	}
	listCmd.Flags().BoolVar(&listActive, "active", false, "Apenas aceitações activas")
	listCmd.Flags().BoolVar(&listExpired, "expired", false, "Apenas aceitações expiradas")
	listCmd.Flags().BoolVar(&listStale, "stale", false, "Apenas aceitações stale (config mudou)")
	listCmd.Flags().StringVar(&listCVE, "cve", "", "Filtra por CVE ID")
	listCmd.Flags().StringVar(&listOutput, "output", "table", "table|json|csv")

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify logic integrity of risk acceptances",
		Run:   runVerify,
	}

	verifyCmd.Flags().StringVar(&verifyOutput, "output", "", "Path to save verification report as JSON artefact")

	verifyFwdCmd := &cobra.Command{
		Use:   "verify-forwarding",
		Short: "Verify log forwarding status",
		Run:   runVerifyForwarding,
	}
	verifyFwdCmd.Flags().StringVar(&verifySince, "since", "", "Período: ISO 8601 ou relativo (ex: 30d)")
	verifyFwdCmd.Flags().StringVar(&verifyBackend, "backend", "", "Backend a verificar (default: todos)")

	revokeCmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke an existing risk acceptance",
		Run:   runRevoke,
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
		Run:   runCheckExpiry,
	}
	checkExpiryCmd.Flags().StringVar(&expiryWarnBefore, "warn-before", "72h", "Período de aviso: ex. 3d, 72h")

	activeExploitCmd := &cobra.Command{
		Use:   "active-exploit",
		Short: "Acknowledge an active exploitation for compliance trail",
		Run:   runActiveExploit,
	}

	activeExploitCmd.Flags().StringVar(&aeCVE, "cve", "", "CVE ID (required)")
	activeExploitCmd.Flags().StringVar(&aeJustif, "justification", "", "Substantive justification (minimum 80 characters)")
	activeExploitCmd.Flags().StringVar(&aeArtefactPath, "art14-artefact", "", "Path to the Article 14 notification artefact")

	_ = activeExploitCmd.MarkFlagRequired("cve")
	_ = activeExploitCmd.MarkFlagRequired("justification")

	acceptCmd.AddCommand(requestCmd, listCmd, verifyCmd, verifyFwdCmd, revokeCmd, checkExpiryCmd, activeExploitCmd)
	rootCmd.AddCommand(acceptCmd)
}
