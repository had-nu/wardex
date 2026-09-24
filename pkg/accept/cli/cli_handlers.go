// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/accept"
	"github.com/had-nu/wardex/v2/pkg/art14"
	filecli "github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/duration"
	"github.com/had-nu/wardex/v2/pkg/exitcodes"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

func runVerify(cmd *cobra.Command, args []string) {
	u := beginAcceptUI(cmd, "verify", *acceptCfgPath)
	u.report(1, "Loading acceptance configuration", "RUNNING", *acceptCfgPath)
	cfg, err := config.Load(*acceptCfgPath)
	if err != nil {
		u.report(1, "Loading acceptance configuration", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "Error loading config: %v\n", err)
		exitFunc(1)
	}

	u.report(1, "Loading acceptance configuration", "DONE", *acceptCfgPath)
	u.report(2, "Resolving acceptance secret", "RUNNING", "environment")
	key, err := accept.ResolveSecret(*cfg)
	if err != nil {
		u.report(2, "Resolving acceptance secret", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "Secret error: %v\n", err)
		exitFunc(1)
	}
	u.report(2, "Resolving acceptance secret", "DONE", "secret resolved")

	currentConfigHash, _ := accept.ConfigHash(*acceptCfgPath)

	u.report(3, "Verifying acceptance store", "RUNNING", "wardex-acceptances.yaml")
	acceptances, err := accept.Load("wardex-acceptances.yaml", key, "wardex-accept-audit.log", "", currentConfigHash, u.stderr)
	if err != nil {
		u.report(3, "Verifying acceptance store", "FAILED", err.Error())
		if errors.Is(err, accept.ErrTampered) {
			fmt.Fprintf(u.stderr, "Tampered validation check failed: %v\n", err)
			exitFunc(exitcodes.IntegrityFailure)
		}
		if errors.Is(err, accept.ErrStoreInconsistent) {
			fmt.Fprintf(u.stderr, "Store trace validation failed: %v\n", err)
			exitFunc(exitcodes.StoreInconsistent)
		}
		fmt.Fprintf(u.stderr, "Standard validation error: %v\n", err)
		exitFunc(1)
	}
	u.report(3, "Verifying acceptance store", "DONE", fmt.Sprintf("%d acceptance(s)", len(acceptances)))

	acceptPrint(u, "All acceptances passed integrity checks.\n")

	if verifyOutput != "" {
		u.report(4, "Writing verification report", "RUNNING", verifyOutput)
		rep := struct {
			GeneratedAt string             `json:"generated_at"`
			ConfigHash  string             `json:"config_hash"`
			Status      string             `json:"status"`
			Total       int                `json:"total_acceptances"`
			Acceptances []model.Acceptance `json:"acceptances"`
		}{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			ConfigHash:  currentConfigHash,
			Status:      "PASS",
			Total:       len(acceptances),
			Acceptances: acceptances,
		}
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			u.report(4, "Writing verification report", "FAILED", err.Error())
			fmt.Fprintf(u.stderr, "Error generating verification report: %v\n", err)
			exitFunc(1)
		}
		if err := filecli.SafeWriteFile(verifyOutput, data); err != nil {
			u.report(4, "Writing verification report", "FAILED", err.Error())
			fmt.Fprintf(u.stderr, "Error writing verification report: %v\n", err)
			exitFunc(1)
		}
		u.report(4, "Writing verification report", "DONE", verifyOutput)
		acceptPrint(u, "Verification report saved to: %s\n", verifyOutput)
	} else {
		u.report(4, "Writing verification report", "SKIPPED", "not requested")
	}

	if u.dashboardEnabled() {
		u.render(buildAcceptVerifyDashboard(len(acceptances), currentConfigHash, verifyOutput))
	}
	exitFunc(exitcodes.OK)
}

func runVerifyForwarding(cmd *cobra.Command, args []string) {
	logPath := "wardex-accept-audit.log"
	u := beginAcceptUI(cmd, "verify-forwarding", logPath)
	u.report(1, "Checking forwarding audit log", "RUNNING", logPath)
	info, err := os.Stat(logPath)
	if os.IsNotExist(err) {
		u.report(1, "Checking forwarding audit log", "SKIPPED", "log not found")
		u.render(buildAcceptForwardingUnavailableDashboard(logPath))
		fmt.Fprintf(u.stderr, "[WARN] Audit log '%s' not found. No events to forward.\n", logPath)
		exitFunc(0)
	}
	if err != nil {
		u.report(1, "Checking forwarding audit log", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "[FAIL] Cannot access audit log: %v\n", err)
		exitFunc(1)
	}
	u.report(1, "Checking forwarding audit log", "DONE", fmt.Sprintf("%d bytes", info.Size()))

	if verifyBackend != "" {
		u.report(2, "Verifying SIEM backend", "RUNNING", "configured backend")
		acceptPrint(u, "[INFO] Verifying reachability of SIEM backend: %s\n", safeBackendLabel(verifyBackend))

		timeout := 3 * time.Second

		if strings.HasPrefix(verifyBackend, "http://") || strings.HasPrefix(verifyBackend, "https://") {
			client := &http.Client{Timeout: timeout}
			resp, err := client.Get(verifyBackend)
			if err != nil {
				u.report(2, "Verifying SIEM backend", "FAILED", safeBackendError(err, verifyBackend))
				fmt.Fprintf(u.stderr, "[FAIL] Failed to connect to HTTP backend %s: %s\n", safeBackendLabel(verifyBackend), safeBackendError(err, verifyBackend))
				exitFunc(1)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode >= 500 {
				u.report(2, "Verifying SIEM backend", "FAILED", fmt.Sprintf("HTTP %d", resp.StatusCode))
				fmt.Fprintf(u.stderr, "[FAIL] HTTP backend returned server error %d\n", resp.StatusCode)
				exitFunc(1)
			}
			acceptPrint(u, "[PASS] HTTP Backend '%s' is reachable (Status: %d).\n", safeBackendLabel(verifyBackend), resp.StatusCode)
		} else {
			network := "tcp"
			address := verifyBackend
			if strings.Contains(verifyBackend, "://") {
				parts := strings.SplitN(verifyBackend, "://", 2)
				network = parts[0]
				address = parts[1]
			}

			conn, err := net.DialTimeout(network, address, timeout)
			if err != nil {
				u.report(2, "Verifying SIEM backend", "FAILED", safeBackendError(err, verifyBackend))
				fmt.Fprintf(u.stderr, "[FAIL] Failed to dial %s backend at %s: %s\n", strings.ToUpper(network), safeBackendLabel(verifyBackend), safeBackendError(err, verifyBackend))
				exitFunc(1)
			}
			_ = conn.Close()
			acceptPrint(u, "[PASS] %s Backend '%s' is reachable and accepting connections.\n", strings.ToUpper(network), safeBackendLabel(verifyBackend))
		}
		u.report(2, "Verifying SIEM backend", "DONE", "backend reachable")
	} else {
		u.report(2, "Verifying SIEM backend", "SKIPPED", "no backend configured")
		acceptPrint(u, "[INFO] No external backend specified. Verifying local log integrity for forwarding agent.\n")
	}

	u.report(3, "Reading forwarding audit log", "RUNNING", logPath)
	acceptPrint(u, "[PASS] Found audit log: %s (%d bytes)\n", logPath, info.Size())

	file, err := os.Open(logPath)
	if err != nil {
		u.report(3, "Reading forwarding audit log", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "[FAIL] Cannot open audit log for parsing: %v\n", err)
		exitFunc(1)
	}
	u.report(3, "Reading forwarding audit log", "DONE", "log opened")
	defer func() { _ = file.Close() }()

	var cutoff time.Time
	if verifySince != "" {
		dur, err := duration.ParseExtended(verifySince)
		if err != nil {
			u.report(4, "Parsing forwarding events", "FAILED", err.Error())
			fmt.Fprintf(u.stderr, "[FAIL] Invalid --since format: %v\n", err)
			exitFunc(1)
		}
		cutoff = time.Now().Add(-dur)
		acceptPrint(u, "[INFO] Filtering events since: %s\n", cutoff.Format(time.RFC3339))
	}

	u.report(4, "Parsing forwarding events", "RUNNING", verifySince)
	validEvents := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec model.Acceptance
		if err := json.Unmarshal(line, &rec); err == nil {
			if verifySince == "" || rec.CreatedAt.After(cutoff) {
				validEvents++
			}
		}
	}

	if err := scanner.Err(); err != nil {
		u.report(4, "Parsing forwarding events", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "[FAIL] Error reading audit log: %v\n", err)
		exitFunc(1)
	}
	u.report(4, "Parsing forwarding events", "DONE", fmt.Sprintf("%d event(s)", validEvents))

	acceptPrint(u, "[PASS] SIEM Forwarding Verification Complete. %d events found ready for telemetry.\n", validEvents)
	if u.dashboardEnabled() {
		sinceLabel := verifySince
		if sinceLabel == "" {
			sinceLabel = "all"
		}
		u.render(buildAcceptForwardingDashboard(logPath, info.Size(), validEvents, sinceLabel, verifyBackend != ""))
	}
	exitFunc(exitcodes.OK)
}

func runRevoke(cmd *cobra.Command, args []string) {
	u := beginAcceptUI(cmd, "revoke", revokeID)
	u.report(1, "Loading acceptance configuration", "RUNNING", *acceptCfgPath)
	cfg, err := config.Load(*acceptCfgPath)
	if err != nil {
		u.report(1, "Loading acceptance configuration", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "Error loading config: %v\n", err)
		exitFunc(1)
	}
	u.report(1, "Loading acceptance configuration", "DONE", *acceptCfgPath)

	u.report(2, "Resolving acceptance secret", "RUNNING", "environment")
	key, err := accept.ResolveSecret(*cfg)
	if err != nil {
		u.report(2, "Resolving acceptance secret", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "Secret error: %v\n", err)
		exitFunc(1)
	}
	u.report(2, "Resolving acceptance secret", "DONE", "secret resolved")

	revocation := &model.RevocationRecord{
		RevokedBy: revokeRevokeBy,
		RevokedAt: time.Now(),
		Reason:    revokeReason,
	}

	u.report(3, "Revoking acceptance", "RUNNING", revokeID)
	if err := accept.UpdateStatus("wardex-acceptances.yaml", revokeID, "revoked", revocation, key); err != nil {
		u.report(3, "Revoking acceptance", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "Failed to revoke: %v\n", err)
		exitFunc(1)
	}
	u.report(3, "Revoking acceptance", "DONE", revokeID)
	acceptPrint(u, "Successfully revoked acceptance %s\n", revokeID)
	if u.dashboardEnabled() {
		u.render(buildAcceptRevokeDashboard(revokeID, revokeRevokeBy))
	}
}

func runCheckExpiry(cmd *cobra.Command, args []string) {
	u := beginAcceptUI(cmd, "check-expiry", *acceptCfgPath)
	u.report(1, "Loading acceptance configuration", "RUNNING", *acceptCfgPath)
	cfg, err := config.Load(*acceptCfgPath)
	if err != nil {
		u.report(1, "Loading acceptance configuration", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "Error loading config: %v\n", err)
		exitFunc(1)
	}
	u.report(1, "Loading acceptance configuration", "DONE", *acceptCfgPath)

	u.report(2, "Resolving acceptance secret", "RUNNING", "environment")
	key, err := accept.ResolveSecret(*cfg)
	if err != nil {
		u.report(2, "Resolving acceptance secret", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "Secret error: %v\n", err)
		exitFunc(1)
	}
	u.report(2, "Resolving acceptance secret", "DONE", "secret resolved")

	currentConfigHash, _ := accept.ConfigHash(*acceptCfgPath)
	u.report(3, "Loading acceptance store", "RUNNING", "wardex-acceptances.yaml")
	acceptances, err := accept.Load("wardex-acceptances.yaml", key, "wardex-accept-audit.log", "", currentConfigHash, u.stderr)
	if err != nil {
		u.report(3, "Loading acceptance store", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "Load error: %v\n", err)
		exitFunc(1)
	}
	u.report(3, "Loading acceptance store", "DONE", fmt.Sprintf("%d acceptance(s)", len(acceptances)))

	u.report(4, "Resolving expiry window", "RUNNING", expiryWarnBefore)
	dur, err := duration.ParseExtended(expiryWarnBefore)
	if err != nil {
		u.report(4, "Resolving expiry window", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "Invalid duration format %q: %v\n", expiryWarnBefore, err)
		exitFunc(1)
	}
	u.report(4, "Resolving expiry window", "DONE", expiryWarnBefore)

	warnTime := time.Now().Add(dur)
	expiring := make([]expiringAcceptance, 0)

	for _, a := range acceptances {
		if a.ExpiresAt.Before(warnTime) {
			acceptPrint(u, "WARNING: Acceptance %s for CVE %s expires at %v\n", a.ID, a.CVE, a.ExpiresAt.Format(time.RFC3339))
			expiring = append(expiring, expiringAcceptance{ID: a.ID, CVE: a.CVE, Expires: a.ExpiresAt})
		}
	}

	if len(expiring) > 0 {
		u.report(5, "Reviewing acceptance expiry", "REVIEW", fmt.Sprintf("%d acceptance(s)", len(expiring)))
		u.render(buildAcceptExpiryDashboard(expiring))
		exitFunc(exitcodes.ExpiringSoon)
	}

	u.report(5, "Reviewing acceptance expiry", "DONE", "no expiring acceptances")
	acceptPrint(u, "No acceptances expiring soon.\n")
	if u.dashboardEnabled() {
		u.render(buildAcceptExpiryDashboard(expiring))
	}
	exitFunc(exitcodes.OK)
}

func runActiveExploit(cmd *cobra.Command, args []string) {
	u := beginAcceptUI(cmd, "active-exploit", aeCVE)
	u.report(1, "Loading acceptance configuration", "RUNNING", *acceptCfgPath)
	cfg, err := config.Load(*acceptCfgPath)
	if err != nil {
		u.report(1, "Loading acceptance configuration", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "Error loading config: %v\n", err)
		exitFunc(1)
	}
	u.report(1, "Loading acceptance configuration", "DONE", *acceptCfgPath)

	if aeCVE == "" {
		u.report(2, "Validating acknowledgement", "FAILED", "CVE is required")
		fmt.Fprintf(u.stderr, "Error: --cve is required\n")
		exitFunc(1)
	}

	if len(aeJustif) < 80 {
		u.report(2, "Validating acknowledgement", "FAILED", "justification too short")
		fmt.Fprintf(u.stderr, "Error: justification must be at least 80 characters (got %d)\n", len(aeJustif))
		exitFunc(1)
	}
	u.report(2, "Validating acknowledgement", "DONE", aeCVE)

	if aeArtefactPath != "" {
		u.report(3, "Validating Article 14 artefact", "RUNNING", aeArtefactPath)
		key, err := accept.ResolveSecret(*cfg)
		if err != nil {
			u.report(3, "Validating Article 14 artefact", "SKIPPED", "secret unavailable")
			fmt.Fprintf(u.stderr, "Warning: WARDEX_ACCEPT_SECRET is not set, unable to verify HMAC: %v\n", err)
		} else {
			art, err := art14.ReadArtefact(aeArtefactPath)
			if err != nil {
				u.report(3, "Validating Article 14 artefact", "FAILED", err.Error())
				fmt.Fprintf(u.stderr, "Error reading Article 14 notification artefact: %v\n", err)
				exitFunc(1)
			}
			if err := art14.VerifyArtefact(art, key); err != nil {
				u.report(3, "Validating Article 14 artefact", "FAILED", err.Error())
				fmt.Fprintf(u.stderr, "Error: Article 14 notification artefact HMAC validation failed: %v\n", err)
				exitFunc(1)
			}
			u.report(3, "Validating Article 14 artefact", "DONE", "HMAC valid")
		}
	} else {
		u.report(3, "Validating Article 14 artefact", "SKIPPED", "not supplied")
	}

	logPath := "wardex-gate-audit.log"
	if cfg.Reporting.GateLog.Path != "" {
		logPath = cfg.Reporting.GateLog.Path
	}

	configHash, _ := accept.ConfigHash(*acceptCfgPath)
	entry := model.AuditEntry{
		Timestamp:                     time.Now().UTC(),
		Event:                         "active-exploit.acknowledged",
		ConfigHash:                    configHash,
		OverallDecision:               model.DecisionBlock,
		Status:                        "block",
		Detail:                        fmt.Sprintf("Active exploitation acknowledged for CVE: %s. Justification: %s", aeCVE, aeJustif),
		ActivelyExploited:             []string{aeCVE},
		Art14NotificationArtefactPath: aeArtefactPath,
	}

	u.report(4, "Writing chained audit entry", "RUNNING", logPath)
	if err := accept.ChainedAuditLog(logPath, entry); err != nil {
		u.report(4, "Writing chained audit entry", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "Error writing audit log: %v\n", err)
		exitFunc(1)
	}
	u.report(4, "Writing chained audit entry", "DONE", logPath)
	acceptPrint(u, "Acknowledged active exploitation for CVE %s in audit log (chained).\n", aeCVE)
	if u.dashboardEnabled() {
		u.render(buildAcceptActiveExploitDashboard(aeCVE, aeArtefactPath))
	}
	exitFunc(exitcodes.OK)
}

func runRequest(cmd *cobra.Command, args []string) {
	u := beginAcceptUI(cmd, "request", reqReport)
	u.report(1, "Loading acceptance configuration", "RUNNING", *acceptCfgPath)
	cfg, err := config.Load(*acceptCfgPath)
	if err != nil {
		u.report(1, "Loading acceptance configuration", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "Error loading config: %v\n", err)
		exitFunc(1)
	}
	u.report(1, "Loading acceptance configuration", "DONE", *acceptCfgPath)

	u.report(2, "Resolving acceptance secret", "RUNNING", "environment")
	key, err := accept.ResolveSecret(*cfg)
	if err != nil {
		u.report(2, "Resolving acceptance secret", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "Secret error: %v\n", err)
		exitFunc(1)
	}
	u.report(2, "Resolving acceptance secret", "DONE", "secret resolved")

	u.report(3, "Reading gate report", "RUNNING", reqReport)
	blockedCVEs, reportHash, err := accept.ReadReport(reqReport, cfg.AcceptanceConfig.Limits.MaxReportAgeHours)
	if err != nil {
		u.report(3, "Reading gate report", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "Report error: %v\n", err)
		exitFunc(1)
	}
	u.report(3, "Reading gate report", "DONE", fmt.Sprintf("%d blocked vulnerability(ies)", len(blockedCVEs)))

	u.report(4, "Validating requested CVEs", "RUNNING", fmt.Sprintf("%d requested", len(reqCVEs)))
	validCVEs := make(map[string]bool)
	for _, v := range blockedCVEs {
		validCVEs[v.CVEID] = true
	}

	for _, reqCVE := range reqCVEs {
		if !validCVEs[reqCVE] {
			u.report(4, "Validating requested CVEs", "FAILED", reqCVE+" not found in report")
			fmt.Fprintf(u.stderr, "CVE %s not found in blocked report\n", reqCVE)
			exitFunc(1)
		}
	}

	var expiresAt time.Time
	if reqExpires != "" {
		dur, err := duration.ParseExtended(reqExpires)
		if err != nil {
			u.report(4, "Validating requested CVEs", "FAILED", err.Error())
			fmt.Fprintf(u.stderr, "Invalid expiration format %q: %v\n", reqExpires, err)
			exitFunc(1)
		}
		expiresAt = time.Now().Add(dur)
	}
	u.report(4, "Validating requested CVEs", "DONE", fmt.Sprintf("%d CVE(s)", len(reqCVEs)))

	currentConfigHash, _ := accept.ConfigHash(*acceptCfgPath)
	baseID := fmt.Sprintf("acc-%s-%d", time.Now().Format("20060102"), time.Now().Unix())

	u.report(5, "Creating risk acceptances", "RUNNING", fmt.Sprintf("%d CVE(s)", len(reqCVEs)))
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

		if err := accept.ValidateBusinessRules(acceptance, cfg.AcceptanceConfig); err != nil {
			u.report(5, "Creating risk acceptances", "FAILED", cve)
			fmt.Fprintf(u.stderr, "Validation error for %s: %v\n", cve, err)
			exitFunc(1)
		}

		_ = accept.AuditLog("wardex-accept-audit.log", model.AuditEntry{
			Event:       "acceptance.created",
			ID:          id,
			CVEID:       cve,
			Actor:       reqAcceptBy,
			Interactive: !reqYes,
			ConfigHash:  currentConfigHash,
		})

		sig, _ := accept.Sign(acceptance, key)
		acceptance.Signature = sig

		if err := accept.Append("wardex-acceptances.yaml", acceptance); err != nil {
			u.report(5, "Creating risk acceptances", "FAILED", err.Error())
			fmt.Fprintf(u.stderr, "Storage error for %s: %v\n", cve, err)
			exitFunc(1)
		}

		createdIDs = append(createdIDs, id)
		acceptPrint(u, "Created acceptance %s for %s\n", id, cve)
	}
	u.report(5, "Creating risk acceptances", "DONE", fmt.Sprintf("%d created", len(createdIDs)))
	acceptPrint(u, "\nTotal: %d acceptance(s) created.\n", len(createdIDs))
	if u.dashboardEnabled() {
		u.render(buildAcceptRequestDashboard(reqReport, reqCVEs, createdIDs, reqAcceptBy, reportHash))
	}
}

func runList(cmd *cobra.Command, args []string) {
	u := beginAcceptUI(cmd, "list", "wardex-acceptances.yaml")
	u.report(1, "Loading acceptance configuration", "RUNNING", *acceptCfgPath)
	cfg, err := config.Load(*acceptCfgPath)
	if err != nil {
		u.report(1, "Loading acceptance configuration", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "Error loading config: %v\n", err)
		exitFunc(1)
	}
	u.report(1, "Loading acceptance configuration", "DONE", *acceptCfgPath)

	u.report(2, "Resolving acceptance secret", "RUNNING", "environment")
	key, err := accept.ResolveSecret(*cfg)
	if err != nil {
		u.report(2, "Resolving acceptance secret", "FAILED", err.Error())
		fmt.Fprintf(u.stderr, "Secret error: %v\n", err)
		exitFunc(1)
	}
	u.report(2, "Resolving acceptance secret", "DONE", "secret resolved")

	currentConfigHash, _ := accept.ConfigHash(*acceptCfgPath)
	u.report(3, "Loading acceptance store", "RUNNING", "wardex-acceptances.yaml")
	acceptances, err := accept.Load("wardex-acceptances.yaml", key, "wardex-accept-audit.log", "", currentConfigHash, u.stderr)
	if err != nil {
		u.report(3, "Loading acceptance store", "FAILED", err.Error())
		if errors.Is(err, accept.ErrTampered) {
			fmt.Fprintf(u.stderr, "Tampered acceptance detected: %v\n", err)
			exitFunc(exitcodes.IntegrityFailure)
		}
		if errors.Is(err, accept.ErrStoreInconsistent) {
			fmt.Fprintf(u.stderr, "Store inconsistent: %v\n", err)
			exitFunc(exitcodes.StoreInconsistent)
		}
		fmt.Fprintf(u.stderr, "Failed to load acceptances: %v\n", err)
		exitFunc(1)
	}
	u.report(3, "Loading acceptance store", "DONE", fmt.Sprintf("%d acceptance(s)", len(acceptances)))

	u.report(4, "Applying list filters", "RUNNING", listOutput)
	var filtered []model.Acceptance
	for _, a := range acceptances {
		if listCVE != "" && a.CVE != listCVE {
			continue
		}
		filtered = append(filtered, a)
	}
	u.report(4, "Applying list filters", "DONE", fmt.Sprintf("%d result(s)", len(filtered)))

	if listOutput != "json" && listOutput != "csv" && u.dashboardEnabled() {
		filter := "all"
		if listCVE != "" {
			filter = listCVE
		}
		u.render(buildAcceptListDashboard(filtered, filter))
		return
	}

	if listOutput == "json" {
		enc := json.NewEncoder(u.output)
		enc.SetIndent("", "  ")
		if err := enc.Encode(filtered); err != nil {
			fmt.Fprintf(u.stderr, "JSON encoding error: %v\n", err)
		}
		return
	}

	if listOutput == "csv" {
		fmt.Fprintln(u.output, "ID,CVE,AcceptedBy,ExpiresAt,Status")
		for _, a := range filtered {
			fmt.Fprintf(u.output, "%s,%s,%s,%s,VALID\n", a.ID, a.CVE, a.AcceptedBy, a.ExpiresAt.Format(time.RFC3339))
		}
		return
	}

	t := ui.NewTable(
		[]string{"ID", "CVE", "Accepted By", "Expires At", "Logic Status"},
		[]int{36, 16, 20, 14, 14},
	)
	for _, a := range filtered {
		status := "VALID"
		statusColor := ui.Green
		if time.Now().After(a.ExpiresAt) {
			status = "EXPIRED"
			statusColor = ui.Red
		} else if a.ExpiresAt.Before(time.Now().Add(30 * 24 * time.Hour)) {
			status = "EXPIRING"
			statusColor = ui.Yellow
		}
		t.AddRowStyled(
			[]string{a.ID, a.CVE, a.AcceptedBy, a.ExpiresAt.Format("2006-01-02"), status},
			nil,
			[]string{"", "", "", "", statusColor},
		)
	}
	t.Render(u.output)
}
