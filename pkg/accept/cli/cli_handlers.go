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
	"github.com/had-nu/wardex/v2/pkg/duration"
	"github.com/had-nu/wardex/v2/pkg/exitcodes"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

func runVerify(cmd *cobra.Command, args []string) {
	cfg, err := config.Load(*acceptCfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error loading config: %v\n", err)
		exitFunc(1)
	}

	key, err := accept.ResolveSecret(*cfg)
	if err != nil {
		fmt.Fprintf(stderr, "Secret error: %v\n", err)
		exitFunc(1)
	}

	currentConfigHash, _ := accept.ConfigHash(*acceptCfgPath)

	acceptances, err := accept.Load("wardex-acceptances.yaml", key, "wardex-accept-audit.log", "", currentConfigHash)
	if err != nil {
		if errors.Is(err, accept.ErrTampered) {
			fmt.Fprintf(stderr, "Tampered validation check failed: %v\n", err)
			exitFunc(exitcodes.Tampered)
		}
		if errors.Is(err, accept.ErrStoreInconsistent) {
			fmt.Fprintf(stderr, "Store trace validation failed: %v\n", err)
			exitFunc(exitcodes.StoreInconsistent)
		}
		fmt.Fprintf(stderr, "Standard validation error: %v\n", err)
		exitFunc(1)
	}

	fmt.Println("All acceptances passed integrity checks.")

	if verifyOutput != "" {
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
			fmt.Fprintf(stderr, "Error generating verification report: %v\n", err)
			exitFunc(1)
		}
		if err := os.WriteFile(verifyOutput, data, 0600); err != nil {
			fmt.Fprintf(stderr, "Error writing verification report: %v\n", err)
			exitFunc(1)
		}
		fmt.Printf("Verification report saved to: %s\n", verifyOutput)
	}

	exitFunc(exitcodes.OK)
}

func runVerifyForwarding(cmd *cobra.Command, args []string) {
	logPath := "wardex-accept-audit.log"
	info, err := os.Stat(logPath)
	if os.IsNotExist(err) {
		fmt.Fprintf(stderr, "[WARN] Audit log '%s' not found. No events to forward.\n", logPath)
		exitFunc(0)
	}
	if err != nil {
		fmt.Fprintf(stderr, "[FAIL] Cannot access audit log: %v\n", err)
		exitFunc(1)
	}

	if verifyBackend != "" {
		fmt.Printf("[INFO] Verifying reachability of SIEM backend: %s\n", verifyBackend)

		timeout := 3 * time.Second

		if strings.HasPrefix(verifyBackend, "http://") || strings.HasPrefix(verifyBackend, "https://") {
			client := &http.Client{Timeout: timeout}
			resp, err := client.Get(verifyBackend)
			if err != nil {
				fmt.Fprintf(stderr, "[FAIL] Failed to connect to HTTP backend %s: %v\n", verifyBackend, err)
				exitFunc(1)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode >= 500 {
				fmt.Fprintf(stderr, "[FAIL] HTTP backend returned server error %d\n", resp.StatusCode)
				exitFunc(1)
			}
			fmt.Printf("[PASS] HTTP Backend '%s' is reachable (Status: %d).\n", verifyBackend, resp.StatusCode)
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
				fmt.Fprintf(stderr, "[FAIL] Failed to dial %s backend at %s: %v\n", strings.ToUpper(network), address, err)
				exitFunc(1)
			}
			_ = conn.Close()
			fmt.Printf("[PASS] %s Backend '%s' is reachable and accepting connections.\n", strings.ToUpper(network), address)
		}
	} else {
		fmt.Printf("[INFO] No external backend specified. Verifying local log integrity for forwarding agent.\n")
	}

	fmt.Printf("[PASS] Found audit log: %s (%d bytes)\n", logPath, info.Size())

	file, err := os.Open(logPath)
	if err != nil {
		fmt.Fprintf(stderr, "[FAIL] Cannot open audit log for parsing: %v\n", err)
		exitFunc(1)
	}
	defer func() { _ = file.Close() }()

	var cutoff time.Time
	if verifySince != "" {
		dur, err := duration.ParseExtended(verifySince)
		if err != nil {
			fmt.Fprintf(stderr, "[FAIL] Invalid --since format: %v\n", err)
			exitFunc(1)
		}
		cutoff = time.Now().Add(-dur)
		fmt.Printf("[INFO] Filtering events since: %s\n", cutoff.Format(time.RFC3339))
	}

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
		fmt.Fprintf(stderr, "[FAIL] Error reading audit log: %v\n", err)
		exitFunc(1)
	}

	fmt.Printf("[PASS] SIEM Forwarding Verification Complete. %d events found ready for telemetry.\n", validEvents)
	exitFunc(exitcodes.OK)
}

func runRevoke(cmd *cobra.Command, args []string) {
	cfg, err := config.Load(*acceptCfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error loading config: %v\n", err)
		exitFunc(1)
	}

	key, err := accept.ResolveSecret(*cfg)
	if err != nil {
		fmt.Fprintf(stderr, "Secret error: %v\n", err)
		exitFunc(1)
	}

	revocation := &model.RevocationRecord{
		RevokedBy: revokeRevokeBy,
		RevokedAt: time.Now(),
		Reason:    revokeReason,
	}

	if err := accept.UpdateStatus("wardex-acceptances.yaml", revokeID, "revoked", revocation, key); err != nil {
		fmt.Fprintf(stderr, "Failed to revoke: %v\n", err)
		exitFunc(1)
	}

	fmt.Printf("Successfully revoked acceptance %s\n", revokeID)
}

func runCheckExpiry(cmd *cobra.Command, args []string) {
	cfg, err := config.Load(*acceptCfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error loading config: %v\n", err)
		exitFunc(1)
	}

	key, err := accept.ResolveSecret(*cfg)
	if err != nil {
		fmt.Fprintf(stderr, "Secret error: %v\n", err)
		exitFunc(1)
	}

	currentConfigHash, _ := accept.ConfigHash(*acceptCfgPath)
	acceptances, err := accept.Load("wardex-acceptances.yaml", key, "wardex-accept-audit.log", "", currentConfigHash)
	if err != nil {
		fmt.Fprintf(stderr, "Load error: %v\n", err)
		exitFunc(1)
	}

	dur, err := duration.ParseExtended(expiryWarnBefore)
	if err != nil {
		fmt.Fprintf(stderr, "Invalid duration format %q: %v\n", expiryWarnBefore, err)
		exitFunc(1)
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
		exitFunc(exitcodes.ExpiringSoon)
	}

	fmt.Println("No acceptances expiring soon.")
	exitFunc(exitcodes.OK)
}

func runActiveExploit(cmd *cobra.Command, args []string) {
	cfg, err := config.Load(*acceptCfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error loading config: %v\n", err)
		exitFunc(1)
	}

	if aeCVE == "" {
		fmt.Fprintf(stderr, "Error: --cve is required\n")
		exitFunc(1)
	}

	if len(aeJustif) < 80 {
		fmt.Fprintf(stderr, "Error: justification must be at least 80 characters (got %d)\n", len(aeJustif))
		exitFunc(1)
	}

	if aeArtefactPath != "" {
		key, err := accept.ResolveSecret(*cfg)
		if err != nil {
			fmt.Fprintf(stderr, "Warning: WARDEX_ACCEPT_SECRET is not set, unable to verify HMAC: %v\n", err)
		} else {
			art, err := art14.ReadArtefact(aeArtefactPath)
			if err != nil {
				fmt.Fprintf(stderr, "Error reading Article 14 notification artefact: %v\n", err)
				exitFunc(1)
			}
			if err := art14.VerifyArtefact(art, key); err != nil {
				fmt.Fprintf(stderr, "Error: Article 14 notification artefact HMAC validation failed: %v\n", err)
				exitFunc(1)
			}
		}
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
		OverallDecision:               "block",
		Status:                        "block",
		Detail:                        fmt.Sprintf("Active exploitation acknowledged for CVE: %s. Justification: %s", aeCVE, aeJustif),
		ActivelyExploited:             []string{aeCVE},
		Art14NotificationArtefactPath: aeArtefactPath,
	}

	if err := accept.ChainedAuditLog(logPath, entry); err != nil {
		fmt.Fprintf(stderr, "Error writing audit log: %v\n", err)
		exitFunc(1)
	}

	fmt.Printf("Acknowledged active exploitation for CVE %s in audit log (chained).\n", aeCVE)
	exitFunc(exitcodes.OK)
}

func runRequest(cmd *cobra.Command, args []string) {
	cfg, err := config.Load(*acceptCfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error loading config: %v\n", err)
		exitFunc(1)
	}

	key, err := accept.ResolveSecret(*cfg)
	if err != nil {
		fmt.Fprintf(stderr, "Secret error: %v\n", err)
		exitFunc(1)
	}

	blockedCVEs, reportHash, err := accept.ReadReport(reqReport, cfg.AcceptanceConfig.Limits.MaxReportAgeHours)
	if err != nil {
		fmt.Fprintf(stderr, "Report error: %v\n", err)
		exitFunc(1)
	}

	validCVEs := make(map[string]bool)
	for _, v := range blockedCVEs {
		validCVEs[v.CVEID] = true
	}

	for _, reqCVE := range reqCVEs {
		if !validCVEs[reqCVE] {
			fmt.Fprintf(stderr, "CVE %s not found in blocked report\n", reqCVE)
			exitFunc(1)
		}
	}

	var expiresAt time.Time
	if reqExpires != "" {
		dur, err := duration.ParseExtended(reqExpires)
		if err != nil {
			fmt.Fprintf(stderr, "Invalid expiration format %q: %v\n", reqExpires, err)
			exitFunc(1)
		}
		expiresAt = time.Now().Add(dur)
	}

	currentConfigHash, _ := accept.ConfigHash(*acceptCfgPath)
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

		if err := accept.ValidateBusinessRules(acceptance, cfg.AcceptanceConfig); err != nil {
			fmt.Fprintf(stderr, "Validation error for %s: %v\n", cve, err)
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
			fmt.Fprintf(stderr, "Storage error for %s: %v\n", cve, err)
			exitFunc(1)
		}

		createdIDs = append(createdIDs, id)
		fmt.Printf("Created acceptance %s for %s\n", id, cve)
	}
	fmt.Printf("\nTotal: %d acceptance(s) created.\n", len(createdIDs))
}

func runList(cmd *cobra.Command, args []string) {
	cfg, err := config.Load(*acceptCfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error loading config: %v\n", err)
		exitFunc(1)
	}

	key, err := accept.ResolveSecret(*cfg)
	if err != nil {
		fmt.Fprintf(stderr, "Secret error: %v\n", err)
		exitFunc(1)
	}

	currentConfigHash, _ := accept.ConfigHash(*acceptCfgPath)

	acceptances, err := accept.Load("wardex-acceptances.yaml", key, "wardex-accept-audit.log", "", currentConfigHash)
	if err != nil {
		if errors.Is(err, accept.ErrTampered) {
			fmt.Fprintf(stderr, "Tampered acceptance detected: %v\n", err)
			exitFunc(exitcodes.Tampered)
		}
		if errors.Is(err, accept.ErrStoreInconsistent) {
			fmt.Fprintf(stderr, "Store inconsistent: %v\n", err)
			exitFunc(exitcodes.StoreInconsistent)
		}
		fmt.Fprintf(stderr, "Failed to load acceptances: %v\n", err)
		exitFunc(1)
	}

	var filtered []model.Acceptance
	for _, a := range acceptances {
		if listCVE != "" && a.CVE != listCVE {
			continue
		}
		filtered = append(filtered, a)
	}

	if listOutput == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(filtered); err != nil {
			fmt.Fprintf(stderr, "JSON encoding error: %v\n", err)
		}
		return
	}

	if listOutput == "csv" {
		fmt.Println("ID,CVE,AcceptedBy,ExpiresAt,Status")
		for _, a := range filtered {
			fmt.Printf("%s,%s,%s,%s,VALID\n", a.ID, a.CVE, a.AcceptedBy, a.ExpiresAt.Format(time.RFC3339))
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
	t.Render(os.Stdout)
}
