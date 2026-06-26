// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package main

import (
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/pkg/analyzer"
	"github.com/had-nu/wardex/v2/pkg/model"
	"gopkg.in/yaml.v3"
)

func main() {
	cwd, _ := os.Getwd()

	// NIS2 catalog
	nis2Data, _ := os.ReadFile(cwd + "/../../pkg/catalog/nis2.yaml") // #nosec G304 -- research PoC, paths are hardcoded
	var nis2 []model.CatalogControl
	yaml.Unmarshal(nis2Data, &nis2)

	// DORA catalog
	doraData, _ := os.ReadFile(cwd + "/../../pkg/catalog/dora.yaml") // #nosec G304 -- research PoC, paths are hardcoded
	var dora []model.CatalogControl
	yaml.Unmarshal(doraData, &dora)

	catalog := append(nis2, dora...)

	// Mappings
	mappingsData, _ := os.ReadFile(cwd + "/mappings.yaml") // #nosec G304 -- research PoC, paths are hardcoded
	var ms struct {
		Mappings []model.Mapping `yaml:"mappings"`
	}
	yaml.Unmarshal(mappingsData, &ms)

	// Controls
	controls := []model.ExistingControl{
		{ID: "CTRL-001", Name: "Firewall", Maturity: 4, Layer: model.LayerImplemented, ContextWeight: 1.5, Evidences: []model.Evidence{{Type: "log", Ref: "fw-logs-q1"}}},
		{ID: "CTRL-002", Name: "SIEM", Maturity: 3, Layer: model.LayerImplemented, Evidences: []model.Evidence{{Type: "test_result", Ref: "siem-alert-test"}}},
		{ID: "CTRL-003", Name: "MFA", Maturity: 4, Layer: model.LayerImplemented, ContextWeight: 2.0, Evidences: []model.Evidence{{Type: "policy", Ref: "mfa-policy"}}},
		{ID: "CTRL-004", Name: "Patch Management", Maturity: 2, Layer: model.LayerDocumented},
		{ID: "CTRL-005", Name: "Backup", Maturity: 3, Layer: model.LayerImplemented, Evidences: []model.Evidence{{Type: "procedure", Ref: "backup-proc"}}},
		{ID: "CTRL-006", Name: "WAF", Maturity: 3, Layer: model.LayerImplemented, Evidences: []model.Evidence{{Type: "log", Ref: "waf-block-logs"}}},
		{ID: "CTRL-007", Name: "SBOM", Maturity: 4, Layer: model.LayerImplemented, Evidences: []model.Evidence{{Type: "test_result", Ref: "cyclonedx-v1"}}},
		{ID: "CTRL-008", Name: "API Gateway", Maturity: 4, Layer: model.LayerImplemented, Evidences: []model.Evidence{{Type: "log", Ref: "gateway-auth-logs"}}},
		{ID: "CTRL-009", Name: "Container Security", Maturity: 3, Layer: model.LayerImplemented, Evidences: []model.Evidence{{Type: "test_result", Ref: "trivy-scan"}}},
		{ID: "CTRL-010", Name: "Encryption at Rest", Maturity: 4, Layer: model.LayerImplemented, Evidences: []model.Evidence{{Type: "policy", Ref: "kms-policy"}}},
		{ID: "CTRL-011", Name: "DDoS Protection", Maturity: 3, Layer: model.LayerDocumented},
		{ID: "CTRL-012", Name: "Incident Response", Maturity: 2, Layer: model.LayerDocumented},
		{ID: "CTRL-013", Name: "Vendor Risk", Maturity: 2, Layer: model.LayerDocumented},
		{ID: "CTRL-014", Name: "Security Training", Maturity: 3, Layer: model.LayerImplemented, Evidences: []model.Evidence{{Type: "test_result", Ref: "training-cert"}}},
		{ID: "CTRL-015", Name: "Vuln Scanner", Maturity: 3, Layer: model.LayerImplemented, Evidences: []model.Evidence{{Type: "log", Ref: "tenable-results"}}},
		{ID: "CTRL-016", Name: "Encryption in Transit", Maturity: 4, Layer: model.LayerImplemented, Evidences: []model.Evidence{{Type: "policy", Ref: "tls-config"}}},
		{ID: "CTRL-017", Name: "Network Segmentation", Maturity: 2, Layer: model.LayerDocumented},
		{ID: "CTRL-018", Name: "Log Retention", Maturity: 3, Layer: model.LayerImplemented, Evidences: []model.Evidence{{Type: "policy", Ref: "retention-policy"}}},
		{ID: "CTRL-019", Name: "Pentest", Maturity: 2, Layer: model.LayerDocumented},
		{ID: "CTRL-020", Name: "Access Reviews", Maturity: 3, Layer: model.LayerImplemented, Evidences: []model.Evidence{{Type: "log", Ref: "iam-review-q1"}}},
	}

	a := analyzer.New(catalog, ms.Mappings, controls)
	findings, err := a.Analyze()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Analysis failed: %v\n", err)
		os.Exit(1)
	}

	gapCount := 0
	partialCount := 0
	coveredCount := 0

	fmt.Println("# Gap Analysis Report - NovaBank SA")
	fmt.Println("")
	fmt.Println("| Catalog Control | Status | Score | Covered By | Gap Reasons |")
	fmt.Println("|----------------|--------|-------|----------|------------|------------")

	for _, f := range findings {
		icon := "[OK]"
		switch f.Status {
		case model.StatusGap:
			icon = "[FAIL]"
			gapCount++
		case model.StatusPartial:
			icon = "[WARN]"
			partialCount++
		case model.StatusCovered:
			coveredCount++
		}

		cb := ""
		for _, m := range f.CoveredBy {
			cb += m.ExistingControlID + " "
		}

		reason := ""
		for _, r := range f.GapReasons {
			reason += r + " "
		}

		fmt.Printf("| %s | %s %s | %.1f | %s | %s |\n",
			f.Control.ID, icon, f.Status, f.FinalScore, cb, reason)
	}

	fmt.Println("")
	fmt.Printf("**Summary:** %d covered, %d partial, %d gaps\n", coveredCount, partialCount, gapCount)
}
