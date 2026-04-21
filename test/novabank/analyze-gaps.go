package main

import (
	"fmt"
	"os"

	"github.com/had-nu/wardex/pkg/analyzer"
	"github.com/had-nu/wardex/pkg/model"
	"gopkg.in/yaml.v3"
)

func main() {
	cwd, _ := os.Getwd()

	// NIS2 catalog
	nis2Data, _ := os.ReadFile(cwd + "/../../pkg/catalog/nis2.yaml")
	var nis2 []model.CatalogControl
	yaml.Unmarshal(nis2Data, &nis2)

	// DORA catalog
	doraData, _ := os.ReadFile(cwd + "/../../pkg/catalog/dora.yaml")
	var dora []model.CatalogControl
	yaml.Unmarshal(doraData, &dora)

	catalog := append(nis2, dora...)

	// Mappings
	mappingsData, _ := os.ReadFile(cwd + "/mappings.yaml")
	var ms struct {
		Mappings []model.Mapping `yaml:"mappings"`
	}
	yaml.Unmarshal(mappingsData, &ms)

	// Controls
	controls := []model.ExistingControl{
		{ID: "CTRL-001", Name: "Firewall", Maturity: 3, Evidences: []model.Evidence{{Type: "policy", Ref: "firewall"}}},
		{ID: "CTRL-002", Name: "SIEM", Maturity: 3, Evidences: []model.Evidence{{Type: "test_result", Ref: "siem"}}},
		{ID: "CTRL-003", Name: "MFA", Maturity: 4, Evidences: []model.Evidence{{Type: "policy", Ref: "mfa"}}},
		{ID: "CTRL-004", Name: "Patch Management", Maturity: 2},
		{ID: "CTRL-005", Name: "Backup", Maturity: 3, Evidences: []model.Evidence{{Type: "procedure", Ref: "backup"}}},
		{ID: "CTRL-006", Name: "WAF", Maturity: 3},
		{ID: "CTRL-007", Name: "SBOM", Maturity: 2, Evidences: []model.Evidence{{Type: "test_result", Ref: "sbom"}}},
		{ID: "CTRL-008", Name: "API Gateway", Maturity: 4},
		{ID: "CTRL-009", Name: "Container Security", Maturity: 3, Evidences: []model.Evidence{{Type: "test_result", Ref: "trivy"}}},
		{ID: "CTRL-010", Name: "Encryption at Rest", Maturity: 4, Evidences: []model.Evidence{{Type: "policy", Ref: "kms"}}},
		{ID: "CTRL-011", Name: "DDoS Protection", Maturity: 3},
		{ID: "CTRL-012", Name: "Incident Response", Maturity: 2},
		{ID: "CTRL-013", Name: "Vendor Risk", Maturity: 2},
		{ID: "CTRL-014", Name: "Security Training", Maturity: 3, Evidences: []model.Evidence{{Type: "test_result", Ref: "training"}}},
		{ID: "CTRL-015", Name: "Vuln Scanner", Maturity: 3},
		{ID: "CTRL-016", Name: "Encryption in Transit", Maturity: 4},
		{ID: "CTRL-017", Name: "Network Segmentation", Maturity: 2},
		{ID: "CTRL-018", Name: "Log Retention", Maturity: 3},
		{ID: "CTRL-019", Name: "Pentest", Maturity: 2},
		{ID: "CTRL-020", Name: "Access Reviews", Maturity: 2},
	}

	a := analyzer.New(catalog, ms.Mappings, controls)
	findings := a.Analyze()

	gapCount := 0
	partialCount := 0
	coveredCount := 0

	fmt.Println("# Gap Analysis Report - NovaBank SA")
	fmt.Println("")
	fmt.Println("| Catalog Control | Status | Score | Covered By | Gap Reasons |")
	fmt.Println("|----------------|--------|-------|----------|------------|------------")

	for _, f := range findings {
		icon := "✅"
		switch f.Status {
		case model.StatusGap:
			icon = "❌"
			gapCount++
		case model.StatusPartial:
			icon = "⚠️"
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
