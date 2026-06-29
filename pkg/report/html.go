// Package report generates compliance gap analysis and release gate evaluation
// outputs in Markdown, HTML, JSON, and CSV formats.
package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"os"
	"strings"

	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/model"
)

//go:embed templates/report.html
var reportTemplate string

type templateData struct {
	Title        string
	GeneratedAt  string
	Version      string
	Summary      templateSummary
	Domains      []templateDomain
	LayerDelta   *templateLayerDelta
	Gate         *templateGate
	Assets       []templateAsset
	Roadmap      []templateRoadmapItem
	HasDelta     bool
	HasLayer     bool
	HasGate      bool
	HasAssets    bool
	HasRoadmap   bool
}

type templateSummary struct {
	GlobalCoverage string
	CoveredCount   int
	PartialCount   int
	GapCount       int
	TotalControls  int
	CoverageChange string
}

type templateDomain struct {
	Name         string
	BarWidth     int
	Remaining    int
	CoveredCount int
	TotalCount   int
	Score        string
}

type templateLayerDelta struct {
	Documented    int
	Implemented   int
	Active        int
	ActivePct     string
	PolicyGap     int
	PolicyGapPct  string
	ShadowSec     int
	ShadowSecPct  string
}

type templateGate struct {
	Decision  string
	DecisionClass string
	Maturity  string
	Decisions []templateGateDecision
	HasDecisions bool
}

type templateGateDecision struct {
	CVE     string
	CVSS    string
	EPSS    string
	Risk    string
	Decision string
	Class   string
}

type templateAsset struct {
	Name       string
	Score      string
	Status     string
	StatusIcon string
	StatusClass string
	Missing    string
}

type templateRoadmapItem struct {
	ID     string
	Name   string
	Score  string
	Reason string
}

func svgBar(filled, total int) string {
	if total <= 0 {
		return ""
	}
	maxWidth := 400
	pct := float64(filled) / float64(total)
	if pct > 1.0 {
		pct = 1.0
	}
	barWidth := int(pct * float64(maxWidth))
	remain := maxWidth - barWidth
	if barWidth < 0 {
		barWidth = 0
	}
	if remain < 0 {
		remain = 0
	}
	var color string
	switch {
	case pct >= 0.8:
		color = "#00c4a7"
	case pct >= 0.5:
		color = "#f5a623"
	default:
		color = "#e74c3c"
	}
	return fmt.Sprintf(
		`<svg class="bar" viewBox="0 0 %d 20" aria-label="%d of %d">
			<rect x="0" y="0" width="%d" height="20" rx="3" fill="%s"/>
			<rect x="%d" y="0" width="%d" height="20" rx="3" fill="#e0e0e0"/>
		</svg>`,
		maxWidth, filled, total, barWidth, color, barWidth, remain,
	)
}

func generateHTML(report model.GapReport, outFile string) error {
	sum := report.Summary
	data := templateData{
		Title:       "Wardex — Compliance & Release Gate Report",
		GeneratedAt: sum.GeneratedAt.Format("2006-01-02 15:04:05"),
		Version:     "2.0.0",
		Summary: templateSummary{
			GlobalCoverage: fmt.Sprintf("%.1f", sum.GlobalCoverage),
			CoveredCount:   sum.CoveredCount,
			PartialCount:   sum.PartialCount,
			GapCount:       sum.GapCount,
			TotalControls:  sum.TotalControls,
		},
	}

	if report.Delta != nil {
		sign := ""
		if report.Delta.CoverageChange > 0 {
			sign = "+"
		}
		data.Summary.CoverageChange = fmt.Sprintf("%s%.1f%%", sign, report.Delta.CoverageChange)
		data.HasDelta = true
	}

	for _, d := range sum.DomainSummaries {
		data.Domains = append(data.Domains, templateDomain{
			Name:         d.Domain,
			Score:        fmt.Sprintf("%.1f", d.MaturityScore),
			CoveredCount: d.CoveredCount,
			TotalCount:   d.TotalControls,
			BarWidth:     d.CoveredCount,
			Remaining:    d.TotalControls - d.CoveredCount,
		})
	}

	if report.LayerDelta != nil {
		total := report.LayerDelta.DocumentedCount + report.LayerDelta.ImplementedCount
		if total == 0 {
			total = 1
		}
		data.LayerDelta = &templateLayerDelta{
			Documented:   report.LayerDelta.DocumentedCount,
			Implemented:  report.LayerDelta.ImplementedCount,
			Active:       len(report.LayerDelta.ActiveCoverage),
			ActivePct:    fmt.Sprintf("%.0f", float64(len(report.LayerDelta.ActiveCoverage))/float64(total)*100),
			PolicyGap:    len(report.LayerDelta.PolicyGap),
			PolicyGapPct: fmt.Sprintf("%.0f", float64(len(report.LayerDelta.PolicyGap))/float64(total)*100),
			ShadowSec:    len(report.LayerDelta.ImplementedOnly),
			ShadowSecPct: fmt.Sprintf("%.0f", float64(len(report.LayerDelta.ImplementedOnly))/float64(total)*100),
		}
		data.HasLayer = true
	}

	if report.Gate != nil {
		decClass := "allow"
		switch report.Gate.OverallDecision {
		case "block":
			decClass = "block"
		case "warn":
			decClass = "warn"
		}
		icon := "ALLOW"
		switch report.Gate.OverallDecision {
		case "block":
			icon = "BLOCK"
		case "warn":
			icon = "WARN"
		}
		gate := templateGate{
			Decision:      strings.ToUpper(icon),
			DecisionClass: decClass,
			Maturity:      fmt.Sprintf("%d / 5", report.Gate.GateMaturityLevel),
		}
		for _, dec := range report.Gate.Decisions {
			dClass := "allow"
			switch dec.Decision {
			case "block":
				dClass = "block"
			case "warn":
				dClass = "warn"
			}
			gate.Decisions = append(gate.Decisions, templateGateDecision{
				CVE:      dec.Vulnerability.CVEID,
				CVSS:     fmt.Sprintf("%.1f", dec.Breakdown.CVSSBase),
				EPSS:     fmt.Sprintf("%.2f", dec.Breakdown.EPSSFactor),
				Risk:     fmt.Sprintf("%.2f", dec.ReleaseRisk),
				Decision: strings.ToUpper(dec.Decision),
				Class:    dClass,
			})
		}
		gate.HasDecisions = len(gate.Decisions) > 0
		data.Gate = &gate
		data.HasGate = true
	}

	for _, ac := range report.AssetCompliance {
		status := "compliant"
		icon := "✓"
		switch ac.Status {
		case "partial":
			status = "partial"
			icon = "!"
		case "non_compliant":
			status = "non-compliant"
			icon = "✗"
		}
		missing := "none"
		if len(ac.MissingControls) > 0 {
			missing = fmt.Sprintf("%d controls", len(ac.MissingControls))
		}
		data.Assets = append(data.Assets, templateAsset{
			Name:        ac.AssetName,
			Score:       fmt.Sprintf("%.0f", ac.ComplianceScore*100),
			Status:      status,
			StatusIcon:  icon,
			StatusClass: status,
			Missing:     missing,
		})
		data.HasAssets = true
	}

	for _, fnd := range report.Roadmap {
		reason := "N/A"
		if len(fnd.GapReasons) > 0 {
			reason = fnd.GapReasons[0]
		}
		data.Roadmap = append(data.Roadmap, templateRoadmapItem{
			ID:     fnd.Control.ID,
			Name:   fnd.Control.Name,
			Score:  fmt.Sprintf("%.1f", fnd.FinalScore),
			Reason: reason,
		})
		data.HasRoadmap = true
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"svgBar": svgBar,
	}).Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute HTML template: %w", err)
	}

	output := buf.Bytes()

	if outFile == "stdout" || outFile == "" {
		_, err = os.Stdout.Write(output)
		return err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	safePath, err := cli.ValidateOutputPath(cwd, outFile)
	if err != nil {
		return err
	}
	return os.WriteFile(safePath, output, 0600)
}
