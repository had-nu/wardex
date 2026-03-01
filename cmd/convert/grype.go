package convert

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type GrypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			CVSS     []struct {
				Metrics struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"metrics"`
			} `json:"cvss"`
		} `json:"vulnerability"`
		Artifact struct {
			Name string `json:"name"`
		} `json:"artifact"`
	} `json:"matches"`
}

var grypeOutFile string
var defaultEpss float64

var GrypeCmd = &cobra.Command{
	Use:   "grype <input.json>",
	Short: "Convert Grype JSON output to Wardex Vulnerabilities YAML",
	Args:  cobra.MinimumNArgs(1),
	Run:   runConvertGrype,
}

func init() {
	GrypeCmd.Flags().StringVarP(&grypeOutFile, "output", "o", "wardex-vulns.yaml", "Output file for Wardex YAML")
	GrypeCmd.Flags().Float64Var(&defaultEpss, "default-epss", 0.05, "Default EPSS score for mapped vulnerabilities")
}

func runConvertGrype(cmd *cobra.Command, args []string) {
	inFile := args[0]
	data, err := os.ReadFile(inFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading Grype JSON: %v\n", err)
		os.Exit(1)
	}

	var report GrypeReport
	if err := json.Unmarshal(data, &report); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing Grype JSON: %v\n", err)
		os.Exit(1)
	}

	type WardexOutput struct {
		Vulnerabilities []model.Vulnerability `yaml:"vulnerabilities"`
	}

	out := WardexOutput{
		Vulnerabilities: make([]model.Vulnerability, 0, len(report.Matches)),
	}

	seen := make(map[string]bool)

	for _, match := range report.Matches {
		vulnID := match.Vulnerability.ID
		comp := match.Artifact.Name
		key := vulnID + "|" + comp

		if seen[key] || vulnID == "" {
			continue
		}
		seen[key] = true

		var bestScore float64
		for _, cvss := range match.Vulnerability.CVSS {
			if cvss.Metrics.BaseScore > bestScore {
				bestScore = cvss.Metrics.BaseScore
			}
		}

		if bestScore == 0 {
			switch match.Vulnerability.Severity {
			case "Critical":
				bestScore = 9.5
			case "High":
				bestScore = 7.5
			case "Medium":
				bestScore = 5.5
			case "Low":
				bestScore = 3.0
			default:
				bestScore = 0.0
			}
		}

		out.Vulnerabilities = append(out.Vulnerabilities, model.Vulnerability{
			CVEID:     vulnID,
			CVSSBase:  bestScore,
			EPSSScore: defaultEpss,
			Component: comp,
			Reachable: true,
		})
	}

	yamlData, err := yaml.Marshal(&out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding YAML: %v\n", err)
		os.Exit(1)
	}

	if grypeOutFile == "stdout" || grypeOutFile == "-" {
		fmt.Print(string(yamlData))
	} else {
		if err := os.WriteFile(grypeOutFile, yamlData, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully converted %d vulnerabilities to %s\n", len(out.Vulnerabilities), grypeOutFile)
	}
}
