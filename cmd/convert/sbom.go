package convert

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/sboms"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var sbomOutFile string

var SbomCmd = &cobra.Command{
	Use:   "sbom <input.[json|xml]>",
	Short: "Convert an SBOM (CycloneDX / SPDX) to Wardex Vulnerabilities YAML",
	Args:  cobra.MinimumNArgs(1),
	Run:   runConvertSbom,
}

func init() {
	SbomCmd.Flags().StringVarP(&sbomOutFile, "output", "o", "wardex-vulns.yaml", "Output file for Wardex YAML")
}

// peekSbomFormat attempts a naive peek into the JSON structure to determine
// if it's CycloneDX or SPDX before invoking the dedicated parsers.
func peekSbomFormat(filepath string) (string, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return "", err
	}

	var generic map[string]interface{}
	if err := json.Unmarshal(data, &generic); err != nil {
		return "", fmt.Errorf("file is not valid JSON")
	}

	if _, ok := generic["bomFormat"]; ok {
		if fmt.Sprintf("%v", generic["bomFormat"]) == "CycloneDX" {
			return "cyclonedx", nil
		}
	}

	if _, ok := generic["spdxVersion"]; ok {
		return "spdx", nil
	}

	return "unknown", nil
}

func runConvertSbom(cmd *cobra.Command, args []string) {
	inFile := args[0]

	format, err := peekSbomFormat(inFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error analyzing SBOM file: %v\n", err)
		os.Exit(1)
	}

	var vulns []model.Vulnerability

	switch format {
	case "cyclonedx":
		vulns, err = sboms.ParseCycloneDX(inFile)
	case "spdx":
		vulns, err = sboms.ParseSPDX(inFile)
	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown or unsupported SBOM format in %s. Supported formats: CycloneDX 1.5 JSON.\n", inFile)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing SBOM: %v\n", err)
		os.Exit(1)
	}

	type WardexOutput struct {
		Vulnerabilities []model.Vulnerability `yaml:"vulnerabilities"`
	}

	out := WardexOutput{
		Vulnerabilities: vulns,
	}

	yamlData, err := yaml.Marshal(&out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding YAML: %v\n", err)
		os.Exit(1)
	}

	if sbomOutFile == "stdout" || sbomOutFile == "-" {
		fmt.Print(string(yamlData))
	} else {
		if err := os.WriteFile(sbomOutFile, yamlData, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully converted %d vulnerabilities to %s\n", len(out.Vulnerabilities), sbomOutFile)
	}
}
