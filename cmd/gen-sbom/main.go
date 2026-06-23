// Command gen-sbom generates a CycloneDX 1.5 SBOM for the Wardex binary
// from go.mod metadata. No external dependencies beyond the Go toolchain.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type goModule struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Main    bool   `json:"main"`
}

type sbomComponent struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	PURL       string `json:"purl,omitempty"`
	Scope      string `json:"scope,omitempty"`
	Licenses   []sbomLicense `json:"licenses,omitempty"`
}

type sbomLicense struct {
	License sbomLicenseID `json:"license"`
}

type sbomLicenseID struct {
	ID string `json:"id"`
}

type bom struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	SerialNumber string `json:"serialNumber"`
	Version     int    `json:"version"`
	Metadata    bomMetadata `json:"metadata"`
	Components  []sbomComponent `json:"components"`
}

type bomMetadata struct {
	Timestamp string `json:"timestamp"`
	Tools     []bomTool `json:"tools"`
	Component sbomComponent `json:"component"`
	Licenses  []sbomLicense `json:"licenses"`
}

type bomTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

func main() {
	modData, err := exec.Command("go", "list", "-m", "-json", "all").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to list modules: %v\n", err)
		os.Exit(1)
	}

	var components []sbomComponent
	dec := json.NewDecoder(strings.NewReader(string(modData)))
	for dec.More() {
		var m goModule
		if err := dec.Decode(&m); err != nil {
			break
		}
		if m.Main {
			continue
		}
		parts := strings.Split(m.Path, "/")
		name := parts[len(parts)-1]
		if len(parts) > 1 {
			name = strings.Join(parts[len(parts)-2:], "/")
		}
		components = append(components, sbomComponent{
			Type:    "library",
			Name:    name,
			Version: strings.TrimPrefix(m.Version, "v"),
			PURL:    fmt.Sprintf("pkg:golang/%s@%s", m.Path, m.Version),
			Scope:   "required",
		})
	}

	bom := bom{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		SerialNumber: fmt.Sprintf("urn:uuid:wardex-%d", time.Now().UnixMilli()),
		Version:     1,
		Metadata: bomMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []bomTool{
				{Vendor: "had-nu", Name: "gen-sbom", Version: "1.0"},
			},
			Component: sbomComponent{
				Type:    "application",
				Name:    "wardex",
				Version: getVersion(),
			},
			Licenses: []sbomLicense{
				{License: sbomLicenseID{ID: "AGPL-3.0-or-later"}},
			},
		},
		Components: components,
	}

	out, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to marshal SBOM: %v\n", err)
		os.Exit(1)
	}

	outPath := "wardex.sbom.json"
	if len(os.Args) > 1 {
		outPath = os.Args[1]
	}
	outPath = filepath.Clean(outPath)
	if err := os.WriteFile(outPath, out, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to write SBOM: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("SBOM written to %s (%d components)\n", outPath, len(components))
}

func getVersion() string {
	cmd := exec.Command("git", "describe", "--tags", "--dirty", "--always")
	out, err := cmd.Output()
	if err != nil {
		return "dev"
	}
	return strings.TrimSpace(string(out))
}
