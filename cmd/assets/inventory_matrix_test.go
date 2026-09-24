package assets

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestInventoryOutputMatrixUsesConfiguredWriter(t *testing.T) {
	oldFile, oldFormat := assetsFile, assetsFormat
	defer func() {
		assetsFile, assetsFormat = oldFile, oldFormat
	}()

	dir := t.TempDir()
	t.Chdir(dir)
	contents := []byte(`- id: api-01
  name: API gateway
  type: service
  criticality: 0.82
  owner: Platform
  controls: [MFA, WAF]
  exposure:
    internet_facing: true
    network_zone: dmz
`)
	if err := os.WriteFile("assets.yaml", contents, 0o600); err != nil {
		t.Fatal(err)
	}
	assetsFile = "assets.yaml"

	for _, format := range []string{"table", "json", "csv"} {
		t.Run(format, func(t *testing.T) {
			assetsFormat = format
			var out, errOut bytes.Buffer
			cmd := &cobra.Command{Use: "inventory"}
			cmd.SetOut(&out)
			cmd.SetErr(&errOut)
			if err := runAssetsInventory(cmd, nil); err != nil {
				t.Fatalf("inventory returned error: %v", err)
			}
			if errOut.Len() != 0 {
				t.Fatalf("unexpected stderr: %q", errOut.String())
			}
			if strings.Contains(out.String(), "\033[") {
				t.Fatalf("non-TTY output contains ANSI: %q", out.String())
			}
			switch format {
			case "table":
				if !strings.Contains(out.String(), "api-01") {
					t.Fatalf("table output missing asset: %q", out.String())
				}
			case "json":
				var parsed []assetEntry
				if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
					t.Fatalf("invalid JSON output: %v\n%s", err, out.String())
				}
				if len(parsed) != 1 || parsed[0].ID != "api-01" {
					t.Fatalf("unexpected JSON output: %+v", parsed)
				}
			case "csv":
				if !strings.HasPrefix(out.String(), "id,name,type,criticality") || !strings.Contains(out.String(), "api-01") {
					t.Fatalf("unexpected CSV output: %q", out.String())
				}
			}
		})
	}
}
