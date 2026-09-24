package auth

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/ui"
)

func canonicalAuthGolden(value []byte) []byte {
	return append(bytes.TrimRight(value, "\n"), '\n')
}

func TestAuthStatusDashboardGolden(t *testing.T) {
	var out bytes.Buffer
	profile := ui.Profile{
		Interactive: true,
		ColorDepth:  ui.ColorNone,
		Unicode:     false,
		Width:       80,
	}
	ui.NewRenderer(&out, profile).Dashboard(
		buildAuthStatusDashboard("wardex-trust.yaml", 3, 1, "admin-01", nil),
	)

	golden := filepath.Join("testdata", "auth-status.golden")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, canonicalAuthGolden(out.Bytes()), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden: %v (run with UPDATE_GOLDEN=1)", err)
	}
	if !bytes.Equal(canonicalAuthGolden(want), canonicalAuthGolden(out.Bytes())) {
		t.Fatalf("auth status dashboard differs from golden %q", golden)
	}
}
