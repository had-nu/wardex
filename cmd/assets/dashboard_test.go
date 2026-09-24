package assets

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
)

func TestAssetsCommandOutputUsesCobraWriter(t *testing.T) {
	var out bytes.Buffer
	cmd := &cobra.Command{Use: "inventory"}
	cmd.SetOut(&out)
	if got := assetsCommandOutput(cmd); got != &out {
		t.Fatal("configured assets stdout writer was not selected")
	}
}
