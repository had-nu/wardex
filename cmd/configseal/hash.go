package configseal

import (
	"fmt"

	"github.com/had-nu/wardex/v2/internal/cpl"
	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

var (
	hashConfigPath string
	hashAlgorithm  string
)

var HashCmd = &cobra.Command{
	Use:   "hash",
	Short: "Compute the cryptographic hash of a configuration file",
	Long: `Compute a deterministic SHA-256 or BLAKE3 hash of a wardex-config.yaml file.

The hash is computed over the canonicalised YAML content (sorted keys, no comments,
normalised whitespace), NOT over raw bytes. This guarantees that semantically
equivalent configurations produce the same hash regardless of formatting.

Output format: <algorithm>:<hex>

Examples:
  wardex config hash --config wardex-config.yaml
  wardex config hash --config wardex-config.yaml --algorithm blake3`,
	RunE: runConfigHash,
}

func init() {
	HashCmd.Flags().StringVar(&hashConfigPath, "config", "", "Path to wardex-config.yaml (required)")
	HashCmd.Flags().StringVar(&hashAlgorithm, "algorithm", "sha256", "Hash algorithm: sha256|blake3")
	_ = HashCmd.MarkFlagRequired("config")
}

func runConfigHash(cmd *cobra.Command, args []string) error {
	var algo cpl.Algorithm
	switch hashAlgorithm {
	case "sha256":
		algo = cpl.AlgoSHA256
	case "blake3":
		algo = cpl.AlgoBLAKE3
	default:
		return fmt.Errorf("unsupported algorithm %q: use sha256 or blake3", hashAlgorithm)
	}

	stderr := cmd.ErrOrStderr()
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(buildConfigHashSession(hashConfigPath, hashAlgorithm))
	reportProgress := func(number int, name, status, detail string) {
		progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
	}
	reportProgress(1, "Reading configuration", "RUNNING", hashConfigPath)
	raw, err := cli.SafeReadFile(hashConfigPath)
	if err != nil {
		reportProgress(1, "Reading configuration", "FAILED", err.Error())
		return fmt.Errorf("reading config file: %w", err)
	}
	reportProgress(1, "Reading configuration", "DONE", fmt.Sprintf("%d bytes", len(raw)))
	reportProgress(2, "Computing canonical hash", "RUNNING", hashAlgorithm)
	hash, err := cpl.ComputeConfigHash(raw, algo)
	if err != nil {
		reportProgress(2, "Computing canonical hash", "FAILED", err.Error())
		return fmt.Errorf("compute hash: %w", err)
	}
	reportProgress(2, "Computing canonical hash", "DONE", hash)
	reportProgress(3, "Finalizing hash result", "RUNNING", "")
	reportProgress(3, "Finalizing hash result", "DONE", "hash ready")
	if configResultEnabled(cmd, progress) {
		_ = ui.RenderResults(stderr, buildConfigHashDashboard(hashConfigPath, hashAlgorithm, hash))
		return nil
	}
	fmt.Fprintln(configCommandOutput(cmd), hash)
	return nil
}
