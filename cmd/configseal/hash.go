package configseal

import (
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/internal/cpl"
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

	raw, err := os.ReadFile(hashConfigPath) // #nosec G304 — user-provided path via --config flag
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	hash, err := cpl.ComputeConfigHash(raw, algo)
	if err != nil {
		return fmt.Errorf("compute hash: %w", err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), hash)
	return nil
}
