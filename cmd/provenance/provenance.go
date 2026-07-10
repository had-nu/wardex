// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package provenance

import (
	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/provenance"
	"github.com/spf13/cobra"
)

var configPath string

var ProvenanceCmd = &cobra.Command{
	Use:   "provenance",
	Short: "Cryptographic provenance anchoring",
	Long: `Anchoring of cryptographic hashes into an immutable provenance chain.

Provides transparent tamper-evident records for releases, builds, and
compliance artifacts. Supports multiple backends:
  - gleipnir-embedded: embed the Gleipnir consensus engine locally
  - grpc: connect to a remote provenance anchor service
  - noop: dry-run mode (default)

Examples:
  wardex provenance submit <sha256hex> --label "release-v2.3.0"
  wardex provenance verify <sha256hex>
  wardex provenance status
  wardex provenance seal --dir ./dist --label "release-v2.3.0"`,
}

func init() {
	ProvenanceCmd.PersistentFlags().StringVar(&configPath, "config", "./wardex-config.yaml", "Path to wardex-config.yaml")
	ProvenanceCmd.AddCommand(submitCmd)
	ProvenanceCmd.AddCommand(verifyCmd)
	ProvenanceCmd.AddCommand(statusCmd)
	ProvenanceCmd.AddCommand(sealCmd)
}

func getAnchorer() (provenance.Anchorer, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	return provenance.New(nil, cfg.Provenance)
}
