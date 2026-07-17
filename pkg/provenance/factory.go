// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package provenance

import (
	"context"
	"fmt"

	"github.com/had-nu/wardex/v2/config"
)

// New creates a 3CP Anchorer backend based on configuration.
// Supported drivers:
//   - "noop" or "": dry-run (no persistence)
//   - "grpc": remote 3CP-compatible gRPC service (Gleipnir, Carcosa, etc.)
//   - "gleipnir-embedded": embedded Gleipnir consensus engine
//
// Each driver maps the 3CP Anchorer interface to its native protocol.
// Adding a new 3CP backend requires implementing the Anchorer interface.
func New(ctx context.Context, cfg config.ProvenanceConfig) (Anchorer, error) {
	switch cfg.Enabled {
	case "noop", "":
		return &noopAnchorer{}, nil
	case "grpc":
		return newGRPCAnchorer(ctx, cfg.Address)
	case "gleipnir-embedded":
		return newEmbeddedGleipnir(cfg.Options)
	default:
		return nil, fmt.Errorf("unknown 3CP provenance driver: %s. Supported: noop, grpc, gleipnir-embedded", cfg.Enabled)
	}
}
