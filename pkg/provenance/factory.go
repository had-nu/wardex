// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package provenance

import (
	"context"
	"fmt"

	"github.com/had-nu/wardex/v2/config"
)

func New(ctx context.Context, cfg config.ProvenanceConfig) (Anchorer, error) {
	switch cfg.Enabled {
	case "noop", "":
		return &noopAnchorer{}, nil
	case "grpc":
		return newGRPCAnchorer(ctx, cfg.Address)
	case "gleipnir-embedded":
		return newEmbeddedGleipnir(cfg.Options)
	default:
		return nil, fmt.Errorf("unknown provenance driver: %s", cfg.Enabled)
	}
}
