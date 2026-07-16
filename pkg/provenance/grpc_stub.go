// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

//go:build !grpc

package provenance

import (
	"context"
	"fmt"
)

type grpcAnchorer struct{}

func newGRPCAnchorer(_ context.Context, _ string) (Anchorer, error) {
	return nil, fmt.Errorf("grpc provenance driver not available: build with -tags grpc")
}
