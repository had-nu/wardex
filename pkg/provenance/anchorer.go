// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package provenance

import "context"

type Anchorer interface {
	Submit(ctx context.Context, hash []byte, label string) (*AnchorResult, error)
	Verify(ctx context.Context, hash []byte) (*AnchorResult, error)
	WaitForAnchor(ctx context.Context, hash []byte) (*AnchorResult, error)
	Status(ctx context.Context) (*Health, error)
	Close() error
}

type AnchorResult struct {
	Found      bool
	BlockIndex uint64
	BlockTime  int64
	StateRoot  []byte
	Proof      []byte
	Label      string
}

type Health struct {
	BlockHeight  uint64
	Pending      int
	ActivePeers  int
}
