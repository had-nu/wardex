// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package provenance

import "context"

type noopAnchorer struct{}

func (*noopAnchorer) Submit(_ context.Context, hash []byte, label string) (*AnchorResult, error) {
	return &AnchorResult{Found: false, Label: label}, nil
}

func (*noopAnchorer) Verify(_ context.Context, _ []byte) (*AnchorResult, error) {
	return &AnchorResult{Found: false}, nil
}

func (*noopAnchorer) WaitForAnchor(_ context.Context, _ []byte) (*AnchorResult, error) {
	return &AnchorResult{Found: false}, nil
}

func (*noopAnchorer) Status(_ context.Context) (*Health, error) {
	return &Health{}, nil
}

func (*noopAnchorer) Close() error { return nil }
