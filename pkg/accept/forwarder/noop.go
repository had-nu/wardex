// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package forwarder

import "github.com/had-nu/wardex/pkg/model"

// NoOpBackend simply discards the payload. Useful for testing and local dev.
type NoOpBackend struct{}

func (b *NoOpBackend) Name() string {
	return "noop"
}

func (b *NoOpBackend) Send(entry model.AuditEntry) error {
	return nil
}
