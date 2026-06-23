// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

//go:build windows

package accept

import (
	"fmt"

	"github.com/had-nu/wardex/v2/pkg/model"
)

// SyslogBackend is not available on Windows.
// NewSyslogBackend returns an error on this platform.
func NewSyslogBackend(address, protocol, facility string) (*SyslogBackend, error) {
	return nil, fmt.Errorf("%w: syslog backend is not supported on Windows", ErrForwardFailed)
}

// SyslogBackend is a stub that is never successfully instantiated on Windows.
type SyslogBackend struct {
	Address  string
	Protocol string
}

// Name returns the backend name for the stub.
func (b *SyslogBackend) Name() string { return "syslog" }

// Send always returns nil for the stub (never called in practice).
func (b *SyslogBackend) Send(entry model.AuditEntry) error { return nil }
