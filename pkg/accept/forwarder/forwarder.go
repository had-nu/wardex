// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package forwarder

import (
	"errors"

	"github.com/had-nu/wardex/pkg/model"
)

var (
	ErrForwardFailed = errors.New("failed to forward audit log to external system")
)

// Forwarder represents a destination backend for audit log entries.
type Forwarder interface {
	Send(entry model.AuditEntry) error
	Name() string
}

// Multiplexer allows sending to multiple forwarders at once
type Multiplexer struct {
	backends []Forwarder
	onFail   string // "block" | "warn" | "best_effort"
}

func NewMultiplexer(backends []Forwarder, onFail string) *Multiplexer {
	if onFail == "" {
		onFail = "warn"
	}
	return &Multiplexer{backends: backends, onFail: onFail}
}

// Dispatch sends the entry to all configured backends.
func (m *Multiplexer) Dispatch(entry model.AuditEntry) error {
	var errs []error
	for _, backend := range m.backends {
		if err := backend.Send(entry); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		if m.onFail == "block" {
			return ErrForwardFailed
		}
		// Otherwise we just warn or best_effort (log the failure but don't stop)
		// Usually we'd want to write `forward.failed` to the local audit log.
	}

	return nil
}
