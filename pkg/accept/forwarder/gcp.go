// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

//go:build gcp

package forwarder

import (
	"context"

	"cloud.google.com/go/logging"
	"github.com/had-nu/wardex/pkg/model"
)

type GCPBackend struct {
	ProjectID string
	LogID     string
	client    *logging.Client
	logger    *logging.Logger
}

func NewGCPBackend(projectID, logID string) (*GCPBackend, error) {
	ctx := context.Background()
	client, err := logging.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}

	logger := client.Logger(logID)
	return &GCPBackend{
		ProjectID: projectID,
		LogID:     logID,
		client:    client,
		logger:    logger,
	}, nil
}

func (b *GCPBackend) Name() string {
	return "gcp_logging"
}

func (b *GCPBackend) Send(entry model.AuditEntry) error {
	b.logger.Log(logging.Entry{
		Payload:  entry,
		Severity: logging.Info,
	})
	// Sync blocks until all logs have been sent.
	return b.logger.Flush()
}
