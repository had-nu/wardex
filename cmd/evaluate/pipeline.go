// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package evaluate

import (
	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/gate"
	"github.com/had-nu/wardex/v2/pkg/model"
	"io"
)

func resolveGateMode(cfg *config.Config, flagMode string) string {
	return gate.ResolveGateMode(cfg, flagMode)
}

func filterAccepted(vulns []model.Vulnerability, cfg *config.Config, configPath string, logw io.Writer) []model.Vulnerability {
	return gate.FilterAccepted(vulns, cfg, configPath, logw)
}

func applyEPSSEnrichment(vulns []model.Vulnerability, cfg *config.Config, epssPath string, logw io.Writer) []model.Vulnerability {
	return gate.ApplyEPSSEnrichment(vulns, cfg, epssPath, logw)
}

func resolveLogPath(cfg *config.Config, flagPath string) string {
	return gate.ResolveLogPath(cfg, flagPath)
}

func forwardAuditEntry(cfg *config.Config, entry model.AuditEntry, logw io.Writer) {
	gate.ForwardAuditEntry(cfg, entry, logw)
}
