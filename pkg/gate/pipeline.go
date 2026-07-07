// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package gate provides shared pipeline helpers for release gate evaluation.
package gate

import (
	"fmt"
	"io"
	"os"

	"github.com/had-nu/wardex/v2/config"
	pathguard "github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/accept"
	"github.com/had-nu/wardex/v2/pkg/epss"
	"github.com/had-nu/wardex/v2/pkg/model"
	"gopkg.in/yaml.v3"
)

// ResolveGateMode returns the effective gate mode from config and CLI flag.
func ResolveGateMode(cfg *config.Config, flagMode string) string {
	mode := "any"
	if cfg.ReleaseGate.Mode != "" {
		mode = cfg.ReleaseGate.Mode
	}
	if flagMode != "any" {
		mode = flagMode
	}
	return mode
}

// FilterAccepted removes CVEs covered by active risk acceptances.
func FilterAccepted(vulns []model.Vulnerability, cfg *config.Config, configPath string, logw io.Writer) []model.Vulnerability {
	key, err := accept.ResolveSecret(*cfg)
	if err != nil {
		fmt.Fprintf(logw, "[WARN] Cannot load acceptances — WARDEX_ACCEPT_SECRET not set. All CVEs will be evaluated without acceptance filtering.\n")
		return vulns
	}

	configHash, _ := accept.ConfigHash(configPath)
	accs, err := accept.Load("wardex-acceptances.yaml", key, "wardex-accept-audit.log", "", configHash, logw)
	if err != nil {
		return vulns
	}

	acceptedMap := make(map[string]bool, len(accs))
	for _, a := range accs {
		if !a.Revoked {
			acceptedMap[a.CVE] = true
		}
	}

	var filtered []model.Vulnerability
	for _, v := range vulns {
		if !acceptedMap[v.CVEID] {
			filtered = append(filtered, v)
		} else {
			fmt.Fprintf(logw, "[INFO] CVE %s covered by active risk acceptance — skipped.\n", v.CVEID)
		}
	}
	return filtered
}

// ApplyEPSSEnrichment loads and verifies a signed EPSS enrichment file,
// then applies scores to the vulnerability list.
func ApplyEPSSEnrichment(vulns []model.Vulnerability, cfg *config.Config, epssPath string, logw io.Writer) []model.Vulnerability {
	if epssPath == "" {
		return vulns
	}

	key, err := accept.ResolveSecret(*cfg)
	if err != nil {
		fmt.Fprintf(logw, "WARNING: Cannot verify EPSS enrichment without WARDEX_ACCEPT_SECRET.\n")
		return vulns
	}

	safeEnrichPath, err := pathguard.SafePath(epssPath)
	if err != nil {
		fmt.Fprintf(logw, "WARNING: EPSS enrichment path validation failed: %v\n", err)
		return vulns
	}

	edata, err := os.ReadFile(safeEnrichPath) // #nosec G304
	if err != nil {
		return vulns
	}

	var enrichFormat model.EPSSEnrichmentFile
	if err := yaml.Unmarshal(edata, &enrichFormat); err != nil {
		return vulns
	}

	if err := epss.Verify(enrichFormat, key); err != nil {
		fmt.Fprintf(logw, "WARNING: EPSS enrichment signature invalid: %v\n", err)
		return vulns
	}

	scoreMap := make(map[string]float64, len(enrichFormat.Enrichments))
	for _, e := range enrichFormat.Enrichments {
		scoreMap[e.CVE] = e.Score
	}

	for i, v := range vulns {
		if s, ok := scoreMap[v.CVEID]; ok {
			vulns[i].EPSSScore = s
			fmt.Fprintf(logw, "[INFO] Applied EPSS enrichment for %s: %.6f\n", v.CVEID, s)
		}
	}
	return vulns
}

// BuildForwarders creates forwarding backends from config.
func BuildForwarders(cfg *config.Config) []accept.Forwarder {
	if len(cfg.Reporting.GateLog.Forward) == 0 {
		return nil
	}

	var backends []accept.Forwarder
	for _, f := range cfg.Reporting.GateLog.Forward {
		switch f {
		case "syslog":
			if b, err := accept.NewSyslogBackend("localhost:514", "udp", "local0"); err == nil {
				backends = append(backends, b)
			}
		case "enisa":
			queuePath := "wardex-enisa-queue.jsonl"
			if cfg.Reporting.ENISAQueue.Path != "" {
				queuePath = cfg.Reporting.ENISAQueue.Path
			}
			fmt.Fprintf(os.Stderr, "[INFO] ENISABackend is a stub. No data will be transmitted.\n"+
				"       Queue path: %s\n"+
				"       When the ENISA single reporting platform API is published,\n"+
				"       update Wardex and configure ENISABackend.endpoint.\n", queuePath)
			backends = append(backends, accept.NewENISABackend(queuePath))
		}
	}
	return backends
}

// ResolveLogPath returns the effective audit log path from config and CLI flag.
func ResolveLogPath(cfg *config.Config, flagPath string) string {
	logPath := "wardex-gate-audit.log"
	if cfg.Reporting.GateLog.Path != "" {
		logPath = cfg.Reporting.GateLog.Path
	}
	if flagPath != "" {
		logPath = flagPath
	}
	return logPath
}

// ForwardAuditEntry dispatches an audit entry to configured forwarding backends.
func ForwardAuditEntry(cfg *config.Config, entry model.AuditEntry, logw io.Writer) {
	backends := BuildForwarders(cfg)
	if len(backends) == 0 {
		return
	}
	mux := accept.NewForwardMultiplexer(backends, cfg.Reporting.GateLog.OnFail)
	if err := mux.Dispatch(entry); err != nil {
		fmt.Fprintf(logw, "Error: gate log forwarding failed: %v\n", err)
	}
}
