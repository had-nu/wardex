// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package orchestrator

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/internal/cpl"
	acceptaudit "github.com/had-nu/wardex/v2/pkg/accept/audit"
	"github.com/had-nu/wardex/v2/pkg/enrich"
	"github.com/had-nu/wardex/v2/pkg/gate"
	"github.com/had-nu/wardex/v2/pkg/model"
)

// Audit event names for the forced_upgrade tripwire (L7, spec §11.2).
const (
	eventForcedUpgradeArmed    = "forced_upgrade.armed"
	eventForcedUpgradeDisarmed = "forced_upgrade.disarmed"
)

// forcedUpgradeStatus carries the L7 regulatory-deadline gate state for one
// RunGate invocation. Absence of a source never freezes the pipeline: the
// tripwire disarms after N consecutive evidence-refresh failures and the gate
// returns to policy evaluation (P11).
type forcedUpgradeStatus struct {
	armed       bool
	tripwireN   int
	consecutive int
	counterPath string
	logPath     string
	opts        GateOptions
	cfg         *config.Config
	ctx         context.Context
}

// newForcedUpgrade arms the gate when forced_upgrade is activated by flag or by
// sealed config (gate.forced_upgrade). It returns nil when inactive, leaving
// current behaviour untouched. On first activation it persists an armed state
// and emits a forced_upgrade.armed audit entry.
func newForcedUpgrade(ctx context.Context, opts GateOptions, cfg *config.Config) *forcedUpgradeStatus {
	enabled := opts.ForcedUpgrade || (cfg.ReleaseGate.ForcedUpgrade != nil && cfg.ReleaseGate.ForcedUpgrade.Enabled)
	if !enabled {
		return nil
	}

	f := &forcedUpgradeStatus{
		tripwireN:   config.DefaultForcedUpgradeTripwireFailures,
		counterPath: resolveForcedUpgradeCounterPath(opts, cfg),
		opts:        opts,
		cfg:         cfg,
		ctx:         ctx,
	}
	if cfg.ReleaseGate.ForcedUpgrade != nil {
		f.tripwireN = cfg.ReleaseGate.ForcedUpgrade.Tripwire()
	}
	f.logPath = gate.ResolveLogPath(cfg, opts.GateLogPath)

	state, err := enrich.LoadTripwire(f.counterPath)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "[WARN] forced_upgrade tripwire state unreadable (%v); starting fresh (armed).\n", err)
		state = &enrich.TripwireState{}
	}
	// A missing file is a legitimate zero-state (not an error from
	// LoadTripwire), so probe existence separately to detect first activation.
	_, statErr := os.Stat(f.counterPath)
	existed := statErr == nil
	f.armed = state.Armed
	f.consecutive = state.Consecutive

	if !existed {
		// First activation: arm the gate and record it in the audit chain.
		state.Armed = true
		if err := state.Save(f.counterPath); err != nil {
			fmt.Fprintf(opts.Stderr, "[WARN] cannot persist forced_upgrade tripwire state: %v\n", err)
		}
		f.armed = true
		if !opts.DryRun {
			f.logTransition(eventForcedUpgradeArmed,
				"CRA regulatory gate armed: releases require attested evidence (valid seal, intact chain, fresh EPSS/KEV)")
		}
		fmt.Fprintf(opts.Stderr, "[FORCED-UPGRADE] armed — release attestation required (tripwire disarms after %d consecutive evidence-refresh failures).\n", f.tripwireN)
		return f
	}

	switch {
	case f.armed:
		fmt.Fprintf(opts.Stderr, "[FORCED-UPGRADE] gate armed (tripwire: %d consecutive failures).\n", f.tripwireN)
	case !f.armed:
		fmt.Fprintf(opts.Stderr, "[FORCED-UPGRADE] gate DISARMED by tripwire (previous run); restoring after fresh evidence.\n")
	}
	return f
}

// resolveForcedUpgradeCounterPath derives the tripwire counter file location,
// honouring an explicit override then the state-store directory.
func resolveForcedUpgradeCounterPath(opts GateOptions, cfg *config.Config) string {
	if opts.ForcedUpgradeState != "" {
		return opts.ForcedUpgradeState
	}
	dir := cfg.StateStore.Dir
	if dir == "" {
		dir = ".wardex"
	}
	return enrich.TripwireFilePath(dir)
}

// failure records an evidence-refresh failure. It returns whether the gate is
// still armed: when the tripwire disarms, the caller must fall back to policy
// evaluation and a forced_upgrade.disarmed entry is chained.
func (f *forcedUpgradeStatus) failure() bool {
	state, err := enrich.LoadTripwire(f.counterPath)
	if err != nil {
		state = &enrich.TripwireState{Armed: f.armed}
	}
	wasArmed := state.Armed
	stillArmed := state.Step(true, f.tripwireN)
	f.armed = stillArmed
	f.consecutive = state.Consecutive

	f.persist(state)
	if f.opts.DryRun {
		if wasArmed && !stillArmed {
			fmt.Fprintf(f.opts.Stderr, "[FORCED-UPGRADE] [dry-run] tripwire would DISARM after %d consecutive failures.\n", f.consecutive)
		}
		return stillArmed
	}
	if wasArmed && !stillArmed {
		f.logTransition(eventForcedUpgradeDisarmed,
			fmt.Sprintf("tripwire disarmed after %d consecutive evidence-refresh failures (threshold %d); gate falls back to policy evaluation",
				f.consecutive, f.tripwireN))
		fmt.Fprintf(f.opts.Stderr, "\n[FORCED-UPGRADE] TRIPWIRE DISARMED after %d consecutive evidence-refresh failures.\n", f.consecutive)
		fmt.Fprintf(f.opts.Stderr, "                 Release attestation suspended; resuming policy evaluation while evidence cannot be refreshed.\n")
	}
	return stillArmed
}

// success records a successful evidence refresh, resetting the failure
// counter. A disarmed gate re-arms with fresh evidence and a
// forced_upgrade.armed entry is chained.
func (f *forcedUpgradeStatus) success() {
	state, err := enrich.LoadTripwire(f.counterPath)
	if err != nil {
		state = &enrich.TripwireState{Armed: f.armed}
	}
	wasArmed := state.Armed
	_ = state.Step(false, f.tripwireN)
	f.armed = true
	f.consecutive = 0

	f.persist(state)
	if f.opts.DryRun {
		if !wasArmed {
			fmt.Fprintf(f.opts.Stderr, "[FORCED-UPGRADE] [dry-run] fresh evidence would re-arm the gate.\n")
		}
		return
	}
	if !wasArmed {
		f.logTransition(eventForcedUpgradeArmed,
			fmt.Sprintf("evidence freshness restored; forced_upgrade gate re-armed after %d accumulated failures", f.consecutive))
		fmt.Fprintf(f.opts.Stderr, "[FORCED-UPGRADE] re-armed — evidence freshness restored.\n")
	}
}

// persist writes the counter state atomically; failures never block the gate.
func (f *forcedUpgradeStatus) persist(state *enrich.TripwireState) {
	if err := state.Save(f.counterPath); err != nil {
		fmt.Fprintf(f.opts.Stderr, "[WARN] cannot persist forced_upgrade tripwire state: %v\n", err)
	}
}

// logTransition chains a forced_upgrade.{armed,disarmed} audit entry. A
// non-writable chain must never block the gate.
func (f *forcedUpgradeStatus) logTransition(event, detail string) {
	if f.logPath == "" || f.logPath == "/dev/null" {
		return
	}
	configHash, _ := cpl.ConfigHash(f.opts.ConfigPath)
	entry := model.AuditEntry{
		Timestamp:        time.Now().UTC(),
		Event:            event,
		CplSchemaVersion: config.CurrentConfigSchemaVersion,
		ConfigHash:       configHash,
		CliOverrides:     collectCLIOverrides(f.opts),
		Detail:           detail,
		Actor:            os.Getenv("WARDEX_ACTOR"),
		ReleaseVersion:   f.opts.ReleaseVersion,
		PolicyRef:        f.opts.PolicyRef,
	}
	if err := acceptaudit.ChainedAuditLog(f.logPath, entry); err != nil {
		fmt.Fprintf(f.opts.Stderr, "Warning: failed to chain forced_upgrade audit entry: %v\n", err)
		return
	}
	fmt.Fprintf(f.opts.Stderr, "[INFO] forced_upgrade transition chained → %s\n", f.logPath)
}
