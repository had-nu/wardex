// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package provenance

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/had-nu/gleipnir/pkg/consensus"
	"github.com/had-nu/gleipnir/pkg/identity"
)

type embeddedGleipnir struct {
	engine   *consensus.Engine
	submitter []byte
}

func newEmbeddedGleipnir(opts map[string]string) (*embeddedGleipnir, error) {
	cycleInterval := 3 * time.Second
	if v, ok := opts["cycle_interval"]; ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("invalid cycle_interval: %w", err)
		}
		cycleInterval = d
	}

	nodeID := "wardex-embedded"
	if v, ok := opts["node_id"]; ok {
		nodeID = v
	}

	simulated := true
	if v, ok := opts["simulated"]; ok {
		simulated, _ = strconv.ParseBool(v)
	}

	uid := identity.NewUIDZero(nodeID, simulated)
	uid.Seal()

	node := consensus.Node{
		UID:  *uid,
		Addr: nodeID,
	}

	engine := consensus.NewEngine(node, cycleInterval)
	engine.Start()

	return &embeddedGleipnir{
		engine:   engine,
		submitter: uid.RootID,
	}, nil
}

func (g *embeddedGleipnir) Submit(ctx context.Context, hash []byte, label string) (*AnchorResult, error) {
	var h [32]byte
	copy(h[:], hash)

	_, err := g.engine.Submit(ctx, h, g.submitter, label)
	if err != nil {
		return nil, err
	}
	return &AnchorResult{
		Found:      false,
		Label:      label,
	}, nil
}

func (g *embeddedGleipnir) Verify(ctx context.Context, hash []byte) (*AnchorResult, error) {
	var h [32]byte
	copy(h[:], hash)

	proof, err := g.engine.VerifyHash(ctx, h)
	if err != nil {
		return nil, err
	}
	return &AnchorResult{
		Found:      proof.Found,
		BlockIndex: proof.BlockIndex,
		BlockTime:  proof.BlockTime,
		StateRoot:  proof.StateRoot,
		Proof:      proof.SMTProof,
		Label:      proof.Label,
	}, nil
}

func (g *embeddedGleipnir) WaitForAnchor(ctx context.Context, hash []byte) (*AnchorResult, error) {
	var h [32]byte
	copy(h[:], hash)

	proof, err := g.engine.WaitForAnchor(ctx, h)
	if err != nil {
		return nil, err
	}
	return &AnchorResult{
		Found:      proof.Found,
		BlockIndex: proof.BlockIndex,
		BlockTime:  proof.BlockTime,
		StateRoot:  proof.StateRoot,
		Proof:      proof.SMTProof,
		Label:      proof.Label,
	}, nil
}

func (g *embeddedGleipnir) Status(ctx context.Context) (*Health, error) {
	h, err := g.engine.GetNetworkHealth(ctx)
	if err != nil {
		return nil, err
	}
	return &Health{
		BlockHeight: h.BlockHeight,
		Pending:     h.PendingHashes,
		ActivePeers: h.ActivePeers,
	}, nil
}

func (g *embeddedGleipnir) Close() error {
	g.engine.Stop()
	return nil
}

var _ Anchorer = (*embeddedGleipnir)(nil)
