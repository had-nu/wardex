// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

//go:build grpc

package provenance

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/had-nu/gleipnir/pkg/server/pb"
)

type grpcAnchorer struct {
	conn   *grpc.ClientConn
	client pb.ProvenanceAnchorClient
}

func newGRPCAnchorer(ctx context.Context, address string) (*grpcAnchorer, error) {
	conn, err := grpc.DialContext(ctx, address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("connecting to provenance anchor: %w", err)
	}
	return &grpcAnchorer{
		conn:   conn,
		client: pb.NewProvenanceAnchorClient(conn),
	}, nil
}

func (g *grpcAnchorer) Submit(ctx context.Context, hash []byte, label string) (*AnchorResult, error) {
	resp, err := g.client.SubmitHash(ctx, &pb.SubmitRequest{
		Hash:      hash,
		Label:     label,
		Timestamp: time.Now().UnixNano(),
	})
	if err != nil {
		return nil, err
	}
	return &AnchorResult{
		Found: resp.Accepted,
		Label: label,
	}, nil
}

func (g *grpcAnchorer) Verify(ctx context.Context, hash []byte) (*AnchorResult, error) {
	resp, err := g.client.VerifyHash(ctx, &pb.VerifyRequest{Hash: hash})
	if err != nil {
		return nil, err
	}
	return &AnchorResult{
		Found:      resp.Found,
		BlockIndex: resp.BlockIndex,
		BlockTime:  resp.BlockTime,
		StateRoot:  resp.StateRoot,
		Proof:      resp.SmtProof,
		Label:      resp.Label,
	}, nil
}

func (g *grpcAnchorer) WaitForAnchor(ctx context.Context, hash []byte) (*AnchorResult, error) {
	resp, err := g.client.WaitForAnchor(ctx, &pb.WaitRequest{Hash: hash})
	if err != nil {
		return nil, err
	}
	return &AnchorResult{
		Found:      resp.Found,
		BlockIndex: resp.BlockIndex,
		BlockTime:  resp.BlockTime,
		StateRoot:  resp.StateRoot,
		Proof:      resp.SmtProof,
		Label:      resp.Label,
	}, nil
}

func (g *grpcAnchorer) Status(ctx context.Context) (*Health, error) {
	resp, err := g.client.GetHealth(ctx, &pb.Empty{})
	if err != nil {
		return nil, err
	}
	return &Health{
		BlockHeight: resp.BlockHeight,
		Pending:     int(resp.PendingHashes),
		ActivePeers: int(resp.ActivePeers),
	}, nil
}

func (g *grpcAnchorer) Close() error {
	return g.conn.Close()
}

var _ Anchorer = (*grpcAnchorer)(nil)
