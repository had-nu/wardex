// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

//go:build grpc

// 3CP gRPC backend — Gleipnir reference implementation adapter.
// Maps 3CP SubmitEnvelope types to Gleipnir's protobuf wire format.
// Replaceable with any 3CP-compatible gRPC service (Carcosa, etc.).

package provenance

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/had-nu/gleipnir/pkg/server/pb"
)

type grpcAnchorer struct {
	conn   *grpc.ClientConn
	client pb.ProvenanceAnchorClient
}

func newGRPCAnchorer(ctx context.Context, address string, tlsConfig *tls.Config) (*grpcAnchorer, error) {
	var opts []grpc.DialOption
	if tlsConfig != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	opts = append(opts, grpc.WithBlock())

	conn, err := grpc.DialContext(ctx, address, opts...)
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

func (g *grpcAnchorer) SubmitAttested(ctx context.Context, hash []byte, label string, reference []byte) (*AnchorResult, error) {
	env := SubmitEnvelope{
		Hash:      hash,
		Label:     label,
		Reference: reference,
		Timestamp: time.Now().UnixNano(),
	}

	resp, err := g.client.SubmitHash(ctx, &pb.SubmitRequest{
		Hash:      env.Hash,
		Label:     env.Label,
		Timestamp: env.Timestamp,
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
