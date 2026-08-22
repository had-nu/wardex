// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package provenance

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/config"
)

// tlsConfigFromOptions builds a *tls.Config from provenance options.
// Supported keys:
//   - tls_cert_file: path to TLS certificate for mTLS
//   - tls_key_file:  path to TLS private key
//   - tls_ca_file:   path to custom CA certificate
//   - tls_server_name: ServerName for TLS verification
//
// Returns nil when no TLS option is set (insecure fallback for dev).
func tlsConfigFromOptions(opts map[string]string) (*tls.Config, error) {
	if opts == nil {
		return nil, nil
	}
	if opts["tls_cert_file"] == "" && opts["tls_ca_file"] == "" {
		return nil, nil
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if opts["tls_server_name"] != "" {
		cfg.ServerName = opts["tls_server_name"]
	}

	if opts["tls_cert_file"] != "" && opts["tls_key_file"] != "" {
		cert, err := tls.LoadX509KeyPair(opts["tls_cert_file"], opts["tls_key_file"])
		if err != nil {
			return nil, fmt.Errorf("loading TLS cert pair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	if opts["tls_ca_file"] != "" {
		caCert, err := os.ReadFile(opts["tls_ca_file"])
		if err != nil {
			return nil, fmt.Errorf("reading CA cert: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", opts["tls_ca_file"])
		}
		cfg.RootCAs = caPool
	}

	return cfg, nil
}

// New creates a 3CP Anchorer backend based on configuration.
// Supported drivers:
//   - "noop" or "": dry-run (no persistence)
//   - "grpc": remote 3CP-compatible gRPC service (Gleipnir, Carcosa, etc.)
//   - "gleipnir-embedded": embedded Gleipnir consensus engine
//
// Each driver maps the 3CP Anchorer interface to its native protocol.
// Adding a new 3CP backend requires implementing the Anchorer interface.
func New(ctx context.Context, cfg config.ProvenanceConfig) (Anchorer, error) {
	switch cfg.Enabled {
	case "noop", "":
		return &noopAnchorer{}, nil
	case "grpc":
		tlsCfg, err := tlsConfigFromOptions(cfg.Options)
		if err != nil {
			return nil, fmt.Errorf("grpc TLS setup: %w", err)
		}
		return newGRPCAnchorer(ctx, cfg.Address, tlsCfg)
	case "gleipnir-embedded":
		return newEmbeddedGleipnir(cfg.Options)
	default:
		return nil, fmt.Errorf("unknown 3CP provenance driver: %s. Supported: noop, grpc, gleipnir-embedded", cfg.Enabled)
	}
}
