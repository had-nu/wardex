// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package trust

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/had-nu/wardex/v3/pkg/cli"
)

const (
	// fetchTimeout bounds one remote trust store read. The trust store is read
	// during release gating, so an unresponsive endpoint must not stall the
	// pipeline. Mirrors the EPSS client ceiling.
	fetchTimeout = 10 * time.Second

	// maxTrustStoreSize caps the remote response at 1MB to prevent abuse.
	maxTrustStoreSize = 1 << 20
)

// remoteClient carries a hard transport ceiling that does not depend on the
// caller's context. A trust store read must stay bounded even when the caller
// passes a context with no deadline.
var remoteClient = &http.Client{Timeout: fetchTimeout}

// ResolveTrustStoreRef resolves the trust store reference by precedence:
// --trust flag > WARDEX_TRUST_STORE env > config trust_store_ref > ./wardex-trust.yaml
func ResolveTrustStoreRef(flagValue, configValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("WARDEX_TRUST_STORE"); env != "" {
		return env
	}
	if configValue != "" {
		return configValue
	}
	return "./wardex-trust.yaml"
}

// FetchTrustStore resolves and reads a trust store from a URL or local path.
// Remote URLs are fetched via HTTP with a bounded deadline and a 1MB limit.
func FetchTrustStore(ctx context.Context, ref string) ([]byte, error) {
	if strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "http://") {
		return fetchRemote(ctx, ref, fetchTimeout)
	}
	// Local path
	data, err := cli.ReadFile(ref) // #nosec G304 -- resolved by ResolveTrustStoreRef
	if err != nil {
		return nil, fmt.Errorf("trust store: read local %q: %w", ref, err)
	}
	return data, nil
}

// fetchRemote reads a remote trust store under an explicit deadline. The
// deadline is a parameter so the bound is testable without a production-length
// wait, and so every caller can pass the ceiling it needs.
func fetchRemote(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = fetchTimeout
	}

	// Bound the read here rather than in the caller. Every entry point that
	// resolves a remote reference must inherit the same ceiling.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("trust store: build request: %w", err)
	}
	req.Header.Set("User-Agent", "wardex/trust-fetch")

	resp, err := remoteClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("trust store: fetch %q: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trust store: fetch %q: HTTP %d", url, resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxTrustStoreSize))
}
