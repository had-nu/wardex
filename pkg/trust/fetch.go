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
)

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
// Remote URLs are fetched via HTTP with a 10s timeout and 1MB limit.
func FetchTrustStore(ref string) ([]byte, error) {
	if strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "http://") {
		return fetchRemote(ref)
	}
	// Local path
	data, err := os.ReadFile(ref) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("trust store: read local %q: %w", ref, err)
	}
	return data, nil
}

func fetchRemote(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("trust store: build request: %w", err)
	}
	req.Header.Set("User-Agent", "wardex/trust-fetch")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("trust store: fetch %q: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trust store: fetch %q: HTTP %d", url, resp.StatusCode)
	}

	// 1MB max to prevent abuse
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
