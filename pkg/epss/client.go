// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package epss

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxEPSSResponseSize = 1 << 20 // 1 MiB

// FirstAPIResponse models the structured response from api.first.org/data/v1/epss
type FirstAPIResponse struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status-code"`
	Version    string `json:"version"`
	Access     string `json:"access"`
	Total      int    `json:"total"`
	Offset     int    `json:"offset"`
	Limit      int    `json:"limit"`
	Data       []Data `json:"data"`
}

// Data holds the individual CVE score record.
type Data struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"` // API returns float as string "0.00412"
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}

// FetchScores queries the FIRST.org API for a list of CVE IDs and parses
// the returned EPSS probabilities. It batches requests natively (the API allows
// comma-separated CVEs). Malformed/out-of-range scores are logged to logw when non-nil.
func FetchScores(cves []string, logw io.Writer) (map[string]float64, map[string]string, error) {
	if len(cves) == 0 {
		return nil, nil, nil // Nothing to fetch
	}

	scores := make(map[string]float64)
	provenance := make(map[string]string)
	chunkSize := 50 // FIRST API accepts multiple CVEs, let's chunk to avoid URI limits
	var skippedMalformed, skippedOutOfRange int

	client := &http.Client{Timeout: 10 * time.Second}

	for i := 0; i < len(cves); i += chunkSize {
		end := i + chunkSize
		if end > len(cves) {
			end = len(cves)
		}

		chunk := cves[i:end]
		query := strings.Join(chunk, ",")
		url := fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s", query)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("failed creating EPSS request: %w", err)
		}

		// User-Agent is good practice for public APIs
		req.Header.Set("User-Agent", "Wardex/2.1.2 (+https://github.com/had-nu/wardex)")

		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, fmt.Errorf("failed executing EPSS request: %w", err)
		}

		defer func() { _ = resp.Body.Close() }()

		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			provenance["tls_peer_cert_sha256"] = fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
		}
		provenance["api_endpoint"] = "api.first.org"

		if resp.StatusCode != http.StatusOK {
			return nil, nil, fmt.Errorf("first API returned non-200 status: %d", resp.StatusCode)
		}

		var apiResp FirstAPIResponse
		decoder := json.NewDecoder(io.LimitReader(resp.Body, maxEPSSResponseSize))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&apiResp); err != nil {
			return nil, nil, fmt.Errorf("failed decoding EPSS JSON response: %w", err)
		}

		for _, item := range apiResp.Data {
			val, err := strconv.ParseFloat(item.EPSS, 64)
			if err != nil {
				skippedMalformed++
				continue
			}

			// Range validation
			if val < 0.0 || val > 1.0 {
				skippedOutOfRange++
				continue
			}

			scores[item.CVE] = val
		}

		// Polite delay between chunks if multiple
		if end < len(cves) {
			time.Sleep(500 * time.Millisecond)
		}
	}

	if logw != nil {
		if skippedMalformed > 0 {
			fmt.Fprintf(logw, "[WARN] %d EPSS scores skipped — malformed float values (will default to worst-case 1.0)\n", skippedMalformed)
		}
		if skippedOutOfRange > 0 {
			fmt.Fprintf(logw, "[WARN] %d EPSS scores skipped — out of range [0.0, 1.0] (will default to worst-case 1.0)\n", skippedOutOfRange)
		}
	}

	return scores, provenance, nil
}
