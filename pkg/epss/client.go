// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package epss

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// FirstAPIResponse models the structured response from api.first.org/data/v1/epss
type FirstAPIResponse struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status-code"`
	Version    string `json:"version"`
	Access     string `json:"access"`
	Total      int    `json:"total"`
	Offset     int    `json:"offset"`
	Limit      int    `json:"limit"`
	Data       []EPSSData `json:"data"`
}

// EPSSData holds the individual CVE score record
type EPSSData struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"` // API returns float as string "0.00412"
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}

// FetchScores queries the FIRST.org API for a list of CVE IDs and parses
// the returned EPSS probabilities. It batches requests natively (the API allows
// comma-separated CVEs).
func FetchScores(cves []string) (map[string]float64, error) {
	if len(cves) == 0 {
		return nil, nil // Nothing to fetch
	}

	scores := make(map[string]float64)
	chunkSize := 50 // FIRST API accepts multiple CVEs, let's chunk to avoid URI limits

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
			return nil, fmt.Errorf("failed creating EPSS request: %w", err)
		}

		// User-Agent is good practice for public APIs
		req.Header.Set("User-Agent", "Wardex/1.7.0 (+https://github.com/had-nu/wardex)")
		
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed executing EPSS request: %w", err)
		}
		
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("first API returned non-200 status: %d", resp.StatusCode)
		}

		var apiResp FirstAPIResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed decoding EPSS JSON response: %w", err)
		}
		resp.Body.Close()

		for _, item := range apiResp.Data {
			val, err := strconv.ParseFloat(item.EPSS, 64)
			if err != nil {
				continue // Skip malformed floats instead of dying
			}
			scores[item.CVE] = val
		}
		
		// Polite delay between chunks if multiple
		if end < len(cves) {
			time.Sleep(500 * time.Millisecond)
		}
	}

	return scores, nil
}
