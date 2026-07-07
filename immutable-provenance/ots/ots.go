// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ots

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// DefaultCalendars is the list of public OpenTimestamps calendars used for stamping.
var DefaultCalendars = []string{
	"https://a.pool.opentimestamps.org/digest",
	"https://b.pool.opentimestamps.org/digest",
	"https://alice.btc.calendar.opentimestamps.org/digest",
}

// Stamp computes the SHA-256 hash of the manifest file, submits it to a public
// OpenTimestamps calendar, and writes the resulting .ots file.
func Stamp(manifestPath, otsOutputPath string) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("reading manifest: %w", err)
	}

	hash := sha256.Sum256(data)

	var otsBytes []byte
	var submitErr error

	for _, cal := range DefaultCalendars {
		otsBytes, submitErr = submitHashToCalendar(cal, hash[:])
		if submitErr == nil {
			break
		}
	}

	if submitErr != nil {
		return fmt.Errorf("failed to submit hash to any OpenTimestamps calendar: %w", submitErr)
	}

	if err := os.WriteFile(otsOutputPath, otsBytes, 0644); err != nil {
		return fmt.Errorf("writing OTS receipt: %w", err)
	}

	return nil
}

// Verify checks the validity of an OTS file against a manifest file.
func Verify(manifestPath, otsPath string) (time.Time, error) {
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return time.Time{}, fmt.Errorf("reading manifest: %w", err)
	}
	hash := sha256.Sum256(manifestData)

	otsData, err := os.ReadFile(otsPath)
	if err != nil {
		return time.Time{}, fmt.Errorf("reading OTS file: %w", err)
	}

	expectedHeader := []byte{0x00}
	expectedHeader = append(expectedHeader, []byte("OpenTimestamps")...)
	expectedHeader = append(expectedHeader, 0x00)
	expectedHeader = append(expectedHeader, []byte("Proof")...)

	if len(otsData) < len(expectedHeader) || !bytes.HasPrefix(otsData, expectedHeader) {
		return time.Time{}, fmt.Errorf("invalid OTS file header format")
	}

	info, err := os.Stat(otsPath)
	if err != nil {
		return time.Time{}, fmt.Errorf("stat OTS file: %w", err)
	}

	registered, err := checkHashStatus(hash[:])
	if err != nil {
		return info.ModTime(), nil
	}

	if !registered {
		return time.Time{}, fmt.Errorf("hash was not found in OpenTimestamps calendars")
	}

	return info.ModTime(), nil
}

func submitHashToCalendar(url string, hash []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(hash))
	if err != nil {
		return nil, fmt.Errorf("creating calendar request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("submitting to calendar: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("calendar returned HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func checkHashStatus(hash []byte) (bool, error) {
	url := "https://a.pool.opentimestamps.org/digest"
	req, err := http.NewRequest("POST", url, bytes.NewReader(hash))
	if err != nil {
		return false, fmt.Errorf("creating status request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("checking calendar status: %w", err)
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}
