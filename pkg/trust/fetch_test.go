// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package trust

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	// testTimeout keeps the bound test fast. The production ceiling is
	// fetchTimeout; this only proves the deadline is applied.
	testTimeout = 200 * time.Millisecond

	// testMargin is the slack allowed on top of the deadline before the test
	// declares the read unbounded.
	testMargin = 3 * time.Second
)

func TestFetchRemoteIsBounded(t *testing.T) {
	// The handler never answers until the client disconnects.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	// context.Background() is the production path: main.go calls
	// rootCmd.Execute(), which supplies a context with no deadline.
	started := time.Now()
	_, err := fetchRemote(context.Background(), srv.URL, testTimeout)
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("expected an error from an unresponsive endpoint")
	}
	if elapsed > testTimeout+testMargin {
		t.Fatalf("fetch took %v, want at most %v", elapsed, testTimeout+testMargin)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want a deadline error", err)
	}
}

func TestFetchRemoteZeroTimeoutFallsBackToDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	got, err := fetchRemote(context.Background(), srv.URL, 0)
	if err != nil {
		t.Fatalf("fetchRemote: %v", err)
	}
	if string(got) != "ok" {
		t.Fatalf("body = %q, want ok", got)
	}
}

func TestFetchRemoteHonoursCallerDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// An already-cancelled caller context must not be extended by the fetch.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := fetchRemote(ctx, srv.URL, testTimeout); err == nil {
		t.Fatal("expected an error from a cancelled context")
	}
}

func TestFetchRemoteSendsUserAgentAndReturnsBody(t *testing.T) {
	payload := "keys: []\n"
	var gotAgent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAgent = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	got, err := fetchRemote(context.Background(), srv.URL, testTimeout)
	if err != nil {
		t.Fatalf("fetchRemote: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("body = %q, want %q", got, payload)
	}
	if gotAgent != "wardex/trust-fetch" {
		t.Fatalf("User-Agent = %q, want wardex/trust-fetch", gotAgent)
	}
}

func TestFetchRemoteRejectsNonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := FetchTrustStore(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected an error for HTTP 403")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("error = %v, want it to report the status code", err)
	}
}

func TestRemoteClientHasTransportCeiling(t *testing.T) {
	if remoteClient.Timeout != fetchTimeout {
		t.Fatalf("remoteClient.Timeout = %v, want %v", remoteClient.Timeout, fetchTimeout)
	}
}

func TestFetchTrustStoreReadsLocalPath(t *testing.T) {
	// A reference without an http scheme stays on the local path branch.
	_, err := FetchTrustStore(context.Background(), "testdata/does-not-exist.yaml")
	if err == nil {
		t.Fatal("expected an error for a missing local trust store")
	}
	if !strings.Contains(err.Error(), "read local") {
		t.Fatalf("error = %v, want a local read failure", err)
	}
}
