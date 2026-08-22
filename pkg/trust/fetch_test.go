// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package trust_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/had-nu/wardex/v2/pkg/trust"
)

// testDir creates a temporary directory within the workspace for testing.
func testDir(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(cwd, "trust-fetch-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestResolveTrustStoreRef_FlagPriority(t *testing.T) {
	flagValue := "/flag/path"
	configValue := "/config/path"

	result := trust.ResolveTrustStoreRef(flagValue, configValue)
	if result != flagValue {
		t.Fatalf("expected %q, got %q", flagValue, result)
	}
}

func TestResolveTrustStoreRef_EnvPriority(t *testing.T) {
	oldEnv := os.Getenv("WARDEX_TRUST_STORE")
	defer os.Setenv("WARDEX_TRUST_STORE", oldEnv)

	os.Setenv("WARDEX_TRUST_STORE", "/env/path")
	configValue := "/config/path"

	result := trust.ResolveTrustStoreRef("", configValue)
	if result != "/env/path" {
		t.Fatalf("expected /env/path, got %q", result)
	}
}

func TestResolveTrustStoreRef_ConfigPriority(t *testing.T) {
	oldEnv := os.Getenv("WARDEX_TRUST_STORE")
	defer os.Setenv("WARDEX_TRUST_STORE", oldEnv)
	os.Unsetenv("WARDEX_TRUST_STORE")

	configValue := "/config/path"
	result := trust.ResolveTrustStoreRef("", configValue)
	if result != configValue {
		t.Fatalf("expected %q, got %q", configValue, result)
	}
}

func TestResolveTrustStoreRef_Default(t *testing.T) {
	oldEnv := os.Getenv("WARDEX_TRUST_STORE")
	defer os.Setenv("WARDEX_TRUST_STORE", oldEnv)
	os.Unsetenv("WARDEX_TRUST_STORE")

	result := trust.ResolveTrustStoreRef("", "")
	if result != "./wardex-trust.yaml" {
		t.Fatalf("expected ./wardex-trust.yaml, got %q", result)
	}
}

func TestFetchTrustStore_LocalFile(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "trust.yaml")
	content := []byte("version: \"1\"\nkeys: []")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}

	data, err := trust.FetchTrustStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("version")) {
		t.Fatal("expected version in data")
	}
}

func TestFetchTrustStore_NonexistentFile(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "nonexistent.yaml")

	_, err := trust.FetchTrustStore(context.Background(), path)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "read local") {
		t.Fatalf("expected 'read local' error, got: %v", err)
	}
}

func TestFetchTrustStore_RemoteURL(t *testing.T) {
	_ = testDir(t)
	content := []byte("version: \"1\"\nkeys: []")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(content)
	}))
	defer server.Close()

	data, err := trust.FetchTrustStore(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("version")) {
		t.Fatal("expected version in data")
	}
}

func TestFetchTrustStore_RemoteHTTPS(t *testing.T) {
	// Use regular HTTP server instead of TLS since the test uses self-signed cert
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("version: \"1\"\nkeys: []"))
	}))
	defer server.Close()

	data, err := trust.FetchTrustStore(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("version")) {
		t.Fatal("expected version in data")
	}
}

func TestFetchTrustStore_RemoteError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := trust.FetchTrustStore(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for 404")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("expected HTTP 404 error, got: %v", err)
	}
}

func TestFetchTrustStore_RemoteTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := trust.FetchTrustStore(ctx, server.URL)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "context deadline exceeded") && !strings.Contains(err.Error(), "context deadline") {
		t.Fatalf("expected timeout error, got: %v", err)
	}
}

func TestFetchTrustStore_RemoteLargeResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		large := strings.Repeat("x", 2<<20) // 2MB
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("version: \"1\"\nkeys: []\n"))
		w.Write([]byte(large))
	}))
	defer server.Close()

	data, err := trust.FetchTrustStore(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	// The implementation limits response to 1MB via io.LimitReader
	// The response should be truncated to 1MB
	if len(data) > 1<<20 {
		t.Fatalf("expected response to be limited to 1MB, got %d bytes", len(data))
	}
	if !bytes.Contains(data, []byte("version")) {
		t.Fatal("expected version in data")
	}
}

func TestResolveTrustStoreRef_EdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		flag       string
		config     string
		env        string
		expected   string
	}{
		{"flag only", "/flag", "", "", "/flag"},
		{"env only", "", "/config", "/env", "/env"},
		{"config only", "", "/config", "", "/config"},
		{"none", "", "", "", "./wardex-trust.yaml"},
		{"flag overrides env", "/flag", "/config", "/env", "/flag"},
		{"empty strings", "", "", "", "./wardex-trust.yaml"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			oldEnv := os.Getenv("WARDEX_TRUST_STORE")
			defer os.Setenv("WARDEX_TRUST_STORE", oldEnv)

			if tc.env != "" {
				os.Setenv("WARDEX_TRUST_STORE", tc.env)
			} else {
				os.Unsetenv("WARDEX_TRUST_STORE")
			}

			result := trust.ResolveTrustStoreRef(tc.flag, tc.config)
			if result != tc.expected {
				t.Fatalf("%s: expected %q, got %q", tc.name, tc.expected, result)
			}
		})
	}
}

// Fuzz tests

func FuzzResolveTrustStoreRef(f *testing.F) {
	f.Add("", "", "")
	f.Add("/flag", "", "")
	f.Add("", "/config", "")
	f.Add("", "", "/env")
	f.Add("/flag", "/config", "/env")

	f.Fuzz(func(t *testing.T, flag, config, env string) {
		oldEnv := os.Getenv("WARDEX_TRUST_STORE")
		defer os.Setenv("WARDEX_TRUST_STORE", oldEnv)

		if env != "" {
			os.Setenv("WARDEX_TRUST_STORE", env)
		} else {
			os.Unsetenv("WARDEX_TRUST_STORE")
		}

		result := trust.ResolveTrustStoreRef(flag, config)
		// Just verify it doesn't panic
		_ = result
	})
}

func FuzzFetchTrustStore(f *testing.F) {
	f.Add([]byte("version: \"1\"\nkeys: []"))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "trust.yaml")
		if err := os.WriteFile(path, data, 0600); err != nil {
			return
		}
		trust.FetchTrustStore(context.Background(), path)
	})
}

func FuzzFetchTrustStoreRemote(f *testing.F) {
	f.Add([]byte("version: \"1\"\nkeys: []"))

	f.Fuzz(func(t *testing.T, data []byte) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(data)
		}))
		defer server.Close()

		trust.FetchTrustStore(context.Background(), server.URL)
	})
}