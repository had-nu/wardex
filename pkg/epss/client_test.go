package epss

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func httpTestClient(t *testing.T, srv *httptest.Server) {
	t.Helper()
	firstAPIURL = srv.URL
	httpClient = &http.Client{Transport: srv.Client().Transport, Timeout: 10 * time.Second}
}

func TestFetchScores_EmptyInput(t *testing.T) {
	scores, provenance, err := FetchScores(nil, nil)
	if err != nil {
		t.Fatalf("expected nil error for empty input, got: %v", err)
	}
	if scores != nil {
		t.Errorf("expected nil scores, got %v", scores)
	}
	if provenance != nil {
		t.Errorf("expected nil provenance, got %v", provenance)
	}
}

func TestFetchScores_EmptySlice(t *testing.T) {
	scores, provenance, err := FetchScores([]string{}, nil)
	if err != nil {
		t.Fatalf("expected nil error for empty slice, got: %v", err)
	}
	if scores != nil {
		t.Errorf("expected nil scores, got %v", scores)
	}
	if provenance != nil {
		t.Errorf("expected nil provenance, got %v", provenance)
	}
}

func TestFetchScores_Success(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cve") == "" {
			t.Error("expected cve query parameter")
		}
		if r.UserAgent() == "" {
			t.Error("expected User-Agent header")
		}

		resp := FirstAPIResponse{
			Status:     "OK",
			StatusCode: 200,
			Version:    "2.1",
			Total:      2,
			Data: []Data{
				{CVE: "CVE-2024-0001", EPSS: "0.95", Percentile: "0.99", Date: "2024-01-01"},
				{CVE: "CVE-2024-0002", EPSS: "0.12", Percentile: "0.50", Date: "2024-01-01"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()
	httpTestClient(t, server)

	scores, provenance, err := FetchScores([]string{"CVE-2024-0001", "CVE-2024-0002"}, os.Stderr)
	if err != nil {
		t.Fatalf("FetchScores failed: %v", err)
	}
	if len(scores) != 2 {
		t.Errorf("expected 2 scores, got %d", len(scores))
	}
	if scores["CVE-2024-0001"] != 0.95 {
		t.Errorf("expected 0.95, got %f", scores["CVE-2024-0001"])
	}
	if scores["CVE-2024-0002"] != 0.12 {
		t.Errorf("expected 0.12, got %f", scores["CVE-2024-0002"])
	}
	if provenance["api_endpoint"] != "api.first.org" {
		t.Errorf("expected api.first.org, got %s", provenance["api_endpoint"])
	}
}

func TestFetchScores_Non200Status(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	httpTestClient(t, server)

	_, _, err := FetchScores([]string{"CVE-2024-0001"}, os.Stderr)
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
	if !strings.Contains(err.Error(), "non-200") {
		t.Errorf("expected 'non-200' error, got: %v", err)
	}
}

func TestFetchScores_ServerError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"invalid json`))
	}))
	defer server.Close()
	httpTestClient(t, server)

	_, _, err := FetchScores([]string{"CVE-2024-0001"}, os.Stderr)
	if err == nil {
		t.Fatal("expected error for malformed response")
	}
}

func TestFetchScores_UnknownFieldsRejected(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"OK","status-code":200,"unknown_field":"should_fail","data":[{"cve":"CVE-2024-0001","epss":"0.5","percentile":"0.5","date":"2024-01-01"}]}`))
	}))
	defer server.Close()
	httpTestClient(t, server)

	_, _, err := FetchScores([]string{"CVE-2024-0001"}, os.Stderr)
	if err == nil {
		t.Fatal("expected error for unknown JSON fields")
	}
}

func TestFetchScores_MalformedScore(t *testing.T) {
	var buf strings.Builder
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := FirstAPIResponse{
			Status:     "OK",
			StatusCode: 200,
			Data: []Data{
				{CVE: "CVE-2024-0001", EPSS: "not-a-float", Percentile: "0.5", Date: "2024-01-01"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()
	httpTestClient(t, server)

	scores, _, err := FetchScores([]string{"CVE-2024-0001"}, &buf)
	if err != nil {
		t.Fatalf("FetchScores should not fail on malformed score: %v", err)
	}
	if len(scores) != 0 {
		t.Errorf("expected 0 scores for malformed input, got %d", len(scores))
	}
	if !strings.Contains(buf.String(), "malformed") {
		t.Errorf("expected warning about malformed scores, got: %s", buf.String())
	}
}

func TestFetchScores_OutOfRangeScore(t *testing.T) {
	var buf strings.Builder
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := FirstAPIResponse{
			Status:     "OK",
			StatusCode: 200,
			Data: []Data{
				{CVE: "CVE-2024-0001", EPSS: "2.5", Percentile: "0.99", Date: "2024-01-01"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()
	httpTestClient(t, server)

	scores, _, err := FetchScores([]string{"CVE-2024-0001"}, &buf)
	if err != nil {
		t.Fatalf("FetchScores should not fail on out-of-range score: %v", err)
	}
	if len(scores) != 0 {
		t.Errorf("expected 0 scores for out-of-range input, got %d", len(scores))
	}
	if !strings.Contains(buf.String(), "out of range") {
		t.Errorf("expected warning about out-of-range scores, got: %s", buf.String())
	}
}

func TestFetchScores_Chunking(t *testing.T) {
	callCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		cves := r.URL.Query().Get("cve")
		if callCount == 1 && strings.Count(cves, ",")+1 != 50 {
			t.Errorf("first chunk should have 50 CVEs, got %d", strings.Count(cves, ",")+1)
		}
		resp := FirstAPIResponse{Status: "OK", StatusCode: 200, Data: []Data{}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()
	httpTestClient(t, server)

	var cves []string
	for i := range 60 {
		cves = append(cves, fmt.Sprintf("CVE-2024-%04d", i))
	}

	_, _, err := FetchScores(cves, os.Stderr)
	if err != nil {
		t.Fatalf("FetchScores failed: %v", err)
	}
	if callCount < 2 {
		t.Errorf("expected at least 2 HTTP calls for 60 CVEs, got %d", callCount)
	}
}
