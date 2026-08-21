// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package forward

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/had-nu/wardex/v2/pkg/model"
)

// testDir creates a temporary directory within the workspace for testing.
func testDir(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(cwd, "forward-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// testAuditEntry creates a valid audit entry for testing.
func testAuditEntry(t *testing.T) model.AuditEntry {
	return model.AuditEntry{
		Timestamp:        time.Now().UTC().Truncate(time.Second),
		Event:            "acceptance.created",
		ConfigHash:       "sha256:abcdef123456",
		CliOverrides:     map[string]string{"flag": "value"},
		EvidenceHash:     "sha256:fedcba654321",
		OverallDecision:  model.DecisionAllow,
		Risk:             0.5,
		Status:           "allow",
		Detail:           "test detail",
		ActivelyExploited: []string{"CVE-2024-1234"},
	}
}

func TestForwardMultiplexer_BlockPolicy(t *testing.T) {
	ctx := context.Background()
	entry := testAuditEntry(t)

	// Create a failing backend
	failBackend := &failingBackend{name: "fail", err: errors.New("connection refused")}

	mux := NewForwardMultiplexer([]Forwarder{failBackend}, "block")

	err := mux.Dispatch(ctx, entry)
	if err == nil {
		t.Fatal("expected error from block policy")
	}
	if !errors.Is(err, ErrForwardFailed) {
		t.Fatalf("expected ErrForwardFailed, got %v", err)
	}
}

func TestForwardMultiplexer_WarnPolicy(t *testing.T) {
	ctx := context.Background()
	entry := testAuditEntry(t)

	// Create a failing backend
	failBackend := &failingBackend{name: "fail", err: errors.New("connection refused")}

	mux := NewForwardMultiplexer([]Forwarder{failBackend}, "warn")

	err := mux.Dispatch(ctx, entry)
	if err != nil {
		t.Fatalf("warn policy should not return error, got: %v", err)
	}
}

func TestForwardMultiplexer_BestEffortPolicy(t *testing.T) {
	ctx := context.Background()
	entry := testAuditEntry(t)

	// Create a failing backend
	failBackend := &failingBackend{name: "fail", err: errors.New("connection refused")}

	mux := NewForwardMultiplexer([]Forwarder{failBackend}, "best_effort")

	err := mux.Dispatch(ctx, entry)
	if err != nil {
		t.Fatalf("best_effort policy should not return error, got: %v", err)
	}
}

func TestForwardMultiplexer_MultipleBackends(t *testing.T) {
	ctx := context.Background()
	entry := testAuditEntry(t)

	successBackend := &successBackend{name: "success"}
	failBackend := &failingBackend{name: "fail", err: errors.New("failed")}

	mux := NewForwardMultiplexer([]Forwarder{successBackend, failBackend}, "warn")

	err := mux.Dispatch(ctx, entry)
	if err != nil {
		t.Fatalf("warn policy with one success should not error: %v", err)
	}
}

func TestForwardMultiplexer_EmptyBackends(t *testing.T) {
	ctx := context.Background()
	entry := testAuditEntry(t)

	mux := NewForwardMultiplexer([]Forwarder{}, "block")

	err := mux.Dispatch(ctx, entry)
	if err != nil {
		t.Fatal("empty backends should not error")
	}
}

func TestForwardMultiplexer_DefaultOnFail(t *testing.T) {
	ctx := context.Background()
	entry := testAuditEntry(t)

	failBackend := &failingBackend{name: "fail", err: errors.New("failed")}

	mux := NewForwardMultiplexer([]Forwarder{failBackend}, "")

	err := mux.Dispatch(ctx, entry)
	if err != nil {
		t.Fatal("default onFail should be warn, not block")
	}
}

func TestNotifyMultiplexer_MultipleChannels(t *testing.T) {
	ctx := context.Background()
	event := NotificationEvent{
		EventName: "acceptance.created",
		Acceptance: &model.Acceptance{
			ID: "test-001",
			CVE: "CVE-2024-1234",
		},
	}

	notifier1 := &successNotifier{name: "webhook1"}
	notifier2 := &successNotifier{name: "webhook2"}

	mux := NewNotifyMultiplexer([]Notifier{notifier1, notifier2})

	errs := mux.Dispatch(ctx, event)
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got: %v", errs)
	}
}

func TestNotifyMultiplexer_EmptyChannels(t *testing.T) {
	ctx := context.Background()
	event := NotificationEvent{EventName: "test"}

	mux := NewNotifyMultiplexer([]Notifier{})

	errs := mux.Dispatch(ctx, event)
	if len(errs) != 0 {
		t.Fatalf("expected no errors with empty channels, got: %v", errs)
	}
}

func TestWebhookNotifier_Notify_NotConfiguredEvent(t *testing.T) {
	tmp := t.TempDir()
	notifier := NewWebhookNotifier("http://localhost:9999", tmp, []string{"other.event"})

	err := notifier.Notify(context.Background(), NotificationEvent{EventName: "unconfigured.event"})
	if err != nil {
		t.Fatalf("unconfigured event should return nil, got: %v", err)
	}
}

func TestWebhookNotifier_Notify_Success(t *testing.T) {
	tmp := t.TempDir()

	// Create template directory and file
	tmplDir := filepath.Join(tmp, "templates")
	os.MkdirAll(tmplDir, 0750)
	tmplContent := `{"text": "Acceptance {{.Acceptance.ID}} created for {{.Acceptance.CVE}}"}`
	os.WriteFile(filepath.Join(tmplDir, "slack-created.tmpl"), []byte(tmplContent), 0600)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewWebhookNotifier(server.URL, tmplDir, []string{"acceptance.created"})

	event := NotificationEvent{
		EventName: "acceptance.created",
		Acceptance: &model.Acceptance{
			ID:  "acc-001",
			CVE: "CVE-2024-1234",
		},
	}

	err := notifier.Notify(context.Background(), event)
	if err != nil {
		t.Fatalf("Notify failed: %v", err)
	}
}

func TestWebhookNotifier_Notify_TemplateError(t *testing.T) {
	tmp := t.TempDir()
	notifier := NewWebhookNotifier("http://localhost:9999", tmp, []string{"acceptance.created"})

	event := NotificationEvent{
		EventName: "acceptance.created",
		Acceptance: &model.Acceptance{ID: "acc-001", CVE: "CVE-2024-1234"},
	}

	err := notifier.Notify(context.Background(), event)
	if err == nil {
		t.Fatal("expected template error")
	}
	if !strings.Contains(err.Error(), "template") {
		t.Fatalf("expected template error, got: %v", err)
	}
}

func TestWebhookNotifier_Notify_HTTPError(t *testing.T) {
	tmp := t.TempDir()
	tmplDir := filepath.Join(tmp, "templates")
	os.MkdirAll(tmplDir, 0750)
	tmplContent := `{"text": "test"}`
	os.WriteFile(filepath.Join(tmplDir, "slack-created.tmpl"), []byte(tmplContent), 0600)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	notifier := NewWebhookNotifier(server.URL, tmplDir, []string{"acceptance.created"})

	event := NotificationEvent{
		EventName: "acceptance.created",
		Acceptance: &model.Acceptance{ID: "acc-001", CVE: "CVE-2024-1234"},
	}

	err := notifier.Notify(context.Background(), event)
	if err == nil {
		t.Fatal("expected HTTP error")
	}
	if !strings.Contains(err.Error(), "500") && !strings.Contains(err.Error(), "unexpected status") {
		t.Fatalf("expected HTTP error, got: %v", err)
	}
}

func TestWebhookNotifier_Notify_Timeout(t *testing.T) {
	tmp := t.TempDir()
	tmplDir := filepath.Join(tmp, "templates")
	os.MkdirAll(tmplDir, 0750)
	tmplContent := `{"text": "test"}`
	os.WriteFile(filepath.Join(tmplDir, "slack-created.tmpl"), []byte(tmplContent), 0600)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewWebhookNotifier(server.URL, tmplDir, []string{"acceptance.created"})
	notifier.client.Timeout = 10 * time.Millisecond

	event := NotificationEvent{
		EventName: "acceptance.created",
		Acceptance: &model.Acceptance{ID: "acc-001", CVE: "CVE-2024-1234"},
	}

	err := notifier.Notify(context.Background(), event)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "context deadline") {
		t.Fatalf("expected timeout error, got: %v", err)
	}
}

func TestENISABackend_Send(t *testing.T) {
	tmp := testDir(t)
	queuePath := filepath.Join(tmp, "enisa-queue.jsonl")

	backend := NewENISABackend(queuePath)
	entry := testAuditEntry(t)

	err := backend.Send(context.Background(), entry)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Verify file was created
	data, err := os.ReadFile(queuePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("queue file is empty")
	}

	// Verify it's valid JSONL
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	var parsedEntry model.AuditEntry
	if err := json.Unmarshal([]byte(lines[0]), &parsedEntry); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsedEntry.Event != "acceptance.created" {
		t.Fatalf("expected acceptance.created, got %s", parsedEntry.Event)
	}
}

func TestENISABackend_Name(t *testing.T) {
	backend := NewENISABackend("")
	if backend.Name() != "enisa" {
		t.Fatalf("expected name 'enisa', got %q", backend.Name())
	}
}

func TestForwardMultiplexer_Name(t *testing.T) {
	_ = NewForwardMultiplexer([]Forwarder{}, "warn")
	// ForwardMultiplexer doesn't have a Name method, skip
}

func TestNotifyMultiplexer_Name(t *testing.T) {
	_ = NewNotifyMultiplexer([]Notifier{})
	// NotifyMultiplexer doesn't have a Name method, skip
}

// failingBackend is a test backend that always fails.
type failingBackend struct {
	name string
	err  error
}

func (f *failingBackend) Send(ctx context.Context, entry model.AuditEntry) error {
	return f.err
}

func (f *failingBackend) Name() string {
	return f.name
}

// successBackend is a test backend that always succeeds.
type successBackend struct {
	name string
}

func (s *successBackend) Send(ctx context.Context, entry model.AuditEntry) error {
	return nil
}

func (s *successBackend) Name() string {
	return s.name
}

// successNotifier is a test notifier that always succeeds.
type successNotifier struct {
	name string
}

func (s *successNotifier) Notify(ctx context.Context, event NotificationEvent) error {
	return nil
}

func (s *successNotifier) Name() string {
	return s.name
}

// Fuzz tests

func FuzzForwardMultiplexerDispatch(f *testing.F) {
	f.Add([]byte("test"))

	f.Fuzz(func(t *testing.T, data []byte) {
		entry := model.AuditEntry{
			Event:            "test",
			Status:           "test",
			Timestamp:        time.Now().UTC(),
			OverallDecision:  model.DecisionAllow,
		}

		backend := &failingBackend{name: "test", err: errors.New("fail")}
		mux := NewForwardMultiplexer([]Forwarder{backend}, "warn")
		mux.Dispatch(context.Background(), entry)
	})
}

func FuzzWebhookNotifierNotify(f *testing.F) {
	f.Add([]byte("test"))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmp := t.TempDir()
		tmplDir := filepath.Join(tmp, "templates")
		os.MkdirAll(tmplDir, 0750)

		tmplContent := `{"text": "test {{.EventName}}"}`
		os.WriteFile(filepath.Join(tmplDir, "slack-created.tmpl"), []byte(tmplContent), 0600)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		notifier := NewWebhookNotifier(server.URL, tmplDir, []string{"acceptance.created"})
		event := NotificationEvent{
			EventName: "acceptance.created",
			Acceptance: &model.Acceptance{
				ID:  "acc-001",
				CVE: "CVE-2024-1234",
			},
		}

		notifier.Notify(context.Background(), event)
	})
}

func FuzzENISABackendSend(f *testing.F) {
	f.Add([]byte("test"))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmp := t.TempDir()
		queuePath := filepath.Join(tmp, "enisa-queue.jsonl")

		backend := NewENISABackend(queuePath)
		entry := model.AuditEntry{
			Event:           "acceptance.created",
			Status:          "allow",
			Timestamp:       time.Now().UTC(),
			OverallDecision: model.DecisionAllow,
		}

		backend.Send(context.Background(), entry)
	})
}