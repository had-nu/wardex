package notification_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/had-nu/wardex/v2/internal/notification"
)

func TestWebhookCalledOnDivergence(t *testing.T) {
	var received notification.DivergencePayload
	called := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := notification.WebhookConfig{
		URL:            srv.URL,
		TimeoutSeconds: 5,
	}
	payload := notification.DivergencePayload{
		Source:    "wardex",
		EventType: "cpl.verify_link.mismatch",
		Timestamp: time.Now().UTC(),
		AuditLog:  "audit.log",
		Summary:   notification.Summary{TotalEntries: 10, OK: 9, Mismatch: 1},
	}

	if err := notification.Send(cfg, payload); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !called {
		t.Error("webhook nao foi chamado")
	}
	if received.EventType != "cpl.verify_link.mismatch" {
		t.Errorf("event_type errado: %q", received.EventType)
	}
}

func TestWebhookNotCalledWhenURLEmpty(t *testing.T) {
	cfg := notification.WebhookConfig{URL: ""}
	err := notification.Send(cfg, notification.DivergencePayload{})
	if err != nil {
		t.Errorf("URL vazia deve retornar nil, obteve: %v", err)
	}
}

func TestWebhookTimeoutDoesNotBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
	}))
	defer srv.Close()

	cfg := notification.WebhookConfig{
		URL:            srv.URL,
		TimeoutSeconds: 1,
	}

	start := time.Now()
	err := notification.Send(cfg, notification.DivergencePayload{})
	elapsed := time.Since(start)

	if err == nil {
		t.Error("esperava erro de timeout, obteve nil")
	}
	if elapsed > 3*time.Second {
		t.Errorf("Send bloqueou alem do timeout: %v", elapsed)
	}
}

func TestWebhookAuthHeaderPresent(t *testing.T) {
	var gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := notification.WebhookConfig{
		URL:            srv.URL,
		Token:          "test-token-abc",
		TimeoutSeconds: 5,
	}
	_ = notification.Send(cfg, notification.DivergencePayload{})

	if gotAuth != "Bearer test-token-abc" {
		t.Errorf("Authorization header errado: %q", gotAuth)
	}
}

func TestWebhookNonOKStatusReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := notification.WebhookConfig{URL: srv.URL, TimeoutSeconds: 5}
	err := notification.Send(cfg, notification.DivergencePayload{})
	if err == nil {
		t.Error("status 500 deve retornar erro, obteve nil")
	}
}
