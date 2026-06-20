// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package accept

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/utils"
)

var (
	// ErrForwardFailed is returned when audit log forwarding to an external
	// system fails and the configured on_fail policy is "block".
	ErrForwardFailed = errors.New("failed to forward audit log to external system")
)

// Forwarder represents a destination backend for audit log entries.
type Forwarder interface {
	Send(entry model.AuditEntry) error
	Name() string
}

// ForwardMultiplexer allows sending to multiple forwarders at once
type ForwardMultiplexer struct {
	backends []Forwarder
	onFail   string // "block" | "warn" | "best_effort"
}

// NewForwardMultiplexer creates a multiplexer that sends each audit entry
// to all configured backends. The onFail policy ("block", "warn",
// "best_effort") controls behaviour when a backend returns an error.
func NewForwardMultiplexer(backends []Forwarder, onFail string) *ForwardMultiplexer {
	if onFail == "" {
		onFail = "warn"
	}
	return &ForwardMultiplexer{backends: backends, onFail: onFail}
}

// Dispatch sends the entry to all configured backends.
func (m *ForwardMultiplexer) Dispatch(entry model.AuditEntry) error {
	var errs []error
	for _, backend := range m.backends {
		if err := backend.Send(entry); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		if m.onFail == "block" {
			return ErrForwardFailed
		}
	}

	return nil
}

// NotificationEvent represents an event that triggers a notification.
type NotificationEvent struct {
	EventName  string
	Acceptance *model.Acceptance
	OldHash    string
	NewHash    string
}

// Notifier defines the interface for notification channels (Webhook, Email)
type Notifier interface {
	Notify(event NotificationEvent) error
	Name() string
}

// NotifyMultiplexer allows sending notifications via multiple channels
type NotifyMultiplexer struct {
	notifiers []Notifier
}

// NewNotifyMultiplexer creates a multiplexer that dispatches notification
// events to all configured notifier channels.
func NewNotifyMultiplexer(channels []Notifier) *NotifyMultiplexer {
	return &NotifyMultiplexer{notifiers: channels}
}

// Dispatch sends the notification event to all configured channels.
func (m *NotifyMultiplexer) Dispatch(event NotificationEvent) []error {
	var errs []error
	for _, n := range m.notifiers {
		if err := n.Notify(event); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// WebhookNotifier implements Notifier for HTTP webhooks.
type WebhookNotifier struct {
	URL         string
	TemplateDir string
	Events      map[string]bool
	client      *http.Client
}

// NewWebhookNotifier creates a new WebhookNotifier that sends HTTP POST
// requests with rendered templates for the specified event types.
func NewWebhookNotifier(url, tmplDir string, events []string) *WebhookNotifier {
	evMap := make(map[string]bool)
	for _, e := range events {
		evMap[e] = true
	}

	return &WebhookNotifier{
		URL:         url,
		TemplateDir: tmplDir,
		Events:      evMap,
		client:      &http.Client{Timeout: 5 * time.Second},
	}
}

// Name returns the notifier identifier "webhook".
func (w *WebhookNotifier) Name() string {
	return "webhook"
}

// Notify sends a templated HTTP POST notification for the given event.
// Returns nil if the event type is not in the configured event set.
func (w *WebhookNotifier) Notify(event NotificationEvent) error {
	if !w.Events[event.EventName] {
		return nil
	}

	var tmplName string
	switch event.EventName {
	case "acceptance.created":
		tmplName = "slack-created.tmpl"
	case "acceptance.expiring":
		tmplName = "slack-expiring.tmpl"
	case "acceptance.expired":
		tmplName = "slack-expired.tmpl"
	case "acceptance.stale":
		tmplName = "slack-stale.tmpl"
	case "acceptance.revoked":
		tmplName = "slack-revoked.tmpl"
	case "verification.tampered":
		tmplName = "slack-tampered.tmpl"
	case "config.changed":
		tmplName = "slack-config-changed.tmpl"
	default:
		return nil
	}

	path := filepath.Join(w.TemplateDir, tmplName)
	payloadStr, err := templateRenderer(path, event)
	if err != nil {
		return fmt.Errorf("rendering template %s: %w", tmplName, err)
	}

	if !json.Valid([]byte(payloadStr)) {
		return fmt.Errorf("rendered template %s is not valid JSON", tmplName)
	}

	req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewBufferString(payloadStr))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("unexpected status code from webhook: %d", resp.StatusCode)
	}
	return nil
}

func templateRenderer(path string, data any) (string, error) {
	tmpl, err := template.ParseFiles(path)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ENISABackend implements Forwarder for the ENISA single reporting platform.
// In v2.0, this is a stub backend that writes to a local queue file.
type ENISABackend struct {
	QueuePath string
}

// NewENISABackend creates a new ENISABackend stub.
func NewENISABackend(queuePath string) *ENISABackend {
	if queuePath == "" {
		queuePath = "wardex-enisa-queue.jsonl"
	}
	return &ENISABackend{QueuePath: queuePath}
}

// Name returns the backend name.
func (e *ENISABackend) Name() string {
	return "enisa"
}

// Send appends the entry to the local queue file.
func (e *ENISABackend) Send(entry model.AuditEntry) error {
	cwd, _ := os.Getwd()
	safePath, err := utils.SafePath(cwd, e.QueuePath)
	if err != nil {
		return err
	}

	dir := filepath.Dir(safePath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	f, err := os.OpenFile(safePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	_, err = f.Write(data)
	return err
}
