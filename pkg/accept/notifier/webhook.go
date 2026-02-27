package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"time"
)

type WebhookNotifier struct {
	URL         string
	TemplateDir string
	Events      map[string]bool
	client      *http.Client
}

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

func (w *WebhookNotifier) Name() string {
	return "webhook"
}

func (w *WebhookNotifier) Send(event NotificationEvent) error {
	if !w.Events[event.EventName] {
		return nil
	}

	// Resolve template based on event
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

	// Validate JSON payload
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
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("unexpected status code from webhook: %d", resp.StatusCode)
	}
	return nil
}
