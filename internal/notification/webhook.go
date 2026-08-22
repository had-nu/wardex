package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type DivergencePayload struct {
	Source      string       `json:"source"`
	EventType   string       `json:"event_type"`
	Timestamp   time.Time    `json:"timestamp"`
	AuditLog    string       `json:"audit_log"`
	Summary     Summary      `json:"summary"`
	Divergences []Divergence `json:"divergences"`
}

type Summary struct {
	TotalEntries int `json:"total_entries"`
	OK           int `json:"ok"`
	Mismatch     int `json:"mismatch"`
	Missing      int `json:"missing"`
}

type Divergence struct {
	EntryTimestamp time.Time `json:"entry_timestamp"`
	Status         string    `json:"status"`
	RecordedHash   string    `json:"recorded_hash,omitempty"`
	ComputedHash   string    `json:"computed_hash,omitempty"`
	ConfigFile     string    `json:"config_file,omitempty"`
}

type WebhookConfig struct {
	URL            string
	Token          string
	TimeoutSeconds int
	Headers        map[string]string
}

func Send(cfg WebhookConfig, payload DivergencePayload) error {
	if cfg.URL == "" {
		return nil
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notification: marshal: %w", err)
	}

	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 5 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notification: build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("notification: send: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notification: endpoint returned %d", resp.StatusCode)
	}

	return nil
}
