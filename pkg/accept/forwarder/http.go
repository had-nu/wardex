package forwarder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/had-nu/wardex/pkg/model"
)

type HTTPBackend struct {
	URL     string
	Headers map[string]string
	Timeout time.Duration
	client  *http.Client
}

func NewHTTPBackend(url string, headers map[string]string, timeoutSecs int) *HTTPBackend {
	return &HTTPBackend{
		URL:     url,
		Headers: headers,
		Timeout: time.Duration(timeoutSecs) * time.Second,
		client: &http.Client{
			Timeout: time.Duration(timeoutSecs) * time.Second,
		},
	}
}

func (b *HTTPBackend) Name() string {
	return "http"
}

func (b *HTTPBackend) Send(entry model.AuditEntry) error {
	payload, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, b.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range b.Headers {
		req.Header.Set(k, v)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("unexpected status code from http forwarder: %d", resp.StatusCode)
	}

	return nil
}
