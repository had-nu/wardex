package notifier

import (
	"bytes"
	"text/template"

	"github.com/had-nu/wardex/pkg/model"
)

type NotificationEvent struct {
	EventName  string
	Acceptance *model.Acceptance
	OldHash    string
	NewHash    string
}

// Notifier defines the interface for notification channels (Webhook, Email)
type Notifier interface {
	Send(event NotificationEvent) error
	Name() string
}

// Multiplexer allows sending notifications via multiple channels
type Multiplexer struct {
	notifiers []Notifier
}

func NewMultiplexer(channels []Notifier) *Multiplexer {
	return &Multiplexer{notifiers: channels}
}

// Dispatch sends the notification event to all configured channels.
// Notification failures are currently logged internally or returned without
// blocking the main operation, as per specifications (RF-13).
func (m *Multiplexer) Dispatch(event NotificationEvent) []error {
	var errs []error
	for _, n := range m.notifiers {
		if err := n.Send(event); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// templateRenderer is a helper for rendering notification templates
func templateRenderer(path string, data interface{}) (string, error) {
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
