package notifier

import (
	"fmt"
	"net/smtp"
	"strings"
)

type EmailNotifier struct {
	Host   string
	Port   int
	From   string
	To     []string
	Events map[string]bool
}

func NewEmailNotifier(host string, port int, from string, to []string, events []string) *EmailNotifier {
	evMap := make(map[string]bool)
	for _, e := range events {
		evMap[e] = true
	}

	return &EmailNotifier{
		Host:   host,
		Port:   port,
		From:   from,
		To:     to,
		Events: evMap,
	}
}

func (e *EmailNotifier) Name() string {
	return "email"
}

func (e *EmailNotifier) Send(event NotificationEvent) error {
	if !e.Events[event.EventName] {
		return nil
	}

	subject := fmt.Sprintf("Wardex Alert: %s", event.EventName)
	body := fmt.Sprintf("Event: %s\n\n", event.EventName)
	if event.Acceptance != nil {
		body += fmt.Sprintf("CVE: %s\nID: %s\nAccepted By: %s\nExpires: %s\n",
			event.Acceptance.CVE, event.Acceptance.ID, event.Acceptance.AcceptedBy, event.Acceptance.ExpiresAt)
	}

	if event.EventName == "config.changed" {
		body += fmt.Sprintf("Old Hash: %s\nNew Hash: %s\n", event.OldHash, event.NewHash)
	}

	msg := []byte("To: " + strings.Join(e.To, ",") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" + body + "\r\n")

	// We typically configure auth using smtp.PlainAuth, but for simplicity assuming open-relay/internal network logic here per specs
	return smtp.SendMail(fmt.Sprintf("%s:%d", e.Host, e.Port), nil, e.From, e.To, msg)
}
