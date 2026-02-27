package forwarder

import "github.com/had-nu/wardex/pkg/model"

// NoOpBackend simply discards the payload. Useful for testing and local dev.
type NoOpBackend struct{}

func (b *NoOpBackend) Name() string {
	return "noop"
}

func (b *NoOpBackend) Send(entry model.AuditEntry) error {
	return nil
}
