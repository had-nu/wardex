// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Logger is the Wardex structured-logging facade built on log/slog.
type Logger struct {
	*slog.Logger
}

var (
	loggerMu sync.RWMutex
	// defaultLogger is the process-wide logger used by the Log*/Info*/Warn*/Error* helpers.
	defaultLogger = &Logger{slog.New(newTextHandler(os.Stderr, slog.LevelInfo))}
)

// NewLogger builds a structured logger.
//
//   - level: minimum severity to emit (slog.LevelDebug/Info/Warn/Error).
//   - useSyslog: emit JSON lines (machine-parseable for log aggregation).
//     When false, emits the classic "[PREFIX] message" text style, coloured on a TTY.
//   - endpoint: optional syslog endpoint ("tcp://host:port", "udp://host:port",
//     "unix:///path"). Empty means stderr is the sink.
func NewLogger(level slog.Level, useSyslog bool, endpoint string) (*Logger, error) {
	w := io.Writer(os.Stderr)
	if endpoint != "" {
		conn, err := dialEndpoint(endpoint)
		if err != nil {
			return nil, err
		}
		w = conn
	}
	var h slog.Handler
	if useSyslog {
		h = newJSONHandler(w, level)
	} else {
		h = newTextHandler(w, level)
	}
	return &Logger{slog.New(h)}, nil
}

// NewLoggerTo builds a text logger writing to w at the given level.
// Used by tests and by components that own their sink (e.g. cobra ErrOrStderr).
func NewLoggerTo(w io.Writer, level slog.Level) *Logger {
	return &Logger{slog.New(newTextHandler(w, level))}
}

// SetLogger swaps the process-wide default logger used by the package helpers.
func SetLogger(l *Logger) {
	if l == nil {
		return
	}
	loggerMu.Lock()
	defer loggerMu.Unlock()
	defaultLogger = l
}

// Default returns the process-wide default logger.
func Default() *Logger {
	loggerMu.RLock()
	defer loggerMu.RUnlock()
	return defaultLogger
}

// Info logs a structured message at INFO level through the default logger.
func Info(msg string, args ...any) { Default().Info(msg, args...) }

// Warn logs a structured message at WARN level through the default logger.
func Warn(msg string, args ...any) { Default().Warn(msg, args...) }

// Error logs a structured message at ERROR level through the default logger.
func Error(msg string, args ...any) { Default().Error(msg, args...) }

// Debug logs a structured message at DEBUG level through the default logger.
func Debug(msg string, args ...any) { Default().Debug(msg, args...) }

// Infof formats and logs a message at INFO level.
func Infof(format string, args ...any) { Info(fmt.Sprintf(format, args...)) }

// Warnf formats and logs a message at WARN level.
func Warnf(format string, args ...any) { Warn(fmt.Sprintf(format, args...)) }

// Errorf formats and logs a message at ERROR level.
func Errorf(format string, args ...any) { Error(fmt.Sprintf(format, args...)) }

// dialEndpoint resolves a scheme://address syslog endpoint into a connected writer.
func dialEndpoint(endpoint string) (net.Conn, error) {
	scheme, address, ok := strings.Cut(endpoint, "://")
	if !ok {
		return nil, fmt.Errorf("ui: invalid syslog endpoint %q (want scheme://address)", endpoint)
	}
	var network string
	switch scheme {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "unix", "unixgram":
		network = scheme
	default:
		return nil, fmt.Errorf("ui: unsupported syslog endpoint scheme %q", scheme)
	}
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, fmt.Errorf("ui: dial syslog endpoint %q: %w", endpoint, err)
	}
	return conn, nil
}

// levelPrefix maps a slog level to the classic Wardex [PREFIX].
func levelPrefix(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "FAIL"
	case l >= slog.LevelWarn:
		return "WARN"
	case l >= slog.LevelInfo:
		return "INFO"
	default:
		return "DEBUG"
	}
}

// levelColour maps a slog level to the classic Wardex ANSI colour.
func levelColour(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return Red + Bold
	case l >= slog.LevelWarn:
		return Yellow
	case l >= slog.LevelInfo:
		return Cyan
	default:
		return Gray
	}
}

// textHandler renders slog records in the classic "[PREFIX] message" style,
// coloured when the sink is a terminal.
type textHandler struct {
	level slog.Level
	w     io.Writer
}

func newTextHandler(w io.Writer, level slog.Level) *textHandler {
	return &textHandler{level: level, w: w}
}

func (h *textHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level
}

func (h *textHandler) Handle(_ context.Context, r slog.Record) error {
	prefix := levelPrefix(r.Level)
	var sb strings.Builder
	if IsTerminal(h.w) {
		sb.WriteString(levelColour(r.Level))
		sb.WriteString("[")
		sb.WriteString(prefix)
		sb.WriteString("]")
		sb.WriteString(Reset)
		sb.WriteString(" ")
	} else {
		sb.WriteString("[")
		sb.WriteString(prefix)
		sb.WriteString("] ")
	}
	sb.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		if a.Equal(slog.Attr{}) {
			return true
		}
		sb.WriteString(" ")
		sb.WriteString(a.Key)
		sb.WriteString("=")
		fmt.Fprint(&sb, a.Value.Any())
		return true
	})
	sb.WriteString("\n")
	_, err := io.WriteString(h.w, sb.String())
	return err
}

func (h *textHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *textHandler) WithGroup(string) slog.Handler      { return h }

// jsonHandler renders slog records as JSON lines for syslog/aggregators.
type jsonHandler struct {
	level slog.Level
	enc   *json.Encoder
}

func newJSONHandler(w io.Writer, level slog.Level) *jsonHandler {
	return &jsonHandler{level: level, enc: json.NewEncoder(w)}
}

func (h *jsonHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level
}

func (h *jsonHandler) Handle(_ context.Context, r slog.Record) error {
	record := map[string]any{
		"level":   levelPrefix(r.Level),
		"time":    r.Time.UTC().Format(time.RFC3339),
		"message": r.Message,
	}
	r.Attrs(func(a slog.Attr) bool {
		if a.Equal(slog.Attr{}) {
			return true
		}
		record[a.Key] = a.Value.Any()
		return true
	})
	return h.enc.Encode(record)
}

func (h *jsonHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *jsonHandler) WithGroup(string) slog.Handler      { return h }
