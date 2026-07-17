package cpl

import (
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func TestMarshalCanonical(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{
			name:    "simple string map",
			input:   map[string]any{"key": "value"},
			wantErr: false,
		},
		{
			name:    "nested map",
			input:   map[string]any{"a": map[string]any{"b": 1}},
			wantErr: false,
		},
		{
			name:    "nil input",
			input:   nil,
			wantErr: false,
		},
		{
			name:    "integer values",
			input:   map[string]any{"count": 42},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := MarshalCanonical(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("MarshalCanonical returned error: %v", err)
			}
			if len(data) == 0 {
				t.Error("expected non-empty output")
			}
		})
	}
}

func TestMarshalCanonicalDeterminism(t *testing.T) {
	input := map[string]any{
		"c": 3,
		"a": 1,
		"b": 2,
	}

	out1, err := MarshalCanonical(input)
	if err != nil {
		t.Fatalf("first marshal: %v", err)
	}

	out2, err := MarshalCanonical(input)
	if err != nil {
		t.Fatalf("second marshal: %v", err)
	}

	if len(out1) != len(out2) {
		t.Errorf("length differs: %d vs %d", len(out1), len(out2))
	}
	for i := range out1 {
		if out1[i] != out2[i] {
			t.Errorf("byte %d differs: %02x vs %02x", i, out1[i], out2[i])
			break
		}
	}
}

func TestMarshalTime(t *testing.T) {
	now := time.Now().Round(time.Second)
	data, err := MarshalTime(now)
	if err != nil {
		t.Fatalf("MarshalTime: %v", err)
	}

	got, err := UnmarshalTime(data)
	if err != nil {
		t.Fatalf("UnmarshalTime: %v", err)
	}

	if !got.Equal(now) {
		t.Errorf("round-trip mismatch: %v vs %v", got, now)
	}
}

func TestMarshalTimeRFC3339(t *testing.T) {
	ts := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	data, err := MarshalTime(ts)
	if err != nil {
		t.Fatalf("MarshalTime: %v", err)
	}

	var decoded string
	if err := cbor.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("CBOR unmarshal: %v", err)
	}
	if decoded != "2026-07-17T12:00:00Z" {
		t.Errorf("expected RFC3339 text, got %q", decoded)
	}
}

func TestUnmarshalTimeErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"invalid CBOR", []byte{0xff, 0xff}},
		{"array type", []byte{0x80}},          // empty array, not a time
		{"map type", []byte{0xa0}},             // empty map, not a time
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalTime(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestMarshalTimeNilSafety(t *testing.T) {
	_, err := MarshalTime(time.Time{})
	if err != nil {
		t.Fatalf("MarshalTime(zero): %v", err)
	}

	_, err = MarshalTime(time.Now())
	if err != nil {
		t.Fatalf("MarshalTime(now): %v", err)
	}
}
