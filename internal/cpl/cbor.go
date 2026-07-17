package cpl

import (
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"gopkg.in/yaml.v3"
)

var deterministicCBOR cbor.EncMode

func init() {
	opts := cbor.CanonicalEncOptions()
	opts.Time = cbor.TimeRFC3339
	var err error
	deterministicCBOR, err = opts.EncMode()
	if err != nil {
		panic(fmt.Sprintf("cpl: failed to initialize CBOR canonical mode: %v", err))
	}
}

func MarshalCanonical(v any) ([]byte, error) {
	return deterministicCBOR.Marshal(v)
}

func canonicalConfigCBOR(raw []byte) ([]byte, error) {
	var data any
	if err := yaml.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("canonical: parse: %w", err)
	}
	return deterministicCBOR.Marshal(data)
}

func MarshalTime(t time.Time) ([]byte, error) {
	return deterministicCBOR.Marshal(t)
}

func UnmarshalTime(data []byte) (time.Time, error) {
	var t time.Time
	if err := cbor.Unmarshal(data, &t); err != nil {
		return t, fmt.Errorf("cpl: unmarshal time: %w", err)
	}
	return t, nil
}
