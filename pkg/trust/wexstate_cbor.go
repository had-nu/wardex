package trust

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
		panic(fmt.Sprintf("trust: failed to initialize CBOR canonical mode: %v", err))
	}
}

type sealMessageV2 struct {
	Version       string `cbor:"0,keyasint"`
	PayloadCBOR   []byte `cbor:"1,keyasint"`
	SealedAt      string `cbor:"2,keyasint"`
	SealedBy      string `cbor:"3,keyasint"`
	TrustStoreRef string `cbor:"4,keyasint"`
	TrustStoreSig string `cbor:"5,keyasint"`
}

func canonicalConfigCBOR(yamlContent string) ([]byte, error) {
	var data any
	if err := yaml.Unmarshal([]byte(yamlContent), &data); err != nil {
		return nil, fmt.Errorf("canonical: parse yaml: %w", err)
	}
	out, err := deterministicCBOR.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("canonical: cbor marshal: %w", err)
	}
	return out, nil
}

func sealMessageCBOR(state *WexState) ([]byte, error) {
	payloadCBOR, err := canonicalConfigCBOR(state.Payload)
	if err != nil {
		return nil, fmt.Errorf("seal message: %w", err)
	}

	msg := sealMessageV2{
		Version:       state.Version,
		PayloadCBOR:   payloadCBOR,
		SealedAt:      state.SealedAt.UTC().Format(time.RFC3339),
		SealedBy:      state.SealedBy,
		TrustStoreRef: state.TrustStoreRef,
		TrustStoreSig: state.TrustStoreSig,
	}

	return deterministicCBOR.Marshal(msg)
}
