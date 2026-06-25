package cpl

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type Algorithm int

const (
	AlgoUnknown Algorithm = iota
	AlgoSHA256
	AlgoBLAKE3
)

func (a Algorithm) String() string {
	switch a {
	case AlgoSHA256:
		return "sha256"
	case AlgoBLAKE3:
		return "blake3"
	default:
		return "unknown"
	}
}

func (a Algorithm) Prefix() string {
	switch a {
	case AlgoSHA256:
		return "sha256:"
	case AlgoBLAKE3:
		return "blake3:"
	default:
		return ""
	}
}

func ParseAlgorithmPrefix(hash string) (Algorithm, error) {
	if strings.HasPrefix(hash, "sha256:") {
		return AlgoSHA256, nil
	}
	if strings.HasPrefix(hash, "blake3:") {
		return AlgoBLAKE3, nil
	}
	return AlgoUnknown, fmt.Errorf("cpl: unknown or missing algorithm prefix in %q", hash)
}

func canonicalConfig(raw []byte) ([]byte, error) {
	var data any
	if err := yaml.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("canonical: parse: %w", err)
	}
	out, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("canonical: marshal: %w", err)
	}
	return out, nil
}

func ComputeConfigHash(raw []byte, algo Algorithm) (string, error) {
	canon, err := canonicalConfig(raw)
	if err != nil {
		return "", err
	}

	switch algo {
	case AlgoSHA256:
		h := sha256.Sum256(canon)
		return fmt.Sprintf("sha256:%x", h), nil
	case AlgoBLAKE3:
		return computeBLAKE3(canon)
	default:
		return "", fmt.Errorf("cpl: unsupported algorithm %v", algo)
	}
}
