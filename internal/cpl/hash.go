package cpl

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"github.com/had-nu/wardex/v2/pkg/cli"
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
	return canonicalConfigCBOR(raw)
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

// ConfigHash loads a configuration file from disk and computes its canonical
// SHA-256 hash. A missing file yields an empty hash with a nil error
// (unsealed/absent configuration). Any other read failure is returned wrapped.
func ConfigHash(configPath string) (string, error) {
	data, err := cli.SafeReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // Sem config file, hash vazio
		}
		return "", fmt.Errorf("reading config file for audit: %w", err)
	}

	return ComputeConfigHash(data, AlgoSHA256)
}
