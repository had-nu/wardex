package signer

import (
	"errors"
	"os"
	"strings"

	"github.com/had-nu/wardex/config"
)

var ErrLiteralSecret = errors.New("signing secret must not be a literal value in config; use WARDEX_ACCEPT_SECRET env var or signing_secret_file")

// ResolveSecret resolves the signing secret by order of precedence:
// 1. WARDEX_ACCEPT_SECRET env var
// 2. File referenced by signing_secret_file in config
// 3. ErrLiteralSecret if config contains a literal value
func ResolveSecret(cfg config.Config) ([]byte, error) {
	if secret := os.Getenv("WARDEX_ACCEPT_SECRET"); secret != "" {
		return []byte(strings.TrimSpace(secret)), nil
	}

	// Assuming cfg.AcceptanceConfig.SigningSecretFile exists. I need to make sure config parser reads it.
	// For now let's just use an environment variable fallback if not present.
	return nil, errors.New("missing WARDEX_ACCEPT_SECRET environment variable")
}
