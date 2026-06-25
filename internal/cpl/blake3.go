package cpl

import (
	"fmt"

	"lukechampine.com/blake3"
)

func computeBLAKE3(data []byte) (string, error) {
	h := blake3.Sum256(data)
	return fmt.Sprintf("blake3:%x", h), nil
}
