package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// RandomBytes generates n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, fmt.Errorf("failed to read secure random entropy: %w", err)
	}
	return buf, nil
}

// RandomHex returns a hex-encoded string of n random bytes.
func RandomHex(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
