package crypto

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// Argon2id recommended production parameters
	Argon2Time    uint32 = 3
	Argon2Memory  uint32 = 64 * 1024 // 64 MB
	Argon2Threads uint8  = 4
	Argon2KeyLen  uint32 = 32        // 256 bits
	SaltLen              = 32
)

// DeriveKey derives a 256-bit key from a passphrase and salt using Argon2id.
func DeriveKey(passphrase, salt []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase cannot be empty")
	}
	if len(salt) != SaltLen {
		return nil, fmt.Errorf("salt length must be %d bytes, got %d", SaltLen, len(salt))
	}

	key := argon2.IDKey(passphrase, salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
	return key, nil
}
