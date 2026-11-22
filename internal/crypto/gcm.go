package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

const (
	GCMNonceLen = 12
	VaultMagic  = "VOUCH_VAULT_V1"
)

// SealGCM encrypts plaintext with AES-256-GCM using the provided 256-bit key.
// The returned envelope format is: [Magic (14B)][Salt (32B)][Nonce (12B)][Ciphertext + Tag].
func SealGCM(key, salt, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256 key must be exactly 32 bytes")
	}
	if len(salt) != SaltLen {
		return nil, fmt.Errorf("salt must be %d bytes", SaltLen)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM block: %w", err)
	}

	nonce, err := RandomBytes(GCMNonceLen)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(nonce)

	magic := []byte(VaultMagic)
	ciphertext := gcm.Seal(nil, nonce, plaintext, magic)

	// Allocate envelope: magic + salt + nonce + ciphertext
	envelope := make([]byte, 0, len(magic)+len(salt)+len(nonce)+len(ciphertext))
	envelope = append(envelope, magic...)
	envelope = append(envelope, salt...)
	envelope = append(envelope, nonce...)
	envelope = append(envelope, ciphertext...)

	return envelope, nil
}

// OpenGCM parses and decrypts an envelope produced by SealGCM.
func OpenGCM(key, envelope []byte) ([]byte, error) {
	magic := []byte(VaultMagic)
	minLen := len(magic) + SaltLen + GCMNonceLen + 16 // min ciphertext with 16-byte tag
	if len(envelope) < minLen {
		return nil, errors.New("envelope is corrupt or truncated")
	}

	if string(envelope[:len(magic)]) != VaultMagic {
		return nil, errors.New("invalid envelope magic header")
	}

	offset := len(magic)
	// salt := envelope[offset : offset+SaltLen] // retrieved if needed by caller
	offset += SaltLen

	nonce := envelope[offset : offset+GCMNonceLen]
	offset += GCMNonceLen

	ciphertext := envelope[offset:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM block: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, magic)
	if err != nil {
		return nil, errors.New("decryption failed: invalid passphrase or corrupted vault")
	}

	return plaintext, nil
}

// ExtractSalt extracts the salt from an envelope without decrypting.
func ExtractSalt(envelope []byte) ([]byte, error) {
	magic := []byte(VaultMagic)
	minLen := len(magic) + SaltLen
	if len(envelope) < minLen {
		return nil, errors.New("envelope is truncated")
	}
	if string(envelope[:len(magic)]) != VaultMagic {
		return nil, errors.New("invalid envelope magic header")
	}
	salt := make([]byte, SaltLen)
	copy(salt, envelope[len(magic):len(magic)+SaltLen])
	return salt, nil
}
