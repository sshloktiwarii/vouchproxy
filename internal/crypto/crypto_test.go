package crypto

import (
	"bytes"
	"testing"
)

func TestCrypto_Argon2AndGCM(t *testing.T) {
	passphrase := []byte("super-secret-master-passphrase-1234")
	defer ZeroBytes(passphrase)

	salt, err := RandomBytes(SaltLen)
	if err != nil {
		t.Fatalf("RandomBytes failed: %v", err)
	}
	defer ZeroBytes(salt)

	key, err := DeriveKey(passphrase, salt)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	defer ZeroBytes(key)

	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}

	plaintext := []byte(`{"OPENAI_API_KEY":"sk-live-1234567890abcdef"}`)
	defer ZeroBytes(plaintext)

	// Seal
	envelope, err := SealGCM(key, salt, plaintext)
	if err != nil {
		t.Fatalf("SealGCM failed: %v", err)
	}

	// Extract Salt
	extractedSalt, err := ExtractSalt(envelope)
	if err != nil {
		t.Fatalf("ExtractSalt failed: %v", err)
	}
	if !bytes.Equal(salt, extractedSalt) {
		t.Fatal("extracted salt does not match original salt")
	}

	// Open
	decrypted, err := OpenGCM(key, envelope)
	if err != nil {
		t.Fatalf("OpenGCM failed: %v", err)
	}
	defer ZeroBytes(decrypted)

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted text %q != plaintext %q", string(decrypted), string(plaintext))
	}

	// Test invalid key failure
	wrongKey, _ := RandomBytes(32)
	defer ZeroBytes(wrongKey)
	_, err = OpenGCM(wrongKey, envelope)
	if err == nil {
		t.Fatal("expected OpenGCM to fail with wrong key, but succeeded")
	}
}

func TestCrypto_ZeroBytes(t *testing.T) {
	b := []byte("confidential_credential_data_987654321")
	ZeroBytes(b)

	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte at index %d was not zeroed: got %d", i, v)
		}
	}
}
