package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/crypto"
)

// Vault manages encrypted credentials in memory and securely synchronizes with vault.enc.
type Vault struct {
	mu         sync.RWMutex
	path       string
	masterPass []byte
	secrets    map[string]SecretEntry
}

// GenerateDummyToken produces a deterministic dummy placeholder token for a given key name.
// Format: VP_<KEY_NAME>_DUMMY_<SHORT_HASH>
func GenerateDummyToken(keyName string) string {
	h := sha256.Sum256([]byte("VOUCH_DUMMY_SALT:" + keyName))
	short := hex.EncodeToString(h[:4])
	return fmt.Sprintf("VP_%s_DUMMY_%s", keyName, short)
}

// Open loads and decrypts an existing vault from disk.
func Open(path string, passphrase []byte) (*Vault, error) {
	envelope, err := ReadVaultFile(path)
	if err != nil {
		return nil, err
	}

	salt, err := crypto.ExtractSalt(envelope)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(salt)

	key, err := crypto.DeriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(key)

	plaintext, err := crypto.OpenGCM(key, envelope)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(plaintext)

	var secrets map[string]SecretEntry
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted vault payload: %w", err)
	}

	passCopy := make([]byte, len(passphrase))
	copy(passCopy, passphrase)

	return &Vault{
		path:       path,
		masterPass: passCopy,
		secrets:    secrets,
	}, nil
}

// Create initializes a new empty encrypted vault file on disk.
func Create(path string, passphrase []byte) (*Vault, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("vault file already exists at %s", path)
	}

	salt, err := crypto.RandomBytes(crypto.SaltLen)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(salt)

	key, err := crypto.DeriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(key)

	emptyPayload := []byte("{}")
	envelope, err := crypto.SealGCM(key, salt, emptyPayload)
	if err != nil {
		return nil, err
	}

	if err := AtomicWriteFile(path, envelope); err != nil {
		return nil, err
	}

	passCopy := make([]byte, len(passphrase))
	copy(passCopy, passphrase)

	return &Vault{
		path:       path,
		masterPass: passCopy,
		secrets:    make(map[string]SecretEntry),
	}, nil
}

// Get retrieves a secret by key name, returning a safe SecretBytes buffer.
func (v *Vault) Get(key string) (SecretBytes, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	entry, ok := v.secrets[key]
	if !ok {
		return nil, fmt.Errorf("secret %q not found in vault", key)
	}

	valBytes := []byte(entry.Value)
	sec := make(SecretBytes, len(valBytes))
	copy(sec, valBytes)
	return sec, nil
}

// Set adds or updates a secret and atomically persists the encrypted vault to disk.
func (v *Vault) Set(key string, value []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now().Unix()
	createdAt := now
	if existing, ok := v.secrets[key]; ok {
		createdAt = existing.CreatedAt
	}

	v.secrets[key] = SecretEntry{
		KeyName:   key,
		Value:     string(value),
		CreatedAt: createdAt,
		UpdatedAt: now,
	}

	return v.saveLocked()
}

// Delete removes a secret and flushes the vault to disk.
func (v *Vault) Delete(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if _, ok := v.secrets[key]; !ok {
		return fmt.Errorf("secret %q does not exist", key)
	}

	delete(v.secrets, key)
	return v.saveLocked()
}

// List returns metadata for all stored secrets (never the values).
func (v *Vault) List() []SecretMetadata {
	v.mu.RLock()
	defer v.mu.RUnlock()

	result := make([]SecretMetadata, 0, len(v.secrets))
	for k, entry := range v.secrets {
		result = append(result, SecretMetadata{
			KeyName:    k,
			DummyToken: GenerateDummyToken(k),
			CreatedAt:  entry.CreatedAt,
			UpdatedAt:  entry.UpdatedAt,
		})
	}
	return result
}

// DummyMap returns a mapping of key name to its generated dummy token.
func (v *Vault) DummyMap() map[string]string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	m := make(map[string]string, len(v.secrets))
	for k := range v.secrets {
		m[k] = GenerateDummyToken(k)
	}
	return m
}

// DummyToKeyMap returns a reverse mapping from dummy token string to key name.
func (v *Vault) DummyToKeyMap() map[string]string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	m := make(map[string]string, len(v.secrets))
	for k := range v.secrets {
		m[GenerateDummyToken(k)] = k
	}
	return m
}

// Close zeroes master passphrase memory and clears in-memory secrets.
func (v *Vault) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()

	if len(v.masterPass) > 0 {
		crypto.ZeroBytes(v.masterPass)
		v.masterPass = nil
	}
	// Zero secret values
	for k, entry := range v.secrets {
		b := []byte(entry.Value)
		crypto.ZeroBytes(b)
		delete(v.secrets, k)
	}
}

// saveLocked persists the internal secrets map to disk using AES-256-GCM + Argon2id.
func (v *Vault) saveLocked() error {
	if len(v.masterPass) == 0 {
		return errors.New("vault is closed or master passphrase is empty")
	}

	payload, err := json.Marshal(v.secrets)
	if err != nil {
		return fmt.Errorf("failed to marshal secrets payload: %w", err)
	}
	defer crypto.ZeroBytes(payload)

	salt, err := crypto.RandomBytes(crypto.SaltLen)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(salt)

	key, err := crypto.DeriveKey(v.masterPass, salt)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)

	envelope, err := crypto.SealGCM(key, salt, payload)
	if err != nil {
		return err
	}

	return AtomicWriteFile(v.path, envelope)
}
