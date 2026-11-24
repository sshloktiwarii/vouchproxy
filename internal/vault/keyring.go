package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/zalando/go-keyring"
)

const (
	// DefaultKeyringService is the default service name used in the OS keychain.
	DefaultKeyringService = "vouchproxy"
	// DefaultKeyringUser is the default account name used in the OS keychain.
	DefaultKeyringUser = "master"
	// KeyringFileEnv specifies an isolated file path for keyring storage during testing or headless operation.
	KeyringFileEnv = "VOUCH_KEYRING_FILE"
)

var fileKeyringMu sync.Mutex

func getFileStore(path string) (map[string]string, error) {
	fileKeyringMu.Lock()
	defer fileKeyringMu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]string), nil
		}
		return nil, err
	}
	var store map[string]string
	if err := json.Unmarshal(data, &store); err != nil {
		return make(map[string]string), nil
	}
	return store, nil
}

func saveFileStore(path string, store map[string]string) error {
	fileKeyringMu.Lock()
	defer fileKeyringMu.Unlock()

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// KeychainManager defines the contract for OS secure keychain operations.
type KeychainManager interface {
	GetMasterPassphrase() ([]byte, error)
	SetMasterPassphrase(passphrase []byte) error
	DeleteMasterPassphrase() error
}

// OSKeyringManager implements KeychainManager backed by github.com/zalando/go-keyring
// with transparent fallback to an isolated file store when VOUCH_KEYRING_FILE is set.
type OSKeyringManager struct {
	service string
	user    string
}

// NewOSKeyringManager creates a new OSKeyringManager.
// If service or user are empty, DefaultKeyringService and DefaultKeyringUser are used.
func NewOSKeyringManager(service, user string) *OSKeyringManager {
	if service == "" {
		service = DefaultKeyringService
	}
	if user == "" {
		user = DefaultKeyringUser
	}
	return &OSKeyringManager{
		service: service,
		user:    user,
	}
}

// Service returns the configured keychain service name.
func (m *OSKeyringManager) Service() string {
	return m.service
}

// User returns the configured keychain user name.
func (m *OSKeyringManager) User() string {
	return m.user
}

// GetMasterPassphrase retrieves the master passphrase from the isolated file or OS keychain.
func (m *OSKeyringManager) GetMasterPassphrase() ([]byte, error) {
	if mockPath := os.Getenv(KeyringFileEnv); mockPath != "" {
		store, err := getFileStore(mockPath)
		if err != nil {
			return nil, err
		}
		key := m.service + ":" + m.user
		val, ok := store[key]
		if !ok || len(val) == 0 {
			return nil, keyring.ErrNotFound
		}
		return []byte(val), nil
	}

	secret, err := keyring.Get(m.service, m.user)
	if err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, errors.New("empty passphrase retrieved from keychain")
	}
	return []byte(secret), nil
}

// SetMasterPassphrase stores the master passphrase in the isolated file or OS keychain.
func (m *OSKeyringManager) SetMasterPassphrase(passphrase []byte) error {
	if len(passphrase) == 0 {
		return errors.New("cannot store empty passphrase in keychain")
	}
	if mockPath := os.Getenv(KeyringFileEnv); mockPath != "" {
		store, err := getFileStore(mockPath)
		if err != nil {
			return err
		}
		key := m.service + ":" + m.user
		store[key] = string(passphrase)
		return saveFileStore(mockPath, store)
	}

	return keyring.Set(m.service, m.user, string(passphrase))
}

// DeleteMasterPassphrase removes the master passphrase from the isolated file or OS keychain.
func (m *OSKeyringManager) DeleteMasterPassphrase() error {
	if mockPath := os.Getenv(KeyringFileEnv); mockPath != "" {
		store, err := getFileStore(mockPath)
		if err != nil {
			return err
		}
		key := m.service + ":" + m.user
		delete(store, key)
		return saveFileStore(mockPath, store)
	}

	return keyring.Delete(m.service, m.user)
}
