package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sshloktiwarii/vouchproxy/internal/crypto"
	"github.com/zalando/go-keyring"
)

func TestKeyring_Lifecycle(t *testing.T) {
	keyring.MockInit()

	km := NewOSKeyringManager("vouchproxy-test-svc", "master-test-user")
	if km.Service() != "vouchproxy-test-svc" {
		t.Fatalf("unexpected service: %s", km.Service())
	}
	if km.User() != "master-test-user" {
		t.Fatalf("unexpected user: %s", km.User())
	}

	// 1. Initial get on empty keychain must fail (ErrNotFound)
	_, err := km.GetMasterPassphrase()
	if err == nil {
		t.Fatal("expected error on empty keyring, got nil")
	}
	if !errors.Is(err, keyring.ErrNotFound) {
		t.Logf("empty keyring returned error: %v (expected ErrNotFound)", err)
	}

	// 2. Setting nil or empty passphrase must be rejected
	if err := km.SetMasterPassphrase(nil); err == nil {
		t.Fatal("expected error setting nil passphrase, got nil")
	}
	if err := km.SetMasterPassphrase([]byte{}); err == nil {
		t.Fatal("expected error setting empty passphrase, got nil")
	}

	// 3. Set valid passphrase
	pass := []byte("correct-horse-battery-staple-999")
	if err := km.SetMasterPassphrase(pass); err != nil {
		t.Fatalf("SetMasterPassphrase failed: %v", err)
	}

	// 4. Retrieve passphrase and verify
	retrieved, err := km.GetMasterPassphrase()
	if err != nil {
		t.Fatalf("GetMasterPassphrase failed: %v", err)
	}
	defer crypto.ZeroBytes(retrieved)

	if !bytes.Equal(retrieved, pass) {
		t.Fatalf("passphrase mismatch: expected %s, got %s", string(pass), string(retrieved))
	}

	// 5. Delete passphrase
	if err := km.DeleteMasterPassphrase(); err != nil {
		t.Fatalf("DeleteMasterPassphrase failed: %v", err)
	}

	// 6. Verify subsequent get fails
	_, err = km.GetMasterPassphrase()
	if err == nil {
		t.Fatal("expected error after delete, got nil")
	}
}

func TestKeyring_DefaultConfig(t *testing.T) {
	km := NewOSKeyringManager("", "")
	if km.Service() != DefaultKeyringService {
		t.Fatalf("expected default service %q, got %q", DefaultKeyringService, km.Service())
	}
	if km.User() != DefaultKeyringUser {
		t.Fatalf("expected default user %q, got %q", DefaultKeyringUser, km.User())
	}
}

func TestKeyring_MockErrors(t *testing.T) {
	expectedErr := errors.New("simulated secure enclave hardware fault")
	keyring.MockInitWithError(expectedErr)

	km := NewOSKeyringManager("vouchproxy-fault-svc", "master-fault-user")

	if _, err := km.GetMasterPassphrase(); err == nil {
		t.Fatal("expected error from mock with error on Get, got nil")
	}
	if err := km.SetMasterPassphrase([]byte("secret")); err == nil {
		t.Fatal("expected error from mock with error on Set, got nil")
	}
	if err := km.DeleteMasterPassphrase(); err == nil {
		t.Fatal("expected error from mock with error on Delete, got nil")
	}
}

func TestKeyring_EndToEndVaultIntegration(t *testing.T) {
	keyring.MockInit()

	tmpDir, err := os.MkdirTemp("", "vouch-vault-keyring-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	vaultPath := filepath.Join(tmpDir, "vault.enc")
	passphrase := []byte("master-zero-prompt-passphrase-888")

	km := NewOSKeyringManager("vouchproxy-vault-svc", "master-vault-user")

	// 1. Create vault with keychain integration
	v, err := CreateWithKeychain(vaultPath, passphrase, km)
	if err != nil {
		t.Fatalf("CreateWithKeychain failed: %v", err)
	}
	if err := v.Set("TEST_API_KEY", []byte("sk-123456789")); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	v.Close()

	// 2. Zero-prompt unlock using OpenWithKeychain
	v2, err := OpenWithKeychain(vaultPath, km)
	if err != nil {
		t.Fatalf("OpenWithKeychain failed: %v", err)
	}
	defer v2.Close()

	val, err := v2.Get("TEST_API_KEY")
	if err != nil {
		t.Fatalf("Get secret failed: %v", err)
	}
	defer crypto.ZeroBytes(val)

	if string(val) != "sk-123456789" {
		t.Fatalf("unexpected secret value: %s", string(val))
	}

	// 3. OpenWithKeychain with nil km should return error
	if _, err := OpenWithKeychain(vaultPath, nil); err == nil {
		t.Fatal("expected error opening vault with nil KeychainManager")
	}

	// 4. CreateWithKeychain with nil km should create vault without saving to km
	vaultPath2 := filepath.Join(tmpDir, "vault2.enc")
	v3, err := CreateWithKeychain(vaultPath2, passphrase, nil)
	if err != nil {
		t.Fatalf("CreateWithKeychain with nil km failed: %v", err)
	}
	v3.Close()

	// 5. OpenWithKeychain with empty keychain returns error
	kmEmpty := NewOSKeyringManager("vouchproxy-empty-svc", "master-empty-user")
	if _, err := OpenWithKeychain(vaultPath, kmEmpty); err == nil {
		t.Fatal("expected error opening vault with empty keychain")
	}
}
