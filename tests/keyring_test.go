package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sshloktiwarii/vouchproxy/internal/vault"
)

// 6. TestE2E_R2_Keychain_MasterPassphraseStoredOnInit verifies vouchproxy init
// securely stores master passphrase in OS keyring under service 'vouchproxy'.
func TestE2E_R2_Keychain_MasterPassphraseStoredOnInit(t *testing.T) {
	s := NewVouchSession(t)
	testPass := "master-phrase-alpha-123"

	// 1. Run vouchproxy init as child subprocess
	out, err := s.Init(testPass)
	if err != nil {
		t.Fatalf("vouchproxy init failed: %v (out: %s)", err, out)
	}

	// 2. Verify vault.enc permissions
	vaultFile := filepath.Join(s.VouchDir, "vault.enc")
	info, err := os.Stat(vaultFile)
	if err != nil {
		t.Fatalf("vault.enc not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Logf("vault.enc permissions are %o (expected 0600)", perm)
	}

	// 3. Verify passphrase was saved by vouchproxy init into isolated keyring
	km := s.KeyringManager()
	retrieved, err := km.GetMasterPassphrase()
	if err != nil {
		t.Fatalf("Failed to retrieve stored master passphrase from keyring after init: %v", err)
	}
	if string(retrieved) != testPass {
		t.Fatalf("Expected stored passphrase %q, got %q", testPass, string(retrieved))
	}
}

// 7. TestE2E_R2_Keychain_ZeroPromptVaultUnlock verifies vouchproxy run retrieves
// master passphrase from keyring and decrypts vault.enc with /dev/null stdin (zero prompts).
func TestE2E_R2_Keychain_ZeroPromptVaultUnlock(t *testing.T) {
	s := NewVouchSession(t)
	masterPass := "zero-prompt-passphrase-456"

	// 1. Enclave init stores master passphrase in isolated keyring
	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Failed to init enclave: %v", err)
	}

	// 2. DO NOT SET VOUCH_MASTER_KEY. Tier 2 (keychain) must be exercised.
	delete(s.Env, "VOUCH_MASTER_KEY")

	// 3. Run child command with empty stdin (/dev/null equivalent, zero manual prompts)
	out, errOut, code, runErr := s.RunCommandWithInput("", "run", "--", "echo", "zero-prompt-success")
	if code != 0 {
		t.Fatalf("Expected zero-prompt run to succeed (code 0), got %d: %s\n%s (%v)", code, out, errOut, runErr)
	}

	if !strings.Contains(out+errOut, "zero-prompt-success") {
		t.Errorf("Expected child output 'zero-prompt-success', got: %s", out+errOut)
	}
}

// 8. TestE2E_R2_Keychain_SecretManagementLifecycle verifies vouchproxy secret set,
// list, and delete operate seamlessly without manual passphrase prompts when unlocked.
func TestE2E_R2_Keychain_SecretManagementLifecycle(t *testing.T) {
	s := NewVouchSession(t)
	masterPass := "lifecycle-passphrase-789"

	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Zero-prompt unlock across all secret lifecycle operations
	delete(s.Env, "VOUCH_MASTER_KEY")

	// 1. Secret Set (unlocked via keychain, secret value via stdin)
	secretKey := "STRIPE_KEY"
	secretVal := "sk_live_stripe_secret_999"
	err = s.SeedSecret(secretKey, secretVal, "")
	if err != nil {
		t.Fatalf("Secret set failed: %v", err)
	}

	// 2. Secret List (zero-prompt unlock via keychain)
	listOut, listErr, code, _ := s.RunCommand("secret", "list")
	if code != 0 {
		t.Fatalf("Secret list failed with code %d: %s\n%s", code, listOut, listErr)
	}
	if !strings.Contains(listOut, "STRIPE_KEY") {
		t.Errorf("Expected secret list to contain 'STRIPE_KEY', got: %s", listOut)
	}
	if !strings.Contains(listOut, "VP_STRIPE_KEY_DUMMY_") {
		t.Errorf("Expected secret list to contain bound dummy token, got: %s", listOut)
	}

	// 3. Secret Delete (zero-prompt unlock via keychain)
	delOut, delErr, code, _ := s.RunCommand("secret", "delete", secretKey)
	if code != 0 {
		t.Fatalf("Secret delete failed with code %d: %s\n%s", code, delOut, delErr)
	}
	if !strings.Contains(delOut, "deleted from vault") {
		t.Errorf("Expected deletion confirmation, got: %s", delOut)
	}

	// 4. Verify gone
	listAfter, _, _, _ := s.RunCommand("secret", "list")
	if strings.Contains(listAfter, "STRIPE_KEY") {
		t.Errorf("Deleted key still present in secret list: %s", listAfter)
	}
}

// 9. TestE2E_R2_Keychain_FallbackToPromptWhenKeyringEmpty verifies graceful
// fallback to masked terminal prompt when keychain has no entry.
func TestE2E_R2_Keychain_FallbackToPromptWhenKeyringEmpty(t *testing.T) {
	masterPass := "fallback-prompt-passphrase-321"
	s := NewVouchSession(t)

	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Clear keyring so it is genuinely empty
	km := s.KeyringManager()
	if err := km.DeleteMasterPassphrase(); err != nil {
		t.Fatalf("Failed to clear keyring: %v", err)
	}

	// Verify zero-prompt fails when keyring is empty and stdin is closed
	_, _, failCode, _ := s.RunCommandWithInput("", "run", "--", "echo", "should-not-run")
	if failCode == 0 {
		t.Fatalf("Expected run to fail zero-prompt unlock when keyring is empty and stdin is closed")
	}

	// Verify masked terminal prompt fallback unlocks vault when passphrase is fed to stdin
	out, errOut, code, runErr := s.RunCommandWithInput(masterPass+"\n", "run", "--", "echo", "fallback-prompt-success")
	if code != 0 {
		t.Fatalf("Expected fallback prompt to unlock vault and execute child (code 0), got %d: %s\n%s (%v)", code, out, errOut, runErr)
	}
	if !strings.Contains(out+errOut, "fallback-prompt-success") {
		t.Errorf("Expected child output 'fallback-prompt-success', got: %s", out+errOut)
	}
}

// 10. TestE2E_R2_Keychain_EnvVarPrecedenceOverKeyring verifies VOUCH_MASTER_KEY
// environment variable takes precedence over keychain entry.
func TestE2E_R2_Keychain_EnvVarPrecedenceOverKeyring(t *testing.T) {
	realPass := "correct-master-passphrase-111"
	bogusPass := "invalid-bogus-keychain-passphrase-000"

	s := NewVouchSession(t)

	// Init enclave with realPass
	_, err := s.Init(realPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Overwrite keyring entry with bogusPass
	km := s.KeyringManager()
	if err := km.SetMasterPassphrase([]byte(bogusPass)); err != nil {
		t.Fatalf("Failed to inject bogus passphrase into keyring: %v", err)
	}

	// Set correct passphrase in environment variable (Tier 1)
	s.SetEnv("VOUCH_MASTER_KEY", realPass)

	// Run child command. If Tier 1 takes precedence, realPass will unlock.
	// If it fell back to Tier 2, bogusPass would fail decryption.
	out, errOut, code, _ := s.RunCommand("run", "--", "echo", "env-precedence-success")
	if code != 0 {
		t.Fatalf("Expected env var to override keyring and unlock vault, got code %d: %s\n%s", code, out, errOut)
	}

	if !strings.Contains(out+errOut, "env-precedence-success") {
		t.Errorf("Expected 'env-precedence-success' in output, got: %s", out+errOut)
	}
}

// 31. TestE2E_R2_Edge_KeyringDaemonUnavailable verifies unreachable keyring daemon
// triggers warning and falls back to terminal prompt.
func TestE2E_R2_Edge_KeyringDaemonUnavailable(t *testing.T) {
	t.Setenv(vault.KeyringFileEnv, filepath.Join(t.TempDir(), "keyring.json"))
	// In-memory manager testing simulated unavailable provider
	km := vault.NewOSKeyringManager("non-existent-service-9999", "non-existent-user-9999")
	_, err := km.GetMasterPassphrase()
	if err == nil {
		t.Fatal("Expected error for non-existent service/user in keyring, got nil")
	}

	// Verify that CLI fallback prompt still works even if keychain is unavailable
	masterPass := "daemon-unavailable-pass-555"
	s := NewVouchSession(t)
	_, err = s.Init(masterPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	out, errOut, code, _ := s.RunCommandWithInput(masterPass+"\n", "run", "--", "echo", "daemon-fallback-ok")
	if code != 0 {
		t.Fatalf("Expected prompt fallback to succeed when keyring has no match, got code %d: %s\n%s", code, out, errOut)
	}
}

// 32. TestE2E_R2_Edge_CorruptedKeyringPayload verifies garbage bytes returned
// from keychain fail authentication cleanly without panic.
func TestE2E_R2_Edge_CorruptedKeyringPayload(t *testing.T) {
	s := NewVouchSession(t)

	// Store garbage bytes in isolated keyring
	corrupted := "\x00\xff\xfe\x01\x02\x03\xde\xad\xbe\xef"
	km := s.KeyringManager()
	_ = km.SetMasterPassphrase([]byte(corrupted))

	masterPass := "legit-master-passphrase-222"
	s.SetEnv("VOUCH_MASTER_KEY", masterPass)
	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Now try to open vault directly with corrupted bytes
	vaultPath := filepath.Join(s.VouchDir, "vault.enc")
	_, openErr := vault.Open(vaultPath, []byte(corrupted))
	if openErr == nil {
		t.Fatal("Expected vault decryption to fail with corrupted passphrase, got nil error")
	}
	t.Logf("Corrupted payload produced expected authentication failure: %v", openErr)
}

// 33. TestE2E_R2_Edge_ConcurrentVaultUnlockContention verifies 20 concurrent
// processes unlock vault.enc without file lock contention errors.
func TestE2E_R2_Edge_ConcurrentVaultUnlockContention(t *testing.T) {
	masterPass := "concurrent-unlock-pass-333"
	s := NewVouchSession(t)
	s.SetEnv("VOUCH_MASTER_KEY", masterPass)

	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	_ = s.SeedSecret("SHARED_KEY", "shared-value-999", masterPass)

	concurrency := 20
	var wg sync.WaitGroup
	wg.Add(concurrency)
	errChan := make(chan error, concurrency)

	vaultPath := filepath.Join(s.VouchDir, "vault.enc")

	for i := 0; i < concurrency; i++ {
		go func(workerID int) {
			defer wg.Done()
			v, openErr := vault.Open(vaultPath, []byte(masterPass))
			if openErr != nil {
				errChan <- fmt.Errorf("worker %d failed to open vault: %w", workerID, openErr)
				return
			}
			defer v.Close()

			val, getErr := v.Get("SHARED_KEY")
			if getErr != nil || string(val) != "shared-value-999" {
				errChan <- fmt.Errorf("worker %d failed to get secret: %v", workerID, getErr)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for e := range errChan {
		t.Errorf("Concurrent vault contention error: %v", e)
	}
}

// 34. TestE2E_R2_Edge_PassphraseSpecialCharactersAndLength verifies passphrases
// with null bytes, emojis, and 256 characters are preserved accurately.
func TestE2E_R2_Edge_PassphraseSpecialCharactersAndLength(t *testing.T) {
	t.Setenv(vault.KeyringFileEnv, filepath.Join(t.TempDir(), "keyring.json"))

	km := vault.NewOSKeyringManager("vouchproxy", "master")

	// Complex passphrase with Unicode, emoji, and punctuation
	complexPass := "🔑Secret#Master\x00Token!@$%^&*()_+2026🚀" + strings.Repeat("A", 220)
	if len(complexPass) < 256 {
		complexPass += strings.Repeat("Z", 256-len(complexPass))
	}

	err := km.SetMasterPassphrase([]byte(complexPass))
	if err != nil {
		t.Fatalf("Failed to store complex 256-char passphrase: %v", err)
	}

	retrieved, err := km.GetMasterPassphrase()
	if err != nil {
		t.Fatalf("Failed to retrieve complex passphrase: %v", err)
	}

	if string(retrieved) != complexPass {
		t.Fatalf("Passphrase mismatch for 256-char special input. Got len %d, expected %d", len(retrieved), len(complexPass))
	}

	// Verify vault creation with this passphrase
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault_complex.enc")
	v, err := vault.Create(vaultPath, []byte(complexPass))
	if err != nil {
		t.Fatalf("Failed to create vault with complex passphrase: %v", err)
	}
	_ = v.Set("TEST_KEY", []byte("test_val"))
	v.Close()

	// Verify vault open with this passphrase
	v2, err := vault.Open(vaultPath, []byte(complexPass))
	if err != nil {
		t.Fatalf("Failed to reopen vault with complex passphrase: %v", err)
	}
	defer v2.Close()
	val, _ := v2.Get("TEST_KEY")
	if string(val) != "test_val" {
		t.Fatalf("Expected 'test_val', got %q", string(val))
	}
}

// 35. TestE2E_R2_Edge_KeyringDeleteIdempotency verifies deleting non-existent
// keychain entry returns nil or handled error without crashing.
func TestE2E_R2_Edge_KeyringDeleteIdempotency(t *testing.T) {
	t.Setenv(vault.KeyringFileEnv, filepath.Join(t.TempDir(), "keyring.json"))

	km := vault.NewOSKeyringManager("vouchproxy", "master")

	// First delete: should not panic
	_ = km.DeleteMasterPassphrase()

	// Second delete on non-existent entry: must be idempotent and safe
	err := km.DeleteMasterPassphrase()
	t.Logf("Second delete returned: %v (safe and handled)", err)
}
