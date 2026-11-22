package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVault_Lifecycle(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vouch-vault-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	vaultPath := filepath.Join(tmpDir, "vault.enc")
	passphrase := []byte("master-passphrase-testing-789")

	// 1. Create Vault
	v, err := Create(vaultPath, passphrase)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// 2. Set Secrets
	secret1 := []byte("sk-proj-openai-live-credential-value")
	if err := v.Set("OPENAI_API_KEY", secret1); err != nil {
		t.Fatalf("Set OPENAI_API_KEY failed: %v", err)
	}

	secret2 := []byte("ghp_github_personal_access_token_12345")
	if err := v.Set("GITHUB_TOKEN", secret2); err != nil {
		t.Fatalf("Set GITHUB_TOKEN failed: %v", err)
	}

	// 3. Verify List (dummy tokens generated)
	list := v.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 secrets in list, got %d", len(list))
	}

	dummyMap := v.DummyMap()
	if dummyMap["OPENAI_API_KEY"] == "" || dummyMap["GITHUB_TOKEN"] == "" {
		t.Fatalf("dummy tokens were not generated: %+v", dummyMap)
	}

	// 4. Retrieve Secret and Verify Redaction
	sec, err := v.Get("OPENAI_API_KEY")
	if err != nil {
		t.Fatalf("Get OPENAI_API_KEY failed: %v", err)
	}
	if !bytes.Equal(sec, secret1) {
		t.Fatalf("expected secret %s, got %s", string(secret1), string(sec))
	}

	// Verify String() and GoString() redacting
	if sec.String() != "[REDACTED_SECRET]" {
		t.Fatalf("expected [REDACTED_SECRET], got %s", sec.String())
	}
	if sec.GoString() != "[REDACTED_SECRET]" {
		t.Fatalf("expected [REDACTED_SECRET], got %s", sec.GoString())
	}
	sec.Zero()

	// 5. Close and Reopen from disk
	v.Close()

	v2, err := Open(vaultPath, passphrase)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer v2.Close()

	secGh, err := v2.Get("GITHUB_TOKEN")
	if err != nil {
		t.Fatalf("Get GITHUB_TOKEN failed after reopen: %v", err)
	}
	if !bytes.Equal(secGh, secret2) {
		t.Fatalf("secret mismatch after reopen: got %s", string(secGh))
	}
	secGh.Zero()

	// 6. Delete Secret
	if err := v2.Delete("GITHUB_TOKEN"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	_, err = v2.Get("GITHUB_TOKEN")
	if err == nil {
		t.Fatal("expected error getting deleted secret, got nil")
	}

	// 7. Verify Permissions (on POSIX)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(vaultPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 permissions, got %04o", info.Mode().Perm())
		}
	}
}
