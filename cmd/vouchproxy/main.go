package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/term"

	"github.com/sshloktiwarii/vouchproxy/internal/crypto"
	"github.com/sshloktiwarii/vouchproxy/internal/vault"
	"github.com/sshloktiwarii/vouchproxy/internal/version"
)

func defaultVouchDir() string {
	if custom := os.Getenv("VOUCH_DIR"); custom != "" {
		return custom
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".vouchproxy"
	}
	return filepath.Join(home, ".vouchproxy")
}

func readPasswordMasked(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)

	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		pass, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("failed to read password: %w", err)
		}
		if len(pass) == 0 {
			return nil, errors.New("passphrase cannot be empty")
		}
		return pass, nil
	}

	// Non-terminal fallback (pipes, redirects, automated tests)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}
	clean := bytes.TrimRight(line, "\r\n")
	if len(clean) == 0 {
		return nil, errors.New("passphrase cannot be empty")
	}
	res := make([]byte, len(clean))
	copy(res, clean)
	crypto.ZeroBytes(line)
	return res, nil
}

// readMasterPassphrase implements the 3-tier master passphrase resolution hierarchy:
// 1. VOUCH_MASTER_KEY environment variable.
// 2. OS Keychain zero-prompt unlock via km.GetMasterPassphrase().
// 3. Masked terminal prompt fallback via readPasswordMasked.
func readMasterPassphrase(km vault.KeychainManager, prompt string) ([]byte, error) {
	// 1. Environment variable override
	if envPass := os.Getenv("VOUCH_MASTER_KEY"); envPass != "" {
		return []byte(envPass), nil
	}

	// 2. OS Keychain zero-prompt unlock
	if km != nil {
		if pass, err := km.GetMasterPassphrase(); err == nil && len(pass) > 0 {
			return pass, nil
		}
	}

	// 3. Masked terminal prompt fallback
	return readPasswordMasked(prompt)
}

// unlockVault unlocks the vault using the 3-tier hierarchy:
// 1. VOUCH_MASTER_KEY environment variable.
// 2. OS Keychain zero-prompt unlock.
// 3. Masked terminal prompt fallback.
func unlockVault(vaultPath string) (*vault.Vault, error) {
	km := vault.NewOSKeyringManager("", "")

	// Tier 1: Environment variable override
	if envPass := os.Getenv("VOUCH_MASTER_KEY"); envPass != "" {
		passBytes := []byte(envPass)
		return vault.Open(vaultPath, passBytes)
	}

	// Tier 2: OS Keychain zero-prompt unlock via vault.OpenWithKeychain
	if v, err := vault.OpenWithKeychain(vaultPath, km); err == nil {
		return v, nil
	}

	// Tier 3: Masked terminal prompt fallback
	passphrase, err := readPasswordMasked("Enter Master Vault Passphrase: ")
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(passphrase)

	v, err := vault.Open(vaultPath, passphrase)
	if err != nil {
		return nil, err
	}

	// Persist to keychain upon successful manual unlock to re-enable zero-prompt
	_ = km.SetMasterPassphrase(passphrase)

	return v, nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "init":
		runInit(args)
	case "secret":
		runSecret(args)
	case "run":
		os.Exit(runRun(args))
	case "audit":
		runAudit(args)
	case "status":
		runStatus(args)
	case "ca":
		runCA(args)
	case "canary":
		runCanary(args)
	case "version", "--version", "-v":
		fmt.Printf("vouchproxy version %s (commit %s)\n", version.Version, version.GitCommit)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`VouchProxy: Host-Scoped Credential Injection & PII-Scrubbing MITM Proxy
Version: %s

Usage:
  vouchproxy <command> [arguments...]

Commands:
  init                       Initialize ~/.vouchproxy, Root CA, and encrypted vault
  secret set <KEY>           Store an encrypted credential in the local vault
  secret list                List registered vault keys and their dummy tokens
  secret delete <KEY>        Delete a credential from the vault
  run -- <cmd> [args...]     Execute a command sandboxed with dummy tokens and MITM proxy
  audit                      Query the local append-only JSONL audit ledger
  status                     Display health, CA status, and vault statistics
  ca export                  Export local Root CA certificate (PEM)
  canary mint / verify       Manage decoy canary tokens
  version                    Print version and build metadata
`, version.Version)
}
