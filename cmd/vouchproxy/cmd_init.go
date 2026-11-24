package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sshloktiwarii/vouchproxy/internal/certs"
	"github.com/sshloktiwarii/vouchproxy/internal/crypto"
	"github.com/sshloktiwarii/vouchproxy/internal/policy"
	"github.com/sshloktiwarii/vouchproxy/internal/vault"
)

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", defaultVouchDir(), "Directory to initialize configuration and vault")
	force := fs.Bool("force", false, "Overwrite existing configuration")
	systemTrust := fs.Bool("system-trust", false, "Register Root CA into OS system trust store")
	_ = fs.Parse(args)

	targetDir := *dir
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating directory %s: %v\n", targetDir, err)
		os.Exit(1)
	}

	caCertPath := filepath.Join(targetDir, "ca.crt")
	caKeyPath := filepath.Join(targetDir, "ca.key")
	vaultPath := filepath.Join(targetDir, "vault.enc")
	configPath := filepath.Join(targetDir, "vouch.yaml")

	if !*force && (certs.VerifyCACertExists(caCertPath) || certs.VerifyCACertExists(vaultPath)) {
		fmt.Fprintf(os.Stderr, "Error: VouchProxy already initialized at %s. Use --force to overwrite.\n", targetDir)
		os.Exit(1)
	}

	fmt.Println("==> Initializing VouchProxy sovereign local enclave...")

	// 1. Generate Root CA
	ca, err := certs.GenerateCA()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating CA: %v\n", err)
		os.Exit(1)
	}
	if _, _, err := ca.SaveCA(targetDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving CA: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Generated local Root CA (%s, %s)\n", caCertPath, caKeyPath)

	if *systemTrust {
		trustMgr := certs.NewSystemTrustManager()
		if err := trustMgr.InstallCA(caCertPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error registering system trust: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✓ Registered local Root CA into OS system trust store")
	}

	// 2. Prompt for master vault passphrase
	var passphrase []byte
	if envPass := os.Getenv("VOUCH_MASTER_KEY"); envPass != "" {
		passphrase = []byte(envPass)
	} else {
		var err error
		passphrase, err = readPasswordMasked("Enter Master Vault Passphrase (min 8 chars): ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
	if len(passphrase) < 8 {
		fmt.Fprintln(os.Stderr, "Error: Passphrase must be at least 8 characters")
		os.Exit(1)
	}
	defer crypto.ZeroBytes(passphrase)

	// 3. Initialize empty encrypted vault
	if *force {
		_ = os.Remove(vaultPath)
	}
	_, err = vault.Create(vaultPath, passphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating encrypted vault: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Created encrypted vault with 0600 permissions (%s)\n", vaultPath)

	// Save master passphrase to OS Keychain for zero-prompt unlock
	km := vault.NewOSKeyringManager("", "")
	if err := km.SetMasterPassphrase(passphrase); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to store passphrase in OS keychain: %v\n", err)
	} else {
		fmt.Println("✓ Stored master passphrase in OS Keychain for zero-prompt unlock")
	}

	// 4. Scaffold default policy template
	if _, err := os.Stat(configPath); os.IsNotExist(err) || *force {
		defaultCfg := policy.DefaultConfig()
		if err := policy.SaveConfig(configPath, defaultCfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating default policy: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Generated policy template (%s)\n", configPath)
	}

	fmt.Println("\n==> Initialization complete! You can now store secrets using:")
	fmt.Println("    vouchproxy secret set OPENAI_API_KEY")
	fmt.Println("    vouchproxy run -- <command>")
}
