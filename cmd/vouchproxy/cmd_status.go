package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sshloktiwarii/vouchproxy/internal/certs"
	"github.com/sshloktiwarii/vouchproxy/internal/policy"
)

func runStatus(args []string) {
	vouchDir := defaultVouchDir()
	fmt.Printf("VouchProxy Status (%s)\n", vouchDir)
	fmt.Printf("--------------------------------------------------\n")

	caCertPath := filepath.Join(vouchDir, "ca.crt")
	if certs.VerifyCACertExists(caCertPath) {
		ca, err := certs.LoadCA(vouchDir)
		if err == nil {
			fmt.Printf("✓ Root CA: Valid (Subject: %s, Expires: %s)\n",
				ca.Certificate.Subject.CommonName, ca.Certificate.NotAfter.Format("2006-01-02"))
		} else {
			fmt.Printf("✗ Root CA: Corrupted or unreadable (%v)\n", err)
		}
	} else {
		fmt.Println("✗ Root CA: Not initialized")
	}

	vaultPath := filepath.Join(vouchDir, "vault.enc")
	if _, err := os.Stat(vaultPath); err == nil {
		fmt.Printf("✓ Vault: Initialized (%s)\n", vaultPath)
	} else {
		fmt.Println("✗ Vault: Not initialized")
	}

	configPath := filepath.Join(vouchDir, "vouch.yaml")
	if cfg, err := policy.LoadConfig(configPath); err == nil {
		fmt.Printf("✓ Policy: %d rules loaded (Strict: %v, PII Emails: %v)\n",
			len(cfg.Rules), cfg.Settings.StrictMode, cfg.Scrubbing.Emails)
	} else {
		fmt.Println("✗ Policy: Missing or invalid vouch.yaml")
	}

	auditPath := filepath.Join(vouchDir, "audit.jsonl")
	if info, err := os.Stat(auditPath); err == nil {
		fmt.Printf("✓ Audit Log: Active (%s, size %d bytes)\n", auditPath, info.Size())
	} else {
		fmt.Println("✗ Audit Log: No events yet")
	}
}
