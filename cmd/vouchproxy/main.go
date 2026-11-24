package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/sshloktiwarii/vouchproxy/internal/audit"
	"github.com/sshloktiwarii/vouchproxy/internal/canary"
	"github.com/sshloktiwarii/vouchproxy/internal/certs"
	"github.com/sshloktiwarii/vouchproxy/internal/crypto"
	"github.com/sshloktiwarii/vouchproxy/internal/mcp"
	"github.com/sshloktiwarii/vouchproxy/internal/policy"
	"github.com/sshloktiwarii/vouchproxy/internal/proxy"
	"github.com/sshloktiwarii/vouchproxy/internal/runner"
	"github.com/sshloktiwarii/vouchproxy/internal/tui"
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
// 3. Masked terminal prompt fallback (saving to keychain on success).
func unlockVault(vaultPath string) (*vault.Vault, error) {
	// Tier 1: Environment variable override
	if envPass := os.Getenv("VOUCH_MASTER_KEY"); envPass != "" {
		pass := []byte(envPass)
		return vault.Open(vaultPath, pass)
	}

	km := vault.NewOSKeyringManager("", "")

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
  version                    Print version and build metadata
`, version.Version)
}

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

func runSecret(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: vouchproxy secret <set|list|delete> [args...]")
		os.Exit(1)
	}

	subCmd := args[0]
	subArgs := args[1:]

	vouchDir := defaultVouchDir()
	vaultPath := filepath.Join(vouchDir, "vault.enc")

	switch subCmd {
	case "set":
		if len(subArgs) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: vouchproxy secret set <KEY_NAME>")
			os.Exit(1)
		}
		keyName := strings.ToUpper(strings.TrimSpace(subArgs[0]))

		v, err := unlockVault(vaultPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening vault: %v\n", err)
			os.Exit(1)
		}
		defer v.Close()

		secretVal, err := readPasswordMasked(fmt.Sprintf("Enter secret value for %s: ", keyName))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer crypto.ZeroBytes(secretVal)

		if err := v.Set(keyName, secretVal); err != nil {
			fmt.Fprintf(os.Stderr, "Error setting secret: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Secret %q stored encrypted in vault. Bound dummy token: %s\n",
			keyName, vault.GenerateDummyToken(keyName))

	case "list":
		v, err := unlockVault(vaultPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening vault: %v\n", err)
			os.Exit(1)
		}
		defer v.Close()

		items := v.List()
		if len(items) == 0 {
			fmt.Println("No secrets stored in vault.")
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "KEY NAME\tDUMMY TOKEN\tCREATED AT")
		for _, item := range items {
			fmt.Fprintf(w, "%s\t%s\t%s\n", item.KeyName, item.DummyToken, time.Unix(item.CreatedAt, 0).Format("2006-01-02 15:04:05"))
		}
		_ = w.Flush()

	case "delete", "rm":
		if len(subArgs) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: vouchproxy secret delete <KEY_NAME>")
			os.Exit(1)
		}
		keyName := strings.ToUpper(strings.TrimSpace(subArgs[0]))

		v, err := unlockVault(vaultPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening vault: %v\n", err)
			os.Exit(1)
		}
		defer v.Close()

		if err := v.Delete(keyName); err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting secret: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Secret %q deleted from vault.\n", keyName)

	default:
		fmt.Fprintf(os.Stderr, "Unknown secret command: %s\n", subCmd)
		os.Exit(1)
	}
}

func runRun(args []string) int {
	var flagArgs []string
	var cmdArgs []string

	for i, arg := range args {
		if arg == "--" {
			flagArgs = args[:i]
			cmdArgs = args[i+1:]
			break
		}
	}
	if len(cmdArgs) == 0 && len(flagArgs) == 0 {
		flagArgs = args
	}

	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to vouch.yaml policy file")
	auditLogPath := fs.String("audit-log", "", "Path to audit JSONL file")
	strict := fs.Bool("strict", false, "Enable strict mode (block all unmapped outbound hosts)")
	systemTrust := fs.Bool("system-trust", false, "Register Root CA into OS system trust store for duration of execution")
	mcpStdio := fs.Bool("mcp-stdio", false, "Enable MCP stdio JSON-RPC semantic firewall")
	tuiMode := fs.Bool("tui", false, "Enable interactive Bubbletea split-pane TUI dashboard")
	_ = fs.Parse(flagArgs)

	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no command provided after '--'. Example: vouchproxy run -- curl https://api.openai.com/v1/models")
		return 1
	}

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigChan)

	vouchDir := defaultVouchDir()
	if *configPath == "" {
		*configPath = filepath.Join(vouchDir, "vouch.yaml")
	}
	if *auditLogPath == "" {
		*auditLogPath = filepath.Join(vouchDir, "audit.jsonl")
	}

	caCertPath := filepath.Join(vouchDir, "ca.crt")
	vaultPath := filepath.Join(vouchDir, "vault.enc")

	// 1. Verify and Load CA
	ca, err := certs.LoadCA(vouchDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading CA from %s: %v\nRun 'vouchproxy init' first.\n", vouchDir, err)
		return 1
	}

	// Register Ephemeral System Trust Store if requested (fail closed on error)
	var cleanupTrust func()
	if *systemTrust {
		trustMgr := certs.NewSystemTrustManager()
		cleanupTrust, err = trustMgr.RegisterTeardown(caCertPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error registering system trust: %v\n", err)
			return 1
		}
		defer cleanupTrust()
	}

	// 2. Unlock Vault
	v, err := unlockVault(vaultPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening vault: %v\n", err)
		return 1
	}
	defer v.Close()

	// 3. Load Policy
	cfg, err := policy.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading policy from %s: %v\n", *configPath, err)
		return 1
	}
	if *strict {
		cfg.Settings.StrictMode = true
	}

	pe, err := policy.NewPolicyEngine(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating policy engine: %v\n", err)
		return 1
	}

	// 4. Initialize Zero-Bloat Append-Only JSONL Audit Logger
	logger, err := audit.NewLogger(*auditLogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening audit log: %v\n", err)
		return 1
	}
	defer func() { _ = logger.Close() }()

	sessionID, _ := crypto.RandomHex(16)
	sessionSecret, err := crypto.RandomHex(32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating session secret: %v\n", err)
		return 1
	}

	// 5. Start Local Proxy Server
	proxySrv, err := proxy.NewServer(proxy.ServerOptions{
		SessionID:     sessionID,
		SessionSecret: sessionSecret,
		Config:        cfg,
		PolicyEngine:  pe,
		Vault:         v,
		AuditLogger:   logger,
		CA:            ca,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating proxy server: %v\n", err)
		return 1
	}

	_ = proxySrv.Start()
	defer func() { _ = proxySrv.Close() }()

	// Format proxy URL with session authentication
	authProxyURL := fmt.Sprintf("http://session:%s@127.0.0.1:%d", sessionSecret, proxySrv.Port())

	// 6. Launch Supervised Child Command
	dummyMap := v.DummyMap()
	var childStdin io.Reader = os.Stdin
	var childStdout io.Writer = os.Stdout
	if *mcpStdio {
		childStdin = nil
		childStdout = nil
	} else if *tuiMode {
		childStdin = nil
	}

	childCmd, err := runner.PrepareCommand(runner.SubprocessConfig{
		Command:     cmdArgs,
		ProxyURL:    authProxyURL,
		CACertPath:  caCertPath,
		DummyTokens: dummyMap,
		Stdin:       childStdin,
		Stdout:      childStdout,
		Stderr:      os.Stderr,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error preparing command: %v\n", err)
		return 1
	}

	var cleanupTUI func()
	var tuiQuitChan <-chan struct{}
	if *tuiMode {
		_, tuiQuitChan, cleanupTUI = tui.StartTUI()
	}
	defer func() {
		if cleanupTUI != nil {
			cleanupTUI()
		}
	}()

	select {
	case sig := <-sigChan:
		if cleanupTrust != nil {
			cleanupTrust()
		}
		if s, ok := sig.(syscall.Signal); ok {
			return 128 + int(s)
		}
		return 130
	default:
	}

	var exitCode int
	if *mcpStdio {
		exitCode, err = mcp.RunStdioProxyWithSignals(childCmd, v, sigChan)
	} else {
		exitCode, err = runner.RunSupervisedWithSignals(childCmd, sigChan, tuiQuitChan)
	}

	if err != nil && exitCode == 0 {
		fmt.Fprintf(os.Stderr, "Child process error: %v\n", err)
	}
	if cleanupTrust != nil {
		cleanupTrust()
	}
	return exitCode
}

func runCanary(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: vouchproxy canary <mint|verify> [arguments...]")
		os.Exit(1)
	}

	subCmd := args[0]
	subArgs := args[1:]

	switch subCmd {
	case "mint":
		fs := flag.NewFlagSet("canary mint", flag.ExitOnError)
		promptID := fs.String("prompt", "", "Prompt identifier")
		keyName := fs.String("key", "", "Key name to associate with canary")
		ttlStr := fs.String("ttl", "1h", "Time-to-live duration (e.g. 10m, 1h, -120s)")
		_ = fs.Parse(subArgs)

		if *promptID == "" || *keyName == "" {
			fmt.Fprintln(os.Stderr, "Error: --prompt and --key are required")
			os.Exit(1)
		}

		ttl, err := time.ParseDuration(*ttlStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing --ttl: %v\n", err)
			os.Exit(1)
		}

		token, err := canary.Mint(*promptID, *keyName, ttl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error minting canary token: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(token)

	case "verify":
		fs := flag.NewFlagSet("canary verify", flag.ExitOnError)
		token := fs.String("token", "", "Canary token to verify")
		_ = fs.Parse(subArgs)

		if *token == "" {
			fmt.Fprintln(os.Stderr, "Error: --token is required")
			os.Exit(1)
		}

		tok, err := canary.Verify(*token)
		if err != nil {
			fmt.Printf("Verification failed: %v\n", err)
			fmt.Fprintf(os.Stderr, "Error: canary token verification failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Canary token valid:\n  Prompt ID: %s\n  Key Name:  %s\n  Expires:   %s\n",
			tok.PromptID, tok.KeyName, tok.ExpiresAt.Format(time.RFC3339))

	default:
		fmt.Fprintf(os.Stderr, "Unknown canary subcommand: %s\n", subCmd)
		os.Exit(1)
	}
}

func runAudit(args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	logPath := fs.String("log", filepath.Join(defaultVouchDir(), "audit.jsonl"), "Path to audit JSONL file")
	hostFilter := fs.String("host", "", "Filter by destination host")
	actionFilter := fs.String("action", "", "Filter by action (INJECT_SECRET, BLOCK_LEAK, SCRUB_PII)")
	limit := fs.Int("limit", 20, "Number of events to display")
	tailMode := fs.Bool("tail", false, "Read latest events in reverse chronological order")
	jsonOutput := fs.Bool("json", false, "Output in JSON format")
	_ = fs.Parse(args)

	var events []audit.AuditEvent
	var err error

	if *tailMode || *limit > 0 {
		events, err = audit.Tail(*logPath, audit.TailOptions{
			Limit:  *limit,
			Host:   *hostFilter,
			Action: *actionFilter,
		})
	} else {
		events, err = audit.ReadAll(*logPath)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading audit log: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(events)
		return
	}

	if len(events) == 0 {
		fmt.Println("No audit events recorded.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIMESTAMP\tACTION\tSTATUS\tMETHOD\tHOST\tPATH\tINJECTED KEY\tSCRUBS\tLATENCY")
	for _, ev := range events {
		ts := ev.Timestamp.Format("15:04:05")
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%d\t%.1fms\n",
			ts, ev.Action, ev.HTTPStatus, ev.HTTPMethod, ev.Host, ev.PathSanitized, ev.InjectedKeyName, ev.ScrubCount, ev.LatencyMs)
	}
	_ = w.Flush()
}

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

func runCA(args []string) {
	if len(args) == 0 || args[0] != "export" {
		fmt.Fprintln(os.Stderr, "Usage: vouchproxy ca export [--out <path>]")
		os.Exit(1)
	}

	fs := flag.NewFlagSet("ca export", flag.ExitOnError)
	outPath := fs.String("out", "", "Destination path to write CA certificate PEM")
	_ = fs.Parse(args[1:])

	vouchDir := defaultVouchDir()
	caCertPath := filepath.Join(vouchDir, "ca.crt")
	data, err := os.ReadFile(caCertPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading CA cert: %v\n", err)
		os.Exit(1)
	}

	if *outPath != "" {
		if err := os.WriteFile(*outPath, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing CA cert to %s: %v\n", *outPath, err)
			os.Exit(1)
		}
		fmt.Printf("✓ Exported Root CA to %s\n", *outPath)
	} else {
		fmt.Print(string(data))
	}
}
