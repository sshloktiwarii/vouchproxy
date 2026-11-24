package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/sshloktiwarii/vouchproxy/internal/audit"
	"github.com/sshloktiwarii/vouchproxy/internal/certs"
	"github.com/sshloktiwarii/vouchproxy/internal/crypto"
	"github.com/sshloktiwarii/vouchproxy/internal/mcp"
	"github.com/sshloktiwarii/vouchproxy/internal/policy"
	"github.com/sshloktiwarii/vouchproxy/internal/proxy"
	"github.com/sshloktiwarii/vouchproxy/internal/runner"
	"github.com/sshloktiwarii/vouchproxy/internal/tui"
)

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
	} else if cfg.Settings.StrictMode {
		*strict = true
	}
	if !*systemTrust && cfg.SystemTrust.Enabled {
		*systemTrust = true
	}
	if !*mcpStdio && cfg.MCP.Enabled {
		*mcpStdio = true
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
