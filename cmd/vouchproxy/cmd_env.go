package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/audit"
	"github.com/sshloktiwarii/vouchproxy/internal/certs"
	"github.com/sshloktiwarii/vouchproxy/internal/crypto"
	"github.com/sshloktiwarii/vouchproxy/internal/policy"
	"github.com/sshloktiwarii/vouchproxy/internal/proxy"
	"github.com/sshloktiwarii/vouchproxy/internal/runner"
)

// DaemonState stores metadata for active background proxy listeners.
type DaemonState struct {
	PID           int       `json:"pid"`
	Port          int       `json:"port"`
	SessionSecret string    `json:"session_secret"`
	SessionID     string    `json:"session_id"`
	StartedAt     time.Time `json:"started_at"`
}

func detectShell(flagVal string) string {
	if flagVal != "" && flagVal != "auto" {
		s := strings.ToLower(flagVal)
		switch s {
		case "fish":
			return "fish"
		case "powershell", "pwsh", "ps1":
			return "powershell"
		case "bash", "zsh", "sh":
			return "sh"
		default:
			return "sh"
		}
	}

	if runtime.GOOS == "windows" {
		return "powershell"
	}

	shell := os.Getenv("SHELL")
	if strings.Contains(shell, "fish") {
		return "fish"
	}
	if strings.Contains(shell, "pwsh") || strings.Contains(shell, "powershell") {
		return "powershell"
	}
	return "sh"
}

// ensureProxyListener verifies the background proxy listener is alive or spawns one.
func ensureProxyListener(vouchDir string) (int, string, error) {
	stateFile := filepath.Join(vouchDir, "daemon.json")

	// Check existing daemon
	if data, err := os.ReadFile(stateFile); err == nil {
		var state DaemonState
		if json.Unmarshal(data, &state) == nil && state.Port > 0 {
			conn, dialErr := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", state.Port), 250*time.Millisecond)
			if dialErr == nil {
				_ = conn.Close()
				return state.Port, state.SessionSecret, nil
			}
		}
		_ = os.Remove(stateFile)
	}

	// Spawn detached background daemon
	self, err := os.Executable()
	if err != nil {
		return 0, "", fmt.Errorf("failed to locate executable: %w", err)
	}

	cmd := exec.Command(self, "daemon")
	cmd.Dir = vouchDir
	cmd.Env = os.Environ()

	// Detach process
	runner.SetProcessGroup(cmd)

	if err := cmd.Start(); err != nil {
		return 0, "", fmt.Errorf("failed to start background daemon: %w", err)
	}

	// Wait up to 3 seconds for daemon.json and active listener
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		if data, err := os.ReadFile(stateFile); err == nil {
			var state DaemonState
			if json.Unmarshal(data, &state) == nil && state.Port > 0 {
				conn, dialErr := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", state.Port), 250*time.Millisecond)
				if dialErr == nil {
					_ = conn.Close()
					return state.Port, state.SessionSecret, nil
				}
			}
		}
	}

	return 0, "", fmt.Errorf("timed out waiting for background proxy daemon on 127.0.0.1")
}

func runEnv(args []string) {
	fs := flag.NewFlagSet("env", flag.ExitOnError)
	shellFlag := fs.String("shell", "auto", "Shell syntax (sh, bash, zsh, fish, powershell)")
	unsetFlag := fs.Bool("u", false, "Generate unset statements to deactivate proxy")
	unsetLong := fs.Bool("unset", false, "Generate unset statements to deactivate proxy")
	_ = fs.Parse(args)

	targetShell := detectShell(*shellFlag)
	isUnset := *unsetFlag || *unsetLong

	vouchDir := defaultVouchDir()
	vaultPath := filepath.Join(vouchDir, "vault.enc")

	// Collect vault keys for dummy injection or unsetting
	dummyTokens := make(map[string]string)
	if v, err := unlockVault(vaultPath); err == nil {
		dummyTokens = v.DummyMap()
		v.Close()
	}

	if isUnset {
		printUnsetEnv(targetShell, dummyTokens)
		return
	}

	// Ensure background proxy listener is running
	port, sessionSecret, err := ensureProxyListener(vouchDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	caCertPath := filepath.Join(vouchDir, "ca.crt")
	proxyURL := fmt.Sprintf("http://session:%s@127.0.0.1:%d", sessionSecret, port)

	envVars := make(map[string]string)

	// Proxy Envs
	envVars["HTTP_PROXY"] = proxyURL
	envVars["http_proxy"] = proxyURL
	envVars["HTTPS_PROXY"] = proxyURL
	envVars["https_proxy"] = proxyURL
	envVars["ALL_PROXY"] = proxyURL
	envVars["all_proxy"] = proxyURL
	envVars["NO_PROXY"] = ""
	envVars["no_proxy"] = ""

	// CA Trust Envs
	for k, v := range certs.TrustEnvironment(caCertPath) {
		envVars[k] = v
	}

	// Vault Dummy Tokens
	for k, v := range dummyTokens {
		envVars[k] = v
		envVars["VP_"+k+"_DUMMY"] = v
	}

	printExportEnv(targetShell, envVars)
}

func printExportEnv(targetShell string, envVars map[string]string) {
	switch targetShell {
	case "fish":
		for k, v := range envVars {
			fmt.Printf("set -gx %s %q;\n", k, v)
		}
	case "powershell":
		for k, v := range envVars {
			fmt.Printf("$env:%s = \"%s\"\n", k, v)
		}
	default: // sh, bash, zsh
		for k, v := range envVars {
			fmt.Printf("export %s=%q\n", k, v)
		}
	}
}

func printUnsetEnv(targetShell string, dummyTokens map[string]string) {
	keysToUnset := []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"ALL_PROXY", "all_proxy",
		"NO_PROXY", "no_proxy",
		"SSL_CERT_FILE",
		"NODE_EXTRA_CA_CERTS",
		"REQUESTS_CA_BUNDLE",
		"CURL_CA_BUNDLE",
		"CARGO_HTTP_CAINFO",
		"AWS_CA_BUNDLE",
		"GIT_SSL_CAINFO",
		"DENO_TLS_CA_STORE",
	}
	for k := range dummyTokens {
		keysToUnset = append(keysToUnset, k, "VP_"+k+"_DUMMY")
	}

	switch targetShell {
	case "fish":
		for _, k := range keysToUnset {
			fmt.Printf("set -e %s;\n", k)
		}
	case "powershell":
		for _, k := range keysToUnset {
			fmt.Printf("Remove-Item env:%s -ErrorAction SilentlyContinue\n", k)
		}
	default:
		fmt.Printf("unset %s\n", strings.Join(keysToUnset, " "))
	}
}

func runDaemon(args []string) {
	vouchDir := defaultVouchDir()
	stateFile := filepath.Join(vouchDir, "daemon.json")
	caCertPath := filepath.Join(vouchDir, "ca.crt")
	vaultPath := filepath.Join(vouchDir, "vault.enc")
	configPath := filepath.Join(vouchDir, "vouch.yaml")
	auditLogPath := filepath.Join(vouchDir, "audit.jsonl")

	ca, err := certs.LoadCA(vouchDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading CA: %v\n", err)
		os.Exit(1)
	}

	v, err := unlockVault(vaultPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening vault: %v\n", err)
		os.Exit(1)
	}
	defer v.Close()

	cfg, err := policy.LoadConfig(configPath)
	if err != nil {
		cfg = policy.DefaultConfig()
	}

	pe, err := policy.NewPolicyEngine(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating policy engine: %v\n", err)
		os.Exit(1)
	}

	logger, err := audit.NewLogger(auditLogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening audit log: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	sessionID, _ := crypto.RandomHex(16)
	sessionSecret, _ := crypto.RandomHex(32)

	srv, err := proxy.NewServer(proxy.ServerOptions{
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
		os.Exit(1)
	}

	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting proxy server: %v\n", err)
		os.Exit(1)
	}
	defer srv.Close()

	// Write daemon state
	state := DaemonState{
		PID:           os.Getpid(),
		Port:          srv.Port(),
		SessionSecret: sessionSecret,
		SessionID:     sessionID,
		StartedAt:     time.Now().UTC(),
	}
	stateBytes, _ := json.MarshalIndent(state, "", "  ")
	_ = os.WriteFile(stateFile, stateBytes, 0600)
	defer os.Remove(stateFile)

	_ = caCertPath

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
}
