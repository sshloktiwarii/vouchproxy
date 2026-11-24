package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/audit"
	"github.com/sshloktiwarii/vouchproxy/internal/policy"
	"github.com/sshloktiwarii/vouchproxy/internal/vault"
)

var (
	cachedBinaryPath string
	buildOnce        sync.Once
	buildErr         error
)

// findRepoRoot walks upwards from the current directory looking for go.mod
func findRepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ".."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ".."
}

// GetVouchProxyBinary builds the vouchproxy binary once per test run and returns its absolute path.
func GetVouchProxyBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		rootDir := findRepoRoot()
		tmpDir, err := os.MkdirTemp("", "vouch-bin-*")
		if err != nil {
			buildErr = fmt.Errorf("failed to create temp dir for binary: %w", err)
			return
		}
		binPath := filepath.Join(tmpDir, "vouchproxy")
		cmdPkg := filepath.Join(rootDir, "cmd", "vouchproxy")
		cmd := exec.Command("go", "build", "-o", binPath, cmdPkg)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("failed to compile vouchproxy: %v\nOutput: %s", err, string(out))
			return
		}
		cachedBinaryPath = binPath
	})

	if buildErr != nil {
		t.Fatalf("GetVouchProxyBinary failed: %v", buildErr)
	}
	return cachedBinaryPath
}

// MockTrustStore intercepts OS certificate store installation and uninstallation commands.
type MockTrustStore struct {
	MockBinDir string
	logFile    string
	failFile   string
	mu         sync.Mutex
}

// NewMockTrustStore scaffolds mock scripts for macOS, Linux, and Windows trust stores.
func NewMockTrustStore(mockBinDir string) (*MockTrustStore, error) {
	if err := os.MkdirAll(mockBinDir, 0755); err != nil {
		return nil, err
	}
	logFile := filepath.Join(mockBinDir, "trust_store.log")
	failFile := filepath.Join(mockBinDir, "fail_trigger")

	m := &MockTrustStore{
		MockBinDir: mockBinDir,
		logFile:    logFile,
		failFile:   failFile,
	}

	// 1. macOS mock: security
	securityScript := filepath.Join(mockBinDir, "security")
	scriptContent := fmt.Sprintf(`#!/bin/sh
if [ -f "%s" ]; then
    echo "security: permission denied" >&2
    exit 1
fi

case "$1" in
    add-trusted-cert|remove-trusted-cert|dump-trust-settings|user-trust-settings-enable)
        echo "security $@" >> "%s"
        exit 0
        ;;
    *)
        if [ -x /usr/bin/security ]; then
            exec /usr/bin/security "$@"
        fi
        echo "security $@" >> "%s"
        exit 0
        ;;
esac
`, failFile, logFile, logFile)
	if err := os.WriteFile(securityScript, []byte(scriptContent), 0755); err != nil {
		return nil, err
	}

	// 2. Linux mock: update-ca-certificates
	updateScript := filepath.Join(mockBinDir, "update-ca-certificates")
	updateContent := fmt.Sprintf(`#!/bin/sh
if [ -f "%s" ]; then
    echo "update-ca-certificates: permission denied" >&2
    exit 1
fi
echo "update-ca-certificates $@" >> "%s"
exit 0
`, failFile, logFile)
	if err := os.WriteFile(updateScript, []byte(updateContent), 0755); err != nil {
		return nil, err
	}

	// 3. Windows mock: certutil
	certutilScript := filepath.Join(mockBinDir, "certutil")
	certutilContent := fmt.Sprintf(`#!/bin/sh
if [ -f "%s" ]; then
    echo "certutil: access is denied" >&2
    exit 1
fi
echo "certutil $@" >> "%s"
exit 0
`, failFile, logFile)
	if err := os.WriteFile(certutilScript, []byte(certutilContent), 0755); err != nil {
		return nil, err
	}

	return m, nil
}

// SetFail configures the mock trust store to simulate permission denied errors.
func (m *MockTrustStore) SetFail(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if fail {
		_ = os.WriteFile(m.failFile, []byte("fail"), 0644)
	} else {
		_ = os.Remove(m.failFile)
	}
}

// Invocations returns all intercepted trust store commands.
func (m *MockTrustStore) Invocations() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := os.ReadFile(m.logFile)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var result []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			result = append(result, l)
		}
	}
	return result
}

// HasInvocation returns true if any invocation contains the specified substring.
func (m *MockTrustStore) HasInvocation(sub string) bool {
	for _, inv := range m.Invocations() {
		if strings.Contains(inv, sub) {
			return true
		}
	}
	return false
}

// Reset clears recorded invocations.
func (m *MockTrustStore) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = os.Remove(m.logFile)
}

// VouchSession manages an isolated vouchproxy test environment and process execution.
type VouchSession struct {
	T           *testing.T
	VouchDir    string
	MockBinDir  string
	KeyringFile string
	TrustStore  *MockTrustStore
	Env         map[string]string
}

// NewVouchSession creates an isolated test environment.
func NewVouchSession(t *testing.T) *VouchSession {
	t.Helper()
	vouchDir := t.TempDir()
	mockBinDir := t.TempDir()
	keyringFile := filepath.Join(vouchDir, "keyring.json")

	trustStore, err := NewMockTrustStore(mockBinDir)
	if err != nil {
		t.Fatalf("Failed to initialize MockTrustStore: %v", err)
	}

	return &VouchSession{
		T:           t,
		VouchDir:    vouchDir,
		MockBinDir:  mockBinDir,
		KeyringFile: keyringFile,
		TrustStore:  trustStore,
		Env:         make(map[string]string),
	}
}

// KeyringManager returns a KeychainManager configured to access this session's isolated keyring.
func (s *VouchSession) KeyringManager() vault.KeychainManager {
	s.T.Helper()
	_ = os.Setenv(vault.KeyringFileEnv, s.KeyringFile)
	return vault.NewOSKeyringManager("vouchproxy", "master")
}

// SetEnv sets an environment variable for subsequent commands.
func (s *VouchSession) SetEnv(key, val string) {
	s.Env[key] = val
}

func (s *VouchSession) buildEnv() []string {
	env := os.Environ()
	// Prepend mock bin directory to PATH
	newPath := s.MockBinDir + string(os.PathListSeparator) + os.Getenv("PATH")

	overrides := map[string]string{
		"VOUCH_DIR":          s.VouchDir,
		"VOUCH_KEYRING_FILE": s.KeyringFile,
		"PATH":               newPath,
	}
	for k, v := range s.Env {
		overrides[k] = v
	}

	var finalEnv []string
	seen := make(map[string]bool)
	for k, v := range overrides {
		finalEnv = append(finalEnv, fmt.Sprintf("%s=%s", k, v))
		seen[k] = true
	}
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 && !seen[parts[0]] {
			finalEnv = append(finalEnv, e)
		}
	}
	return finalEnv
}

// RunCommand executes vouchproxy with args synchronously.
func (s *VouchSession) RunCommand(args ...string) (stdout, stderr string, exitCode int, err error) {
	return s.RunCommandWithInput("", args...)
}

// RunCommandWithInput executes vouchproxy with provided stdin input.
func (s *VouchSession) RunCommandWithInput(input string, args ...string) (stdout, stderr string, exitCode int, err error) {
	bin := GetVouchProxyBinary(s.T)
	cmd := exec.Command(bin, args...)
	cmd.Env = s.buildEnv()

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}

	runErr := cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
		err = runErr
	} else {
		exitCode = 0
	}
	return stdout, stderr, exitCode, err
}

// SafeBuffer is a thread-safe bytes.Buffer that prevents data races when used with exec.Cmd
type SafeBuffer struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (s *SafeBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *SafeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *SafeBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := make([]byte, s.buf.Len())
	copy(b, s.buf.Bytes())
	return b
}

// StartCommand spawns vouchproxy as an asynchronous background child process.
func (s *VouchSession) StartCommand(args ...string) (*exec.Cmd, io.WriteCloser, *SafeBuffer, *SafeBuffer, error) {
	bin := GetVouchProxyBinary(s.T)
	cmd := exec.Command(bin, args...)
	cmd.Env = s.buildEnv()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	outBuf := new(SafeBuffer)
	errBuf := new(SafeBuffer)
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf

	if err := cmd.Start(); err != nil {
		return nil, nil, nil, nil, err
	}

	return cmd, stdin, outBuf, errBuf, nil
}

// Init initializes the VouchProxy enclave with the given master passphrase.
func (s *VouchSession) Init(passphrase string, extraArgs ...string) (string, error) {
	args := []string{"init", "-dir", s.VouchDir}
	args = append(args, extraArgs...)
	out, stderr, code, err := s.RunCommandWithInput(passphrase+"\n", args...)
	if code != 0 {
		return out + "\n" + stderr, fmt.Errorf("init failed with code %d: %s %s", code, out, stderr)
	}
	return out, err
}

// SeedSecret stores a secret in the vault via vouchproxy secret set.
func (s *VouchSession) SeedSecret(key, value, passphrase string) error {
	var input string
	if s.Env["VOUCH_MASTER_KEY"] != "" || passphrase == "" {
		input = value + "\n"
	} else {
		input = fmt.Sprintf("%s\n%s\n", passphrase, value)
	}
	out, stderr, code, err := s.RunCommandWithInput(input, "secret", "set", key)
	if code != 0 {
		return fmt.Errorf("secret set failed with code %d: %s %s (%v)", code, out, stderr, err)
	}
	return nil
}

// CreatePolicy writes a custom vouch.yaml policy file.
func (s *VouchSession) CreatePolicy(cfg *policy.Config) error {
	configPath := filepath.Join(s.VouchDir, "vouch.yaml")
	return policy.SaveConfig(configPath, cfg)
}

// ReadAuditLog returns all parsed audit events from the session's audit.jsonl.
func (s *VouchSession) ReadAuditLog() ([]audit.AuditEvent, error) {
	auditPath := filepath.Join(s.VouchDir, "audit.jsonl")
	return audit.ReadAll(auditPath)
}

// IsFlagUnimplemented checks if the output indicates an unknown or unimplemented CLI flag or command.
func (s *VouchSession) IsFlagUnimplemented(output string, flagName string) bool {
	lower := strings.ToLower(output)
	cleanName := strings.TrimPrefix(flagName, "-")
	target := "-" + cleanName
	return strings.Contains(lower, "flag provided but not defined: "+target) ||
		strings.Contains(lower, "flag provided but not defined: -"+target) ||
		strings.Contains(lower, "unknown flag: "+target) ||
		strings.Contains(lower, "unknown command: "+target) ||
		strings.Contains(lower, "unknown command: "+cleanName)
}

// MockUpstreamServer provides a programmable HTTP/1.1 and SSE upstream server.
type MockUpstreamServer struct {
	Server           *httptest.Server
	URL              string
	Host             string
	Port             int
	mu               sync.Mutex
	ReceivedRequests []*http.Request
	ReceivedBodies   []string
	CustomHandler    http.HandlerFunc
}

// NewMockUpstreamServer starts a new httptest server with request capture.
func NewMockUpstreamServer() *MockUpstreamServer {
	m := &MockUpstreamServer{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.ReceivedRequests = append(m.ReceivedRequests, r)
		body, _ := io.ReadAll(r.Body)
		m.ReceivedBodies = append(m.ReceivedBodies, string(body))
		custom := m.CustomHandler
		m.mu.Unlock()

		if custom != nil {
			custom(w, r)
			return
		}

		// Default SSE handler for /sse
		if r.URL.Path == "/sse" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			flusher, ok := w.(http.Flusher)
			if ok {
				flusher.Flush()
			}
			for i := 0; i < 3; i++ {
				_, _ = fmt.Fprintf(w, "event: progress\ndata: {\"index\": %d}\n\n", i)
				if ok {
					flusher.Flush()
				}
				time.Sleep(10 * time.Millisecond)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	})

	m.Server = httptest.NewServer(handler)
	m.URL = m.Server.URL
	u, _ := url.Parse(m.Server.URL)
	m.Host = u.Host
	_, portStr, _ := net.SplitHostPort(u.Host)
	m.Port, _ = strconv.Atoi(portStr)
	return m
}

// Close shuts down the server.
func (m *MockUpstreamServer) Close() {
	if m.Server != nil {
		m.Server.Close()
	}
}

// GetLastRequestBody returns the body of the most recently received request.
func (m *MockUpstreamServer) GetLastRequestBody() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.ReceivedBodies) == 0 {
		return ""
	}
	return m.ReceivedBodies[len(m.ReceivedBodies)-1]
}

// GetReceivedCount returns total received requests.
func (m *MockUpstreamServer) GetReceivedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.ReceivedRequests)
}

// MockMCPClient creates and parses JSON-RPC 2.0 messages.
type MockMCPClient struct{}

// NewMCPToolCall creates a standard JSON-RPC 2.0 tools/call message.
func (c *MockMCPClient) NewMCPToolCall(id any, toolName string, arguments map[string]any) []byte {
	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      toolName,
			"arguments": arguments,
		},
	}
	data, _ := json.Marshal(msg)
	return append(data, '\n')
}

// MockMCPServer simulates an MCP tool execution server over stdio.
type MockMCPServer struct {
	InReader  *io.PipeReader
	InWriter  *io.PipeWriter
	OutReader *io.PipeReader
	OutWriter *io.PipeWriter
}

// NewMockMCPServer initializes stdio pipes.
func NewMockMCPServer() *MockMCPServer {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	return &MockMCPServer{
		InReader:  inR,
		InWriter:  inW,
		OutReader: outR,
		OutWriter: outW,
	}
}

// Close closes all pipe endpoints.
func (s *MockMCPServer) Close() {
	_ = s.InReader.Close()
	_ = s.InWriter.Close()
	_ = s.OutReader.Close()
	_ = s.OutWriter.Close()
}

// StripANSI removes ANSI escape codes from terminal output.
func StripANSI(str string) string {
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]|\x1b\([B0-9]`)
	return ansiRegex.ReplaceAllString(str, "")
}

// HasAmberStyle checks if string contains ANSI escape codes for amber/yellow/orange colors.
func HasAmberStyle(str string) bool {
	// Amber / orange / yellow terminal color patterns:
	// \x1b[33m (standard yellow)
	// \x1b[38;5;214m, \x1b[38;5;208m, \x1b[38;5;220m (extended 256 amber/orange)
	// \x1b[38;2;... (24-bit RGB containing amber tones e.g. 217, 119, 6 or 245, 158, 11)
	patterns := []string{
		`\x1b\[33m`,
		`\x1b\[38;5;214m`,
		`\x1b\[38;5;208m`,
		`\x1b\[38;5;220m`,
		`\x1b\[38;5;178m`,
		`\x1b\[38;5;130m`,
		`\x1b\[38;2;2[0-9]{2};[0-9]{2,3};[0-9]{1,3}m`, // Amber/Orange RGB range
	}
	for _, p := range patterns {
		if matched, _ := regexp.MatchString(p, str); matched {
			return true
		}
	}
	return false
}

// HasCyanStyle checks if string contains ANSI escape codes for cyan colors.
func HasCyanStyle(str string) bool {
	// Cyan terminal color patterns:
	// \x1b[36m, \x1b[96m (standard cyan)
	// \x1b[38;5;6m, \x1b[38;5;14m, \x1b[38;5;44m, \x1b[38;5;45m, \x1b[38;5;51m
	// \x1b[38;2;... (24-bit RGB containing cyan tones e.g. 6, 182, 212)
	patterns := []string{
		`\x1b\[36m`,
		`\x1b\[96m`,
		`\x1b\[38;5;6m`,
		`\x1b\[38;5;14m`,
		`\x1b\[38;5;44m`,
		`\x1b\[38;5;45m`,
		`\x1b\[38;5;51m`,
		`\x1b\[38;2;[0-9]{1,2};[0-9]{2,3};2[0-9]{2}m`, // Cyan RGB range
	}
	for _, p := range patterns {
		if matched, _ := regexp.MatchString(p, str); matched {
			return true
		}
	}
	return false
}

// KillProcessGracefully attempts SIGINT/SIGTERM before falling back to Kill.
func KillProcessGracefully(cmd *exec.Cmd, timeout time.Duration) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	_ = cmd.Process.Signal(syscall.SIGINT)

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return fmt.Errorf("process killed after timeout")
	case err := <-done:
		return err
	}
}

// ContextWithTimeout returns a context and cancel func.
func ContextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
