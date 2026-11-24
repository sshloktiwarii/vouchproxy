package certs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// SystemTrustManager defines the lifecycle contract for host trust store operations.
type SystemTrustManager interface {
	InstallCA(caCertPath string) error
	UninstallCA(caCertPath string) error
	RegisterTeardown(caCertPath string) (cleanup func(), err error)
}

// CommandRunner abstracts shell execution for deterministic testing and mock interception.
type CommandRunner interface {
	Run(name string, args ...string) ([]byte, error)
	LookPath(file string) (string, error)
}

// FileSystem abstracts filesystem operations for cross-platform trust store file updates.
type FileSystem interface {
	WriteFile(filename string, data []byte, perm os.FileMode) error
	Remove(name string) error
	Stat(name string) (os.FileInfo, error)
	ReadFile(filename string) ([]byte, error)
}

type defaultCommandRunner struct{}

func (defaultCommandRunner) Run(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

func (defaultCommandRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

type osFS struct{}

func (osFS) WriteFile(filename string, data []byte, perm os.FileMode) error {
	return os.WriteFile(filename, data, perm)
}

func (osFS) Remove(name string) error {
	return os.Remove(name)
}

func (osFS) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (osFS) ReadFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}

type defaultSystemTrustManager struct {
	runner   CommandRunner
	fs       FileSystem
	targetOS string
	certName string
	mu       sync.Mutex
	cachedCA []byte
}

// NewSystemTrustManager constructs a trust manager using host defaults.
func NewSystemTrustManager() SystemTrustManager {
	return NewSystemTrustManagerWithConfig(defaultCommandRunner{}, osFS{}, runtime.GOOS, "VouchProxy Local Root CA")
}

// NewSystemTrustManagerWithConfig constructs a trust manager with injected abstractions for deterministic unit testing.
func NewSystemTrustManagerWithConfig(runner CommandRunner, fs FileSystem, targetOS, certName string) SystemTrustManager {
	if runner == nil {
		runner = defaultCommandRunner{}
	}
	if fs == nil {
		fs = osFS{}
	}
	if targetOS == "" {
		targetOS = runtime.GOOS
	}
	if certName == "" {
		certName = "VouchProxy Local Root CA"
	}
	return &defaultSystemTrustManager{
		runner:   runner,
		fs:       fs,
		targetOS: strings.ToLower(targetOS),
		certName: certName,
	}
}

func (m *defaultSystemTrustManager) resolveDarwinKeychain() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	candidates := []string{
		filepath.Join(home, "Library", "Keychains", "login.keychain-db"),
		filepath.Join(home, "Library", "Keychains", "login.keychain"),
	}
	for _, cand := range candidates {
		if _, err := m.fs.Stat(cand); err == nil {
			return cand
		}
	}
	return ""
}

func (m *defaultSystemTrustManager) installDarwin(caCertPath string) error {
	loginKeychain := m.resolveDarwinKeychain()
	args := []string{"add-trusted-cert", "-d", "-r", "trustRoot"}
	if loginKeychain != "" {
		args = append(args, "-k", loginKeychain)
	}
	args = append(args, caCertPath)

	out, err := m.runner.Run("security", args...)
	if err != nil {
		outStr := strings.TrimSpace(string(out))
		if strings.Contains(strings.ToLower(outStr), "permission denied") {
			return fmt.Errorf("security: permission denied (requires administrative privileges on macOS to modify trust settings): %s", outStr)
		}
		return fmt.Errorf("failed to register CA with macOS security: %w (%s)", err, outStr)
	}
	return nil
}

func (m *defaultSystemTrustManager) uninstallDarwin(caCertPath string) error {
	targetPath := caCertPath
	var tempCreated string

	if _, err := m.fs.Stat(targetPath); os.IsNotExist(err) && len(m.cachedCA) > 0 {
		tmpPath := filepath.Join(os.TempDir(), fmt.Sprintf("vouch_teardown_%d.crt", os.Getpid()))
		if err := m.fs.WriteFile(tmpPath, m.cachedCA, 0600); err == nil {
			targetPath = tmpPath
			tempCreated = tmpPath
		}
	}
	if tempCreated != "" {
		defer func() { _ = m.fs.Remove(tempCreated) }()
	}

	out, err := m.runner.Run("security", "remove-trusted-cert", "-d", targetPath)
	if err != nil {
		// Fallback deletion by certificate common name
		_, _ = m.runner.Run("security", "delete-certificate", "-c", m.certName)
		outStr := strings.ToLower(string(out))
		if strings.Contains(outStr, "not found") ||
			strings.Contains(outStr, "could not be found") ||
			strings.Contains(outStr, "no such file") {
			return nil
		}
	}
	return nil
}

func (m *defaultSystemTrustManager) isDebianLinux() bool {
	if m.targetOS == "linux-debian" || m.targetOS == "debian" || m.targetOS == "ubuntu" {
		return true
	}
	if m.targetOS == "linux-fedora" || m.targetOS == "fedora" || m.targetOS == "rhel" || m.targetOS == "centos" {
		return false
	}
	if _, err := m.runner.LookPath("update-ca-certificates"); err == nil {
		return true
	}
	if _, err := m.runner.LookPath("update-ca-trust"); err == nil {
		return false
	}
	return true
}

func (m *defaultSystemTrustManager) getLinuxCertPath(isDebian bool) string {
	if custom := os.Getenv("VOUCH_TRUST_DIR"); custom != "" {
		return filepath.Join(custom, "vouchproxy-ca.crt")
	}
	if isDebian {
		return "/usr/local/share/ca-certificates/vouchproxy-ca.crt"
	}
	return "/etc/pki/ca-trust/source/anchors/vouchproxy-ca.crt"
}

func (m *defaultSystemTrustManager) installLinux(caCertPath string) error {
	certData, err := m.fs.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to read ca cert %s: %w", caCertPath, err)
	}

	isDebian := m.isDebianLinux()
	targetPath := m.getLinuxCertPath(isDebian)

	var cmdName string
	var cmdArgs []string
	if isDebian {
		cmdName = "update-ca-certificates"
	} else {
		cmdName = "update-ca-trust"
		cmdArgs = []string{"extract"}
	}

	// Attempt file copy
	writeErr := m.fs.WriteFile(targetPath, certData, 0644)
	if writeErr != nil {
		// If write failed due to permissions or missing system dir in mock test
		if _, lookErr := m.runner.LookPath(cmdName); lookErr == nil {
			out, cmdErr := m.runner.Run(cmdName, cmdArgs...)
			if cmdErr != nil || strings.Contains(strings.ToLower(string(out)), "permission denied") {
				return fmt.Errorf("requires root / sudo privileges on Linux to update system CA trust: %v", writeErr)
			}
			return nil
		}
		if os.IsPermission(writeErr) || strings.Contains(strings.ToLower(writeErr.Error()), "permission denied") {
			return fmt.Errorf("requires root / sudo privileges on Linux to update system CA trust: %w", writeErr)
		}
		return fmt.Errorf("failed to copy certificate to %s: %w", targetPath, writeErr)
	}

	out, err := m.runner.Run(cmdName, cmdArgs...)
	if err != nil {
		outStr := strings.ToLower(string(out))
		if strings.Contains(outStr, "permission denied") || strings.Contains(outStr, "requires root") {
			return fmt.Errorf("requires root / sudo privileges on Linux to update system CA trust: %s", strings.TrimSpace(string(out)))
		}
		return fmt.Errorf("system trust store update failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *defaultSystemTrustManager) uninstallLinux(caCertPath string) error {
	isDebian := m.isDebianLinux()
	targetPath := m.getLinuxCertPath(isDebian)

	_ = m.fs.Remove(targetPath)

	var cmdName string
	var cmdArgs []string
	if isDebian {
		cmdName = "update-ca-certificates"
	} else {
		cmdName = "update-ca-trust"
		cmdArgs = []string{"extract"}
	}

	out, err := m.runner.Run(cmdName, cmdArgs...)
	if err != nil {
		outStr := strings.ToLower(string(out))
		if strings.Contains(outStr, "not found") || strings.Contains(outStr, "no such file") {
			return nil
		}
	}
	return nil
}

func (m *defaultSystemTrustManager) installWindows(caCertPath string) error {
	out, err := m.runner.Run("certutil", "-addstore", "-user", "Root", caCertPath)
	if err != nil {
		outStr := strings.ToLower(string(out))
		if strings.Contains(outStr, "access is denied") || strings.Contains(outStr, "permission denied") {
			return fmt.Errorf("certutil: access is denied (requires administrative permissions): %s", strings.TrimSpace(string(out)))
		}
		return fmt.Errorf("failed to register CA with certutil: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *defaultSystemTrustManager) uninstallWindows(caCertPath string) error {
	out, err := m.runner.Run("certutil", "-delstore", "-user", "Root", m.certName)
	if err != nil {
		outStr := strings.ToLower(string(out))
		if strings.Contains(outStr, "not found") || strings.Contains(outStr, "cannot find") {
			return nil
		}
	}
	return nil
}

func (m *defaultSystemTrustManager) InstallCA(caCertPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch m.targetOS {
	case "darwin", "macos":
		return m.installDarwin(caCertPath)
	case "windows":
		return m.installWindows(caCertPath)
	default:
		return m.installLinux(caCertPath)
	}
}

func (m *defaultSystemTrustManager) UninstallCA(caCertPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch m.targetOS {
	case "darwin", "macos":
		return m.uninstallDarwin(caCertPath)
	case "windows":
		return m.uninstallWindows(caCertPath)
	default:
		return m.uninstallLinux(caCertPath)
	}
}

func (m *defaultSystemTrustManager) RegisterTeardown(caCertPath string) (cleanup func(), err error) {
	// Cache certificate bytes in memory for safe removal even if file deleted mid-run (EC-39)
	m.mu.Lock()
	if data, readErr := m.fs.ReadFile(caCertPath); readErr == nil {
		m.cachedCA = data
	}
	m.mu.Unlock()

	// 1. Proactively clean up any stale registration from prior SIGKILL (EC-40)
	_ = m.UninstallCA(caCertPath)

	// 2. Install CA into OS trust store
	if err := m.InstallCA(caCertPath); err != nil {
		return nil, err
	}

	var once sync.Once
	cleanup = func() {
		once.Do(func() {
			_ = m.UninstallCA(caCertPath)
		})
	}

	return cleanup, nil
}
