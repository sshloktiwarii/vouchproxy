package certs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockRunner struct {
	mu          sync.Mutex
	invocations [][]string
	failCmd     string
	failErr     error
	failOutput  string
	knownBins   map[string]bool
}

func newMockRunner() *mockRunner {
	return &mockRunner{
		knownBins: make(map[string]bool),
	}
}

func (m *mockRunner) Run(name string, args ...string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := append([]string{name}, args...)
	m.invocations = append(m.invocations, entry)

	if m.failCmd != "" && name == m.failCmd {
		return []byte(m.failOutput), m.failErr
	}
	return []byte("ok"), nil
}

func (m *mockRunner) LookPath(file string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.knownBins[file] {
		return "/mock/bin/" + file, nil
	}
	return "", errors.New("command not found: " + file)
}

func (m *mockRunner) Invocations() [][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := make([][]string, len(m.invocations))
	copy(copied, m.invocations)
	return copied
}

func (m *mockRunner) HasInvocation(sub string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, inv := range m.invocations {
		line := strings.Join(inv, " ")
		if strings.Contains(line, sub) {
			return true
		}
	}
	return false
}

func (m *mockRunner) CountInvocation(sub string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, inv := range m.invocations {
		line := strings.Join(inv, " ")
		if strings.Contains(line, sub) {
			count++
		}
	}
	return count
}

type mockFileInfo struct {
	name string
	size int64
}

func (m mockFileInfo) Name() string       { return m.name }
func (m mockFileInfo) Size() int64        { return m.size }
func (m mockFileInfo) Mode() os.FileMode  { return 0644 }
func (m mockFileInfo) ModTime() time.Time { return time.Now() }
func (m mockFileInfo) IsDir() bool        { return false }
func (m mockFileInfo) Sys() any           { return nil }

type mockFS struct {
	mu        sync.Mutex
	files     map[string][]byte
	writeErr  error
	removeErr error
}

func newMockFS() *mockFS {
	return &mockFS{
		files: make(map[string][]byte),
	}
}

func (fs *mockFS) WriteFile(filename string, data []byte, perm os.FileMode) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.writeErr != nil {
		return fs.writeErr
	}
	fs.files[filename] = data
	return nil
}

func (fs *mockFS) Remove(name string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.removeErr != nil {
		return fs.removeErr
	}
	delete(fs.files, name)
	return nil
}

func (fs *mockFS) Stat(name string) (os.FileInfo, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	data, exists := fs.files[name]
	if !exists {
		return nil, os.ErrNotExist
	}
	return mockFileInfo{name: name, size: int64(len(data))}, nil
}

func (fs *mockFS) ReadFile(filename string) ([]byte, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	data, exists := fs.files[filename]
	if !exists {
		return nil, os.ErrNotExist
	}
	return data, nil
}

func TestSystemTrust_Darwin_InstallAndUninstallArgs(t *testing.T) {
	runner := newMockRunner()
	fs := newMockFS()
	mgr := NewSystemTrustManagerWithConfig(runner, fs, "darwin", "VouchProxy Local Root CA")

	caPath := "/tmp/test_ca.crt"
	if err := mgr.InstallCA(caPath); err != nil {
		t.Fatalf("InstallCA failed: %v", err)
	}

	if !runner.HasInvocation("security add-trusted-cert -d -r trustRoot") {
		t.Errorf("Expected Darwin install command with add-trusted-cert, got: %v", runner.Invocations())
	}

	if err := mgr.UninstallCA(caPath); err != nil {
		t.Fatalf("UninstallCA failed: %v", err)
	}

	if !runner.HasInvocation("security remove-trusted-cert -d") {
		t.Errorf("Expected Darwin uninstall command with remove-trusted-cert, got: %v", runner.Invocations())
	}
}

func TestSystemTrust_Darwin_KeychainResolution(t *testing.T) {
	runner := newMockRunner()
	fs := newMockFS()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("Cannot resolve UserHomeDir")
	}

	keychainPath := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
	fs.files[keychainPath] = []byte("mock-keychain")

	mgr := NewSystemTrustManagerWithConfig(runner, fs, "darwin", "VouchProxy Local Root CA")
	caPath := "/tmp/test_ca.crt"
	if err := mgr.InstallCA(caPath); err != nil {
		t.Fatalf("InstallCA failed: %v", err)
	}

	expectedArg := "-k " + keychainPath
	if !runner.HasInvocation(expectedArg) {
		t.Errorf("Expected Darwin install to include keychain path %q, got: %v", expectedArg, runner.Invocations())
	}
}

func TestSystemTrust_LinuxDebian_InstallAndUninstallArgs(t *testing.T) {
	runner := newMockRunner()
	runner.knownBins["update-ca-certificates"] = true
	fs := newMockFS()
	caPath := "/tmp/vouch_test.crt"
	fs.files[caPath] = []byte("DEBIAN_CERT_DATA")

	mgr := NewSystemTrustManagerWithConfig(runner, fs, "linux", "VouchProxy Local Root CA")

	if err := mgr.InstallCA(caPath); err != nil {
		t.Fatalf("InstallCA failed: %v", err)
	}

	destPath := "/usr/local/share/ca-certificates/vouchproxy-ca.crt"
	if string(fs.files[destPath]) != "DEBIAN_CERT_DATA" {
		t.Errorf("Expected cert written to %s, got: %s", destPath, string(fs.files[destPath]))
	}

	if !runner.HasInvocation("update-ca-certificates") {
		t.Errorf("Expected update-ca-certificates invocation, got: %v", runner.Invocations())
	}

	if err := mgr.UninstallCA(caPath); err != nil {
		t.Fatalf("UninstallCA failed: %v", err)
	}

	if _, exists := fs.files[destPath]; exists {
		t.Errorf("Expected %s to be deleted on uninstall", destPath)
	}
}

func TestSystemTrust_LinuxFedora_InstallAndUninstallArgs(t *testing.T) {
	runner := newMockRunner()
	runner.knownBins["update-ca-trust"] = true
	fs := newMockFS()
	caPath := "/tmp/vouch_test.crt"
	fs.files[caPath] = []byte("FEDORA_CERT_DATA")

	mgr := NewSystemTrustManagerWithConfig(runner, fs, "linux-fedora", "VouchProxy Local Root CA")

	if err := mgr.InstallCA(caPath); err != nil {
		t.Fatalf("InstallCA failed: %v", err)
	}

	destPath := "/etc/pki/ca-trust/source/anchors/vouchproxy-ca.crt"
	if string(fs.files[destPath]) != "FEDORA_CERT_DATA" {
		t.Errorf("Expected cert written to %s, got: %s", destPath, string(fs.files[destPath]))
	}

	if !runner.HasInvocation("update-ca-trust extract") {
		t.Errorf("Expected 'update-ca-trust extract' invocation, got: %v", runner.Invocations())
	}

	if err := mgr.UninstallCA(caPath); err != nil {
		t.Fatalf("UninstallCA failed: %v", err)
	}

	if _, exists := fs.files[destPath]; exists {
		t.Errorf("Expected %s to be deleted on uninstall", destPath)
	}
}

func TestSystemTrust_Windows_InstallAndUninstallArgs(t *testing.T) {
	runner := newMockRunner()
	fs := newMockFS()
	mgr := NewSystemTrustManagerWithConfig(runner, fs, "windows", "VouchProxy Local Root CA")

	caPath := `C:\vouch\ca.crt`
	if err := mgr.InstallCA(caPath); err != nil {
		t.Fatalf("InstallCA failed: %v", err)
	}

	if !runner.HasInvocation("certutil -addstore -user Root " + caPath) {
		t.Errorf("Expected certutil -addstore invocation, got: %v", runner.Invocations())
	}

	if err := mgr.UninstallCA(caPath); err != nil {
		t.Fatalf("UninstallCA failed: %v", err)
	}

	if !runner.HasInvocation("certutil -delstore -user Root VouchProxy Local Root CA") {
		t.Errorf("Expected certutil -delstore invocation, got: %v", runner.Invocations())
	}
}

func TestSystemTrust_NonRoot_HumanActionableError(t *testing.T) {
	// Darwin permission denied
	{
		runner := newMockRunner()
		runner.failCmd = "security"
		runner.failErr = errors.New("exit 1")
		runner.failOutput = "security: permission denied"
		mgr := NewSystemTrustManagerWithConfig(runner, newMockFS(), "darwin", "")
		err := mgr.InstallCA("/tmp/ca.crt")
		if err == nil || !strings.Contains(err.Error(), "requires administrative privileges on macOS") {
			t.Errorf("Expected Darwin permission error message, got: %v", err)
		}
	}

	// Linux permission denied
	{
		runner := newMockRunner()
		runner.knownBins["update-ca-certificates"] = true
		runner.failCmd = "update-ca-certificates"
		runner.failErr = errors.New("exit 1")
		runner.failOutput = "update-ca-certificates: permission denied"
		fs := newMockFS()
		fs.files["/tmp/ca.crt"] = []byte("CERT")
		mgr := NewSystemTrustManagerWithConfig(runner, fs, "linux", "")
		err := mgr.InstallCA("/tmp/ca.crt")
		if err == nil || !strings.Contains(err.Error(), "requires root / sudo privileges on Linux") {
			t.Errorf("Expected Linux permission error message, got: %v", err)
		}
	}

	// Windows access denied
	{
		runner := newMockRunner()
		runner.failCmd = "certutil"
		runner.failErr = errors.New("exit 1")
		runner.failOutput = "certutil: access is denied"
		mgr := NewSystemTrustManagerWithConfig(runner, newMockFS(), "windows", "")
		err := mgr.InstallCA(`C:\ca.crt`)
		if err == nil || !strings.Contains(err.Error(), "requires administrative permissions") {
			t.Errorf("Expected Windows permission error message, got: %v", err)
		}
	}
}

func TestSystemTrust_Teardown_Idempotency(t *testing.T) {
	runner := newMockRunner()
	fs := newMockFS()
	caPath := "/tmp/idempotent_ca.crt"
	fs.files[caPath] = []byte("IDEMPOTENT_CERT")

	mgr := NewSystemTrustManagerWithConfig(runner, fs, "darwin", "VouchProxy Local Root CA")

	cleanup, err := mgr.RegisterTeardown(caPath)
	if err != nil {
		t.Fatalf("RegisterTeardown failed: %v", err)
	}

	// Call cleanup 5 times in succession
	for i := 0; i < 5; i++ {
		cleanup()
	}

	// Total uninstalls should be exactly 2:
	// 1 proactive startup cleanup + 1 teardown cleanup
	uninstalls := runner.CountInvocation("remove-trusted-cert")
	if uninstalls != 2 {
		t.Errorf("Expected exactly 2 uninstall invocations (1 proactive + 1 teardown), got %d: %v",
			uninstalls, runner.Invocations())
	}
}

func TestSystemTrust_DeletedCACert_TeardownSafe(t *testing.T) {
	runner := newMockRunner()
	fs := newMockFS()
	caPath := "/tmp/deleted_ca.crt"
	fs.files[caPath] = []byte("CA_DATA_TO_CACHE")

	mgr := NewSystemTrustManagerWithConfig(runner, fs, "darwin", "VouchProxy Local Root CA")

	cleanup, err := mgr.RegisterTeardown(caPath)
	if err != nil {
		t.Fatalf("RegisterTeardown failed: %v", err)
	}

	// Simulate mid-run deletion of ca.crt
	_ = fs.Remove(caPath)

	// Cleanup should not hang, crash, or fail
	cleanup()

	if !runner.HasInvocation("remove-trusted-cert") {
		t.Errorf("Expected teardown remove-trusted-cert even after ca.crt was removed, got: %v", runner.Invocations())
	}
}

func TestSystemTrust_SIGKILLRecovery_ProactiveCleanup(t *testing.T) {
	runner := newMockRunner()
	fs := newMockFS()
	caPath := "/tmp/sigkill_ca.crt"
	fs.files[caPath] = []byte("RECOVERY_CERT")

	mgr := NewSystemTrustManagerWithConfig(runner, fs, "darwin", "VouchProxy Local Root CA")

	cleanup, err := mgr.RegisterTeardown(caPath)
	if err != nil {
		t.Fatalf("RegisterTeardown failed: %v", err)
	}
	defer cleanup()

	invs := runner.Invocations()
	if len(invs) < 2 {
		t.Fatalf("Expected at least 2 invocations on RegisterTeardown, got: %v", invs)
	}

	// Verify first invocation was uninstall (proactive cleanup of stale state)
	firstCmd := strings.Join(invs[0], " ")
	if !strings.Contains(firstCmd, "remove-trusted-cert") {
		t.Errorf("Expected first command to be proactive uninstall, got: %s", firstCmd)
	}

	// Verify second invocation was install
	secondCmd := strings.Join(invs[1], " ")
	if !strings.Contains(secondCmd, "add-trusted-cert") {
		t.Errorf("Expected second command to be install, got: %s", secondCmd)
	}
}

func TestSystemTrust_DefaultConstructors(t *testing.T) {
	mgr := NewSystemTrustManager()
	if mgr == nil {
		t.Fatal("NewSystemTrustManager returned nil")
	}

	mgrWithCfg := NewSystemTrustManagerWithConfig(nil, nil, "", "")
	if mgrWithCfg == nil {
		t.Fatal("NewSystemTrustManagerWithConfig returned nil")
	}
}
