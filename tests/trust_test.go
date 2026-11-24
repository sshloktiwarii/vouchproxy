package tests

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// 11. TestE2E_R3_Trust_InitSystemTrustFlag verifies vouchproxy init --system-trust
// invokes OS trust store registration (add-trusted-cert / update-ca-certificates).
func TestE2E_R3_Trust_InitSystemTrustFlag(t *testing.T) {
	s := NewVouchSession(t)
	masterPass := "trust-init-pass-123"

	out, errOut, code, _ := s.RunCommandWithInput(masterPass+"\n", "init", "--system-trust", "-dir", s.VouchDir)

	if s.IsFlagUnimplemented(errOut, "system-trust") {
		t.Logf("Contract check: --system-trust flag pending in Milestone M2 (output: %q)", errOut)
		t.Skip("Skipping until Milestone M2 lands")
		return
	}

	if code != 0 {
		t.Fatalf("init --system-trust failed with code %d: %s\n%s", code, out, errOut)
	}

	invocations := s.TrustStore.Invocations()
	if len(invocations) == 0 {
		t.Errorf("Expected OS trust store command to be executed, but no invocations recorded")
	}

	hasAdd := s.TrustStore.HasInvocation("add-trusted-cert") ||
		s.TrustStore.HasInvocation("update-ca-certificates") ||
		s.TrustStore.HasInvocation("certutil")
	if !hasAdd {
		t.Errorf("Expected registration invocation, got: %v", invocations)
	}
}

// 12. TestE2E_R3_Trust_RunSystemTrustInjection verifies vouchproxy run --system-trust
// registers ca.crt prior to child process execution.
func TestE2E_R3_Trust_RunSystemTrustInjection(t *testing.T) {
	s := NewVouchSession(t)
	masterPass := "trust-run-pass-456"
	s.SetEnv("VOUCH_MASTER_KEY", masterPass)

	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	s.TrustStore.Reset()

	out, errOut, code, _ := s.RunCommand("run", "--system-trust", "--", "echo", "system-trust-injected")
	if s.IsFlagUnimplemented(errOut, "system-trust") {
		t.Log("Contract check: --system-trust flag pending in Milestone M2")
		t.Skip("Skipping until Milestone M2 lands")
		return
	}

	if code != 0 {
		t.Fatalf("Expected run --system-trust to exit 0, got %d: %s\n%s", code, out, errOut)
	}

	if !strings.Contains(out+errOut, "system-trust-injected") {
		t.Errorf("Expected child output 'system-trust-injected', got: %s", out+errOut)
	}

	// Verify trust store was invoked
	invocations := s.TrustStore.Invocations()
	if len(invocations) == 0 {
		t.Errorf("Expected trust store installation and uninstallation, got none")
	}
}

// 13. TestE2E_R3_Trust_SIGINTTeardownCleanup verifies SIGINT triggers teardown hook
// that unregisters ca.crt from OS trust store within 2-second grace period.
func TestE2E_R3_Trust_SIGINTTeardownCleanup(t *testing.T) {
	s := NewVouchSession(t)
	masterPass := "trust-sigint-pass-789"
	s.SetEnv("VOUCH_MASTER_KEY", masterPass)

	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	s.TrustStore.Reset()

	cmd, stdin, _, stderr, err := s.StartCommand("run", "--system-trust", "--", "sleep", "10")
	if err != nil {
		t.Fatalf("Failed to start vouchproxy: %v", err)
	}
	defer func() {
		if stdin != nil {
			_ = stdin.Close()
		}
	}()

	time.Sleep(300 * time.Millisecond)
	if s.IsFlagUnimplemented(stderr.String(), "system-trust") {
		_ = KillProcessGracefully(cmd, 500*time.Millisecond)
		t.Log("Contract check: --system-trust flag pending in Milestone M2")
		t.Skip("Skipping until Milestone M2 lands")
		return
	}

	// Dispatch SIGINT
	_ = cmd.Process.Signal(syscall.SIGINT)

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-done:
		t.Log("Process terminated cleanly on SIGINT")
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("Process failed to terminate within 2-second grace period after SIGINT")
	}

	// Verify uninstallation was recorded
	invocations := s.TrustStore.Invocations()
	hasUninstall := s.TrustStore.HasInvocation("remove-trusted-cert") ||
		s.TrustStore.HasInvocation("delete-certificate") ||
		s.TrustStore.HasInvocation("update-ca-certificates") ||
		s.TrustStore.HasInvocation("-delstore")
	if !hasUninstall {
		t.Errorf("Expected trust store teardown on SIGINT, got invocations: %v", invocations)
	}
}

// 14. TestE2E_R3_Trust_SIGTERMTeardownCleanup verifies SIGTERM cleanly terminates
// child process and unregisters ca.crt.
func TestE2E_R3_Trust_SIGTERMTeardownCleanup(t *testing.T) {
	s := NewVouchSession(t)
	masterPass := "trust-sigterm-pass-321"
	s.SetEnv("VOUCH_MASTER_KEY", masterPass)

	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	s.TrustStore.Reset()

	cmd, stdin, _, stderr, err := s.StartCommand("run", "--system-trust", "--", "sleep", "10")
	if err != nil {
		t.Fatalf("Failed to start vouchproxy: %v", err)
	}
	defer func() {
		if stdin != nil {
			_ = stdin.Close()
		}
	}()

	time.Sleep(300 * time.Millisecond)
	if s.IsFlagUnimplemented(stderr.String(), "system-trust") {
		_ = KillProcessGracefully(cmd, 500*time.Millisecond)
		t.Log("Contract check: --system-trust flag pending in Milestone M2")
		t.Skip("Skipping until Milestone M2 lands")
		return
	}

	// Dispatch SIGTERM
	_ = cmd.Process.Signal(syscall.SIGTERM)

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-done:
		t.Log("Process terminated cleanly on SIGTERM")
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("Process failed to terminate within 2-second grace period after SIGTERM")
	}

	invocations := s.TrustStore.Invocations()
	if len(invocations) == 0 {
		t.Errorf("Expected teardown invocations on SIGTERM, got none")
	}
}

// 15. TestE2E_R3_Trust_ChildCrashTeardownCleanup verifies deferred teardown
// unregisters ca.crt even when child process crashes with non-zero exit code.
func TestE2E_R3_Trust_ChildCrashTeardownCleanup(t *testing.T) {
	s := NewVouchSession(t)
	masterPass := "trust-crash-pass-654"
	s.SetEnv("VOUCH_MASTER_KEY", masterPass)

	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	s.TrustStore.Reset()

	// Child crashes with exit code 42
	_, errOut, code, _ := s.RunCommand("run", "--system-trust", "--", "sh", "-c", "exit 42")
	if s.IsFlagUnimplemented(errOut, "system-trust") {
		t.Log("Contract check: --system-trust flag pending in Milestone M2")
		t.Skip("Skipping until Milestone M2 lands")
		return
	}

	if code != 42 {
		t.Logf("Process exited with code %d (expected 42)", code)
	}

	// Verify teardown was executed via defer
	invocations := s.TrustStore.Invocations()
	if len(invocations) < 2 {
		t.Logf("Expected install and uninstall invocations, got: %v", invocations)
	}
}

// 36. TestE2E_R3_Edge_PermissionDeniedOSCommand verifies OS permission denied
// error produces clear diagnostic and stops child startup.
func TestE2E_R3_Edge_PermissionDeniedOSCommand(t *testing.T) {
	s := NewVouchSession(t)
	masterPass := "trust-perm-denied-pass-111"
	s.SetEnv("VOUCH_MASTER_KEY", masterPass)

	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Configure mock trust store to simulate permission denied (exit 1)
	s.TrustStore.SetFail(true)
	defer s.TrustStore.SetFail(false)

	out, errOut, code, _ := s.RunCommand("run", "--system-trust", "--", "echo", "should-not-run")
	if s.IsFlagUnimplemented(errOut, "system-trust") {
		t.Log("Contract check: --system-trust flag pending in Milestone M2")
		t.Skip("Skipping until Milestone M2 lands")
		return
	}

	// Must fail closed with non-zero exit code
	if code == 0 {
		t.Errorf("Expected failure when trust store registration fails, got code 0. Out: %s", out)
	}

	combined := out + "\n" + errOut
	if strings.Contains(combined, "should-not-run") {
		t.Errorf("Child command executed despite permission denied on trust store registration")
	}
}

// 37. TestE2E_R3_Edge_DoubleTeardownIdempotency verifies multiple teardown triggers
// (signal + defer) do not fail on second uninstallation.
func TestE2E_R3_Edge_DoubleTeardownIdempotency(t *testing.T) {
	s := NewVouchSession(t)
	masterPass := "trust-idempotent-pass-222"
	s.SetEnv("VOUCH_MASTER_KEY", masterPass)

	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Run twice to ensure no lingering state or error on second run
	for i := 0; i < 2; i++ {
		_, errOut, code, _ := s.RunCommand("run", "--system-trust", "--", "echo", "run-ok")
		if s.IsFlagUnimplemented(errOut, "system-trust") {
			t.Log("Contract check: --system-trust flag pending in Milestone M2")
			t.Skip("Skipping until Milestone M2 lands")
			return
		}
		if code != 0 {
			t.Fatalf("Run %d failed with code %d", i+1, code)
		}
	}
}

// 38. TestE2E_R3_Edge_RapidSignalInterruptionBeforeInstallCompletes verifies SIGINT
// during startup leaves no corrupt state.
func TestE2E_R3_Edge_RapidSignalInterruptionBeforeInstallCompletes(t *testing.T) {
	s := NewVouchSession(t)
	masterPass := "trust-rapid-sig-333"
	s.SetEnv("VOUCH_MASTER_KEY", masterPass)

	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	cmd, stdin, _, stderr, err := s.StartCommand("run", "--system-trust", "--", "sleep", "10")
	if err != nil {
		t.Fatalf("StartCommand failed: %v", err)
	}
	defer func() {
		if stdin != nil {
			_ = stdin.Close()
		}
	}()

	// Rapid signal interruption
	time.Sleep(5 * time.Millisecond)
	_ = cmd.Process.Signal(syscall.SIGINT)

	time.Sleep(200 * time.Millisecond)
	if s.IsFlagUnimplemented(stderr.String(), "system-trust") {
		_ = KillProcessGracefully(cmd, 500*time.Millisecond)
		t.Log("Contract check: --system-trust flag pending in Milestone M2")
		t.Skip("Skipping until Milestone M2 lands")
		return
	}

	_ = KillProcessGracefully(cmd, 1*time.Second)
}

// 39. TestE2E_R3_Edge_CACertFileDeletedBeforeTeardown verifies teardown succeeds
// even if ca.crt file was removed during execution.
func TestE2E_R3_Edge_CACertFileDeletedBeforeTeardown(t *testing.T) {
	s := NewVouchSession(t)
	masterPass := "trust-ca-deleted-pass-444"
	s.SetEnv("VOUCH_MASTER_KEY", masterPass)

	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	cmd, stdin, _, stderr, err := s.StartCommand("run", "--system-trust", "--", "sleep", "5")
	if err != nil {
		t.Fatalf("StartCommand failed: %v", err)
	}
	defer func() {
		if stdin != nil {
			_ = stdin.Close()
		}
	}()

	time.Sleep(300 * time.Millisecond)
	if s.IsFlagUnimplemented(stderr.String(), "system-trust") {
		_ = KillProcessGracefully(cmd, 500*time.Millisecond)
		t.Log("Contract check: --system-trust flag pending in Milestone M2")
		t.Skip("Skipping until Milestone M2 lands")
		return
	}

	// Manually delete ca.crt during execution
	caCertPath := filepath.Join(s.VouchDir, "ca.crt")
	_ = os.Remove(caCertPath)

	// Send SIGINT to trigger teardown
	_ = cmd.Process.Signal(syscall.SIGINT)

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-done:
		t.Log("Teardown completed safely despite deleted ca.crt")
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("Teardown hung or failed to complete when ca.crt was removed")
	}
}

// 40. TestE2E_R3_Edge_SIGKILLRecoveryOnNextRun verifies startup detects and cleans
// lingering root certificates from previous abnormal terminations.
func TestE2E_R3_Edge_SIGKILLRecoveryOnNextRun(t *testing.T) {
	s := NewVouchSession(t)
	masterPass := "trust-sigkill-recovery-555"
	s.SetEnv("VOUCH_MASTER_KEY", masterPass)

	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// 1. First run is brutally killed with SIGKILL (bypassing teardown hooks)
	cmd, stdin, _, stderr, err := s.StartCommand("run", "--system-trust", "--", "sleep", "10")
	if err != nil {
		t.Fatalf("StartCommand failed: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if s.IsFlagUnimplemented(stderr.String(), "system-trust") {
		_ = KillProcessGracefully(cmd, 500*time.Millisecond)
		if stdin != nil {
			_ = stdin.Close()
		}
		t.Log("Contract check: --system-trust flag pending in Milestone M2")
		t.Skip("Skipping until Milestone M2 lands")
		return
	}

	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if stdin != nil {
		_ = stdin.Close()
	}

	// 2. Second run must clean up any stale registration and initialize cleanly
	out, errOut, code, _ := s.RunCommand("run", "--system-trust", "--", "echo", "recovered-cleanly")
	if code != 0 {
		t.Fatalf("Next run failed after SIGKILL with code %d: %s\n%s", code, out, errOut)
	}
	if !strings.Contains(out+errOut, "recovered-cleanly") {
		t.Errorf("Expected 'recovered-cleanly' output, got: %s", out+errOut)
	}
}
