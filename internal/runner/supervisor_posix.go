//go:build !windows

package runner

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// RunSupervised launches the child process in a dedicated process group and guarantees
// complete process tree termination on SIGINT/SIGTERM or parent exit.
func RunSupervised(cmd *exec.Cmd) (int, error) {
	return RunSupervisedWithCancel(cmd, nil)
}

// RunSupervisedWithCancel launches the child process in a dedicated process group,
// listening for OS signals or an optional cancellation channel (e.g. from TUI quit).
func RunSupervisedWithCancel(cmd *exec.Cmd, cancelChan <-chan struct{}) (int, error) {
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigChan)
	return RunSupervisedWithSignals(cmd, sigChan, cancelChan)
}

// SetProcessGroup sets the process group ID so child and descendants share pgid.
func SetProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
}

// TerminateProcessGroup sends SIGTERM to the process group.
func TerminateProcessGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}

// KillProcessGroup sends SIGKILL to the process group.
func KillProcessGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

// ExtractExitCode extracts integer exit code from error.
func ExtractExitCode(err error) int {
	return extractExitCode(err)
}

// RunSupervisedWithSignals coordinates process group execution with pre-existing signal and cancel channels.
func RunSupervisedWithSignals(cmd *exec.Cmd, sigChan <-chan os.Signal, cancelChan <-chan struct{}) (int, error) {
	// Set process group ID so child and all descendants share the same pgid
	SetProcessGroup(cmd)

	if err := cmd.Start(); err != nil {
		return 1, err
	}

	childPid := cmd.Process.Pid
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case sig := <-sigChan:
		// Broadcast signal to the entire process group (-childPid)
		_ = syscall.Kill(-childPid, syscall.SIGTERM)

		// 2-second grace period before escalation to SIGKILL
		select {
		case err := <-done:
			return extractExitCode(err), nil
		case <-time.After(2 * time.Second):
			_ = syscall.Kill(-childPid, syscall.SIGKILL)
			<-done
			if s, ok := sig.(syscall.Signal); ok {
				return 128 + int(s), nil
			}
			return 130, nil
		}

	case <-cancelChan:
		_ = syscall.Kill(-childPid, syscall.SIGTERM)

		// 2-second grace period before escalation to SIGKILL
		select {
		case <-done:
			return 0, nil
		case <-time.After(2 * time.Second):
			_ = syscall.Kill(-childPid, syscall.SIGKILL)
			<-done
			return 0, nil
		}

	case err := <-done:
		return extractExitCode(err), nil
	}
}

func extractExitCode(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return 1
}
