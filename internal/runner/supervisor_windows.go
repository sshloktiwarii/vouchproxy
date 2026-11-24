//go:build windows

package runner

import (
	"os"
	"os/exec"
	"os/signal"
)

// RunSupervised on Windows executes the command and waits for completion.
func RunSupervised(cmd *exec.Cmd) (int, error) {
	return RunSupervisedWithCancel(cmd, nil)
}

// RunSupervisedWithCancel on Windows executes the command and waits for completion or cancellation.
func RunSupervisedWithCancel(cmd *exec.Cmd, cancelChan <-chan struct{}) (int, error) {
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt)
	defer signal.Stop(sigChan)
	return RunSupervisedWithSignals(cmd, sigChan, cancelChan)
}

// SetProcessGroup is a no-op on Windows.
func SetProcessGroup(cmd *exec.Cmd) {
}

// TerminateProcessGroup terminates the process on Windows.
func TerminateProcessGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}

// KillProcessGroup forcefully terminates the process on Windows.
func KillProcessGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}

// ExtractExitCode extracts integer exit code from error.
func ExtractExitCode(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return 1
}

// RunSupervisedWithSignals on Windows coordinates execution with signals.
func RunSupervisedWithSignals(cmd *exec.Cmd, sigChan <-chan os.Signal, cancelChan <-chan struct{}) (int, error) {
	SetProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		return 1, err
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-sigChan:
		_ = cmd.Process.Kill()
		<-done
		return 130, nil

	case <-cancelChan:
		_ = cmd.Process.Kill()
		<-done
		return 0, nil

	case err := <-done:
		return ExtractExitCode(err), nil
	}
}
