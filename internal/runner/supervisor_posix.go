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
	// Set process group ID so child and all descendants share the same pgid
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	if err := cmd.Start(); err != nil {
		return 1, err
	}

	childPid := cmd.Process.Pid
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

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
			return 128 + int(sig.(syscall.Signal)), nil
		}

	case err := <-done:
		signal.Stop(sigChan)
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
