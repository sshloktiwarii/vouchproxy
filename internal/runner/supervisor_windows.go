//go:build windows

package runner

import (
	"os"
	"os/exec"
	"os/signal"
)

// RunSupervised on Windows executes the command and waits for completion.
func RunSupervised(cmd *exec.Cmd) (int, error) {
	if err := cmd.Start(); err != nil {
		return 1, err
	}

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt)

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-sigChan:
		_ = cmd.Process.Kill()
		<-done
		return 130, nil

	case err := <-done:
		signal.Stop(sigChan)
		if err == nil {
			return 0, nil
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 1, err
	}
}
