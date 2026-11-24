//go:build !windows

package tests

import (
	"os"
	"syscall"
)

// sendWindowResizeSignal sends a SIGWINCH terminal resize signal on POSIX platforms.
func sendWindowResizeSignal(p *os.Process) error {
	if p == nil {
		return nil
	}
	return p.Signal(syscall.SIGWINCH)
}
