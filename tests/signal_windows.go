//go:build windows

package tests

import (
	"os"
)

// sendWindowResizeSignal is a no-op on Windows where SIGWINCH is not supported.
func sendWindowResizeSignal(p *os.Process) error {
	return nil
}
