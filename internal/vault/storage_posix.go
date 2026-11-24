//go:build !windows

package vault

import (
	"fmt"
	"os"
)

func validatePlatformPermissions(path string, info os.FileInfo) error {
	perm := info.Mode().Perm()
	if perm&0077 != 0 {
		return fmt.Errorf("insecure file permissions on %s: %04o (must be 0600 or stricter)", path, perm)
	}
	return nil
}

func enforceFilePermissions(path string) error {
	return os.Chmod(path, 0600)
}
