//go:build windows

package vault

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func validatePlatformPermissions(path string, info os.FileInfo) error {
	// On Windows, verify DACL and Owner security descriptor can be read
	secDesc, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("failed to inspect Windows security descriptor on %s: %w", path, err)
	}
	_ = secDesc
	return nil
}

func enforceFilePermissions(path string) error {
	return os.Chmod(path, 0600)
}
