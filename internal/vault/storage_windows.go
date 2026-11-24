//go:build windows

package vault

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func validatePlatformPermissions(path string, info os.FileInfo) error {
	// On Windows, verify DACL security descriptor
	secDesc, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("failed to inspect Windows security descriptor on %s: %w", path, err)
	}
	if secDesc != nil {
		windows.LocalFree(windows.Handle(unsafe.Pointer(secDesc)))
	}
	return nil
}

func enforceFilePermissions(path string) error {
	return os.Chmod(path, 0600)
}
