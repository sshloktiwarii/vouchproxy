package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ValidateFilePermissions ensures a file is not accessible by other users.
// On POSIX, it verifies the file does not have group or other permissions (0600).
// On Windows, it verifies DACL security descriptors.
func ValidateFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return validatePlatformPermissions(path, info)
}

// AtomicWriteFile writes data to a temporary file with 0600 permissions,
// syncs to persistent disk storage, and atomically renames it to target.
func AtomicWriteFile(targetPath string, data []byte) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	tmpFile, err := os.CreateTemp(dir, ".vault-tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpName := tmpFile.Name()

	// Ensure cleanup if rename does not succeed
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
	}()

	// Enforce 0600 permissions
	if err := enforceFilePermissions(tmpName); err != nil {
		return fmt.Errorf("failed to set 0600 permissions: %w", err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("failed to write to temp file: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp file to disk: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tmpName, targetPath); err != nil {
		return fmt.Errorf("failed to atomically rename temp file to %s: %w", targetPath, err)
	}

	// Verify permissions on target
	if err := ValidateFilePermissions(targetPath); err != nil {
		return err
	}

	return nil
}

// ReadVaultFile reads the encrypted vault file, validating strict permissions first.
func ReadVaultFile(path string) ([]byte, error) {
	if err := ValidateFilePermissions(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("vault file does not exist")
		}
		return nil, fmt.Errorf("failed to read vault file: %w", err)
	}
	return data, nil
}
