package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/vault"
)

// Logger manages the append-only JSONL audit log with 0600 permissions.
type Logger struct {
	mu     sync.Mutex
	file   *os.File
	writer *bufio.Writer
	path   string
}

// NewLogger opens or creates the audit.jsonl log file with strict 0600 permissions.
func NewLogger(path string) (*Logger, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create audit directory %s: %w", dir, err)
	}

	// Validate permissions if file already exists
	if err := vault.ValidateFilePermissions(path); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log %s: %w", path, err)
	}

	return &Logger{
		file:   f,
		writer: bufio.NewWriterSize(f, 32*1024),
		path:   path,
	}, nil
}

// Log writes a structured AuditEvent to the JSONL ledger and flushes it immediately.
func (l *Logger) Log(event AuditEvent) error {
	if l == nil || l.file == nil {
		return nil
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if _, err := l.writer.Write(data); err != nil {
		return err
	}
	if err := l.writer.WriteByte('\n'); err != nil {
		return err
	}
	return l.writer.Flush()
}

// Close flushes and closes the audit file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.writer != nil {
		_ = l.writer.Flush()
	}
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
