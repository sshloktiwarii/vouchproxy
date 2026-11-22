package audit

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strings"
)

// TailOptions configures filtering and limits for tailing the audit log.
type TailOptions struct {
	Limit  int
	Host   string
	Action string
}

// Tail reads up to limit matching events from the end of the JSONL file without loading the whole file into memory.
func Tail(path string, opts TailOptions) ([]AuditEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}

	fileSize := stat.Size()
	if fileSize == 0 {
		return nil, nil
	}

	if opts.Limit <= 0 {
		opts.Limit = 50
	}

	// Read backwards in 64 KB chunks
	const chunkSize = 64 * 1024
	var events []AuditEvent
	var leftover string
	offset := fileSize

	for offset > 0 && len(events) < opts.Limit {
		readSize := int64(chunkSize)
		if offset < readSize {
			readSize = offset
		}
		offset -= readSize

		buf := make([]byte, readSize)
		if _, err := f.ReadAt(buf, offset); err != nil && err != io.EOF {
			return nil, err
		}

		chunkText := string(buf) + leftover
		lines := strings.Split(chunkText, "\n")

		// The first element might be an incomplete line if offset > 0
		if offset > 0 {
			leftover = lines[0]
			lines = lines[1:]
		} else {
			leftover = ""
		}

		// Process lines in reverse
		for i := len(lines) - 1; i >= 0 && len(events) < opts.Limit; i-- {
			line := strings.TrimSpace(lines[i])
			if line == "" {
				continue
			}

			var ev AuditEvent
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				continue
			}

			if opts.Host != "" && !strings.EqualFold(ev.Host, opts.Host) {
				continue
			}
			if opts.Action != "" && !strings.EqualFold(ev.Action, opts.Action) {
				continue
			}

			events = append(events, ev)
		}
	}

	// Reverse events array so they are in chronological order
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}

	return events, nil
}

// ReadAll streams and parses all events from the beginning.
func ReadAll(path string) ([]AuditEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var events []AuditEvent
	scanner := bufio.NewScanner(f)
	// Support up to 1 MB per line
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		events = append(events, ev)
	}

	return events, scanner.Err()
}
