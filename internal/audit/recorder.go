//go:build sqlite

package audit

import (
	"database/sql"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// OpenDB opens a local SQLite database in WAL mode and runs schema migrations.
func OpenDB(dbPath string) (*sql.DB, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory for audit database: %w", err)
	}

	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=wal_autocheckpoint(1000)&_pragma=foreign_keys(ON)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if _, err := db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to execute audit schema migration: %w", err)
	}

	return db, nil
}

// Recorder asynchronously writes audit events to SQLite without blocking proxy latency.
type Recorder struct {
	db        *sql.DB
	sessionID string
	queue     chan AuditEvent
	wg        sync.WaitGroup
	closed    chan struct{}
}

// NewRecorder creates and starts a background event logging worker.
func NewRecorder(db *sql.DB, sessionID, command string) (*Recorder, error) {
	if sessionID == "" {
		sessionID = uuid.NewString()
	}

	_, err := db.Exec(
		"INSERT OR REPLACE INTO audit_sessions (session_id, started_at, command) VALUES (?, ?, ?)",
		sessionID, time.Now().UTC(), command,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize audit session: %w", err)
	}

	r := &Recorder{
		db:        db,
		sessionID: sessionID,
		queue:     make(chan AuditEvent, 2048),
		closed:    make(chan struct{}),
	}

	r.wg.Add(1)
	go r.worker()

	return r, nil
}

func (r *Recorder) worker() {
	defer r.wg.Done()

	stmt, err := r.db.Prepare(`
		INSERT INTO audit_events (
			event_id, session_id, timestamp, http_method, host, port,
			path_sanitized, action, injected_key_name, scrub_count,
			http_status, latency_ms, details
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return
	}
	defer func() { _ = stmt.Close() }()

	for event := range r.queue {
		if event.EventID == "" {
			event.EventID = uuid.NewString()
		}
		if event.SessionID == "" {
			event.SessionID = r.sessionID
		}
		if event.Timestamp.IsZero() {
			event.Timestamp = time.Now().UTC()
		}

		_, _ = stmt.Exec(
			event.EventID,
			event.SessionID,
			event.Timestamp,
			event.HTTPMethod,
			event.Host,
			event.Port,
			event.PathSanitized,
			event.Action,
			event.InjectedKeyName,
			event.ScrubCount,
			event.HTTPStatus,
			event.LatencyMs,
			event.Details,
		)
	}
}

// Record queues an audit event safely.
func (r *Recorder) Record(event AuditEvent) {
	if r == nil || r.queue == nil {
		return
	}
	select {
	case r.queue <- event:
	default:
		if event.Action == "BLOCK_LEAK" {
			r.queue <- event
		}
	}
}

// Close gracefully flushes the queue, marks session complete, and stops the worker.
func (r *Recorder) Close(exitCode int) error {
	if r == nil || r.queue == nil {
		return nil
	}
	close(r.queue)
	r.wg.Wait()

	_, err := r.db.Exec(
		"UPDATE audit_sessions SET ended_at = ?, exit_code = ? WHERE session_id = ?",
		time.Now().UTC(), exitCode, r.sessionID,
	)
	return err
}

// QueryOptions specifies search filters for audit events.
type QueryOptions struct {
	SessionID string
	Host      string
	Action    string
	Limit     int
	Offset    int
	Tail      bool
}

// QueryEvents returns matching audit events sorted by timestamp descending.
func QueryEvents(db *sql.DB, opts QueryOptions) ([]AuditEvent, error) {
	if opts.Limit <= 0 {
		opts.Limit = 50
	}

	var whereClauses []string
	var args []interface{}

	if opts.SessionID != "" {
		whereClauses = append(whereClauses, "session_id = ?")
		args = append(args, opts.SessionID)
	}
	if opts.Host != "" {
		whereClauses = append(whereClauses, "host LIKE ?")
		args = append(args, "%"+opts.Host+"%")
	}
	if opts.Action != "" {
		whereClauses = append(whereClauses, "action = ?")
		args = append(args, strings.ToUpper(opts.Action))
	}

	query := "SELECT event_id, session_id, timestamp, http_method, host, port, path_sanitized, action, COALESCE(injected_key_name, ''), scrub_count, http_status, latency_ms, COALESCE(details, '') FROM audit_events"
	if len(whereClauses) > 0 {
		query += " WHERE " + strings.Join(whereClauses, " AND ")
	}
	query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	args = append(args, opts.Limit, opts.Offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []AuditEvent
	for rows.Next() {
		var ev AuditEvent
		var ts time.Time
		if err := rows.Scan(
			&ev.EventID,
			&ev.SessionID,
			&ts,
			&ev.HTTPMethod,
			&ev.Host,
			&ev.Port,
			&ev.PathSanitized,
			&ev.Action,
			&ev.InjectedKeyName,
			&ev.ScrubCount,
			&ev.HTTPStatus,
			&ev.LatencyMs,
			&ev.Details,
		); err != nil {
			return nil, fmt.Errorf("failed to scan audit event row: %w", err)
		}
		ev.Timestamp = ts
		results = append(results, ev)
	}

	return results, nil
}
