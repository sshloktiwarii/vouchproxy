package audit

import "time"

// AuditEvent represents a logged proxy routing and security decision.
type AuditEvent struct {
	EventID         string    `json:"event_id"`
	SessionID       string    `json:"session_id"`
	Timestamp       time.Time `json:"timestamp"`
	HTTPMethod      string    `json:"http_method"`
	Host            string    `json:"host"`
	Port            int       `json:"port"`
	PathSanitized   string    `json:"path_sanitized"`
	Action          string    `json:"action"`            // INJECT_SECRET, SCRUB_PII, BLOCK_LEAK, PASSTHROUGH, REJECT
	InjectedKeyName string    `json:"injected_key_name"` // e.g. 'OPENAI_API_KEY' (NEVER the raw secret)
	ScrubCount      int       `json:"scrub_count"`
	HTTPStatus      int       `json:"http_status"`
	LatencyMs       float64   `json:"latency_ms"`
	Details         string    `json:"details"`
}

// Session represents a running vouchproxy session.
type Session struct {
	SessionID string     `json:"session_id"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Command   string     `json:"command"`
	ExitCode  int        `json:"exit_code"`
}
