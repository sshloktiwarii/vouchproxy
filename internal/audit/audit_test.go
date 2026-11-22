package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestJSONLAuditLoggerAndTail(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vouch-jsonl-audit-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "audit.jsonl")
	logger, err := NewLogger(logPath)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}

	sessionID := "test_session_01"

	// 1. Record 100 sequential events
	for i := 0; i < 100; i++ {
		err := logger.Log(AuditEvent{
			EventID:         fmt.Sprintf("ev_%03d", i),
			SessionID:       sessionID,
			Timestamp:       time.Now().UTC(),
			HTTPMethod:      "POST",
			Host:            "api.openai.com",
			Port:            443,
			PathSanitized:   "/v1/chat/completions",
			Action:          "INJECT_SECRET",
			InjectedKeyName: "OPENAI_API_KEY",
			HTTPStatus:      200,
			LatencyMs:       0.9,
			Details:         "OpenAI API Rule",
		})
		if err != nil {
			t.Fatalf("Log failed at %d: %v", i, err)
		}
	}

	// 2. High Concurrency Stress: 500 concurrent goroutines recording events
	var wg sync.WaitGroup
	concurrentCount := 500
	wg.Add(concurrentCount)

	for i := 0; i < concurrentCount; i++ {
		idx := i
		go func() {
			defer wg.Done()
			_ = logger.Log(AuditEvent{
				EventID:         fmt.Sprintf("conc_%03d", idx),
				SessionID:       sessionID,
				Timestamp:       time.Now().UTC(),
				HTTPMethod:      "GET",
				Host:            "api.github.com",
				Port:            443,
				PathSanitized:   "/user",
				Action:          "PASSTHROUGH",
				InjectedKeyName: "",
				HTTPStatus:      200,
				LatencyMs:       0.4,
			})
		}()
	}
	wg.Wait()
	_ = logger.Close()

	// 3. Test ReadAll to assert all 600 records exist
	allEvents, err := ReadAll(logPath)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if len(allEvents) != 600 {
		t.Fatalf("expected 600 total audit events, got %d", len(allEvents))
	}

	// 4. Test Reverse-Seek Tail
	tailEvents, err := Tail(logPath, TailOptions{Limit: 10})
	if err != nil {
		t.Fatalf("Tail failed: %v", err)
	}
	if len(tailEvents) != 10 {
		t.Fatalf("expected 10 events from Tail, got %d", len(tailEvents))
	}

	// 5. Test Host Filter on Tail
	openaiEvents, err := Tail(logPath, TailOptions{
		Limit: 50,
		Host:  "api.openai.com",
	})
	if err != nil {
		t.Fatalf("Tail with host filter failed: %v", err)
	}
	for _, ev := range openaiEvents {
		if ev.Host != "api.openai.com" {
			t.Fatalf("unexpected host in filtered tail: %s", ev.Host)
		}
	}
}
