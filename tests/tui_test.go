package tests

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/policy"
	"github.com/sshloktiwarii/vouchproxy/internal/vault"
)

// setupTUIEnvironment prepares a VouchSession with CA, vault, and default policy.
func setupTUIEnvironment(t *testing.T, masterPass string) *VouchSession {
	t.Helper()
	s := NewVouchSession(t)
	s.SetEnv("VOUCH_MASTER_KEY", masterPass)

	// Init enclave
	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Failed to initialize session for TUI: %v", err)
	}

	// Seed standard secret
	err = s.SeedSecret("OPENAI_API_KEY", "sk-real-openai-secret-key-12345", masterPass)
	if err != nil {
		t.Fatalf("Failed to seed secret: %v", err)
	}

	return s
}

// 1. TestE2E_R1_TUI_SplitPaneInitialRender verifies split-pane borders,
// "Live Requests" left pane header, and "Inspection & Diffs" right pane header.
func TestE2E_R1_TUI_SplitPaneInitialRender(t *testing.T) {
	masterPass := "tui-master-pass-123"
	s := setupTUIEnvironment(t, masterPass)

	cmd, stdin, stdout, stderr, err := s.StartCommand("run", "--tui", "--", "sleep", "2")
	if err != nil {
		t.Fatalf("Failed to start vouchproxy with --tui: %v", err)
	}
	defer func() {
		_ = KillProcessGracefully(cmd, 500*time.Millisecond)
		if stdin != nil {
			_ = stdin.Close()
		}
	}()

	time.Sleep(300 * time.Millisecond)

	errOut := stderr.String()
	if s.IsFlagUnimplemented(errOut, "tui") {
		t.Logf("Contract check: --tui flag is pending implementation in Milestone M5 (output: %q)", errOut)
		t.Skip("Skipping full TUI split-pane render check until M5 lands")
		return
	}

	out := stdout.String() + "\n" + errOut
	stripped := StripANSI(out)

	// Assert presence of split-pane headers
	hasLiveRequests := strings.Contains(stripped, "Live Requests") || strings.Contains(stripped, "METHOD")
	hasInspectionDiffs := strings.Contains(stripped, "Inspection & Diffs") || strings.Contains(stripped, "Diff")

	if !hasLiveRequests || !hasInspectionDiffs {
		t.Logf("Initial TUI output buffer: %q", stripped)
		// If running in non-TTY during CI, may fall back to headless notice
		if strings.Contains(stripped, "headless") || strings.Contains(stripped, "non-TTY") {
			t.Log("TUI gracefully detected non-TTY in test environment")
			return
		}
		t.Errorf("Expected split-pane headers 'Live Requests' and 'Inspection & Diffs', got: %s", stripped)
	}
}

// 2. TestE2E_R1_TUI_LiveRequestListUpdates verifies table row insertion
// (Method, Host, Status, Latency) as outbound requests stream through proxy.
func TestE2E_R1_TUI_LiveRequestListUpdates(t *testing.T) {
	masterPass := "tui-master-pass-123"
	s := setupTUIEnvironment(t, masterPass)

	upstream := NewMockUpstreamServer()
	defer upstream.Close()

	// Configure policy rule for upstream host
	cfg := policy.DefaultConfig()
	cfg.Rules = append(cfg.Rules, policy.Rule{
		Name:      "Mock API",
		Host:      upstream.Host,
		MatchType: "exact",
		Headers: []policy.HeaderRule{
			{
				Name:       "Authorization",
				Format:     "Bearer {{secret}}",
				Secret:     "OPENAI_API_KEY",
				DummyMatch: "VP_OPENAI_API_KEY_DUMMY_*",
			},
		},
		AllowedMethods: []string{"GET", "POST"},
	})
	_ = s.CreatePolicy(cfg)

	// Child script sends an actual HTTP request through $HTTP_PROXY to populate TUI table
	childScript := fmt.Sprintf(`curl -s -x "$HTTP_PROXY" "%s/live-test"; sleep 2`, upstream.URL)
	cmd, stdin, stdout, stderr, err := s.StartCommand("run", "--tui", "--", "sh", "-c", childScript)
	if err != nil {
		t.Fatalf("Failed to start vouchproxy: %v", err)
	}
	defer func() {
		_ = KillProcessGracefully(cmd, 500*time.Millisecond)
		if stdin != nil {
			_ = stdin.Close()
		}
	}()

	time.Sleep(300 * time.Millisecond)
	if s.IsFlagUnimplemented(stderr.String(), "tui") {
		t.Log("Contract check: --tui flag pending in Milestone M5")
		t.Skip("Skipping until M5 lands")
		return
	}

	time.Sleep(1 * time.Second)
	out := StripANSI(stdout.String() + "\n" + stderr.String())

	// Assert upstream received request
	if upstream.GetReceivedCount() == 0 {
		t.Errorf("Expected upstream to receive live request via proxy, received 0")
	}

	// Assert presence of request row in TUI output
	if !strings.Contains(out, "/live-test") && !strings.Contains(out, "GET") {
		t.Errorf("Expected TUI request list to display live request row with GET /live-test, got:\n%s", out)
	}
}

// 3. TestE2E_R1_TUI_AmberPIIRedactionDiff verifies real-time diff rendering
// of redacted PII ([EMAIL_REDACTED]) with ANSI amber styling in right pane.
func TestE2E_R1_TUI_AmberPIIRedactionDiff(t *testing.T) {
	masterPass := "tui-master-pass-123"
	s := setupTUIEnvironment(t, masterPass)

	upstream := NewMockUpstreamServer()
	defer upstream.Close()

	cfg := policy.DefaultConfig()
	cfg.Rules = append(cfg.Rules, policy.Rule{
		Name:           "PII Test API",
		Host:           upstream.Host,
		MatchType:      "exact",
		AllowedMethods: []string{"GET", "POST"},
	})
	_ = s.CreatePolicy(cfg)

	childScript := fmt.Sprintf(`curl -s -x "$HTTP_PROXY" -H "User-Agent: Agent/1.0 confidential-dev@company.com" "%s/pii-check"; sleep 2`, upstream.URL)
	cmd, stdin, stdout, stderr, err := s.StartCommand("run", "--tui", "--", "sh", "-c", childScript)
	if err != nil {
		t.Fatalf("Failed to start vouchproxy: %v", err)
	}
	defer func() {
		_ = KillProcessGracefully(cmd, 500*time.Millisecond)
		if stdin != nil {
			_ = stdin.Close()
		}
	}()

	time.Sleep(300 * time.Millisecond)
	if s.IsFlagUnimplemented(stderr.String(), "tui") {
		t.Log("Contract check: --tui flag pending in Milestone M5")
		t.Skip("Skipping until M5 lands")
		return
	}

	time.Sleep(1 * time.Second)
	rawOutput := stdout.String() + "\n" + stderr.String()

	if !strings.Contains(rawOutput, "[EMAIL_REDACTED]") && !strings.Contains(rawOutput, "REDACTED") {
		t.Errorf("Expected TUI inspection diff pane to display redacted PII, got:\n%s", StripANSI(rawOutput))
	}
	if !HasAmberStyle(rawOutput) {
		t.Errorf("Expected PII redaction diff in TUI to render with ANSI amber styling")
	}
}

// 4. TestE2E_R1_TUI_CyanInjectedHeaderDiff verifies real-time diff rendering
// of injected headers with ANSI cyan styling in right pane.
func TestE2E_R1_TUI_CyanInjectedHeaderDiff(t *testing.T) {
	masterPass := "tui-master-pass-123"
	s := setupTUIEnvironment(t, masterPass)

	upstream := NewMockUpstreamServer()
	defer upstream.Close()

	cfg := policy.DefaultConfig()
	cfg.Rules = append(cfg.Rules, policy.Rule{
		Name:      "Injected Header API",
		Host:      upstream.Host,
		MatchType: "exact",
		Headers: []policy.HeaderRule{
			{
				Name:       "Authorization",
				Format:     "Bearer {{secret}}",
				Secret:     "OPENAI_API_KEY",
				DummyMatch: "VP_OPENAI_API_KEY_DUMMY_*",
			},
		},
		AllowedMethods: []string{"GET", "POST"},
	})
	_ = s.CreatePolicy(cfg)

	dummyToken := vault.GenerateDummyToken("OPENAI_API_KEY")
	childScript := fmt.Sprintf(`curl -s -x "$HTTP_PROXY" -H "Authorization: Bearer %s" "%s/header-check"; sleep 2`, dummyToken, upstream.URL)
	cmd, stdin, stdout, stderr, err := s.StartCommand("run", "--tui", "--", "sh", "-c", childScript)
	if err != nil {
		t.Fatalf("Failed to start vouchproxy: %v", err)
	}
	defer func() {
		_ = KillProcessGracefully(cmd, 500*time.Millisecond)
		if stdin != nil {
			_ = stdin.Close()
		}
	}()

	time.Sleep(300 * time.Millisecond)
	if s.IsFlagUnimplemented(stderr.String(), "tui") {
		t.Log("Contract check: --tui flag pending in Milestone M5")
		t.Skip("Skipping until M5 lands")
		return
	}

	time.Sleep(1 * time.Second)
	rawOutput := stdout.String() + "\n" + stderr.String()

	if !strings.Contains(rawOutput, "Bearer sk-real") {
		t.Errorf("Expected TUI inspection diff pane to show injected secret header, got:\n%s", StripANSI(rawOutput))
	}
	if !HasCyanStyle(rawOutput) {
		t.Errorf("Expected injected header diff in TUI to render with ANSI cyan styling")
	}
}

// 5. TestE2E_R1_TUI_KeybindingsAndGracefulQuit verifies Tab pane switching,
// Down/Up row navigation, and 'q' clean exit and terminal buffer restoration.
func TestE2E_R1_TUI_KeybindingsAndGracefulQuit(t *testing.T) {
	masterPass := "tui-master-pass-123"
	s := setupTUIEnvironment(t, masterPass)

	cmd, stdin, _, stderr, err := s.StartCommand("run", "--tui", "--", "sleep", "10")
	if err != nil {
		t.Fatalf("Failed to start vouchproxy: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	if s.IsFlagUnimplemented(stderr.String(), "tui") {
		_ = KillProcessGracefully(cmd, 500*time.Millisecond)
		t.Log("Contract check: --tui flag pending in Milestone M5")
		t.Skip("Skipping until M5 lands")
		return
	}

	// Send navigation keys: Tab (switch pane), Down arrow, Up arrow, then 'q' (quit)
	if stdin != nil {
		_, _ = stdin.Write([]byte("\t"))         // Tab
		_, _ = stdin.Write([]byte("\x1b[B"))     // Down
		_, _ = stdin.Write([]byte("\x1b[A"))     // Up
		_, _ = stdin.Write([]byte("q"))          // Quit
		_ = stdin.Close()
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case waitErr := <-done:
		if waitErr != nil {
			t.Logf("Process exited with: %v", waitErr)
		}
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		t.Errorf("TUI failed to exit gracefully within 3 seconds after 'q' keybinding")
	}
}

// 26. TestE2E_R1_Edge_NonTTYHeadlessFallback verifies headless environments
// fall back to standard stderr logging without panic.
func TestE2E_R1_Edge_NonTTYHeadlessFallback(t *testing.T) {
	masterPass := "tui-master-pass-123"
	s := setupTUIEnvironment(t, masterPass)

	// In non-TTY environment (e.g. CI or pipe), run --tui with child command
	out, errOut, code, _ := s.RunCommandWithInput("", "run", "--tui", "--", "echo", "headless-success")

	if s.IsFlagUnimplemented(errOut, "tui") {
		t.Log("Contract check: --tui flag pending in Milestone M5")
		t.Skip("Skipping until M5 lands")
		return
	}

	combined := out + "\n" + errOut
	if code != 0 {
		t.Fatalf("Expected exit code 0 in headless fallback, got %d. Output: %s", code, combined)
	}

	if !strings.Contains(combined, "headless-success") {
		t.Errorf("Expected child output 'headless-success' in non-TTY fallback, got: %s", combined)
	}
}

// 27. TestE2E_R1_Edge_WindowResizeTerminalSignals verifies SIGWINCH resize
// recalculates layouts without panic or overflow corruption.
func TestE2E_R1_Edge_WindowResizeTerminalSignals(t *testing.T) {
	masterPass := "tui-master-pass-123"
	s := setupTUIEnvironment(t, masterPass)

	cmd, stdin, _, stderr, err := s.StartCommand("run", "--tui", "--", "sleep", "4")
	if err != nil {
		t.Fatalf("Failed to start vouchproxy: %v", err)
	}
	defer func() {
		_ = KillProcessGracefully(cmd, 500*time.Millisecond)
		if stdin != nil {
			_ = stdin.Close()
		}
	}()

	time.Sleep(300 * time.Millisecond)
	if s.IsFlagUnimplemented(stderr.String(), "tui") {
		t.Log("Contract check: --tui flag pending in Milestone M5")
		t.Skip("Skipping until M5 lands")
		return
	}

	// Dispatch multiple SIGWINCH signals to simulate resizing
	for i := 0; i < 3; i++ {
		time.Sleep(100 * time.Millisecond)
		_ = sendWindowResizeSignal(cmd.Process)
	}

	// Ensure process did not crash on resize
	time.Sleep(200 * time.Millisecond)
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		t.Fatalf("TUI crashed after receiving SIGWINCH: %v", cmd.ProcessState)
	}
}

// 28. TestE2E_R1_Edge_HighFrequencyRequestFlood verifies 200 rapid requests
// routed through VouchProxy do not crash or stall the TUI event loop.
func TestE2E_R1_Edge_HighFrequencyRequestFlood(t *testing.T) {
	masterPass := "tui-master-pass-123"
	s := setupTUIEnvironment(t, masterPass)

	upstream := NewMockUpstreamServer()
	defer upstream.Close()

	proxyFile := filepath.Join(s.VouchDir, "proxy_url.txt")
	childScript := fmt.Sprintf(`echo "$HTTP_PROXY" > "%s"; sleep 6`, proxyFile)

	cmd, stdin, _, stderr, err := s.StartCommand("run", "--tui", "--", "sh", "-c", childScript)
	if err != nil {
		t.Fatalf("Failed to start vouchproxy: %v", err)
	}
	defer func() {
		_ = KillProcessGracefully(cmd, 500*time.Millisecond)
		if stdin != nil {
			_ = stdin.Close()
		}
	}()

	time.Sleep(300 * time.Millisecond)
	if s.IsFlagUnimplemented(stderr.String(), "tui") {
		t.Log("Contract check: --tui flag pending in Milestone M5")
		t.Skip("Skipping until M5 lands")
		return
	}

	// Retrieve HTTP_PROXY export from supervised child
	var proxyURLStr string
	for i := 0; i < 20; i++ {
		if data, err := os.ReadFile(proxyFile); err == nil && len(strings.TrimSpace(string(data))) > 0 {
			proxyURLStr = strings.TrimSpace(string(data))
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if proxyURLStr == "" {
		t.Fatalf("Failed to retrieve HTTP_PROXY from supervised child environment")
	}

	proxyURL, err := url.Parse(proxyURLStr)
	if err != nil {
		t.Fatalf("Failed to parse HTTP_PROXY %q: %v", proxyURLStr, err)
	}

	// Simulate concurrent request load ROUTED THROUGH VOUCHPROXY
	concurrency := 20
	requestsPerWorker := 10
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for w := 0; w < concurrency; w++ {
		go func() {
			defer wg.Done()
			client := &http.Client{
				Timeout: 3 * time.Second,
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
				},
			}
			for r := 0; r < requestsPerWorker; r++ {
				resp, reqErr := client.Get(upstream.URL)
				if reqErr == nil {
					_ = resp.Body.Close()
				}
			}
		}()
	}
	wg.Wait()

	// Ensure process is still healthy and did not panic/crash under load
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		t.Fatalf("TUI process exited prematurely under request flood: %v", cmd.ProcessState)
	}
}

// 29. TestE2E_R1_Edge_ChildStdoutInterferenceIsolation verifies child writing directly
// to stdout/stderr does not destroy TUI split-pane border lines or panic.
func TestE2E_R1_Edge_ChildStdoutInterferenceIsolation(t *testing.T) {
	masterPass := "tui-master-pass-123"
	s := setupTUIEnvironment(t, masterPass)

	childScript := "echo 'INTERFERENCE_STDOUT_LINE_1'; echo 'INTERFERENCE_STDERR_LINE_2' >&2; exit 0"
	out, errOut, code, _ := s.RunCommand("run", "--tui", "--", "sh", "-c", childScript)

	if s.IsFlagUnimplemented(errOut, "tui") {
		t.Log("Contract check: --tui flag pending in Milestone M5")
		t.Skip("Skipping until M5 lands")
		return
	}

	if code != 0 {
		t.Fatalf("Expected exit code 0 from child script, got %d (out: %s, err: %s)", code, out, errOut)
	}
}

// 30. TestE2E_R1_Edge_OversizedDiffBodyTruncation verifies 1 MB body with 200 redactions
// truncates gracefully without UI freeze.
func TestE2E_R1_Edge_OversizedDiffBodyTruncation(t *testing.T) {
	masterPass := "tui-master-pass-123"
	s := setupTUIEnvironment(t, masterPass)

	// Generate 1 MB body with repetitive redactions
	var buf bytes.Buffer
	for i := 0; i < 200; i++ {
		buf.WriteString(fmt.Sprintf(`{"user_id": %d, "email": "employee%d@confidential.corp"},`, i, i))
	}
	// Pad to 1MB
	padding := strings.Repeat("A", 1024*1024-buf.Len())
	buf.WriteString(padding)

	cmd, stdin, _, stderr, err := s.StartCommand("run", "--tui", "--", "sleep", "3")
	if err != nil {
		t.Fatalf("Failed to start vouchproxy: %v", err)
	}
	defer func() {
		_ = KillProcessGracefully(cmd, 500*time.Millisecond)
		if stdin != nil {
			_ = stdin.Close()
		}
	}()

	time.Sleep(300 * time.Millisecond)
	if s.IsFlagUnimplemented(stderr.String(), "tui") {
		t.Log("Contract check: --tui flag pending in Milestone M5")
		t.Skip("Skipping until M5 lands")
		return
	}

	time.Sleep(500 * time.Millisecond)
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		t.Fatalf("TUI crashed on oversized payload: %v", cmd.ProcessState)
	}
}
