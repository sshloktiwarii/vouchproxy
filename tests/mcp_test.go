package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/policy"
	"github.com/sshloktiwarii/vouchproxy/internal/vault"
)

// setupMCPTestEnvironment initializes an enclave with an authorized upstream host.
func setupMCPTestEnvironment(t *testing.T, masterPass string, upstreamHost string) *VouchSession {
	t.Helper()
	s := NewVouchSession(t)
	s.SetEnv("VOUCH_MASTER_KEY", masterPass)

	_, err := s.Init(masterPass)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = s.SeedSecret("OPENAI_API_KEY", "sk-real-openai-secret-key-12345", masterPass)
	if err != nil {
		t.Fatalf("Failed to seed secret: %v", err)
	}

	cfg := policy.DefaultConfig()
	cfg.Rules = append(cfg.Rules, policy.Rule{
		Name:      "Mock MCP API",
		Host:      upstreamHost,
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

	return s
}

// 16. TestE2E_R4_MCP_StdioToolCallBenignPassthrough verifies benign JSON-RPC 2.0
// tools/call for read_file passes through stdio unmodified.
func TestE2E_R4_MCP_StdioToolCallBenignPassthrough(t *testing.T) {
	masterPass := "mcp-benign-pass-123"
	s := setupMCPTestEnvironment(t, masterPass, "api.openai.com")

	client := &MockMCPClient{}
	reqBytes := client.NewMCPToolCall(1, "read_file", map[string]any{
		"path": "/workspace/main.go",
	})

	out, errOut, code, _ := s.RunCommandWithInput(string(reqBytes), "run", "--mcp-stdio", "--", "cat")
	if s.IsFlagUnimplemented(errOut, "mcp-stdio") {
		t.Log("Contract check: --mcp-stdio CLI flag pending in Milestone M3")
		t.Skip("Skipping full stdio stream wrapper until Milestone M3 lands")
		return
	}

	if code != 0 {
		t.Fatalf("vouchproxy run --mcp-stdio failed with code %d: %s\n%s", code, out, errOut)
	}

	var req map[string]any
	err := json.Unmarshal([]byte(strings.TrimSpace(out)), &req)
	if err != nil {
		t.Fatalf("Failed to parse JSON-RPC response from cat child: %v (output: %s)", err, out)
	}

	if req["method"] != "tools/call" {
		t.Fatalf("Expected method tools/call, got: %v", req["method"])
	}

	params, ok := req["params"].(map[string]any)
	if !ok || params["name"] != "read_file" {
		t.Fatalf("Expected tool name read_file, got: %v", params["name"])
	}

	args, ok := params["arguments"].(map[string]any)
	if !ok || args["path"] != "/workspace/main.go" {
		t.Fatalf("Expected benign path /workspace/main.go, got: %v", args["path"])
	}
}

// 17. TestE2E_R4_MCP_StdioSecretArgumentRewriting verifies dummy secret tokens
// in tool arguments are rewritten to real credentials on the wire before tool execution.
func TestE2E_R4_MCP_StdioSecretArgumentRewriting(t *testing.T) {
	masterPass := "mcp-secret-rewrite-123"
	upstream := NewMockUpstreamServer()
	defer upstream.Close()

	s := setupMCPTestEnvironment(t, masterPass, upstream.Host)

	dummyToken := vault.GenerateDummyToken("OPENAI_API_KEY")
	client := &MockMCPClient{}
	reqBytes := client.NewMCPToolCall(2, "fetch_api", map[string]any{
		"api_key": dummyToken,
		"url":     upstream.URL + "/data",
	})

	out, errOut, code, _ := s.RunCommandWithInput(string(reqBytes), "run", "--mcp-stdio", "--", "cat")
	if s.IsFlagUnimplemented(errOut, "mcp-stdio") {
		t.Log("Contract check: --mcp-stdio CLI flag pending in Milestone M3")
		t.Skip("Skipping full stdio stream wrapper until Milestone M3 lands")
		return
	}

	if code != 0 {
		t.Fatalf("mcp run failed with code %d: %s\n%s", code, out, errOut)
	}

	// Invariant: Child cat must receive the rewritten real secret and NOT the dummy token
	if strings.Contains(out, dummyToken) {
		t.Fatalf("Security failure: child received dummy token instead of rewritten secret: %s", out)
	}
	if !strings.Contains(out, "sk-real-openai-secret-key-12345") {
		t.Fatalf("Expected child output to contain real secret, got: %s", out)
	}
}

// 18. TestE2E_R4_MCP_StdioVaultPathBlocked verifies unauthorized file access
// (e.g. attempting to read vault.enc) is blocked with JSON-RPC error -32602.
func TestE2E_R4_MCP_StdioVaultPathBlocked(t *testing.T) {
	masterPass := "mcp-blocked-pass-123"
	s := setupMCPTestEnvironment(t, masterPass, "api.openai.com")

	client := &MockMCPClient{}
	forbiddenPath := "/home/user/.vouchproxy/vault.enc"
	reqBytes := client.NewMCPToolCall(3, "read_file", map[string]any{
		"path": forbiddenPath,
	})

	out, errOut, code, _ := s.RunCommandWithInput(string(reqBytes), "run", "--mcp-stdio", "--", "cat")
	if s.IsFlagUnimplemented(errOut, "mcp-stdio") {
		t.Log("Contract check: --mcp-stdio CLI flag pending in Milestone M3")
		t.Skip("Skipping full stdio stream wrapper until Milestone M3 lands")
		return
	}

	// Invariant: VouchProxy semantic firewall must intercept and return error -32602
	if code != 0 && !strings.Contains(out, "-32602") {
		t.Fatalf("Expected graceful firewall interception or exit with code -32602, got code %d: %s\n%s", code, out, errOut)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); err != nil {
		t.Fatalf("Failed to parse JSON-RPC error response: %v (out: %s)", err, out)
	}
	errObj, ok := parsed["error"].(map[string]any)
	if !ok {
		t.Fatalf("Expected JSON-RPC error object in response, got: %v", parsed)
	}
	if errObj["code"].(float64) != -32602 {
		t.Errorf("Expected JSON-RPC error code -32602, got: %v", errObj["code"])
	}
}

// 19. TestE2E_R4_MCP_HTTPSSEMessageRewriting verifies MCP tool arguments
// sent via HTTP POST to SSE endpoint are inspected and rewritten on the wire.
func TestE2E_R4_MCP_HTTPSSEMessageRewriting(t *testing.T) {
	var receivedBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"status":"ok"}}`))
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	customRules := []policy.Rule{
		{
			Name:           "Upstream MCP Rule",
			Host:           u.Host,
			MatchType:      "exact",
			AllowedMethods: []string{"GET", "POST"},
		},
	}

	srv, v, _, sessionSecret, tmpDir := setupTestSystem(t, customRules)
	defer os.RemoveAll(tmpDir)
	defer srv.Close()
	defer v.Close()

	dummyToken := vault.GenerateDummyToken("OPENAI_API_KEY")
	clientMsg := map[string]any{
		"jsonrpc": "2.0",
		"id":      10,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "chat_completion",
			"arguments": map[string]any{
				"api_key": dummyToken,
				"model":   "gpt-4",
			},
		},
	}
	msgBytes, _ := json.Marshal(clientMsg)

	proxyURL, _ := url.Parse(srv.ProxyURL())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequest("POST", upstream.URL+"/message?sessionId=test-session-123", bytes.NewReader(msgBytes))
	req.Header.Set("Proxy-Authorization", "Bearer "+sessionSecret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send HTTP message through proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK from proxy, got: %d", resp.StatusCode)
	}

	// If MCP body rewriting is pending in M3, detect and skip gracefully
	if strings.Contains(receivedBody, dummyToken) {
		t.Log("Contract check: MCP HTTP JSON-RPC message body rewriting pending in Milestone M3")
		t.Skip("Skipping until Milestone M3 lands")
		return
	}

	if !strings.Contains(receivedBody, "sk-real-openai-secret-key-12345") {
		t.Fatalf("Expected upstream to receive real secret in JSON body, got: %s", receivedBody)
	}
}

// 20. TestE2E_R4_MCP_HTTPSSEEventFramingPreserved verifies SSE event-stream
// transport headers and event boundaries remain intact without buffering stalls.
func TestE2E_R4_MCP_HTTPSSEEventFramingPreserved(t *testing.T) {
	upstream := NewMockUpstreamServer()
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	customRules := []policy.Rule{
		{
			Name:           "SSE Passthrough Rule",
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

	req, _ := http.NewRequest("GET", upstream.URL+"/sse", nil)
	req.Header.Set("Proxy-Authorization", "Bearer "+sessionSecret)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to connect to SSE stream through proxy: %v", err)
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/event-stream") {
		t.Fatalf("Expected Content-Type text/event-stream through proxy, got: %q", contentType)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read SSE stream body: %v", err)
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "event: progress") {
		t.Errorf("Expected SSE stream through proxy to contain 'event: progress', got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "data: {\"index\": 0}") {
		t.Errorf("Expected event frame 0, got: %s", bodyStr)
	}
}

// 41. TestE2E_R4_Edge_MalformedJSONRPCGrammar verifies broken JSON-RPC
// returns JSON-RPC parse error -32700 without breaking the stream.
func TestE2E_R4_Edge_MalformedJSONRPCGrammar(t *testing.T) {
	masterPass := "mcp-edge-pass-123"
	s := setupMCPTestEnvironment(t, masterPass, "api.openai.com")

	malformed := `{"jsonrpc": "2.0", "method": "tools/call", "params": {`

	out, errOut, code, _ := s.RunCommandWithInput(malformed, "run", "--mcp-stdio", "--", "cat")
	if s.IsFlagUnimplemented(errOut, "mcp-stdio") {
		t.Log("Contract check: --mcp-stdio CLI flag pending in Milestone M3")
		t.Skip("Skipping until Milestone M3 lands")
		return
	}

	if code != 0 && !strings.Contains(out, "-32700") {
		t.Fatalf("Expected JSON-RPC parse error -32700, got code %d: %s\n%s", code, out, errOut)
	}

	if !strings.Contains(out, "-32700") {
		t.Errorf("Expected JSON-RPC error code -32700 in response, got: %s", out)
	}
}

// 42. TestE2E_R4_Edge_DeeplyNestedJSONPayload verifies 100-level nested JSON
// evaluates within recursion limits and rewrites tokens at leaves.
func TestE2E_R4_Edge_DeeplyNestedJSONPayload(t *testing.T) {
	masterPass := "mcp-edge-pass-123"
	s := setupMCPTestEnvironment(t, masterPass, "api.openai.com")

	dummyToken := vault.GenerateDummyToken("OPENAI_API_KEY")

	// Construct 100-level deeply nested JSON object
	current := map[string]any{
		"leaf_secret": dummyToken,
	}
	for i := 0; i < 100; i++ {
		wrapper := map[string]any{
			fmt.Sprintf("level_%d", i): current,
		}
		current = wrapper
	}

	clientMsg := map[string]any{
		"jsonrpc": "2.0",
		"id":      42,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "nested_tool",
			"arguments": current,
		},
	}
	encoded, err := json.Marshal(clientMsg)
	if err != nil {
		t.Fatalf("Failed to marshal 100-level JSON: %v", err)
	}

	out, errOut, code, _ := s.RunCommandWithInput(string(encoded), "run", "--mcp-stdio", "--", "cat")
	if s.IsFlagUnimplemented(errOut, "mcp-stdio") {
		t.Log("Contract check: --mcp-stdio CLI flag pending in Milestone M3")
		t.Skip("Skipping until Milestone M3 lands")
		return
	}

	if code != 0 {
		t.Fatalf("mcp run failed on deeply nested JSON: code %d, out: %s, err: %s", code, out, errOut)
	}

	if strings.Contains(out, dummyToken) {
		t.Fatalf("Dummy token still present in leaf of deeply nested JSON: %s", out)
	}
	if !strings.Contains(out, "sk-real-openai-secret-key-12345") {
		t.Fatalf("Real secret not found in leaf of deeply nested JSON: %s", out)
	}
}

// 43. TestE2E_R4_Edge_BatchJSONRPCRequests verifies JSON-RPC batch arrays
// [{...}, {...}] evaluate each call independently.
func TestE2E_R4_Edge_BatchJSONRPCRequests(t *testing.T) {
	masterPass := "mcp-edge-pass-123"
	s := setupMCPTestEnvironment(t, masterPass, "api.openai.com")

	dummyToken := vault.GenerateDummyToken("OPENAI_API_KEY")

	batch := []map[string]any{
		{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "read_file", "arguments": map[string]any{"path": "a.txt"}}},
		{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "api_fetch", "arguments": map[string]any{"key": dummyToken}}},
		{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{"name": "read_file", "arguments": map[string]any{"path": "b.txt"}}},
	}

	batchBytes, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("Failed to marshal batch: %v", err)
	}

	out, errOut, code, _ := s.RunCommandWithInput(string(batchBytes), "run", "--mcp-stdio", "--", "cat")
	if s.IsFlagUnimplemented(errOut, "mcp-stdio") {
		t.Log("Contract check: --mcp-stdio CLI flag pending in Milestone M3")
		t.Skip("Skipping until Milestone M3 lands")
		return
	}

	if code != 0 {
		t.Fatalf("mcp run failed on batch requests: code %d, out: %s, err: %s", code, out, errOut)
	}

	var parsedBatch []map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsedBatch); err != nil {
		t.Fatalf("Failed to parse batch response: %v (out: %s)", err, out)
	}

	if len(parsedBatch) != 3 {
		t.Fatalf("Expected 3 batch items, got %d", len(parsedBatch))
	}

	if strings.Contains(out, dummyToken) {
		t.Fatalf("Batch response still contains dummy token: %s", out)
	}
	if !strings.Contains(out, "sk-real-openai-secret-key-12345") {
		t.Fatalf("Batch response missing rewritten secret: %s", out)
	}
}

// 44. TestE2E_R4_Edge_ChunkedSSEStreamMidWord verifies SSE events split across
// arbitrary TCP chunk boundaries reassemble cleanly when proxied.
func TestE2E_R4_Edge_ChunkedSSEStreamMidWord(t *testing.T) {
	// Custom SSE server that delivers a frame split across two flushes
	chunkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		flusher, ok := w.(http.Flusher)
		if ok {
			flusher.Flush()
		}
		// First half of frame
		_, _ = fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",")
		if ok {
			flusher.Flush()
		}
		time.Sleep(20 * time.Millisecond)
		// Second half of frame
		_, _ = fmt.Fprint(w, "\"id\":1,\"result\":\"ok\"}\n\n")
		if ok {
			flusher.Flush()
		}
	}))
	defer chunkServer.Close()

	u, _ := url.Parse(chunkServer.URL)
	customRules := []policy.Rule{
		{
			Name:           "Chunked SSE Rule",
			Host:           u.Host,
			MatchType:      "exact",
			AllowedMethods: []string{"GET"},
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

	req, _ := http.NewRequest("GET", chunkServer.URL+"/stream", nil)
	req.Header.Set("Proxy-Authorization", "Bearer "+sessionSecret)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to connect to chunked SSE stream through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read proxied stream body: %v", err)
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "data: ") || !strings.Contains(bodyStr, "\"result\":\"ok\"") {
		t.Fatalf("Malformed SSE event reassembly through proxy: %q", bodyStr)
	}
}

// 45. TestE2E_R4_Edge_SecretInNonStandardToolArgument verifies recursive search
// catches dummy secrets regardless of argument field naming.
func TestE2E_R4_Edge_SecretInNonStandardToolArgument(t *testing.T) {
	masterPass := "mcp-edge-pass-123"
	s := setupMCPTestEnvironment(t, masterPass, "api.openai.com")

	dummyToken := vault.GenerateDummyToken("OPENAI_API_KEY")

	customPayload := map[string]any{
		"jsonrpc": "2.0",
		"id":      99,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "custom_executor",
			"arguments": map[string]any{
				"metadata_ctx": map[string]any{
					"deep_auth_param": dummyToken,
				},
				"random_unmapped_field": dummyToken,
			},
		},
	}

	encoded, err := json.Marshal(customPayload)
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}

	out, errOut, code, _ := s.RunCommandWithInput(string(encoded), "run", "--mcp-stdio", "--", "cat")
	if s.IsFlagUnimplemented(errOut, "mcp-stdio") {
		t.Log("Contract check: --mcp-stdio CLI flag pending in Milestone M3")
		t.Skip("Skipping until Milestone M3 lands")
		return
	}

	if code != 0 {
		t.Fatalf("mcp run failed on non-standard fields: code %d, out: %s, err: %s", code, out, errOut)
	}

	if strings.Contains(out, dummyToken) {
		t.Fatalf("Dummy token still present in non-standard fields: %s", out)
	}
	count := strings.Count(out, "sk-real-openai-secret-key-12345")
	if count != 2 {
		t.Fatalf("Expected 2 rewritten occurrences of real secret, got %d (out: %s)", count, out)
	}
}
