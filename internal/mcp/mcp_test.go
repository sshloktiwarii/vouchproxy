package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sshloktiwarii/vouchproxy/internal/canary"
	"github.com/sshloktiwarii/vouchproxy/internal/vault"
)

func createTestVault(t *testing.T) (*vault.Vault, string) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "mcp-test-vault-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	vaultPath := filepath.Join(tmpDir, "vault.enc")
	v, err := vault.Create(vaultPath, []byte("mcp-test-passphrase-1234"))
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}

	if err := v.Set("OPENAI_API_KEY", []byte("sk-real-openai-secret-key-12345")); err != nil {
		t.Fatalf("failed to set secret: %v", err)
	}
	if err := v.Set("GITHUB_TOKEN", []byte("ghp_real_github_token_67890")); err != nil {
		t.Fatalf("failed to set secret: %v", err)
	}

	return v, tmpDir
}

func TestInspectToolCall_ParseError(t *testing.T) {
	v, tmpDir := createTestVault(t)
	defer os.RemoveAll(tmpDir)
	defer v.Close()

	badJSON := []byte(`{"jsonrpc": "2.0", "method": "tools/call", invalid}`)
	res := InspectToolCall(badJSON, v)
	if !res.Blocked {
		t.Fatal("expected invalid JSON to be blocked")
	}
	if res.ErrorCode != -32700 {
		t.Fatalf("expected error code -32700, got %d", res.ErrorCode)
	}
}

func TestInspectToolCall_SensitivePathsBlocked(t *testing.T) {
	v, tmpDir := createTestVault(t)
	defer os.RemoveAll(tmpDir)
	defer v.Close()

	blockedPaths := []string{
		"~/.vouchproxy/vault.enc",
		"/etc/passwd",
		"/etc/shadow",
		"id_rsa",
		"../../sensitive.txt",
	}

	for _, p := range blockedPaths {
		req := JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/call",
			Params: map[string]any{
				"name": "read_file",
				"arguments": map[string]any{
					"path": p,
				},
			},
		}
		raw, _ := json.Marshal(req)
		res := InspectToolCall(raw, v)
		if !res.Blocked {
			t.Fatalf("expected path %q to be blocked", p)
		}
		if res.ErrorCode != -32602 {
			t.Fatalf("expected error code -32602, got %d", res.ErrorCode)
		}
	}
}

func TestInspectToolCall_SecretRewriting(t *testing.T) {
	v, tmpDir := createTestVault(t)
	defer os.RemoveAll(tmpDir)
	defer v.Close()

	dummyToken := vault.GenerateDummyToken("OPENAI_API_KEY")

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      42,
		Method:  "tools/call",
		Params: map[string]any{
			"name": "query_model",
			"arguments": map[string]any{
				"api_key": dummyToken,
				"nested": map[string]any{
					"bearer": "Bearer " + dummyToken,
				},
				"list": []any{"item1", dummyToken},
			},
		},
	}
	raw, _ := json.Marshal(req)
	res := InspectToolCall(raw, v)
	if res.Blocked {
		t.Fatalf("unexpected block: %s", res.ErrorMessage)
	}

	rewrittenStr := string(res.Rewritten)
	if strings.Contains(rewrittenStr, dummyToken) {
		t.Fatal("expected dummy token to be swapped out of rewritten payload")
	}
	if !strings.Contains(rewrittenStr, "sk-real-openai-secret-key-12345") {
		t.Fatal("expected real secret to be present in rewritten payload")
	}
}

func TestInspectToolCall_BatchRequests(t *testing.T) {
	v, tmpDir := createTestVault(t)
	defer os.RemoveAll(tmpDir)
	defer v.Close()

	dummyToken := vault.GenerateDummyToken("OPENAI_API_KEY")

	batch := []JSONRPCRequest{
		{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/call",
			Params: map[string]any{
				"name": "api_call",
				"arguments": map[string]any{
					"token": dummyToken,
				},
			},
		},
		{
			JSONRPC: "2.0",
			ID:      2,
			Method:  "ping",
		},
	}
	raw, _ := json.Marshal(batch)
	res := InspectToolCall(raw, v)
	if res.Blocked {
		t.Fatalf("unexpected block in batch: %s", res.ErrorMessage)
	}

	rewrittenStr := string(res.Rewritten)
	if strings.Contains(rewrittenStr, dummyToken) {
		t.Fatal("expected dummy token to be replaced in batch request")
	}
	if !strings.Contains(rewrittenStr, "sk-real-openai-secret-key-12345") {
		t.Fatal("expected real secret in batch request")
	}
}

func TestRewritePayloadString(t *testing.T) {
	v, tmpDir := createTestVault(t)
	defer os.RemoveAll(tmpDir)
	defer v.Close()

	dummyToken := vault.GenerateDummyToken("OPENAI_API_KEY")
	input := `data: {"params":{"arguments":{"key":"` + dummyToken + `"}}}`

	output := RewritePayloadString(input, v)
	if strings.Contains(output, dummyToken) {
		t.Fatal("expected dummy token to be substituted in payload string")
	}
	if !strings.Contains(output, "sk-real-openai-secret-key-12345") {
		t.Fatal("expected real secret in output")
	}
}

func TestMCP_ContextReadingToolDetection(t *testing.T) {
	contextTools := []string{"read_file", "grep_search", "view_file", "cat", "mcp__read_file", "fs:read_file"}
	for _, tool := range contextTools {
		if !IsContextReadingTool(tool) {
			t.Errorf("expected %s to be recognized as context-reading tool", tool)
		}
	}

	nonContextTools := []string{"execute_sql", "calculate", "search_web", "list_models"}
	for _, tool := range nonContextTools {
		if IsContextReadingTool(tool) {
			t.Errorf("expected %s NOT to be recognized as context-reading tool", tool)
		}
	}
}

func TestMCP_WatermarkToolResponse(t *testing.T) {
	sessionSecret := "test_mcp_session_secret_12345"

	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      101,
		"result": map[string]any{
			"content": []any{
				map[string]any{
					"type": "text",
					"text": "CRITICAL CONFIG: database_password = secret_root_password",
				},
			},
		},
	}
	rawResp, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}

	watermarked, modified := WatermarkToolResponse(rawResp, sessionSecret)
	if !modified {
		t.Fatal("expected response to be modified with watermark")
	}

	// 1. Verify JSON framing is valid
	var parsedResp map[string]any
	if err := json.Unmarshal(watermarked, &parsedResp); err != nil {
		t.Fatalf("watermarked response broke JSON framing: %v", err)
	}

	// 2. Extract text field and verify visible text is preserved
	resultMap, _ := parsedResp["result"].(map[string]any)
	contentList, _ := resultMap["content"].([]any)
	firstItem, _ := contentList[0].(map[string]any)
	textVal, _ := firstItem["text"].(string)

	expectedVisible := "CRITICAL CONFIG: database_password = secret_root_password"
	if !strings.Contains(textVal, expectedVisible) {
		t.Fatalf("expected visible text to be preserved, got %q", textVal)
	}

	// 3. Verify watermark detection
	if !canary.DetectWatermark(textVal, sessionSecret) {
		t.Fatal("expected session watermark to be detected in text field")
	}

	// 4. Verify detection fails for a different session
	wrongSecret := "different_session_secret_99999"
	if canary.DetectWatermark(textVal, wrongSecret) {
		t.Fatal("expected watermark verification to fail for wrong session secret")
	}
}
