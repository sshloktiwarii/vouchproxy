package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
