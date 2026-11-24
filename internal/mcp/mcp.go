package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/sshloktiwarii/vouchproxy/internal/vault"
)

// JSONRPCRequest represents an MCP JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      any            `json:"id,omitempty"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
}

// JSONRPCResponse represents an MCP JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id"`
	Result  any           `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError represents an MCP JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// FilterResult represents the outcome of MCP tool call inspection.
type FilterResult struct {
	Blocked      bool
	ErrorMessage string
	ErrorCode    int
	Rewritten    []byte
}

// InspectToolCall analyzes an MCP request, blocking forbidden file reads and rewriting dummy tokens.
func InspectToolCall(reqBytes []byte, v *vault.Vault) FilterResult {
	var req JSONRPCRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return FilterResult{Rewritten: reqBytes}
	}

	if req.Method != "tools/call" || req.Params == nil {
		return FilterResult{Rewritten: reqBytes}
	}

	args, _ := req.Params["arguments"].(map[string]any)
	if args == nil {
		return FilterResult{Rewritten: reqBytes}
	}

	// 1. Forbidden path check (e.g. vault.enc, ca.key)
	for _, val := range args {
		if strVal, ok := val.(string); ok {
			lower := strings.ToLower(strVal)
			if strings.Contains(lower, "vault.enc") || strings.Contains(lower, "ca.key") {
				return FilterResult{
					Blocked:      true,
					ErrorCode:    -32602,
					ErrorMessage: fmt.Sprintf("Access to sensitive file %q blocked by VouchProxy MCP semantic firewall", strVal),
				}
			}
		}
	}

	// 2. Secret argument rewriting: swap dummy tokens with real secrets
	dummyToKey := v.DummyToKeyMap()
	modified := false

	// Helper closure to read real secret safely
	vVaultGet := func(key string) ([]byte, error) {
		s, err := v.Get(key)
		if err != nil {
			return nil, err
		}
		res := make([]byte, len(s))
		copy(res, s)
		s.Zero()
		return res, nil
	}

	var rewriteVal func(v any) any
	rewriteVal = func(v any) any {
		switch val := v.(type) {
		case string:
			for dummyToken, keyName := range dummyToKey {
				if strings.Contains(val, dummyToken) {
					realSecret, err := vVaultGet(keyName)
					if err == nil {
						val = strings.ReplaceAll(val, dummyToken, string(realSecret))
						modified = true
					}
				}
			}
			return val
		case map[string]any:
			for k, innerVal := range val {
				val[k] = rewriteVal(innerVal)
			}
			return val
		case []any:
			for i, item := range val {
				val[i] = rewriteVal(item)
			}
			return val
		default:
			return val
		}
	}

	for k, argVal := range args {
		args[k] = rewriteVal(argVal)
	}

	if modified {
		req.Params["arguments"] = args
		rewritten, err := json.Marshal(req)
		if err == nil {
			return FilterResult{Rewritten: rewritten}
		}
	}

	return FilterResult{Rewritten: reqBytes}
}

// RunStdioProxy wraps child process stdio, applying JSON-RPC inspection to incoming lines.
func RunStdioProxy(childCmd *exec.Cmd, v *vault.Vault) error {
	childStdin, err := childCmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to open child stdin pipe: %w", err)
	}
	childStdout, err := childCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to open child stdout pipe: %w", err)
	}
	childCmd.Stderr = os.Stderr

	if err := childCmd.Start(); err != nil {
		return fmt.Errorf("failed to start child command: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Stream 1: Parent Stdin -> Semantic Firewall -> Child Stdin
	go func() {
		defer wg.Done()
		defer childStdin.Close()

		reader := bufio.NewReader(os.Stdin)
		for {
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 {
				trimmed := bytes.TrimSpace(line)
				res := InspectToolCall(trimmed, v)

				if res.Blocked {
					// Return JSON-RPC error directly to parent stdout (client)
					var req JSONRPCRequest
					_ = json.Unmarshal(trimmed, &req)

					resp := JSONRPCResponse{
						JSONRPC: "2.0",
						ID:      req.ID,
						Error: &JSONRPCError{
							Code:    res.ErrorCode,
							Message: res.ErrorMessage,
						},
					}
					respBytes, _ := json.Marshal(resp)
					os.Stdout.Write(append(respBytes, '\n'))
				} else {
					childStdin.Write(append(res.Rewritten, '\n'))
				}
			}
			if err != nil {
				break
			}
		}
	}()

	// Stream 2: Child Stdout -> Parent Stdout
	go func() {
		defer wg.Done()
		_, _ = io.Copy(os.Stdout, childStdout)
	}()

	waitErr := childCmd.Wait()
	wg.Wait()
	return waitErr
}

// RewritePayloadString replaces dummy tokens in a JSON/text payload string.
func RewritePayloadString(body string, v *vault.Vault) string {
	dummyToKey := v.DummyToKeyMap()
	for dummy, key := range dummyToKey {
		if strings.Contains(body, dummy) {
			realSecret, err := v.Get(key)
			if err == nil {
				body = strings.ReplaceAll(body, dummy, string(realSecret))
				realSecret.Zero()
			}
		}
	}
	return body
}
