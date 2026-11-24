package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/canary"
	"github.com/sshloktiwarii/vouchproxy/internal/runner"
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

// isSensitiveValue checks for forbidden files and directory traversals recursively.
func isSensitiveValue(v any) (bool, string) {
	switch val := v.(type) {
	case string:
		lower := strings.ToLower(val)
		sensitiveTargets := []string{
			"vault.enc",
			"ca.key",
			"/etc/passwd",
			"/etc/shadow",
			".ssh/id_rsa",
			".ssh/id_ed25519",
			"id_rsa",
			"id_ed25519",
		}
		for _, s := range sensitiveTargets {
			if strings.Contains(lower, s) {
				return true, val
			}
		}
		if val == ".." || strings.Contains(val, "../") || strings.Contains(val, `..\`) || strings.Contains(val, "/..") || strings.Contains(val, `\..`) {
			return true, val
		}
	case map[string]any:
		for _, item := range val {
			if blocked, target := isSensitiveValue(item); blocked {
				return true, target
			}
		}
	case []any:
		for _, item := range val {
			if blocked, target := isSensitiveValue(item); blocked {
				return true, target
			}
		}
	}
	return false, ""
}

// InspectToolCall analyzes an MCP request, blocking forbidden file reads and rewriting dummy tokens.
func InspectToolCall(reqBytes []byte, v *vault.Vault) FilterResult {
	trimmed := bytes.TrimSpace(reqBytes)
	if len(trimmed) == 0 {
		return FilterResult{Rewritten: reqBytes}
	}

	// 0. Check for JSON-RPC 2.0 syntax / parse errors (-32700)
	var raw any
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return FilterResult{
			Blocked:      true,
			ErrorCode:    -32700,
			ErrorMessage: "Parse error: invalid JSON-RPC 2.0",
		}
	}

	// Batch JSON-RPC request support: detect array [...]
	if trimmed[0] == '[' {
		var batch []json.RawMessage
		if err := json.Unmarshal(trimmed, &batch); err == nil {
			var rewrittenBatch []json.RawMessage
			modified := false
			for _, item := range batch {
				res := InspectToolCall(item, v)
				if res.Blocked {
					return res
				}
				if len(res.Rewritten) > 0 && !bytes.Equal(res.Rewritten, item) {
					modified = true
					rewrittenBatch = append(rewrittenBatch, json.RawMessage(res.Rewritten))
				} else {
					rewrittenBatch = append(rewrittenBatch, item)
				}
			}
			if modified {
				out, err := json.Marshal(rewrittenBatch)
				if err == nil {
					return FilterResult{Rewritten: out}
				}
			}
			return FilterResult{Rewritten: reqBytes}
		}
	}

	var req JSONRPCRequest
	if err := json.Unmarshal(trimmed, &req); err != nil {
		return FilterResult{Rewritten: reqBytes}
	}

	if req.Method != "tools/call" || req.Params == nil {
		return FilterResult{Rewritten: reqBytes}
	}

	args, _ := req.Params["arguments"].(map[string]any)
	if args == nil {
		return FilterResult{Rewritten: reqBytes}
	}

	// 1. Forbidden path check (e.g. vault.enc, ca.key, /etc/passwd, /etc/shadow, etc.)
	if blocked, target := isSensitiveValue(args); blocked {
		return FilterResult{
			Blocked:      true,
			ErrorCode:    -32602,
			ErrorMessage: fmt.Sprintf("Access to sensitive target %q blocked by VouchProxy MCP semantic firewall", target),
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

// IsContextReadingTool checks whether a tool name corresponds to a sensitive context-reading operation.
func IsContextReadingTool(toolName string) bool {
	lower := strings.ToLower(toolName)
	contextTools := []string{"read_file", "grep_search", "view_file", "cat"}
	for _, ct := range contextTools {
		if lower == ct || strings.HasSuffix(lower, "_"+ct) || strings.HasSuffix(lower, ":"+ct) || strings.HasSuffix(lower, "/"+ct) {
			return true
		}
	}
	return false
}

// WatermarkToolResult recursively injects zero-width canary watermarks into text fields of an MCP tool result.
func WatermarkToolResult(result any, sessionSecret string) any {
	switch val := result.(type) {
	case string:
		return canary.WatermarkContent(val, sessionSecret)
	case map[string]any:
		newMap := make(map[string]any, len(val))
		for k, v := range val {
			if k == "text" {
				if s, ok := v.(string); ok {
					newMap[k] = canary.WatermarkContent(s, sessionSecret)
					continue
				}
			}
			newMap[k] = WatermarkToolResult(v, sessionSecret)
		}
		return newMap
	case []any:
		newSlice := make([]any, len(val))
		for i, item := range val {
			newSlice[i] = WatermarkToolResult(item, sessionSecret)
		}
		return newSlice
	default:
		return result
	}
}

// WatermarkToolResponse intercepts a JSON-RPC response from a context-reading tool and injects the canary watermark.
func WatermarkToolResponse(respBytes []byte, sessionSecret string) ([]byte, bool) {
	if len(respBytes) == 0 {
		return respBytes, false
	}

	var raw map[string]any
	if err := json.Unmarshal(respBytes, &raw); err != nil {
		return respBytes, false
	}

	res, exists := raw["result"]
	if !exists || res == nil {
		return respBytes, false
	}

	raw["result"] = WatermarkToolResult(res, sessionSecret)
	out, err := json.Marshal(raw)
	if err != nil {
		return respBytes, false
	}
	return out, true
}

// StdioProxyOptions configures the MCP stdio proxy with session and watermarking support.
type StdioProxyOptions struct {
	Vault         *vault.Vault
	SigChan       <-chan os.Signal
	SessionID     string
	SessionSecret string
	AutoWatermark bool
}

// RunStdioProxy wraps child process stdio, applying JSON-RPC inspection to incoming lines.
func RunStdioProxy(childCmd *exec.Cmd, v *vault.Vault) error {
	_, err := RunStdioProxyWithOptions(childCmd, StdioProxyOptions{Vault: v})
	return err
}

// RunStdioProxyWithSignals wraps child process stdio, coordinating with signals and semantic inspection.
func RunStdioProxyWithSignals(childCmd *exec.Cmd, v *vault.Vault, sigChan <-chan os.Signal) (int, error) {
	return RunStdioProxyWithOptions(childCmd, StdioProxyOptions{
		Vault:         v,
		SigChan:       sigChan,
		AutoWatermark: true,
	})
}

// RunStdioProxyWithOptions wraps child process stdio, coordinating with signals, semantic inspection,
// and automatic MCP file-context canary watermarking.
func RunStdioProxyWithOptions(childCmd *exec.Cmd, opts StdioProxyOptions) (int, error) {
	childStdin, err := childCmd.StdinPipe()
	if err != nil {
		return 1, fmt.Errorf("failed to open child stdin pipe: %w", err)
	}
	childStdout, err := childCmd.StdoutPipe()
	if err != nil {
		return 1, fmt.Errorf("failed to open child stdout pipe: %w", err)
	}
	childCmd.Stderr = os.Stderr

	runner.SetProcessGroup(childCmd)

	if err := childCmd.Start(); err != nil {
		return 1, fmt.Errorf("failed to start child command: %w", err)
	}

	inFlightContext := &sync.Map{}
	stdoutDone := make(chan struct{})

	// Stream 2: Child Stdout -> Automatic Canary Watermarking -> Parent Stdout
	go func() {
		defer close(stdoutDone)
		reader := bufio.NewReader(childStdout)
		for {
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 {
				trimmed := bytes.TrimSpace(line)
				if opts.AutoWatermark && len(trimmed) > 0 {
					var raw map[string]any
					if json.Unmarshal(trimmed, &raw) == nil {
						if idVal, exists := raw["id"]; exists && idVal != nil {
							idKey := fmt.Sprintf("%v", idVal)
							if _, isContext := inFlightContext.LoadAndDelete(idKey); isContext {
								if watermarked, modified := WatermarkToolResponse(trimmed, opts.SessionSecret); modified {
									trimmed = watermarked
								}
							}
						}
					}
				}
				_, _ = os.Stdout.Write(append(trimmed, '\n'))
			}
			if err != nil {
				return
			}
		}
	}()

	// Stream 1: Parent Stdin -> Semantic Firewall -> Child Stdin
	go func() {
		defer childStdin.Close()

		reader := bufio.NewReader(os.Stdin)
		for {
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 {
				trimmed := bytes.TrimSpace(line)

				// Track in-flight context tool calls for response watermarking
				var rpcReq JSONRPCRequest
				if err := json.Unmarshal(trimmed, &rpcReq); err == nil && rpcReq.Method == "tools/call" && rpcReq.Params != nil {
					if name, ok := rpcReq.Params["name"].(string); ok && IsContextReadingTool(name) {
						inFlightContext.Store(fmt.Sprintf("%v", rpcReq.ID), name)
					}
				}

				res := InspectToolCall(trimmed, opts.Vault)

				if res.Blocked {
					// Return JSON-RPC error directly to parent stdout (client)
					var respBytes []byte
					var req JSONRPCRequest
					if err := json.Unmarshal(trimmed, &req); err == nil && req.Method != "" {
						resp := JSONRPCResponse{
							JSONRPC: "2.0",
							ID:      req.ID,
							Error: &JSONRPCError{
								Code:    res.ErrorCode,
								Message: res.ErrorMessage,
							},
						}
						respBytes, _ = json.Marshal(resp)
					} else if len(trimmed) > 0 && trimmed[0] == '[' {
						var batch []JSONRPCRequest
						if err := json.Unmarshal(trimmed, &batch); err == nil && len(batch) > 0 {
							var batchResp []JSONRPCResponse
							for _, b := range batch {
								batchResp = append(batchResp, JSONRPCResponse{
									JSONRPC: "2.0",
									ID:      b.ID,
									Error: &JSONRPCError{
										Code:    res.ErrorCode,
										Message: res.ErrorMessage,
									},
								})
							}
							respBytes, _ = json.Marshal(batchResp)
						}
					}
					if len(respBytes) == 0 {
						resp := JSONRPCResponse{
							JSONRPC: "2.0",
							ID:      nil,
							Error: &JSONRPCError{
								Code:    res.ErrorCode,
								Message: res.ErrorMessage,
							},
						}
						respBytes, _ = json.Marshal(resp)
					}
					os.Stdout.Write(append(respBytes, '\n'))
				} else {
					_, writeErr := childStdin.Write(append(res.Rewritten, '\n'))
					if writeErr != nil {
						return
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()

	childDone := make(chan error, 1)
	go func() {
		childDone <- childCmd.Wait()
	}()

	select {
	case sig := <-opts.SigChan:
		_ = runner.TerminateProcessGroup(childCmd)
		select {
		case err := <-childDone:
			<-stdoutDone
			return runner.ExtractExitCode(err), nil
		case <-time.After(2 * time.Second):
			_ = runner.KillProcessGroup(childCmd)
			<-childDone
			<-stdoutDone
			if s, ok := sig.(interface{ Signal() }); ok {
				_ = s
			}
			return 130, nil
		}

	case err := <-childDone:
		<-stdoutDone
		return runner.ExtractExitCode(err), err
	}
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
