package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/audit"
	"github.com/sshloktiwarii/vouchproxy/internal/canary"
	"github.com/sshloktiwarii/vouchproxy/internal/policy"
	"github.com/sshloktiwarii/vouchproxy/internal/tui"
	"github.com/sshloktiwarii/vouchproxy/internal/vault"
)

type pipelineResult struct {
	policy.EvaluationResult
	HTTPMethod    string
	PathSanitized string
	LatencyMs     float64
}

func (pr *pipelineResult) ToAuditEvent(sessionID, host string, port int) audit.AuditEvent {
	actionStr := string(pr.Action)
	var keyName string
	if len(pr.InjectedKeys) > 0 {
		keyName = strings.Join(pr.InjectedKeys, ",")
	}

	return audit.AuditEvent{
		EventID:         fmt.Sprintf("ev_%d", time.Now().UnixNano()),
		SessionID:       sessionID,
		Timestamp:       time.Now().UTC(),
		HTTPMethod:      pr.HTTPMethod,
		Host:            host,
		Port:            port,
		PathSanitized:   pr.PathSanitized,
		Action:          actionStr,
		InjectedKeyName: keyName,
		ScrubCount:      pr.ScrubCount,
		HTTPStatus:      pr.BlockStatus,
		LatencyMs:       pr.LatencyMs,
		Details:         pr.ErrorMessage,
	}
}

// executePipeline performs canary checking, secret injection, PII scrubbing, and upstream round-trip
// using O(1) rolling-window body streaming without buffering the entire body into memory.
func (h *Handler) executePipeline(req *http.Request, start time.Time) (*http.Response, pipelineResult) {
	// Stage 1: Canary Token & Session Watermark Exfiltration Check (Headers & URL)
	if blocked, canaryResult := h.checkCanaryTokens(req, start); blocked {
		return nil, canaryResult
	}

	dummyToKey := h.vaultInstance.DummyToKeyMap()
	eval := h.policyEngine.EvaluateRequest(req, dummyToKey)

	res := pipelineResult{
		EvaluationResult: eval,
		HTTPMethod:       req.Method,
		PathSanitized:    req.URL.Path,
		LatencyMs:        float64(time.Since(start).Microseconds()) / 1000.0,
	}

	if eval.ShouldBlock {
		tui.GlobalFeed.Publish(tui.RequestEntry{
			Method:    req.Method,
			Host:      req.Host,
			Path:      req.URL.Path,
			Status:    res.BlockStatus,
			LatencyMs: res.LatencyMs,
			Timestamp: time.Now(),
		})
		return nil, res
	}

	// Stage 2: Secret Injection (Headers)
	h.injectSecrets(req, eval)

	// Stage 3: PII Scrubbing (Headers)
	res.ScrubCount = h.scrubHeaders(req.Header)

	// Remove hop-by-hop headers
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")

	// Stage 4: Wrap Body with O(1) Rolling-Window StreamScannerReader
	var streamScanner *StreamScannerReader
	if req.Body != nil && req.Body != http.NoBody {
		rule := h.policyEngine.FindRule(req.Host, req.Method)
		streamScanner = NewStreamScannerReader(StreamScannerOptions{
			Source:        req.Body,
			TargetHost:    req.Host,
			Method:        req.Method,
			Rule:          rule,
			DummyToKey:    dummyToKey,
			Vault:         h.vaultInstance,
			Scrubber:      h.policyEngine.Scrubber(),
			SessionSecret: h.sessionSecret,
			SessionID:     h.sessionID,
		})

		// Whenever body substitution alters byte length or is eligible for rewriting,
		// delete Content-Length and set ContentLength = -1 so Go's http.Transport uses chunked transfer encoding.
		if rule != nil || h.policyEngine.Scrubber() != nil {
			EnsureChunkedEncoding(req)
		}
		req.Body = streamScanner
	}

	// Stage 5: Outbound Dispatch
	resp, err := h.dispatchUpstream(req)
	if err != nil {
		// Check if the stream scanner aborted due to an exfiltration attempt mid-stream
		if streamScanner != nil && streamScanner.Blocked() {
			res.Action = policy.ActionBlockLeak
			res.ShouldBlock = true
			res.BlockStatus = http.StatusForbidden
			res.ErrorMessage = streamScanner.BlockReason()
			res.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0

			tui.GlobalFeed.Publish(tui.RequestEntry{
				Method:    req.Method,
				Host:      req.Host,
				Path:      req.URL.Path,
				Status:    res.BlockStatus,
				LatencyMs: res.LatencyMs,
				Timestamp: time.Now(),
			})
			return nil, res
		}

		res.ErrorMessage = fmt.Sprintf("Upstream dial failure: %v", err)
		res.BlockStatus = http.StatusBadGateway
		return nil, res
	}

	// Stage 6: Response Canary Regurgitation Check
	h.inspectResponseCanaries(resp, req, res.LatencyMs)

	res.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
	res.BlockStatus = resp.StatusCode

	tui.GlobalFeed.Publish(tui.RequestEntry{
		Method:    req.Method,
		Host:      req.Host,
		Path:      req.URL.Path,
		Status:    res.BlockStatus,
		LatencyMs: res.LatencyMs,
		Timestamp: time.Now(),
	})

	return resp, res
}

func (h *Handler) checkCanaryTokens(req *http.Request, start time.Time) (bool, pipelineResult) {
	searchCorpus := req.URL.RequestURI()
	for _, vals := range req.Header {
		searchCorpus += " " + strings.Join(vals, " ")
	}

	canaries := canary.FindCanaryTokens(searchCorpus)
	hasWatermark := canary.DetectWatermark(searchCorpus, h.sessionSecret)
	if len(canaries) == 0 && !hasWatermark {
		return false, pipelineResult{}
	}

	rule := h.policyEngine.FindRule(req.Host, req.Method)
	if rule != nil {
		return false, pipelineResult{}
	}

	var promptIDs []string
	seenPrompts := make(map[string]bool)
	for _, c := range canaries {
		pid := canary.ExtractPromptID(c)
		if !seenPrompts[pid] {
			seenPrompts[pid] = true
			promptIDs = append(promptIDs, pid)
		}
	}

	res := pipelineResult{
		HTTPMethod:    req.Method,
		PathSanitized: req.URL.Path,
		LatencyMs:     float64(time.Since(start).Microseconds()) / 1000.0,
	}
	res.Action = policy.ActionBlockLeak
	res.ShouldBlock = true
	res.BlockStatus = http.StatusForbidden

	if hasWatermark {
		res.ErrorMessage = fmt.Sprintf("Blocked attempt to exfiltrate session canary watermark to unauthorized host %s", req.Host)
	} else {
		res.ErrorMessage = fmt.Sprintf("Blocked attempt to exfiltrate canary token for prompt(s): %s to unauthorized host %s", strings.Join(promptIDs, ", "), req.Host)
	}

	tui.GlobalFeed.Publish(tui.RequestEntry{
		Method:    req.Method,
		Host:      req.Host,
		Path:      req.URL.Path,
		Status:    res.BlockStatus,
		LatencyMs: res.LatencyMs,
		Timestamp: time.Now(),
	})

	return true, res
}

func (h *Handler) injectSecrets(req *http.Request, eval policy.EvaluationResult) {
	if eval.Action == policy.ActionInjectSecret && eval.RuleName != "" {
		rule := h.policyEngine.FindRule(req.Host, req.Method)
		if rule != nil {
			for _, hr := range rule.Headers {
				dummyToken := vault.GenerateDummyToken(hr.Secret)
				headerVal := req.Header.Get(hr.Name)

				if strings.Contains(headerVal, dummyToken) {
					realSecret, err := h.vaultInstance.Get(hr.Secret)
					if err == nil {
						defer realSecret.Zero() // Memory zeroing guarantee!

						var newHeader string
						if hr.Format != "" {
							formattedSecret := strings.ReplaceAll(hr.Format, "{{secret}}", string(realSecret))
							if strings.HasPrefix(hr.Format, "Bearer ") && strings.HasPrefix(headerVal, "Bearer ") {
								newHeader = strings.ReplaceAll(headerVal, dummyToken, string(realSecret))
							} else {
								newHeader = strings.ReplaceAll(headerVal, dummyToken, formattedSecret)
							}
						} else {
							newHeader = strings.ReplaceAll(headerVal, dummyToken, string(realSecret))
						}
						req.Header.Set(hr.Name, newHeader)
					}
				}
			}
		}
	}
}

func (h *Handler) scrubHeaders(headers http.Header) int {
	scrubber := h.policyEngine.Scrubber()
	return scrubber.ScrubHeaders(headers)
}

func (h *Handler) dispatchUpstream(req *http.Request) (*http.Response, error) {
	outReq := req.Clone(req.Context())
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "https"
	}
	if outReq.URL.Host == "" {
		outReq.URL.Host = req.Host
	}
	outReq.RequestURI = "" // Required by net/http Client

	if outReq.Host == "" {
		outReq.Host = req.Host
	}

	return h.transport.RoundTrip(outReq)
}

func (h *Handler) inspectResponseCanaries(resp *http.Response, req *http.Request, latencyMs float64) {
	if resp == nil || resp.Body == nil {
		return
	}
	head, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(head), resp.Body))
	respCanaries := canary.FindCanaryTokens(string(head))
	if len(respCanaries) == 0 || h.auditLogger == nil {
		return
	}

	var promptIDs []string
	seenPrompts := make(map[string]bool)
	for _, c := range respCanaries {
		pid := canary.ExtractPromptID(c)
		if !seenPrompts[pid] {
			seenPrompts[pid] = true
			promptIDs = append(promptIDs, pid)
		}
	}

	_ = h.auditLogger.Log(audit.AuditEvent{
		EventID:         fmt.Sprintf("ev_canary_%d", time.Now().UnixNano()),
		SessionID:       h.sessionID,
		Timestamp:       time.Now().UTC(),
		HTTPMethod:      req.Method,
		Host:            req.Host,
		Port:            443,
		Action:          "BLOCK_LEAK",
		HTTPStatus:      resp.StatusCode,
		LatencyMs:       latencyMs,
		Details:         fmt.Sprintf("Upstream response contained canary token for prompt(s): %s", strings.Join(promptIDs, ", ")),
	})
}
