package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/audit"
	"github.com/sshloktiwarii/vouchproxy/internal/canary"
	"github.com/sshloktiwarii/vouchproxy/internal/mcp"
	"github.com/sshloktiwarii/vouchproxy/internal/policy"
	"github.com/sshloktiwarii/vouchproxy/internal/tui"
	"github.com/sshloktiwarii/vouchproxy/internal/vault"
)

// Handler coordinates request authentication, policy evaluation, PII scrubbing, and secret injection.
type Handler struct {
	sessionID     string
	sessionSecret string
	policyEngine  *policy.PolicyEngine
	vaultInstance *vault.Vault
	auditLogger   *audit.Logger
	mitmEngine    *MITMEngine
	transport     *UpstreamTransport
}

// NewHandler creates a new proxy request handler.
func NewHandler(
	sessionID string,
	sessionSecret string,
	pe *policy.PolicyEngine,
	v *vault.Vault,
	logger *audit.Logger,
	mitm *MITMEngine,
	timeout time.Duration,
) *Handler {
	return &Handler{
		sessionID:     sessionID,
		sessionSecret: sessionSecret,
		policyEngine:  pe,
		vaultInstance: v,
		auditLogger: logger,
		mitmEngine:    mitm,
		transport:     NewUpstreamTransport(timeout),
	}
}

// ServeHTTP routes incoming proxy requests (CONNECT or standard HTTP).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Validate Proxy Authentication
	if !ValidateProxyAuth(r, h.sessionSecret) {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"VouchProxy Enclave\"")
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
	} else {
		h.handleHTTP(w, r)
	}
}

// handleConnect handles HTTPS tunneling, TLS termination, policy inspection, and upstream dispatch.
func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request) {
	targetHost := r.Host
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to hijack connection: %v", err), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Respond 200 Connection Established
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}

	// Upgrade client connection to TLS using MITM dynamic certificate callback
	tlsConfig := &tls.Config{
		GetCertificate: h.mitmEngine.GetCertificateCallback(targetHost),
		MinVersion:     tls.VersionTLS12,
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		// Handshake failed (e.g. SNI mismatch or untrusted CA)
		return
	}
	defer tlsClientConn.Close()

	// Read decrypted HTTP requests from the TLS connection
	br := bufio.NewReader(tlsClientConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return // Connection closed or keepalive timeout
		}

		// Ensure full URL and Host are configured
		if req.URL.Scheme == "" {
			req.URL.Scheme = "https"
		}
		if req.URL.Host == "" {
			req.URL.Host = targetHost
		}
		req.Host = targetHost

		start := time.Now()
		h.processAndForward(tlsClientConn, req, start)
	}
}

// handleHTTP handles plain unencrypted HTTP proxy requests.
func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	// Strip proxy-authorization before forwarding
	r.Header.Del("Proxy-Authorization")

	resp, auditEvent := h.executePipeline(r, start)
	if resp != nil {
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		buf := GetCopyBuffer()
		defer PutCopyBuffer(buf)
		_, _ = io.CopyBuffer(w, resp.Body, *buf)
	} else if auditEvent.ShouldBlock {
		http.Error(w, auditEvent.ErrorMessage, auditEvent.BlockStatus)
	} else {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	if h.auditLogger != nil {
		_ = h.auditLogger.Log(auditEvent.ToAuditEvent(h.sessionID, r.Host, 80))
	}
}

// processAndForward executes the interception pipeline inside a TLS CONNECT tunnel.
func (h *Handler) processAndForward(clientConn net.Conn, req *http.Request, start time.Time) {
	resp, auditDecision := h.executePipeline(req, start)

	if auditDecision.ShouldBlock {
		body := []byte(fmt.Sprintf("HTTP/1.1 %d Forbidden\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			auditDecision.BlockStatus, len(auditDecision.ErrorMessage), auditDecision.ErrorMessage))
		_, _ = clientConn.Write(body)
		if h.auditLogger != nil {
			_ = h.auditLogger.Log(auditDecision.ToAuditEvent(h.sessionID, req.Host, 443))
		}
		return
	}

	if resp == nil {
		body := []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		_, _ = clientConn.Write(body)
		return
	}
	defer resp.Body.Close()

	// Write response status line and headers to client connection
	var headerBuf bytes.Buffer
	headerBuf.WriteString(fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status))
	_ = resp.Header.Write(&headerBuf)
	headerBuf.WriteString("\r\n")

	if _, err := clientConn.Write(headerBuf.Bytes()); err != nil {
		return
	}

	// Stream response body directly using pooled 32 KB buffer (Zero-Buffering)
	buf := GetCopyBuffer()
	defer PutCopyBuffer(buf)
	_, _ = io.CopyBuffer(clientConn, resp.Body, *buf)

	ev := auditDecision.ToAuditEvent(h.sessionID, req.Host, 443)
	ev.HTTPStatus = resp.StatusCode
	if h.auditLogger != nil {
		_ = h.auditLogger.Log(ev)
	}
}

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

// executePipeline performs dummy checking, secret injection, PII scrubbing, and upstream round-trip.
func (h *Handler) executePipeline(req *http.Request, start time.Time) (*http.Response, pipelineResult) {
	// Pre-read body up to 10 MB for canary scanning and MCP inspection
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(io.LimitReader(req.Body, 10*1024*1024))
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyBytes), req.Body))
	}

	// 0. Canary Token Exfiltration Check
	searchCorpus := string(bodyBytes) + " " + req.URL.RequestURI()
	for _, vals := range req.Header {
		searchCorpus += " " + strings.Join(vals, " ")
	}
	canaries := canary.FindCanaryTokens(searchCorpus)
	if len(canaries) > 0 {
		rule := h.policyEngine.FindRule(req.Host, req.Method)
		if rule == nil {
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
			res.ErrorMessage = fmt.Sprintf("Blocked attempt to exfiltrate canary token for prompt(s): %s to unauthorized host %s", strings.Join(promptIDs, ", "), req.Host)
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
	}

	dummyToKey := h.vaultInstance.DummyToKeyMap()
	eval := h.policyEngine.EvaluateRequestBody(req, bodyBytes, dummyToKey)

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

	// 1. Perform Dummy Token Substitution if authorized
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

	// 1b. MCP HTTP-SSE message rewriting: rewrite dummy tokens in JSON payload for authorized hosts only
	if len(bodyBytes) > 0 {
		rule := h.policyEngine.FindRule(req.Host, req.Method)
		if rule != nil {
			bodyStr := string(bodyBytes)
			rewrittenStr := mcp.RewritePayloadString(bodyStr, h.vaultInstance)
			if rewrittenStr != bodyStr {
				bodyBytes = []byte(rewrittenStr)
				req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				req.ContentLength = int64(len(bodyBytes))
			}
		}
	}

	// 2. Perform PII Scrubbing on outbound headers
	scrubber := h.policyEngine.Scrubber()
	scrubCount := scrubber.ScrubHeaders(req.Header)

	// 3. Perform PII Scrubbing on outbound request body (bounded to 1 MB limit)
	if len(bodyBytes) > 0 {
		isGzip := strings.Contains(req.Header.Get("Content-Encoding"), "gzip")
		scrubbedBody, bCount, sErr := scrubber.ScrubBody(bodyBytes, isGzip)
		if sErr == nil && bCount > 0 {
			scrubCount += bCount
			req.Body = io.NopCloser(bytes.NewReader(scrubbedBody))
			req.ContentLength = int64(len(scrubbedBody))
		} else {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}
	res.ScrubCount = scrubCount

	// Remove hop-by-hop headers
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")

	// 4. Construct outbound request for upstream
	outReq := req.Clone(req.Context())
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "https"
	}
	if outReq.URL.Host == "" {
		outReq.URL.Host = req.Host
	}
	outReq.RequestURI = "" // Required by net/http Client

	// Ensure Host header matches target host
	if outReq.Host == "" {
		outReq.Host = req.Host
	}

	// Execute outbound request
	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		res.ErrorMessage = fmt.Sprintf("Upstream dial failure: %v", err)
		res.BlockStatus = http.StatusBadGateway
		return nil, res
	}

	// Inspect upstream response for canary regurgitation
	if resp != nil && resp.Body != nil {
		head, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(head), resp.Body))
		respCanaries := canary.FindCanaryTokens(string(head))
		if len(respCanaries) > 0 {
			var promptIDs []string
			seenPrompts := make(map[string]bool)
			for _, c := range respCanaries {
				pid := canary.ExtractPromptID(c)
				if !seenPrompts[pid] {
					seenPrompts[pid] = true
					promptIDs = append(promptIDs, pid)
				}
			}
			if h.auditLogger != nil {
				_ = h.auditLogger.Log(audit.AuditEvent{
					EventID:         fmt.Sprintf("ev_canary_%d", time.Now().UnixNano()),
					SessionID:       h.sessionID,
					Timestamp:       time.Now().UTC(),
					HTTPMethod:      req.Method,
					Host:            req.Host,
					Port:            443,
					Action:          "BLOCK_LEAK",
					HTTPStatus:      resp.StatusCode,
					LatencyMs:       res.LatencyMs,
					Details:         fmt.Sprintf("Upstream response contained canary token for prompt(s): %s", strings.Join(promptIDs, ", ")),
				})
			}
		}
	}

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
