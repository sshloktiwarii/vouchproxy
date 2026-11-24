package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/audit"
	"github.com/sshloktiwarii/vouchproxy/internal/policy"
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
		auditLogger:   logger,
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
		return
	}
	defer tlsClientConn.Close()

	// Handle decrypted HTTP requests within the TLS tunnel
	reader := bufio.NewReader(tlsClientConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			break
		}

		start := time.Now()
		req.URL.Scheme = "https"
		req.URL.Host = targetHost
		req.Host = targetHost

		h.processAndForward(tlsClientConn, req, start)
	}
}

// handleHTTP proxies standard plaintext HTTP requests with secret injection and PII scrubbing.
func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	resp, auditEvent := h.executePipeline(r, start)

	if auditEvent.ShouldBlock {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(auditEvent.BlockStatus)
		_, _ = w.Write([]byte(auditEvent.ErrorMessage))
		if h.auditLogger != nil {
			_ = h.auditLogger.Log(auditEvent.ToAuditEvent(h.sessionID, r.Host, 80))
		}
		return
	}

	if resp == nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy upstream response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream upstream response body using pooled buffer
	buf := GetCopyBuffer()
	defer PutCopyBuffer(buf)
	_, _ = io.CopyBuffer(w, resp.Body, *buf)

	auditEv := auditEvent.ToAuditEvent(h.sessionID, r.Host, 80)
	auditEv.HTTPStatus = resp.StatusCode
	if h.auditLogger != nil {
		_ = h.auditLogger.Log(auditEv)
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
