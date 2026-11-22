package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/audit"
	"github.com/sshloktiwarii/vouchproxy/internal/certs"
	"github.com/sshloktiwarii/vouchproxy/internal/crypto"
	"github.com/sshloktiwarii/vouchproxy/internal/policy"
	"github.com/sshloktiwarii/vouchproxy/internal/vault"
)

// ProxyOptions holds initialization settings for ProxyServer.
type ProxyOptions struct {
	SessionID     string
	Config        *policy.Config
	PolicyEngine  *policy.PolicyEngine
	Vault         *vault.Vault
	AuditLogger   *audit.Logger
	CA            *certs.CertificateAuthority
	SessionSecret string
	Timeout       time.Duration
}

// ServerOptions is an alias for ProxyOptions.
type ServerOptions = ProxyOptions

// ProxyServer represents the local VouchProxy HTTP/HTTPS CONNECT server.
type ProxyServer struct {
	listener      net.Listener
	httpServer    *http.Server
	sessionID     string
	sessionSecret string
	port          int
	mu            sync.Mutex
	running       bool
}

// Server is an alias for ProxyServer.
type Server = ProxyServer

// NewProxyServer spins up an ephemeral localhost listener on 127.0.0.1:0.
func NewProxyServer(opts ProxyOptions) (*ProxyServer, error) {
	if opts.SessionSecret == "" {
		sec, err := crypto.RandomHex(32)
		if err != nil {
			return nil, fmt.Errorf("failed to generate session secret: %w", err)
		}
		opts.SessionSecret = sec
	}

	sessionID := opts.SessionID
	if sessionID == "" {
		sessionID, _ = crypto.RandomHex(16)
	}

	// Strictly bind to IPv4 loopback 127.0.0.1
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to bind to 127.0.0.1 loopback: %w", err)
	}

	tcpAddr := ln.Addr().(*net.TCPAddr)
	port := tcpAddr.Port

	cacheSize := 256
	if opts.Config != nil && opts.Config.Settings.MitmCacheSize > 0 {
		cacheSize = opts.Config.Settings.MitmCacheSize
	}

	timeout := 30 * time.Second
	if opts.Config != nil && opts.Config.Settings.RequestTimeoutSeconds > 0 {
		timeout = time.Duration(opts.Config.Settings.RequestTimeoutSeconds) * time.Second
	}

	mitm := NewMITMEngine(opts.CA, cacheSize)
	handler := NewHandler(
		sessionID,
		opts.SessionSecret,
		opts.PolicyEngine,
		opts.Vault,
		opts.AuditLogger,
		mitm,
		timeout,
	)

	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	s := &ProxyServer{
		listener:      ln,
		httpServer:    srv,
		sessionID:     sessionID,
		sessionSecret: opts.SessionSecret,
		port:          port,
	}

	return s, nil
}

// NewServer is an alias for NewProxyServer.
func NewServer(opts ServerOptions) (*Server, error) {
	return NewProxyServer(opts)
}

// Start begins serving requests asynchronously.
func (s *ProxyServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.running = true
	go func() {
		_ = s.httpServer.Serve(s.listener)
	}()
	return nil
}

// Port returns the assigned ephemeral port.
func (s *ProxyServer) Port() int {
	return s.port
}

// URL returns the full proxy address URL (e.g. http://127.0.0.1:54321).
func (s *ProxyServer) URL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", s.port)
}

// ProxyURL is an alias for URL.
func (s *ProxyServer) ProxyURL() string {
	return s.URL()
}

// SessionSecret returns the active session authentication secret.
func (s *ProxyServer) SessionSecret() string {
	return s.sessionSecret
}

// Close gracefully stops the server and closes the loopback listener.
func (s *ProxyServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}
	s.running = false

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_ = s.httpServer.Shutdown(ctx)
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
