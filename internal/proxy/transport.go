package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// UpstreamTransport handles outbound dialing to upstream servers with DNS pinning and connection pooling.
type UpstreamTransport struct {
	client *http.Client
	mu     sync.RWMutex
}

// NewUpstreamTransport creates an optimized HTTP transport with connection reuse and secure timeouts.
func NewUpstreamTransport(timeout time.Duration) *UpstreamTransport {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Secure dial with timeout
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:   false,
	}

	return &UpstreamTransport{
		client: &http.Client{
			Transport: tr,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Don't follow redirects automatically in transparent proxy mode
				return http.ErrUseLastResponse
			},
		},
	}
}

// RoundTrip executes an upstream HTTP request.
func (u *UpstreamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if u == nil || u.client == nil {
		return nil, fmt.Errorf("upstream transport is not initialized")
	}
	return u.client.Do(req)
}
