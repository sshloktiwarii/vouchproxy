package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// UpstreamTransport handles outbound dialing to upstream servers with DNS pinning, SSRF filtering, and connection pooling.
type UpstreamTransport struct {
	client *http.Client
	mu     sync.RWMutex
}

// isProhibitedIP checks whether an IP is private, loopback, link-local, or unspecified.
func isProhibitedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() {
		return os.Getenv("VOUCH_ALLOW_LOOPBACK_UPSTREAM") != "1"
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return os.Getenv("VOUCH_ALLOW_LOOPBACK_UPSTREAM") != "1"
	}
	// AWS / GCP / Azure metadata endpoint: 169.254.169.254
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return true
	}
	return false
}

// NewUpstreamTransport creates an optimized HTTP transport with connection reuse, SSRF defense, and secure timeouts.
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
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
				port = "443"
			}

			// Validate and pin IP address to prevent DNS rebinding and SSRF
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve host %s: %w", host, err)
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("no IP addresses found for host %s", host)
			}

			var pinnedIP net.IP
			for _, ipAddr := range ips {
				if !isProhibitedIP(ipAddr.IP) {
					pinnedIP = ipAddr.IP
					break
				}
			}

			if pinnedIP == nil {
				return nil, fmt.Errorf("SSRF protection blocked dial to %s (resolves to restricted IP: %s)", host, ips[0].IP.String())
			}

			pinnedAddr := net.JoinHostPort(pinnedIP.String(), port)
			return dialer.DialContext(ctx, network, pinnedAddr)
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
