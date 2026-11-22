package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/certs"
)

// MITMEngine handles dynamic TLS interception, SNI validation, and on-the-fly leaf cert generation.
type MITMEngine struct {
	ca    *certs.CertificateAuthority
	cache *certs.CertCache
}

// NewMITMEngine initializes the MITM engine with the Root CA and a bounded 256-item LRU cache.
func NewMITMEngine(ca *certs.CertificateAuthority, cacheSize int) *MITMEngine {
	if cacheSize <= 0 {
		cacheSize = 256
	}
	return &MITMEngine{
		ca:    ca,
		cache: certs.NewCertCache(cacheSize),
	}
}

// GetCertificateCallback returns a tls.Config.GetCertificate handler that mints or fetches ECDSA P-256 leaf certs.
func (m *MITMEngine) GetCertificateCallback(expectedHost string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		sniHost := strings.ToLower(hello.ServerName)
		normExpected := strings.ToLower(expectedHost)
		if h, _, err := net.SplitHostPort(normExpected); err == nil {
			normExpected = h
		}

		// Security Check: If SNI is provided, it must match or be a subdomain of expected host
		if sniHost != "" && sniHost != normExpected {
			return nil, fmt.Errorf("TLS SNI mismatch: client SNI %q != CONNECT target %q", sniHost, normExpected)
		}

		target := sniHost
		if target == "" {
			target = normExpected
		}

		// Check LRU cache
		if cert, found := m.cache.Get(target); found {
			return cert, nil
		}

		// Mint dynamic ECDSA P-256 leaf certificate
		cert, err := m.ca.MintLeafCertificate(target)
		if err != nil {
			return nil, fmt.Errorf("failed to mint leaf cert for %s: %w", target, err)
		}

		// Cache for 7 days
		m.cache.Set(target, cert, time.Now().Add(7*24*time.Hour))
		return cert, nil
	}
}
