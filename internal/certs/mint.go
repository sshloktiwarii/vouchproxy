package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

// MintLeafCertificate dynamically issues an in-memory TLS certificate for targetHost signed by the root CA.
func (ca *CertificateAuthority) MintLeafCertificate(targetHost string) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf serial: %w", err)
	}

	// Clean host (strip port if present)
	host, _, err := net.SplitHostPort(targetHost)
	if err != nil {
		host = targetHost
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"VouchProxy Dynamic MITM"},
			CommonName:   host,
		},
		NotBefore:             now.Add(-10 * time.Minute),
		NotAfter:              now.Add(7 * 24 * time.Hour), // 7-day leaf certificate
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, &priv.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create leaf cert for %s: %w", host, err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{derBytes, ca.Certificate.Raw},
		PrivateKey:  priv,
	}

	return tlsCert, nil
}
