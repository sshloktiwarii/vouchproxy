package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/vault"
)

// CertificateAuthority holds the Root CA certificate and private key.
type CertificateAuthority struct {
	Certificate *x509.Certificate
	PrivateKey  *ecdsa.PrivateKey
	CertPEM     []byte
	KeyPEM      []byte
}

// GenerateCA creates a new self-signed Root Certificate Authority valid for 10 years.
func GenerateCA() (*CertificateAuthority, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"VouchProxy Sovereign Authority"},
			OrganizationalUnit: []string{"Local Security Enclave"},
			CommonName:         "VouchProxy Local Root CA",
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privDer, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CA private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDer})

	return &CertificateAuthority{
		Certificate: cert,
		PrivateKey:  priv,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// SaveCA persists ca.crt and ca.key to dir with strict 0600 permissions.
func (ca *CertificateAuthority) SaveCA(dir string) (certPath, keyPath string, err error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", fmt.Errorf("failed to create CA directory: %w", err)
	}

	certPath = filepath.Join(dir, "ca.crt")
	keyPath = filepath.Join(dir, "ca.key")

	if err := os.WriteFile(certPath, ca.CertPEM, 0644); err != nil {
		return "", "", fmt.Errorf("failed to write CA cert: %w", err)
	}

	if err := vault.AtomicWriteFile(keyPath, ca.KeyPEM); err != nil {
		return "", "", fmt.Errorf("failed to write CA key: %w", err)
	}

	return certPath, keyPath, nil
}

// LoadCA loads and verifies ca.crt and ca.key from dir.
func LoadCA(dir string) (*CertificateAuthority, error) {
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	if err := vault.ValidateFilePermissions(keyPath); err != nil {
		return nil, err
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA private key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("failed to decode CA key PEM")
	}

	priv, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA EC private key: %w", err)
	}

	return &CertificateAuthority{
		Certificate: cert,
		PrivateKey:  priv,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}
