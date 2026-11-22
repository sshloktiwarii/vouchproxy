package certs

import (
	"os"
	"testing"
	"time"
)

func TestCerts_CALifecycleAndMinting(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vouch-certs-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// 1. Generate and Save CA
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	certPath, keyPath, err := ca.SaveCA(tmpDir)
	if err != nil {
		t.Fatalf("SaveCA failed: %v", err)
	}

	if !VerifyCACertExists(certPath) {
		t.Fatalf("VerifyCACertExists failed for %s", certPath)
	}

	// 2. Load CA from disk
	loadedCA, err := LoadCA(tmpDir)
	if err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}
	if loadedCA.Certificate.Subject.CommonName != "VouchProxy Local Root CA" {
		t.Fatalf("unexpected CA common name: %s", loadedCA.Certificate.Subject.CommonName)
	}

	// 3. Mint Dynamic Leaf Certificate
	leafCert, err := loadedCA.MintLeafCertificate("api.anthropic.com:443")
	if err != nil {
		t.Fatalf("MintLeafCertificate failed: %v", err)
	}
	if leafCert == nil || len(leafCert.Certificate) == 0 {
		t.Fatal("minted certificate has empty certificate chain")
	}

	// 4. Test LRU Cache
	cache := NewCertCache(2)
	cache.Set("api.openai.com", leafCert, time.Now().Add(48*time.Hour))
	cache.Set("api.github.com", leafCert, time.Now().Add(48*time.Hour))

	if _, found := cache.Get("api.openai.com"); !found {
		t.Fatal("expected api.openai.com in cache")
	}

	// Eviction test
	cache.Set("api.anthropic.com", leafCert, time.Now().Add(48*time.Hour))
	if _, found := cache.Get("api.openai.com"); found {
		t.Fatal("expected api.openai.com to be evicted by LRU capacity limit")
	}

	// 5. Test TrustEnvironment
	envMap := TrustEnvironment(certPath)
	if envMap["SSL_CERT_FILE"] != certPath {
		t.Fatalf("expected SSL_CERT_FILE=%s, got %s", certPath, envMap["SSL_CERT_FILE"])
	}
	if envMap["NODE_EXTRA_CA_CERTS"] != certPath {
		t.Fatalf("expected NODE_EXTRA_CA_CERTS=%s, got %s", certPath, envMap["NODE_EXTRA_CA_CERTS"])
	}

	_ = keyPath
}
