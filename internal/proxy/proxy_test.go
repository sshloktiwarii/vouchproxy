package proxy

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/audit"
	"github.com/sshloktiwarii/vouchproxy/internal/certs"
	"github.com/sshloktiwarii/vouchproxy/internal/policy"
	"github.com/sshloktiwarii/vouchproxy/internal/vault"
)

func setupTestEnclave(t testing.TB) (*vault.Vault, *policy.PolicyEngine, *certs.CertificateAuthority, *audit.Logger, string) {
	tmpDir, err := os.MkdirTemp("", "vouch-proxy-test-*")
	if err != nil {
		t.Fatal(err)
	}

	vaultPath := filepath.Join(tmpDir, "vault.enc")
	v, err := vault.Create(vaultPath, []byte("test-passphrase-123"))
	if err != nil {
		t.Fatal(err)
	}

	if err := v.Set("OPENAI_API_KEY", []byte("sk-live-real-secret-token")); err != nil {
		t.Fatal(err)
	}

	cfg := policy.DefaultConfig()
	pe, err := policy.NewPolicyEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ca, err := certs.GenerateCA()
	if err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(tmpDir, "audit.jsonl")
	logger, err := audit.NewLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}

	return v, pe, ca, logger, tmpDir
}

func TestProxyAuthValidation(t *testing.T) {
	sessionSecret := "test-secret-token-12345"

	// 1. Missing Auth Header -> false
	req1 := httptest.NewRequest("GET", "http://api.openai.com", nil)
	if ValidateProxyAuth(req1, sessionSecret) {
		t.Fatal("expected missing auth to fail")
	}

	// 2. Invalid Bearer Token -> false
	req2 := httptest.NewRequest("GET", "http://api.openai.com", nil)
	req2.Header.Set("Proxy-Authorization", "Bearer wrong-token")
	if ValidateProxyAuth(req2, sessionSecret) {
		t.Fatal("expected wrong token to fail")
	}

	// 3. Valid Bearer Token -> true
	req3 := httptest.NewRequest("GET", "http://api.openai.com", nil)
	req3.Header.Set("Proxy-Authorization", "Bearer "+sessionSecret)
	if !ValidateProxyAuth(req3, sessionSecret) {
		t.Fatal("expected valid bearer token to succeed")
	}

	// 4. Valid Basic Auth -> true
	req4 := httptest.NewRequest("GET", "http://api.openai.com", nil)
	basicVal := base64.StdEncoding.EncodeToString([]byte("session:" + sessionSecret))
	req4.Header.Set("Proxy-Authorization", "Basic "+basicVal)
	if !ValidateProxyAuth(req4, sessionSecret) {
		t.Fatal("expected valid basic auth to succeed")
	}
}

func TestBufferPools(t *testing.T) {
	buf := GetCopyBuffer()
	if len(*buf) != BufferSize {
		t.Fatalf("expected buffer size %d, got %d", BufferSize, len(*buf))
	}
	PutCopyBuffer(buf)

	bBuf := GetBytesBuffer()
	bBuf.WriteString("hello world")
	PutBytesBuffer(bBuf)

	bBuf2 := GetBytesBuffer()
	if bBuf2.Len() != 0 {
		t.Fatalf("expected reset buffer with 0 len, got %d", bBuf2.Len())
	}
	PutBytesBuffer(bBuf2)
}

// BenchmarkProxyPipeline benchmarks the core request processing, policy evaluation,
// dummy token substitution, and PII scrubbing hot path (< 1 ms requirement).
func BenchmarkProxyPipeline(b *testing.B) {
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockUpstream.Close()

	u, _ := url.Parse(mockUpstream.URL)
	targetHost := u.Host

	v, _, ca, logger, tmpDir := setupTestEnclave(b)
	defer os.RemoveAll(tmpDir)
	defer v.Close()
	defer func() { _ = logger.Close() }()

	cfg := &policy.Config{
		Version: "1.0",
		Scrubbing: policy.ScrubbingConfig{
			Emails: true,
		},
		Rules: []policy.Rule{
			{
				Name:      "Mock API",
				Host:      targetHost,
				MatchType: "exact",
				Headers: []policy.HeaderRule{
					{
						Name:       "Authorization",
						Format:     "Bearer {{secret}}",
						Secret:     "OPENAI_API_KEY",
						DummyMatch: "VP_OPENAI_API_KEY_DUMMY_*",
					},
				},
				AllowedMethods: []string{"POST", "GET"},
			},
		},
	}
	pe, err := policy.NewPolicyEngine(cfg)
	if err != nil {
		b.Fatal(err)
	}

	mitm := NewMITMEngine(ca, 256)
	handler := NewHandler(
		"bench_sess",
		"secret_123",
		pe,
		v,
		logger,
		mitm,
		10*time.Second,
	)

	dummyToken := vault.GenerateDummyToken("OPENAI_API_KEY")
	bodyPayload := []byte(`{"model": "gpt-4", "prompt": "Hello test dev@company.com"}`)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", mockUpstream.URL+"/v1/chat", bytes.NewReader(bodyPayload))
		req.Host = targetHost
		req.Header.Set("Authorization", "Bearer "+dummyToken)
		req.Header.Set("User-Agent", "TestAgent/1.0 dev@company.com")

		// Execute internal pipeline
		start := time.Now()
		resp, result := handler.executePipeline(req, start)
		if result.ShouldBlock || resp == nil {
			b.Fatal("unexpected block in benchmark")
		}
		_ = resp.Body.Close()
	}
}
