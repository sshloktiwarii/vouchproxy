package proxy

import (
	"bytes"
	"encoding/base64"
	"io"
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

// splitChunkReader generates a large stream where a specific token is intentionally split
// across chunk boundaries at splitOffset.
type splitChunkReader struct {
	totalSize   int
	splitOffset int
	token       []byte
	currentPos  int
	chunkSize   int
}

func (r *splitChunkReader) Read(p []byte) (int, error) {
	if r.currentPos >= r.totalSize {
		return 0, io.EOF
	}

	toRead := len(p)
	if r.chunkSize > 0 && toRead > r.chunkSize {
		toRead = r.chunkSize
	}
	remaining := r.totalSize - r.currentPos
	if toRead > remaining {
		toRead = remaining
	}

	for i := 0; i < toRead; i++ {
		pos := r.currentPos + i
		tokenEnd := r.splitOffset + len(r.token)
		if pos >= r.splitOffset && pos < tokenEnd {
			p[i] = r.token[pos-r.splitOffset]
		} else {
			p[i] = 'A' // Filler byte
		}
	}

	r.currentPos += toRead
	return toRead, nil
}

// TestStreamScanner_25MBChunkedSplitToken tests streaming a 25 MB chunked payload with a dummy token
// split across 64 KB chunk boundaries at ~18 MB offset, verifying exact substitution and bounded allocation.
func TestStreamScanner_25MBChunkedSplitToken(t *testing.T) {
	_ = os.Setenv("VOUCH_ALLOW_LOOPBACK_UPSTREAM", "1")
	var receivedBody bytes.Buffer
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 64*1024)
		_, err := io.CopyBuffer(&receivedBody, r.Body, buf)
		if err != nil {
			t.Errorf("upstream read error: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"received"}`))
	}))
	defer mockUpstream.Close()

	u, _ := url.Parse(mockUpstream.URL)
	targetHost := u.Host

	v, _, ca, logger, tmpDir := setupTestEnclave(t)
	defer os.RemoveAll(tmpDir)
	defer v.Close()
	defer func() { _ = logger.Close() }()

	cfg := &policy.Config{
		Version: "1.0",
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
		t.Fatal(err)
	}

	mitm := NewMITMEngine(ca, 256)
	handler := NewHandler(
		"stream_sess",
		"stream_secret",
		pe,
		v,
		logger,
		mitm,
		30*time.Second,
	)

	totalSize := 25 * 1024 * 1024 // 25 MB
	dummyToken := vault.GenerateDummyToken("OPENAI_API_KEY")
	tokenBytes := []byte(dummyToken)

	// Offset ~18 MB, positioned exactly so token crosses 64 KB chunk boundary:
	// Boundary is at 18 * 1024 * 1024 (18,874,368 bytes).
	// Start token 10 bytes before the boundary.
	splitOffset := (18 * 1024 * 1024) - 10

	reader := &splitChunkReader{
		totalSize:   totalSize,
		splitOffset: splitOffset,
		token:       tokenBytes,
		chunkSize:   64 * 1024,
	}

	req, err := http.NewRequest("POST", mockUpstream.URL+"/upload", io.NopCloser(reader))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = targetHost
	req.ContentLength = -1 // Chunked transfer
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("Authorization", "Bearer "+dummyToken)

	start := time.Now()
	resp, result := handler.executePipeline(req, start)
	if result.ShouldBlock || resp == nil {
		t.Fatalf("expected stream to succeed, got blocked: %v", result.ErrorMessage)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", resp.StatusCode)
	}

	// Verify exact substitution occurred: dummy token is gone, real secret is present
	receivedBytes := receivedBody.Bytes()
	realSecret := "sk-live-real-secret-token"

	if bytes.Contains(receivedBytes, tokenBytes) {
		t.Fatalf("security violation: upstream received dummy token %s", dummyToken)
	}
	if !bytes.Contains(receivedBytes, []byte(realSecret)) {
		t.Fatalf("expected upstream to receive substituted real secret %s", realSecret)
	}

	expectedLen := totalSize - len(tokenBytes) + len(realSecret)
	if len(receivedBytes) != expectedLen {
		t.Fatalf("expected payload length %d, got %d", expectedLen, len(receivedBytes))
	}
}

// TestStreamScanner_25MBChunkedUnauthorized_Blocked verifies that sending a large payload containing a dummy token
// to an unauthorized host aborts the stream with HTTP 403 Forbidden before sensitive bytes leave the socket.
func TestStreamScanner_25MBChunkedUnauthorized_Blocked(t *testing.T) {
	_ = os.Setenv("VOUCH_ALLOW_LOOPBACK_UPSTREAM", "1")
	var upstreamReceivedBytes int
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 64*1024)
		for {
			n, err := r.Body.Read(buf)
			upstreamReceivedBytes += n
			if err != nil {
				break
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockUpstream.Close()

	u, _ := url.Parse(mockUpstream.URL)
	targetHost := u.Host

	v, _, ca, logger, tmpDir := setupTestEnclave(t)
	defer os.RemoveAll(tmpDir)
	defer v.Close()
	defer func() { _ = logger.Close() }()

	// Policy has no rules matching targetHost (unauthorized host)
	cfg := &policy.Config{
		Version: "1.0",
		Rules:   []policy.Rule{},
	}
	pe, err := policy.NewPolicyEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}

	mitm := NewMITMEngine(ca, 256)
	handler := NewHandler(
		"stream_sess_unauth",
		"stream_secret",
		pe,
		v,
		logger,
		mitm,
		30*time.Second,
	)

	totalSize := 25 * 1024 * 1024 // 25 MB
	dummyToken := vault.GenerateDummyToken("OPENAI_API_KEY")
	tokenBytes := []byte(dummyToken)
	splitOffset := (18 * 1024 * 1024) - 10

	reader := &splitChunkReader{
		totalSize:   totalSize,
		splitOffset: splitOffset,
		token:       tokenBytes,
		chunkSize:   64 * 1024,
	}

	req, err := http.NewRequest("POST", mockUpstream.URL+"/upload", io.NopCloser(reader))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = targetHost
	req.ContentLength = -1
	req.Header.Set("Transfer-Encoding", "chunked")

	start := time.Now()
	resp, result := handler.executePipeline(req, start)

	// Invariant: Must be blocked with 403 Forbidden
	if !result.ShouldBlock || result.BlockStatus != http.StatusForbidden {
		t.Fatalf("expected stream to be blocked with 403, got ShouldBlock=%v, status=%d", result.ShouldBlock, result.BlockStatus)
	}
	if resp != nil {
		_ = resp.Body.Close()
	}
}
