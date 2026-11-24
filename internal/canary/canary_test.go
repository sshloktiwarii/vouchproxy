package canary

import (
	"strings"
	"testing"
	"time"
)

func TestMintAndVerify(t *testing.T) {
	tok, err := Mint("prompt_123", "API_KEY", 10*time.Minute)
	if err != nil {
		t.Fatalf("Mint failed: %v", err)
	}

	parts := strings.Split(tok, "_")
	if len(parts) != 4 {
		t.Fatalf("Expected 4 segments, got %d: %s", len(parts), tok)
	}

	parsed, err := Verify(tok)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if parsed.PromptID != "prompt_123" {
		t.Errorf("Expected prompt_123, got %s", parsed.PromptID)
	}
	if parsed.KeyName != "API_KEY" {
		t.Errorf("Expected API_KEY, got %s", parsed.KeyName)
	}
}

func TestExpiration(t *testing.T) {
	tok, err := Mint("expired_prompt", "KEY", -120*time.Second)
	if err != nil {
		t.Fatalf("Mint failed: %v", err)
	}

	_, err = Verify(tok)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Expected expiration error, got: %v", err)
	}
}

func TestClockSkewTolerance(t *testing.T) {
	// -30s should be within the 60s tolerance window
	tok, err := Mint("skew_prompt", "KEY", -30*time.Second)
	if err != nil {
		t.Fatalf("Mint failed: %v", err)
	}

	_, err = Verify(tok)
	if err != nil {
		t.Fatalf("Expected -30s token to be tolerated by clock skew, got error: %v", err)
	}
}

func TestTamperedSignature(t *testing.T) {
	tok, err := Mint("test_prompt", "KEY", 10*time.Minute)
	if err != nil {
		t.Fatalf("Mint failed: %v", err)
	}

	tampered := tok[:len(tok)-4] + "0000"
	_, err = Verify(tampered)
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("Expected invalid signature error, got: %v", err)
	}
}
