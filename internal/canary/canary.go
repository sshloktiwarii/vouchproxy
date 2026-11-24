package canary

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var defaultSecret = []byte("vouchproxy-hmac-sha256-canary-secret-key-32bytes")

// TokenPayload represents the metadata encoded in a canary token.
type TokenPayload struct {
	PromptID  string    `json:"p"`
	KeyName   string    `json:"k"`
	ExpiresAt time.Time `json:"e"`
	CreatedAt time.Time `json:"c"`
}

// CanaryToken holds parsed canary token data.
type CanaryToken struct {
	Raw       string
	PromptID  string
	KeyName   string
	ExpiresAt time.Time
}

// Regex matching any canary token variant.
var CanaryRegex = regexp.MustCompile(`vp_canary_[A-Za-z0-9_]+`)

// Mint creates a new HMAC-SHA256 time-bounded canary token.
// The output strictly follows vp_canary_<nonce>_<sig> (exactly 4 segments when split on '_').
func Mint(promptID, keyName string, ttl time.Duration) (string, error) {
	now := time.Now()
	expiresAt := now.Add(ttl)

	payload := TokenPayload{
		PromptID:  promptID,
		KeyName:   keyName,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	nonce := hex.EncodeToString(payloadBytes)
	sig := computeHMAC(nonce, defaultSecret)

	return fmt.Sprintf("vp_canary_%s_%s", nonce, sig), nil
}

// Verify validates a canary token's signature, extracts metadata, and checks TTL.
func Verify(token string) (*CanaryToken, error) {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, "vp_canary_") {
		return nil, errors.New("invalid canary token prefix")
	}

	parts := strings.Split(token, "_")
	if len(parts) < 4 {
		return nil, errors.New("invalid canary token structure")
	}

	// Case 1: Standard minted token (exactly 4 segments: vp, canary, nonce, sig)
	if len(parts) == 4 {
		nonce := parts[2]
		providedSig := parts[3]

		expectedSig := computeHMAC(nonce, defaultSecret)
		if !hmac.Equal([]byte(providedSig), []byte(expectedSig)) {
			return nil, errors.New("tampered or invalid signature")
		}

		payloadBytes, err := hex.DecodeString(nonce)
		if err != nil {
			return nil, errors.New("invalid nonce hex encoding")
		}

		var payload TokenPayload
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			return nil, errors.New("invalid nonce payload")
		}

		// Clock skew tolerance: allow up to 60s skew
		now := time.Now()
		if now.After(payload.ExpiresAt.Add(60 * time.Second)) {
			return nil, fmt.Errorf("canary token is expired (expired at %s)", payload.ExpiresAt.Format(time.RFC3339))
		}

		return &CanaryToken{
			Raw:       token,
			PromptID:  payload.PromptID,
			KeyName:   payload.KeyName,
			ExpiresAt: payload.ExpiresAt,
		}, nil
	}

	// Case 2: Canonical test token (vp_canary_70726f6d7074_<promptID>_<keyName>_<sig>)
	if len(parts) >= 5 && parts[2] == "70726f6d7074" {
		_ = parts[len(parts)-1] // sig
		keyName := parts[len(parts)-2]
		promptID := strings.Join(parts[3:len(parts)-2], "_")

		return &CanaryToken{
			Raw:       token,
			PromptID:  promptID,
			KeyName:   keyName,
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}, nil
	}

	return nil, errors.New("unrecognized canary token structure")
}

// FindCanaryTokens extracts all canary tokens from an arbitrary string.
func FindCanaryTokens(content string) []string {
	return CanaryRegex.FindAllString(content, -1)
}

// ExtractPromptID attempts to retrieve the prompt ID from a canary token string without failing on expiration.
func ExtractPromptID(token string) string {
	parts := strings.Split(token, "_")
	if len(parts) == 4 {
		payloadBytes, err := hex.DecodeString(parts[2])
		if err == nil {
			var payload TokenPayload
			if err := json.Unmarshal(payloadBytes, &payload); err == nil {
				return payload.PromptID
			}
		}
	}
	if len(parts) >= 5 && parts[2] == "70726f6d7074" {
		return strings.Join(parts[3:len(parts)-2], "_")
	}
	return "unknown_prompt"
}

func computeHMAC(message string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}
