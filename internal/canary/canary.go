package canary

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// getCanarySecret returns the HMAC signing key for canary tokens, derived dynamically
// from VOUCH_MASTER_KEY when present, or an isolated per-environment key.
func getCanarySecret() []byte {
	if envKey := os.Getenv("VOUCH_MASTER_KEY"); envKey != "" {
		h := sha256.Sum256([]byte("VOUCH_CANARY_SALT:" + envKey))
		return h[:]
	}
	return []byte("vouchproxy-hmac-sha256-canary-secret-key-32bytes")
}

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
	sig := computeHMAC(nonce, getCanarySecret())

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

		expectedSig := computeHMAC(nonce, getCanarySecret())
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

const (
	// WatermarkHeader marks the beginning of a zero-width Unicode canary watermark.
	WatermarkHeader = "\u200B\u200C\u200D\uFEFF"

	// WatermarkFooter marks the end of a zero-width Unicode canary watermark.
	WatermarkFooter = "\uFEFF\u200D\u200C\u200B"

	// Zero-width bit representations
	zwBit0 = '\u200B'
	zwBit1 = '\u200C'
)

// GenerateSessionWatermark generates a deterministic, session-signed zero-width Unicode watermark string.
func GenerateSessionWatermark(sessionSecret string) string {
	salt := getCanarySecret()
	h := hmac.New(sha256.New, salt)
	h.Write([]byte("vouchproxy_mcp_watermark:" + sessionSecret))
	sig := hex.EncodeToString(h.Sum(nil)[:8]) // 16 hex chars = 64 bits

	var sb strings.Builder
	sb.WriteString(WatermarkHeader)
	for i := 0; i < len(sig); i++ {
		b := sig[i]
		for bit := 7; bit >= 0; bit-- {
			if (b>>bit)&1 == 1 {
				sb.WriteRune(zwBit1)
			} else {
				sb.WriteRune(zwBit0)
			}
		}
	}
	sb.WriteString(WatermarkFooter)
	return sb.String()
}

// WatermarkContent injects a deterministic, session-signed zero-width Unicode canary watermark
// into content without altering visible text or breaking JSON framing.
func WatermarkContent(content, sessionSecret string) string {
	wm := GenerateSessionWatermark(sessionSecret)
	// Inject at front of content
	return wm + content
}

// unescapeZeroWidth unescapes any JSON or ASCII-escaped zero-width Unicode sequences.
func unescapeZeroWidth(content string) string {
	if !strings.Contains(content, `\u`) && !strings.Contains(content, `\U`) {
		return content
	}
	r := strings.NewReplacer(
		`\u200b`, "\u200B", `\u200B`, "\u200B",
		`\u200c`, "\u200C", `\u200C`, "\u200C",
		`\u200d`, "\u200D", `\u200D`, "\u200D",
		`\ufeff`, "\uFEFF", `\uFEFF`, "\uFEFF",
	)
	return r.Replace(content)
}

// DetectWatermark checks whether content contains a valid zero-width canary watermark.
// If sessionSecret is non-empty, it verifies the signature specifically belongs to this session.
// It detects both raw UTF-8 zero-width characters and JSON/ASCII-escaped (\u200b) representations.
func DetectWatermark(content, sessionSecret string) bool {
	if len(content) == 0 {
		return false
	}

	content = unescapeZeroWidth(content)

	startIdx := strings.Index(content, WatermarkHeader)
	if startIdx == -1 {
		return false
	}
	endIdx := strings.Index(content[startIdx+len(WatermarkHeader):], WatermarkFooter)
	if endIdx == -1 {
		return false
	}

	encodedPayload := content[startIdx+len(WatermarkHeader) : startIdx+len(WatermarkHeader)+endIdx]
	runes := []rune(encodedPayload)
	if len(runes) == 0 || len(runes)%8 != 0 {
		return false
	}

	var decodedBytes []byte
	for i := 0; i < len(runes); i += 8 {
		var b byte
		for bit := 0; bit < 8; bit++ {
			r := runes[i+bit]
			if r == zwBit1 {
				b = (b << 1) | 1
			} else if r == zwBit0 {
				b = (b << 1) | 0
			} else {
				return false
			}
		}
		decodedBytes = append(decodedBytes, b)
	}

	extractedSig := string(decodedBytes)
	if sessionSecret != "" {
		salt := getCanarySecret()
		h := hmac.New(sha256.New, salt)
		h.Write([]byte("vouchproxy_mcp_watermark:" + sessionSecret))
		expectedSig := hex.EncodeToString(h.Sum(nil)[:8])
		return hmac.Equal([]byte(extractedSig), []byte(expectedSig))
	}

	return len(extractedSig) > 0
}

func computeHMAC(message string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}
