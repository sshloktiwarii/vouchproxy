package vault

import (
	"encoding/json"

	"github.com/sshloktiwarii/vouchproxy/internal/crypto"
)

// SecretBytes represents sensitive credential bytes in memory.
// It implements fmt.Stringer and fmt.GoStringer to strictly prevent accidental
// credential leakage into logs, fmt.Printf calls, error strings, and stack traces.
type SecretBytes []byte

func (s SecretBytes) String() string {
	return "[REDACTED_SECRET]"
}

func (s SecretBytes) GoString() string {
	return "[REDACTED_SECRET]"
}

// Zero securely wipes the underlying memory buffer with zeros.
func (s SecretBytes) Zero() {
	crypto.ZeroBytes(s)
}

// Clone creates a new independent SecretBytes buffer.
func (s SecretBytes) Clone() SecretBytes {
	if s == nil {
		return nil
	}
	c := make(SecretBytes, len(s))
	copy(c, s)
	return c
}

// MarshalJSON marshals the secret bytes as a JSON string for transparent storage compatibility.
func (s SecretBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}

// UnmarshalJSON unmarshals either a JSON string or raw byte array into SecretBytes.
func (s *SecretBytes) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*s = nil
		return nil
	}
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = SecretBytes(str)
		return nil
	}
	var b []byte
	if err := json.Unmarshal(data, &b); err == nil {
		*s = SecretBytes(b)
		return nil
	}
	*s = make(SecretBytes, len(data))
	copy(*s, data)
	return nil
}

// SecretEntry represents metadata and secret payload in vault storage.
type SecretEntry struct {
	KeyName   string      `json:"key_name"`
	Value     SecretBytes `json:"value"`
	CreatedAt int64       `json:"created_at"`
	UpdatedAt int64       `json:"updated_at"`
}

// SecretMetadata represents public safe metadata for a secret.
type SecretMetadata struct {
	KeyName    string `json:"key_name"`
	DummyToken string `json:"dummy_token"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
}
