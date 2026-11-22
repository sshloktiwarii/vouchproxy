package vault

import (
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
	c := make(SecretBytes, len(s))
	copy(c, s)
	return c
}

// SecretEntry represents metadata and secret payload in vault storage.
type SecretEntry struct {
	KeyName   string `json:"key_name"`
	Value     string `json:"value"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// SecretMetadata represents public safe metadata for a secret.
type SecretMetadata struct {
	KeyName    string `json:"key_name"`
	DummyToken string `json:"dummy_token"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
}
