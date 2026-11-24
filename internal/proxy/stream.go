package proxy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/sshloktiwarii/vouchproxy/internal/canary"
	"github.com/sshloktiwarii/vouchproxy/internal/mcp"
	"github.com/sshloktiwarii/vouchproxy/internal/policy"
	"github.com/sshloktiwarii/vouchproxy/internal/vault"
)

const (
	// StreamChunkSize is the buffer size for streaming body reads (64 KB).
	StreamChunkSize = 64 * 1024

	// DefaultMaxTokenLen is the default rolling window overlap tail (4 KB).
	DefaultMaxTokenLen = 4 * 1024

	// MaxOverlapCeiling is the maximum allowable rolling window overlap tail (64 KB ceiling).
	MaxOverlapCeiling = 64 * 1024
)

var (
	// ErrStreamBlocked is returned when an unauthorized credential or canary is detected mid-stream.
	ErrStreamBlocked = errors.New("vouchproxy: stream blocked due to exfiltration attempt")

	// streamBufferPool recycles 64 KB byte slices to enforce O(1) memory usage across multi-gigabyte uploads.
	streamBufferPool = sync.Pool{
		New: func() any {
			b := make([]byte, StreamChunkSize)
			return &b
		},
	}
)

// GetStreamBuffer retrieves a 64 KB buffer from the pool.
func GetStreamBuffer() *[]byte {
	return streamBufferPool.Get().(*[]byte)
}

// PutStreamBuffer securely wipes and returns a 64 KB buffer to the pool.
func PutStreamBuffer(b *[]byte) {
	if b != nil && len(*b) == StreamChunkSize {
		for i := range *b {
			(*b)[i] = 0
		}
		streamBufferPool.Put(b)
	}
}

// StreamScannerOptions configures the O(1) rolling-window stream scanner reader.
type StreamScannerOptions struct {
	Source        io.ReadCloser
	TargetHost    string
	Method        string
	Rule          *policy.Rule
	DummyToKey    map[string]string
	Vault         *vault.Vault
	Scrubber      *policy.CompiledScrubber
	SessionSecret string
	SessionID     string
	MaxTokenLen   int
}

// StreamScannerReader wraps an incoming request body (io.ReadCloser) with an O(1)
// rolling-window inspection engine. It catches dummy credentials, canary watermarks,
// and PII patterns split across chunk boundaries, rewriting authorized credentials
// and immediately aborting with ErrStreamBlocked if exfiltration is detected.
type StreamScannerReader struct {
	source                  io.ReadCloser
	targetHost              string
	method                  string
	rule                    *policy.Rule
	dummyToKey              map[string]string
	vaultInstance           *vault.Vault
	scrubber                *policy.CompiledScrubber
	sessionSecret           string
	sessionID               string
	overlapLen              int
	tail                    []byte
	outBuf                  []byte
	outOffset               int
	eofReached              bool
	blocked                 bool
	blockReason             string
	substitutionsAlteredLen bool
	mu                      sync.Mutex
}

// NewStreamScannerReader creates a new O(1) rolling-window stream scanner.
func NewStreamScannerReader(opts StreamScannerOptions) *StreamScannerReader {
	overlap := opts.MaxTokenLen
	if overlap <= 0 {
		overlap = DefaultMaxTokenLen
	}
	if overlap > MaxOverlapCeiling {
		overlap = MaxOverlapCeiling
	}

	return &StreamScannerReader{
		source:        opts.Source,
		targetHost:    opts.TargetHost,
		method:        opts.Method,
		rule:          opts.Rule,
		dummyToKey:    opts.DummyToKey,
		vaultInstance: opts.Vault,
		scrubber:      opts.Scrubber,
		sessionSecret: opts.SessionSecret,
		sessionID:     opts.SessionID,
		overlapLen:    overlap,
	}
}

// Read reads processed and sanitized bytes into p, filling from the stream and scanning in 64 KB chunks.
func (s *StreamScannerReader) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.blocked {
		return 0, fmt.Errorf("%w: %s", ErrStreamBlocked, s.blockReason)
	}

	for s.outOffset >= len(s.outBuf) {
		if s.eofReached {
			return 0, io.EOF
		}
		if err := s.fillNextChunk(); err != nil {
			if s.blocked {
				return 0, fmt.Errorf("%w: %s", ErrStreamBlocked, s.blockReason)
			}
			if err == io.EOF && len(s.outBuf) == 0 {
				return 0, io.EOF
			}
			if err != io.EOF {
				return 0, err
			}
		}
	}

	n := copy(p, s.outBuf[s.outOffset:])
	s.outOffset += n
	return n, nil
}

// fillNextChunk reads up to 64 KB from source, prepends the rolling tail, scans for leaks/substitutions,
// retains the new overlap tail, and prepares the safe output buffer.
func (s *StreamScannerReader) fillNextChunk() error {
	bufPtr := GetStreamBuffer()
	defer PutStreamBuffer(bufPtr)
	rawBuf := *bufPtr

	n, readErr := s.source.Read(rawBuf)
	if readErr != nil && readErr != io.EOF {
		return readErr
	}
	if readErr == io.EOF {
		s.eofReached = true
	}
	if n == 0 && s.eofReached {
		if len(s.tail) > 0 {
			processed, blocked, reason, altered := s.processChunk(s.tail)
			if blocked {
				s.blocked = true
				s.blockReason = reason
				return ErrStreamBlocked
			}
			if altered {
				s.substitutionsAlteredLen = true
			}
			s.outBuf = processed
			s.outOffset = 0
			s.tail = nil
			return nil
		}
		return io.EOF
	}

	combined := make([]byte, len(s.tail)+n)
	copy(combined, s.tail)
	copy(combined[len(s.tail):], rawBuf[:n])

	if s.eofReached {
		processed, blocked, reason, altered := s.processChunk(combined)
		if blocked {
			s.blocked = true
			s.blockReason = reason
			return ErrStreamBlocked
		}
		if altered {
			s.substitutionsAlteredLen = true
		}
		s.outBuf = processed
		s.outOffset = 0
		s.tail = nil
		return nil
	}

	// For mid-stream chunks: if total length is less than or equal to overlap, keep buffering
	if len(combined) <= s.overlapLen {
		s.tail = combined
		s.outBuf = nil
		s.outOffset = 0
		return nil
	}

	// First scan the full combined slice for security leaks across the boundary
	processed, blocked, reason, altered := s.processChunk(combined)
	if blocked {
		s.blocked = true
		s.blockReason = reason
		return ErrStreamBlocked
	}
	if altered {
		s.substitutionsAlteredLen = true
	}

	// Emit everything up to len(processed) - overlapLen, retaining overlapLen as the new tail
	cutoff := len(processed) - s.overlapLen
	if cutoff < 0 {
		cutoff = 0
	}

	s.outBuf = processed[:cutoff]
	s.outOffset = 0
	s.tail = make([]byte, len(processed)-cutoff)
	copy(s.tail, processed[cutoff:])

	return nil
}

// processChunk performs canary checking, exfiltration blocking, dummy token substitution, and PII scrubbing.
func (s *StreamScannerReader) processChunk(chunk []byte) ([]byte, bool, string, bool) {
	if len(chunk) == 0 {
		return chunk, false, "", false
	}

	chunkStr := string(chunk)

	// 1. Canary Token & Watermark Exfiltration Check
	canaries := canary.FindCanaryTokens(chunkStr)
	hasWatermark := canary.DetectWatermark(chunkStr, s.sessionSecret)
	if len(canaries) > 0 || hasWatermark {
		if s.rule == nil {
			reason := fmt.Sprintf("Blocked attempt to exfiltrate canary token or session watermark to unauthorized host %s", s.targetHost)
			return nil, true, reason, false
		}
	}

	// 2. Dummy Token Check
	foundDummies := policy.FindDummyTokens(chunkStr, s.dummyToKey)
	if len(foundDummies) > 0 {
		if s.rule == nil {
			reason := fmt.Sprintf("Blocked attempt to exfiltrate dummy token(s) to unauthorized host %s", s.targetHost)
			return nil, true, reason, false
		}

		// Verify each dummy token maps to an allowed secret in this rule
		for _, dummy := range foundDummies {
			keyName := s.dummyToKey[dummy]
			keyPermitted := false
			for _, hr := range s.rule.Headers {
				if hr.Secret == keyName {
					keyPermitted = true
					break
				}
			}
			if !keyPermitted {
				reason := fmt.Sprintf("Blocked attempt to send token %s to unpermitted rule %s", keyName, s.rule.Name)
				return nil, true, reason, false
			}
		}
	}

	// 3. Authorized Secret Substitution
	var altered bool
	origLen := len(chunk)

	if s.rule != nil && s.vaultInstance != nil && len(foundDummies) > 0 {
		rewritten := mcp.RewritePayloadString(chunkStr, s.vaultInstance)
		if rewritten != chunkStr {
			chunkStr = rewritten
			chunk = []byte(chunkStr)
			if len(chunk) != origLen {
				altered = true
			}
		}
	}

	// 4. PII Scrubbing
	if s.scrubber != nil {
		scrubbed, count := s.scrubber.ScrubText(chunkStr)
		if count > 0 {
			chunkStr = scrubbed
			chunk = []byte(chunkStr)
			altered = true
		}
	}

	return chunk, false, "", altered
}

// Close closes the underlying source reader.
func (s *StreamScannerReader) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.source != nil {
		return s.source.Close()
	}
	return nil
}

// Blocked returns whether the stream was aborted due to an exfiltration attempt.
func (s *StreamScannerReader) Blocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blocked
}

// BlockReason returns the human-readable explanation if the stream was blocked.
func (s *StreamScannerReader) BlockReason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blockReason
}

// SubstitutionsAlteredLen returns true if any substitution changed the byte length.
func (s *StreamScannerReader) SubstitutionsAlteredLen() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.substitutionsAlteredLen
}

// EnsureChunkedEncoding deletes Content-Length and sets ContentLength = -1 on the request.
func EnsureChunkedEncoding(req *http.Request) {
	if req != nil {
		req.Header.Del("Content-Length")
		req.ContentLength = -1
	}
}
