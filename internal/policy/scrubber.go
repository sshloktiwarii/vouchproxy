package policy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var (
	// RFC 5322 compliant practical email pattern
	emailRegex = regexp.MustCompile(`(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
)

// CompiledScrubber holds pre-compiled regex replacements.
type CompiledScrubber struct {
	rules []scrubRule
}

type scrubRule struct {
	name        string
	re          *regexp.Regexp
	replacement string
}

// NewCompiledScrubber compiles all active PII scrubbing rules from configuration.
func NewCompiledScrubber(cfg ScrubbingConfig) (*CompiledScrubber, error) {
	var rules []scrubRule

	if cfg.Emails {
		rules = append(rules, scrubRule{
			name:        "Email",
			re:          emailRegex,
			replacement: "[EMAIL_REDACTED]",
		})
	}

	for _, username := range cfg.Usernames {
		resolved := os.ExpandEnv(username)
		if len(resolved) > 2 { // avoid redacting single characters
			escaped := regexp.QuoteMeta(resolved)
			re, err := regexp.Compile(`\b` + escaped + `\b`)
			if err == nil {
				rules = append(rules, scrubRule{
					name:        "Username:" + username,
					re:          re,
					replacement: "[USER_REDACTED]",
				})
			}
		}
	}

	for _, cr := range cfg.CustomRegex {
		re, err := regexp.Compile(cr.Pattern)
		if err != nil {
			return nil, err
		}
		rules = append(rules, scrubRule{
			name:        cr.Name,
			re:          re,
			replacement: cr.Replacement,
		})
	}

	return &CompiledScrubber{rules: rules}, nil
}

// ScrubText replaces all matched PII in input string and returns the scrubbed string and count.
func (cs *CompiledScrubber) ScrubText(input string) (string, int) {
	if cs == nil || len(cs.rules) == 0 || input == "" {
		return input, 0
	}

	count := 0
	out := input
	for _, rule := range cs.rules {
		matches := rule.re.FindAllStringIndex(out, -1)
		if len(matches) > 0 {
			count += len(matches)
			out = rule.re.ReplaceAllString(out, rule.replacement)
		}
	}
	return out, count
}

// ScrubHeaders inspects and scrubs all outbound HTTP headers, skipping proxy authorization.
func (cs *CompiledScrubber) ScrubHeaders(headers http.Header) int {
	if cs == nil || len(cs.rules) == 0 {
		return 0
	}

	scrubCount := 0
	for key, values := range headers {
		// Do not modify proxy authentication credentials
		if strings.EqualFold(key, "Proxy-Authorization") {
			continue
		}
		for i, val := range values {
			if val != "" {
				scrubbed, count := cs.ScrubText(val)
				if count > 0 {
					values[i] = scrubbed
					scrubCount += count
				}
			}
		}
	}

	return scrubCount
}

// ScrubBody scrubs byte payloads, automatically handling optional gzip compression.
func (cs *CompiledScrubber) ScrubBody(body []byte, isGzip bool) ([]byte, int, error) {
	if cs == nil || len(cs.rules) == 0 || len(body) == 0 {
		return body, 0, nil
	}

	var rawBytes []byte
	if isGzip {
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, 0, err
		}
		rawBytes, err = io.ReadAll(gr)
		_ = gr.Close()
		if err != nil {
			return body, 0, err
		}
	} else {
		rawBytes = body
	}

	text := string(rawBytes)
	scrubbedText, count := cs.ScrubText(text)
	if count == 0 {
		return body, 0, nil
	}

	outBytes := []byte(scrubbedText)
	if isGzip {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, err := gw.Write(outBytes); err != nil {
			return body, 0, err
		}
		if err := gw.Close(); err != nil {
			return body, 0, err
		}
		return buf.Bytes(), count, nil
	}

	return outBytes, count, nil
}
