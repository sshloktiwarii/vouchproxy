package policy

import (
	"net"
	"strings"
)

// MatchHost checks whether requestHost matches pattern (exact or wildcard).
// Examples:
// - exact: "api.openai.com" matches "api.openai.com"
// - wildcard: "*.github.com" matches "api.github.com" and "raw.github.com"
func MatchHost(pattern, matchType, requestHost string) bool {
	// Strip port from request host if present
	host, _, err := net.SplitHostPort(requestHost)
	if err != nil {
		host = requestHost
	}

	pHost, _, err := net.SplitHostPort(pattern)
	if err == nil {
		pattern = pHost
	}

	host = strings.ToLower(strings.TrimSpace(host))
	pattern = strings.ToLower(strings.TrimSpace(pattern))

	switch strings.ToLower(matchType) {
	case "wildcard":
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // e.g. ".github.com"
			return strings.HasSuffix(host, suffix) && host != pattern[2:]
		}
		if pattern == "*" {
			return true
		}
		return host == pattern
	default: // exact match
		return host == pattern
	}
}

// NormalizeHost cleans a hostname by removing ports and converting to lowercase.
func NormalizeHost(rawHost string) string {
	host, _, err := net.SplitHostPort(rawHost)
	if err != nil {
		host = rawHost
	}
	return strings.ToLower(strings.TrimSpace(host))
}
