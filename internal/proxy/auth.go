package proxy

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
)

// ValidateProxyAuth verifies that the incoming request contains a valid Proxy-Authorization header
// matching the per-session cryptographic secret token.
func ValidateProxyAuth(r *http.Request, sessionSecret string) bool {
	if sessionSecret == "" {
		return true // Auth not required if sessionSecret is empty
	}

	authHeader := r.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		return false
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return false
	}

	scheme := strings.ToLower(parts[0])
	credential := strings.TrimSpace(parts[1])

	switch scheme {
	case "bearer":
		return subtle.ConstantTimeCompare([]byte(credential), []byte(sessionSecret)) == 1
	case "basic":
		decoded, err := base64.StdEncoding.DecodeString(credential)
		if err != nil {
			return false
		}
		userPass := strings.SplitN(string(decoded), ":", 2)
		if len(userPass) == 2 {
			// Accept either username or password matching session secret
			matchedUser := subtle.ConstantTimeCompare([]byte(userPass[0]), []byte(sessionSecret)) == 1
			matchedPass := subtle.ConstantTimeCompare([]byte(userPass[1]), []byte(sessionSecret)) == 1
			return matchedUser || matchedPass
		}
		return false
	default:
		return false
	}
}
