package certs

import (
	"os"
)

// TrustEnvironment returns the environment variable map required to ensure
// child runtimes (Node.js, Python, curl, Go, Rust, AWS CLI) trust the local Root CA.
func TrustEnvironment(caCertPath string) map[string]string {
	return map[string]string{
		"SSL_CERT_FILE":        caCertPath,
		"REQUESTS_CA_BUNDLE":   caCertPath,
		"CURL_CA_BUNDLE":       caCertPath,
		"NODE_EXTRA_CA_CERTS":  caCertPath,
		"CARGO_HTTP_CAINFO":    caCertPath,
		"AWS_CA_BUNDLE":        caCertPath,
		"GIT_SSL_CAINFO":       caCertPath,
		"DENO_TLS_CA_STORE":    "system," + caCertPath,
	}
}

// VerifyCACertExists verifies the root CA file exists and is readable.
func VerifyCACertExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Size() > 0
}
