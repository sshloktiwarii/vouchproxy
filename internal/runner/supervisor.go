package runner

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/sshloktiwarii/vouchproxy/internal/certs"
)

// SubprocessConfig defines parameters for launching a monitored child agent command.
type SubprocessConfig struct {
	Command       []string
	ProxyURL      string
	CACertPath    string
	DummyTokens   map[string]string // KEY_NAME -> DummyTokenValue
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
	ExtraEnv      map[string]string
}

// BuildChildEnvironment generates the sanitized environment variable slice.
func BuildChildEnvironment(cfg SubprocessConfig) []string {
	// Start with host environment, stripping existing proxy configurations
	rawEnv := os.Environ()
	filtered := make([]string, 0, len(rawEnv)+30)

	proxyBlacklist := map[string]bool{
		"http_proxy": true, "https_proxy": true, "all_proxy": true, "no_proxy": true,
		"HTTP_PROXY": true, "HTTPS_PROXY": true, "ALL_PROXY": true, "NO_PROXY": true,
	}

	for _, kv := range rawEnv {
		eqIdx := strings.IndexByte(kv, '=')
		if eqIdx == -1 {
			continue
		}
		key := kv[:eqIdx]
		if proxyBlacklist[key] {
			continue
		}
		// Also strip existing keys that match our managed vault dummy keys
		if _, exists := cfg.DummyTokens[key]; exists {
			continue
		}
		filtered = append(filtered, kv)
	}

	// 1. Inject Proxy Envs (both lowercase and uppercase for cross-runtime parity)
	filtered = append(filtered,
		fmt.Sprintf("HTTP_PROXY=%s", cfg.ProxyURL),
		fmt.Sprintf("http_proxy=%s", cfg.ProxyURL),
		fmt.Sprintf("HTTPS_PROXY=%s", cfg.ProxyURL),
		fmt.Sprintf("https_proxy=%s", cfg.ProxyURL),
		fmt.Sprintf("ALL_PROXY=%s", cfg.ProxyURL),
		fmt.Sprintf("all_proxy=%s", cfg.ProxyURL),
		"NO_PROXY=",
		"no_proxy=",
	)

	// 2. Inject Certificate Authority Trust Envs
	caEnvs := certs.TrustEnvironment(cfg.CACertPath)
	for k, v := range caEnvs {
		filtered = append(filtered, fmt.Sprintf("%s=%s", k, v))
	}

	// 3. Inject Dummy Placeholder Tokens (NEVER the real credentials)
	for keyName, dummyToken := range cfg.DummyTokens {
		filtered = append(filtered, fmt.Sprintf("%s=%s", keyName, dummyToken))
	}

	// 4. Inject Extra Envs
	for k, v := range cfg.ExtraEnv {
		filtered = append(filtered, fmt.Sprintf("%s=%s", k, v))
	}

	return filtered
}

// PrepareCommand constructs an *exec.Cmd with the proper environment and stdio bindings.
func PrepareCommand(cfg SubprocessConfig) (*exec.Cmd, error) {
	if len(cfg.Command) == 0 {
		return nil, fmt.Errorf("command cannot be empty")
	}

	cmd := exec.Command(cfg.Command[0], cfg.Command[1:]...)
	cmd.Env = BuildChildEnvironment(cfg)
	cmd.Stdin = cfg.Stdin
	cmd.Stdout = cfg.Stdout
	cmd.Stderr = cfg.Stderr

	return cmd, nil
}
