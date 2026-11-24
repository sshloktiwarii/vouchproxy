package policy

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the complete vouch.yaml configuration structure.
type Config struct {
	Version     string            `yaml:"version"`
	Settings    SettingsConfig    `yaml:"settings"`
	Canary      CanaryConfig      `yaml:"canary,omitempty"`
	Keyring     KeyringConfig     `yaml:"keyring,omitempty"`
	SystemTrust SystemTrustConfig `yaml:"system_trust,omitempty"`
	MCP         MCPConfig         `yaml:"mcp,omitempty"`
	Scrubbing   ScrubbingConfig   `yaml:"scrubbing"`
	Rules       []Rule            `yaml:"rules"`
}

// CanaryConfig defines decoy canary token detection rules.
type CanaryConfig struct {
	Enabled       bool   `yaml:"enabled"`
	DefaultTTL    string `yaml:"default_ttl"`
	BlockOnDetect bool   `yaml:"block_on_detect"`
}

// KeyringConfig defines OS keychain persistence options.
type KeyringConfig struct {
	Enabled bool   `yaml:"enabled"`
	Service string `yaml:"service"`
}

// SystemTrustConfig defines OS trust store registration flags.
type SystemTrustConfig struct {
	Enabled bool `yaml:"enabled"`
}

// MCPConfig defines Model Context Protocol firewall parameters.
type MCPConfig struct {
	Enabled       bool     `yaml:"enabled"`
	AutoWatermark *bool    `yaml:"auto_watermark,omitempty"`
	BlockedPaths  []string `yaml:"blocked_paths"`
}

// IsAutoWatermarkEnabled returns true if auto watermarking is enabled (default true when MCP is active).
func (m MCPConfig) IsAutoWatermarkEnabled() bool {
	if m.AutoWatermark == nil {
		return true
	}
	return *m.AutoWatermark
}

// SettingsConfig defines runtime proxy operational flags.
type SettingsConfig struct {
	StrictMode            bool `yaml:"strict_mode"`
	ProxyAuthRequired     bool `yaml:"proxy_auth_required"`
	MitmCacheSize         int  `yaml:"mitm_cache_size"`
	ConnectTimeoutSeconds int  `yaml:"connect_timeout_seconds"`
	RequestTimeoutSeconds int  `yaml:"request_timeout_seconds"`
}

// ScrubbingConfig controls PII sanitization across outbound requests.
type ScrubbingConfig struct {
	Emails      bool              `yaml:"emails"`
	Usernames   []string          `yaml:"usernames"`
	CustomRegex []CustomRegexRule `yaml:"custom_regex"`
}

// CustomRegexRule defines a user-defined redaction pattern.
type CustomRegexRule struct {
	Name        string `yaml:"name"`
	Pattern     string `yaml:"pattern"`
	Replacement string `yaml:"replacement"`
}

// Rule defines a host-scoped credential injection policy.
type Rule struct {
	Name           string       `yaml:"name"`
	Host           string       `yaml:"host"`
	MatchType      string       `yaml:"match_type"` // exact | wildcard
	Headers        []HeaderRule `yaml:"headers"`
	AllowedMethods []string     `yaml:"allowed_methods"`
}

// HeaderRule specifies which header receives which secret.
type HeaderRule struct {
	Name       string `yaml:"name"`
	Format     string `yaml:"format"` // e.g. "Bearer {{secret}}" or raw "{{secret}}"
	Secret     string `yaml:"secret"` // Vault key name
	DummyMatch string `yaml:"dummy_match"`
}

// DefaultConfig generates a secure starter configuration.
func DefaultConfig() *Config {
	return &Config{
		Version: "1.0",
		Settings: SettingsConfig{
			StrictMode:            false,
			ProxyAuthRequired:     true,
			MitmCacheSize:         500,
			ConnectTimeoutSeconds: 15,
			RequestTimeoutSeconds: 60,
		},
		Scrubbing: ScrubbingConfig{
			Emails:    true,
			Usernames: []string{"$USER", "$HOSTNAME"},
			CustomRegex: []CustomRegexRule{
				{
					Name:        "Internal-IPv4",
					Pattern:     `\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b`,
					Replacement: "[INTERNAL_IP_REDACTED]",
				},
			},
		},
		Rules: []Rule{
			{
				Name:      "OpenAI API",
				Host:      "api.openai.com",
				MatchType: "exact",
				Headers: []HeaderRule{
					{
						Name:       "Authorization",
						Format:     "Bearer {{secret}}",
						Secret:     "OPENAI_API_KEY",
						DummyMatch: "VP_OPENAI_API_KEY_DUMMY_*",
					},
				},
				AllowedMethods: []string{"POST", "GET"},
			},
			{
				Name:      "Anthropic API",
				Host:      "api.anthropic.com",
				MatchType: "exact",
				Headers: []HeaderRule{
					{
						Name:       "x-api-key",
						Format:     "{{secret}}",
						Secret:     "ANTHROPIC_API_KEY",
						DummyMatch: "VP_ANTHROPIC_API_KEY_DUMMY_*",
					},
				},
				AllowedMethods: []string{"POST", "GET"},
			},
			{
				Name:      "GitHub API",
				Host:      "api.github.com",
				MatchType: "exact",
				Headers: []HeaderRule{
					{
						Name:       "Authorization",
						Format:     "Bearer {{secret}}",
						Secret:     "GITHUB_TOKEN",
						DummyMatch: "VP_GITHUB_TOKEN_DUMMY_*",
					},
				},
				AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "PATCH"},
			},
		},
	}
}

// LoadConfig reads and validates a vouch.yaml file from path.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML policy: %w", err)
	}

	if cfg.Version == "" {
		return nil, errors.New("policy config missing 'version' field")
	}

	return &cfg, nil
}

// SaveConfig writes a config to path.
func SaveConfig(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}
