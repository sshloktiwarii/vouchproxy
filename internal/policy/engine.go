package policy

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// PolicyEngine evaluates incoming requests against rules and coordinates secret injection.
type PolicyEngine struct {
	mu       sync.RWMutex
	config   *Config
	scrubber *CompiledScrubber
}

// NewPolicyEngine initializes the policy engine with compiled matchers.
func NewPolicyEngine(cfg *Config) (*PolicyEngine, error) {
	scrubber, err := NewCompiledScrubber(cfg.Scrubbing)
	if err != nil {
		return nil, fmt.Errorf("failed to compile PII scrubbers: %w", err)
	}

	return &PolicyEngine{
		config:   cfg,
		scrubber: scrubber,
	}, nil
}

// Action represents the outcome of policy evaluation.
type Action string

const (
	ActionInjectSecret Action = "INJECT_SECRET"
	ActionBlockLeak    Action = "BLOCK_LEAK"
	ActionScrubPII     Action = "SCRUB_PII"
	ActionPassthrough  Action = "PASSTHROUGH"
	ActionRejectStrict Action = "REJECT_STRICT"
)

// EvaluationResult details the policy decision for an outbound request.
type EvaluationResult struct {
	Action        Action
	RuleName      string
	InjectedKeys  []string
	ScrubCount    int
	ErrorMessage  string
	ShouldBlock   bool
	BlockStatus   int
}

// FindRule returns the first matching rule for host and method.
func (pe *PolicyEngine) FindRule(host, method string) *Rule {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	normHost := NormalizeHost(host)
	upperMethod := strings.ToUpper(method)

	for _, rule := range pe.config.Rules {
		if MatchHost(rule.Host, rule.MatchType, normHost) {
			// Check method if specified
			if len(rule.AllowedMethods) > 0 {
				methodAllowed := false
				for _, m := range rule.AllowedMethods {
					if strings.ToUpper(m) == upperMethod {
						methodAllowed = true
						break
					}
				}
				if !methodAllowed {
					continue
				}
			}
			return &rule
		}
	}
	return nil
}

// FindDummyTokens returns all registered dummy tokens found inside text.
func FindDummyTokens(text string, dummyToKey map[string]string) []string {
	if text == "" || len(dummyToKey) == 0 {
		return nil
	}

	var found []string
	for dummy := range dummyToKey {
		if strings.Contains(text, dummy) {
			found = append(found, dummy)
		}
	}
	return found
}

// Scrubber returns the active compiled scrubber instance.
func (pe *PolicyEngine) Scrubber() *CompiledScrubber {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.scrubber
}

// Config returns the active policy configuration.
func (pe *PolicyEngine) Config() *Config {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.config
}

// EvaluateRequest inspects headers, URL path, and dummy tokens to determine action.
func (pe *PolicyEngine) EvaluateRequest(
	req *http.Request,
	dummyToKey map[string]string,
) EvaluationResult {
	targetHost := req.Host
	if targetHost == "" && req.URL != nil {
		targetHost = req.URL.Host
	}
	normHost := NormalizeHost(targetHost)
	rule := pe.FindRule(normHost, req.Method)

	// Collect all text from headers, query string to scan for dummy token leakage
	var searchCorpus strings.Builder
	searchCorpus.WriteString(req.URL.RequestURI())
	searchCorpus.WriteString(" ")
	for hKey, hVals := range req.Header {
		searchCorpus.WriteString(hKey)
		searchCorpus.WriteString(": ")
		searchCorpus.WriteString(strings.Join(hVals, " "))
		searchCorpus.WriteString("\n")
	}

	foundDummies := FindDummyTokens(searchCorpus.String(), dummyToKey)

	// If dummy tokens are present, verify whether the host is authorized
	if len(foundDummies) > 0 {
		if rule == nil {
			// CRITICAL INVARIANT: Dummy token sent to an unmapped host -> FAIL CLOSED
			return EvaluationResult{
				Action:       ActionBlockLeak,
				ErrorMessage: fmt.Sprintf("Blocked attempt to exfiltrate dummy token(s) to unauthorized host %s", normHost),
				ShouldBlock:  true,
				BlockStatus:  http.StatusForbidden,
			}
		}

		// Verify each dummy token maps to an allowed secret in this rule
		var allowedKeys []string
		for _, dummy := range foundDummies {
			keyName := dummyToKey[dummy]
			keyPermitted := false
			for _, hr := range rule.Headers {
				if hr.Secret == keyName {
					keyPermitted = true
					break
				}
			}
			if !keyPermitted {
				return EvaluationResult{
					Action:       ActionBlockLeak,
					ErrorMessage: fmt.Sprintf("Blocked attempt to send token %s to unpermitted rule %s", keyName, rule.Name),
					ShouldBlock:  true,
					BlockStatus:  http.StatusForbidden,
				}
			}
			allowedKeys = append(allowedKeys, keyName)
		}

		return EvaluationResult{
			Action:       ActionInjectSecret,
			RuleName:     rule.Name,
			InjectedKeys: allowedKeys,
			ShouldBlock:  false,
		}
	}

	// No dummy tokens present: check strict mode
	if rule == nil && pe.config.Settings.StrictMode {
		return EvaluationResult{
			Action:       ActionRejectStrict,
			ErrorMessage: fmt.Sprintf("Strict mode: outbound connection to unmapped domain %s rejected", normHost),
			ShouldBlock:  true,
			BlockStatus:  http.StatusBadGateway,
		}
	}

	return EvaluationResult{
		Action:      ActionPassthrough,
		ShouldBlock: false,
	}
}
