package policy

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// Rule defines a single call policy rule.
type Rule struct {
	// Caller is the module ID making the call. Supports "*" for any caller.
	Caller string `yaml:"caller"`
	// Target is the module ID being called. Supports "*" for any target.
	Target string `yaml:"target"`
	// Methods is the list of method names allowed. Supports "*" for any method.
	Methods []string `yaml:"methods"`
}

// Policy holds the complete set of call policy rules.
type Policy struct {
	mu    sync.RWMutex
	rules []Rule
}

// Load parses a YAML policy file and returns a Policy.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return Parse(data)
}

// Parse parses YAML policy data and returns a Policy.
func Parse(data []byte) (*Policy, error) {
	var rules []Rule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	for i, r := range rules {
		if r.Caller == "" {
			return nil, fmt.Errorf("rule %d: caller is required", i)
		}
		if r.Target == "" {
			return nil, fmt.Errorf("rule %d: target is required", i)
		}
		if len(r.Methods) == 0 {
			return nil, fmt.Errorf("rule %d: at least one method is required", i)
		}
	}
	return &Policy{rules: rules}, nil
}

// Allow checks whether a call from caller to target with the given method is permitted.
// Rules are evaluated in order; the first matching rule decides. If no rule matches, the
// call is denied (deny-by-default).
func (p *Policy) Allow(caller, target, method string) (bool, string) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, r := range p.rules {
		if !matchWildcard(r.Caller, caller) {
			continue
		}
		if !matchWildcard(r.Target, target) {
			continue
		}
		if !matchMethod(r.Methods, method) {
			continue
		}
		return true, ""
	}
	return false, fmt.Sprintf("no policy rule matches caller=%q target=%q method=%q", caller, target, method)
}

// ReplaceRules atomically replaces all rules with those from another Policy.
// Used for SIGHUP hot-reload. src is not modified.
func (p *Policy) ReplaceRules(src *Policy) {
	src.mu.RLock()
	rules := make([]Rule, len(src.rules))
	copy(rules, src.rules)
	src.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = rules
}

// matchWildcard checks whether pattern matches value.
// pattern "*" matches everything. Otherwise, exact match.
func matchWildcard(pattern, value string) bool {
	return pattern == "*" || pattern == value
}

// matchMethod checks whether methods contains the given method.
// If any entry is "*", all methods match.
func matchMethod(methods []string, method string) bool {
	for _, m := range methods {
		if m == "*" || m == method {
			return true
		}
	}
	return false
}
