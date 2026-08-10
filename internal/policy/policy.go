package policy

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Rule defines a single call policy rule.
type Rule struct {
	// Caller is the module ID making the call. Supports "*" for any caller.
	Caller string `yaml:"caller"`
	// CallerGroup references a named group from the policy document's groups map.
	CallerGroup string `yaml:"caller_group"`
	// Target is the module ID being called. Supports "*" for any target.
	Target string `yaml:"target"`
	// Methods is the list of method names allowed. Supports "*" for any method.
	Methods []string `yaml:"methods"`
	// RateLimitPerMin caps matching calls per caller+target+method per rolling minute.
	// Zero means unlimited.
	RateLimitPerMin int `yaml:"rate_limit_per_min"`
	// After / Before are local-time HH:MM windows (inclusive after, exclusive before).
	// Empty means no bound. Spans midnight when After > Before.
	After  string `yaml:"after"`
	Before string `yaml:"before"`
	// Days restricts the rule to weekdays (mon..sun). Empty means every day.
	Days []string `yaml:"days"`
}

type policyDoc struct {
	Groups map[string][]string `yaml:"groups"`
	Rules  []Rule              `yaml:"rules"`
}

// Policy holds the complete set of call policy rules.
type Policy struct {
	mu     sync.RWMutex
	rules  []Rule
	groups map[string][]string

	dynamic []dynamicGrant

	rateMu sync.Mutex
	rates  map[string]*rateWindow

	// now is injectable for tests; defaults to time.Now.
	now func() time.Time
}

type dynamicGrant struct {
	ID      string
	Rule    Rule
	Expires time.Time // zero means no expiry
}

type rateWindow struct {
	start time.Time
	count int
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
// Accepts either a legacy rule list or a document with optional groups + rules.
func Parse(data []byte) (*Policy, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = *node.Content[0]
	}

	var rules []Rule
	var groups map[string][]string

	switch node.Kind {
	case yaml.SequenceNode, 0:
		if err := yaml.Unmarshal(data, &rules); err != nil {
			return nil, fmt.Errorf("parse policy: %w", err)
		}
	case yaml.MappingNode:
		var doc policyDoc
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parse policy: %w", err)
		}
		rules = doc.Rules
		groups = doc.Groups
	default:
		// empty / null → deny-all
		rules = nil
	}

	for i, r := range rules {
		if r.Caller == "" && r.CallerGroup == "" {
			return nil, fmt.Errorf("rule %d: caller or caller_group is required", i)
		}
		if r.Caller != "" && r.CallerGroup != "" {
			return nil, fmt.Errorf("rule %d: set caller or caller_group, not both", i)
		}
		if r.CallerGroup != "" {
			if _, ok := groups[r.CallerGroup]; !ok {
				return nil, fmt.Errorf("rule %d: unknown caller_group %q", i, r.CallerGroup)
			}
		}
		if r.Target == "" {
			return nil, fmt.Errorf("rule %d: target is required", i)
		}
		if len(r.Methods) == 0 {
			return nil, fmt.Errorf("rule %d: at least one method is required", i)
		}
		if r.RateLimitPerMin < 0 {
			return nil, fmt.Errorf("rule %d: rate_limit_per_min must be >= 0", i)
		}
		if _, err := parseHHMM(r.After); err != nil {
			return nil, fmt.Errorf("rule %d: after: %w", i, err)
		}
		if _, err := parseHHMM(r.Before); err != nil {
			return nil, fmt.Errorf("rule %d: before: %w", i, err)
		}
		for _, d := range r.Days {
			if !validDay(d) {
				return nil, fmt.Errorf("rule %d: invalid day %q", i, d)
			}
		}
	}
	return &Policy{
		rules:  rules,
		groups: groups,
		rates:  make(map[string]*rateWindow),
		now:    time.Now,
	}, nil
}

// Allow checks whether a call from caller to target with the given method is permitted.
// Rules are evaluated in order; the first matching rule decides. If no static rule
// matches, dynamic grants from the event bus are checked. If none match, denied.
func (p *Policy) Allow(caller, target, method string) (bool, string) {
	p.mu.Lock()
	p.pruneExpiredLocked()
	p.mu.Unlock()

	p.mu.RLock()
	defer p.mu.RUnlock()

	now := p.now()
	if p.now == nil {
		now = time.Now()
	}

	for i, r := range p.rules {
		if !p.callerMatches(r, caller) {
			continue
		}
		if !matchWildcard(r.Target, target) {
			continue
		}
		if !matchMethod(r.Methods, method) {
			continue
		}
		if !dayAllowed(r.Days, now) {
			continue
		}
		if !timeWindowAllows(r.After, r.Before, now) {
			continue
		}
		if r.RateLimitPerMin > 0 {
			key := fmt.Sprintf("%d|%s|%s|%s", i, caller, target, method)
			if !p.allowRate(key, r.RateLimitPerMin, now) {
				return false, fmt.Sprintf("rate limit exceeded (%d/min) for caller=%q target=%q method=%q",
					r.RateLimitPerMin, caller, target, method)
			}
		}
		return true, ""
	}

	for _, g := range p.dynamic {
		r := g.Rule
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

func (p *Policy) callerMatches(r Rule, caller string) bool {
	if r.CallerGroup != "" {
		members := p.groups[r.CallerGroup]
		for _, m := range members {
			if matchWildcard(m, caller) {
				return true
			}
		}
		return false
	}
	return matchWildcard(r.Caller, caller)
}

func (p *Policy) allowRate(key string, limit int, now time.Time) bool {
	p.rateMu.Lock()
	defer p.rateMu.Unlock()
	w, ok := p.rates[key]
	if !ok || now.Sub(w.start) >= time.Minute {
		p.rates[key] = &rateWindow{start: now, count: 1}
		return true
	}
	if w.count >= limit {
		return false
	}
	w.count++
	return true
}

// ReplaceRules atomically replaces all static rules with those from another Policy.
// Used for SIGHUP hot-reload. Dynamic event-bus grants are preserved. Rate windows reset.
func (p *Policy) ReplaceRules(src *Policy) {
	src.mu.RLock()
	rules := make([]Rule, len(src.rules))
	copy(rules, src.rules)
	groups := cloneGroups(src.groups)
	src.mu.RUnlock()

	p.mu.Lock()
	p.rules = rules
	p.groups = groups
	p.mu.Unlock()

	p.rateMu.Lock()
	p.rates = make(map[string]*rateWindow)
	p.rateMu.Unlock()
}

// GrantDynamic adds a runtime allow rule (from call.policy.grant).
// If id is empty, one is generated. ttl<=0 means until revoke or process exit.
// Replacing an existing id updates the grant.
func (p *Policy) GrantDynamic(id, caller, target string, methods []string, ttl time.Duration) (string, error) {
	if caller == "" {
		return "", fmt.Errorf("caller is required")
	}
	if target == "" {
		return "", fmt.Errorf("target is required")
	}
	if len(methods) == 0 {
		return "", fmt.Errorf("at least one method is required")
	}
	if id == "" {
		id = fmt.Sprintf("dyn_%d", time.Now().UnixNano())
	}
	var expires time.Time
	if ttl > 0 {
		now := time.Now()
		if p.now != nil {
			now = p.now()
		}
		expires = now.Add(ttl)
	}
	g := dynamicGrant{
		ID: id,
		Rule: Rule{
			Caller:  caller,
			Target:  target,
			Methods: append([]string(nil), methods...),
		},
		Expires: expires,
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.dynamic {
		if p.dynamic[i].ID == id {
			p.dynamic[i] = g
			return id, nil
		}
	}
	p.dynamic = append(p.dynamic, g)
	return id, nil
}

// RevokeDynamic removes a grant by id. Returns true if a grant was removed.
func (p *Policy) RevokeDynamic(id string) bool {
	if id == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.dynamic[:0]
	removed := false
	for _, g := range p.dynamic {
		if g.ID == id {
			removed = true
			continue
		}
		out = append(out, g)
	}
	p.dynamic = out
	return removed
}

// RevokeDynamicMatch removes grants matching caller and/or target.
// Empty caller or target means "any". At least one of caller/target must be set.
func (p *Policy) RevokeDynamicMatch(caller, target string) int {
	if caller == "" && target == "" {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.dynamic[:0]
	n := 0
	for _, g := range p.dynamic {
		callerOK := caller == "" || g.Rule.Caller == caller || matchWildcard(caller, g.Rule.Caller)
		targetOK := target == "" || g.Rule.Target == target || matchWildcard(target, g.Rule.Target)
		if callerOK && targetOK {
			n++
			continue
		}
		out = append(out, g)
	}
	p.dynamic = out
	return n
}

func (p *Policy) pruneExpiredLocked() {
	now := time.Now()
	if p.now != nil {
		now = p.now()
	}
	out := p.dynamic[:0]
	for _, g := range p.dynamic {
		if !g.Expires.IsZero() && !now.Before(g.Expires) {
			continue
		}
		out = append(out, g)
	}
	p.dynamic = out
}

// DynamicCount returns the number of active dynamic grants (after pruning).
func (p *Policy) DynamicCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneExpiredLocked()
	return len(p.dynamic)
}

func cloneGroups(in map[string][]string) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func matchWildcard(pattern, value string) bool {
	return pattern == "*" || pattern == value
}

func matchMethod(methods []string, method string) bool {
	for _, m := range methods {
		if m == "*" || m == method {
			return true
		}
	}
	return false
}

func parseHHMM(s string) (minutes int, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	var h, m int
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil {
		return 0, fmt.Errorf("want HH:MM, got %q", s)
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("invalid time %q", s)
	}
	return h*60 + m, nil
}

func timeWindowAllows(after, before string, now time.Time) bool {
	if after == "" && before == "" {
		return true
	}
	cur := now.Hour()*60 + now.Minute()
	a, _ := parseHHMM(after)
	b, _ := parseHHMM(before)
	if after != "" && before != "" {
		if a <= b {
			return cur >= a && cur < b
		}
		// spans midnight
		return cur >= a || cur < b
	}
	if after != "" {
		return cur >= a
	}
	return cur < b
}

func validDay(d string) bool {
	switch strings.ToLower(d) {
	case "mon", "tue", "wed", "thu", "fri", "sat", "sun":
		return true
	default:
		return false
	}
}

func dayAllowed(days []string, now time.Time) bool {
	if len(days) == 0 {
		return true
	}
	want := strings.ToLower(now.Weekday().String()[:3])
	for _, d := range days {
		if strings.ToLower(d) == want {
			return true
		}
	}
	return false
}
