package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParse_EmptyRules(t *testing.T) {
	p, err := Parse([]byte{})
	if err != nil {
		t.Fatalf("Parse empty: %v", err)
	}
	if p == nil {
		t.Fatal("Parse returned nil Policy")
	}
	allowed, reason := p.Allow("a", "b", "Method")
	if allowed {
		t.Error("expected empty policy to deny all")
	}
	if reason == "" {
		t.Error("expected non-empty reason for denial")
	}
}

func TestParse_InvalidYAML(t *testing.T) {
	_, err := Parse([]byte(`{{{invalid}}}`))
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestParse_MissingCaller(t *testing.T) {
	_, err := Parse([]byte(`
- target: "b"
  methods: ["Method"]
`))
	if err == nil {
		t.Fatal("expected error for missing caller")
	}
}

func TestParse_MissingMethods(t *testing.T) {
	_, err := Parse([]byte(`
- caller: "a"
  target: "b"
`))
	if err == nil {
		t.Fatal("expected error for missing methods")
	}
}

func TestAllow_ExactMatch(t *testing.T) {
	p, err := Parse([]byte(`
- caller: "mod-a"
  target: "mod-b"
  methods: ["Get", "Put"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	tests := []struct {
		caller  string
		target  string
		method  string
		allowed bool
	}{
		{"mod-a", "mod-b", "Get", true},
		{"mod-a", "mod-b", "Put", true},
		{"mod-a", "mod-b", "Delete", false},
		{"mod-c", "mod-b", "Get", false},
		{"mod-a", "mod-d", "Get", false},
	}
	for _, tt := range tests {
		allowed, _ := p.Allow(tt.caller, tt.target, tt.method)
		if allowed != tt.allowed {
			t.Errorf("Allow(%q, %q, %q) = %v, want %v",
				tt.caller, tt.target, tt.method, allowed, tt.allowed)
		}
	}
}

func TestAllow_WildcardCaller(t *testing.T) {
	p, err := Parse([]byte(`
- caller: "*"
  target: "storage"
  methods: ["Get"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if allowed, _ := p.Allow("any-module", "storage", "Get"); !allowed {
		t.Error("expected wildcard caller to match any module")
	}
	if allowed, _ := p.Allow("", "storage", "Get"); !allowed {
		t.Error("expected wildcard caller to match empty caller")
	}
}

func TestAllow_WildcardTarget(t *testing.T) {
	p, err := Parse([]byte(`
- caller: "scanner"
  target: "*"
  methods: ["Scan"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	for _, target := range []string{"fs", "network", "memory"} {
		if allowed, _ := p.Allow("scanner", target, "Scan"); !allowed {
			t.Errorf("expected wildcard target to match %q", target)
		}
	}
}

func TestAllow_WildcardMethods(t *testing.T) {
	p, err := Parse([]byte(`
- caller: "admin"
  target: "module-x"
  methods: ["*"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	for _, method := range []string{"Start", "Stop", "Restart", "Configure"} {
		if allowed, _ := p.Allow("admin", "module-x", method); !allowed {
			t.Errorf("expected wildcard method to match %q", method)
		}
	}
}

func TestAllow_FirstMatchWins(t *testing.T) {
	p, err := Parse([]byte(`
- caller: "a"
  target: "b"
  methods: ["Get"]
- caller: "a"
  target: "*"
  methods: ["Get"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// First rule: a→b/Get matches. Second rule never evaluated.
	if allowed, _ := p.Allow("a", "b", "Get"); !allowed {
		t.Error("expected first rule to match")
	}
}

func TestAllow_OrderDependent(t *testing.T) {
	p, err := Parse([]byte(`
- caller: "*"
  target: "*"
  methods: ["*"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if allowed, _ := p.Allow("anything", "anything", "anything"); !allowed {
		t.Error("expected catch-all rule to match anything")
	}
}

func TestReplaceRules(t *testing.T) {
	p, err := Parse([]byte(`
- caller: "a"
  target: "b"
  methods: ["Get"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	newP, err := Parse([]byte(`
- caller: "x"
  target: "y"
  methods: ["Post"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	p.ReplaceRules(newP)

	if allowed, _ := p.Allow("a", "b", "Get"); allowed {
		t.Error("expected old rules to be replaced")
	}
	if allowed, _ := p.Allow("x", "y", "Post"); !allowed {
		t.Error("expected new rules to apply after replacement")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/policy.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	content := []byte("- caller: \"a\"\n  target: \"b\"\n  methods: [\"Get\"]\n")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if allowed, _ := p.Allow("a", "b", "Get"); !allowed {
		t.Error("expected loaded policy to allow matching call")
	}
}

func TestAllow_MultipleRules(t *testing.T) {
	p, err := Parse([]byte(`
- caller: "downloader"
  target: "storage"
  methods: ["Put", "Get", "Stat"]
- caller: "transcoder"
  target: "storage"
  methods: ["Get", "Stream"]
- caller: "*"
  target: "auth"
  methods: ["Validate"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	tests := []struct {
		caller  string
		target  string
		method  string
		allowed bool
	}{
		{"downloader", "storage", "Put", true},
		{"downloader", "storage", "Stat", true},
		{"downloader", "storage", "Delete", false},
		{"transcoder", "storage", "Stream", true},
		{"transcoder", "storage", "Put", false},
		{"any-module", "auth", "Validate", true},
		{"downloader", "auth", "Validate", true},
		{"downloader", "unknown", "Get", false},
	}
	for _, tt := range tests {
		allowed, _ := p.Allow(tt.caller, tt.target, tt.method)
		if allowed != tt.allowed {
			t.Errorf("Allow(%q, %q, %q) = %v, want %v",
				tt.caller, tt.target, tt.method, allowed, tt.allowed)
		}
	}
}

func TestAllow_RateLimit(t *testing.T) {
	p, err := Parse([]byte(`
- caller: "a"
  target: "b"
  methods: ["M"]
  rate_limit_per_min: 2
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	fixed := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return fixed }
	if ok, _ := p.Allow("a", "b", "M"); !ok {
		t.Fatal("1st should allow")
	}
	if ok, _ := p.Allow("a", "b", "M"); !ok {
		t.Fatal("2nd should allow")
	}
	if ok, reason := p.Allow("a", "b", "M"); ok {
		t.Fatalf("3rd should deny, got allow")
	} else if reason == "" {
		t.Fatal("expected rate limit reason")
	}
}

func TestAllow_TimeWindow(t *testing.T) {
	p, err := Parse([]byte(`
- caller: "a"
  target: "b"
  methods: ["M"]
  after: "09:00"
  before: "17:00"
  days: ["mon"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Monday 2026-08-10 is a Monday
	p.now = func() time.Time { return time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC) }
	if ok, _ := p.Allow("a", "b", "M"); !ok {
		t.Fatal("expected allow inside window on Monday")
	}
	p.now = func() time.Time { return time.Date(2026, 8, 10, 18, 0, 0, 0, time.UTC) }
	if ok, _ := p.Allow("a", "b", "M"); ok {
		t.Fatal("expected deny outside window")
	}
	p.now = func() time.Time { return time.Date(2026, 8, 11, 10, 0, 0, 0, time.UTC) } // Tuesday
	if ok, _ := p.Allow("a", "b", "M"); ok {
		t.Fatal("expected deny on Tuesday")
	}
}

func TestAllow_CallerGroup(t *testing.T) {
	p, err := Parse([]byte(`
groups:
  media:
    - media-movies
    - media-tv
rules:
  - caller_group: media
    target: "storage"
    methods: ["Get"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if ok, _ := p.Allow("media-movies", "storage", "Get"); !ok {
		t.Fatal("group member should allow")
	}
	if ok, _ := p.Allow("other", "storage", "Get"); ok {
		t.Fatal("non-member should deny")
	}
}

func TestParse_UnknownGroup(t *testing.T) {
	_, err := Parse([]byte(`
groups: {}
rules:
  - caller_group: nope
    target: "b"
    methods: ["M"]
`))
	if err == nil {
		t.Fatal("expected unknown group error")
	}
}

func TestDynamicGrantAndRevoke(t *testing.T) {
	p, err := Parse([]byte(`[]`))
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := p.Allow("mod-a", "mod-b", "Call"); ok {
		t.Fatal("expected deny before grant")
	}
	id, err := p.GrantDynamic("g1", "mod-a", "mod-b", []string{"Call"}, 0)
	if err != nil || id != "g1" {
		t.Fatalf("grant: id=%s err=%v", id, err)
	}
	if ok, _ := p.Allow("mod-a", "mod-b", "Call"); !ok {
		t.Fatal("expected allow after grant")
	}
	if ok, _ := p.Allow("mod-a", "mod-b", "Other"); ok {
		t.Fatal("other method still denied")
	}
	if !p.RevokeDynamic("g1") {
		t.Fatal("expected revoke")
	}
	if ok, _ := p.Allow("mod-a", "mod-b", "Call"); ok {
		t.Fatal("expected deny after revoke")
	}
}

func TestDynamicGrantTTL(t *testing.T) {
	p, err := Parse([]byte(`[]`))
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return base }
	if _, err := p.GrantDynamic("ttl1", "a", "b", []string{"M"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if ok, _ := p.Allow("a", "b", "M"); !ok {
		t.Fatal("allow inside ttl")
	}
	p.now = func() time.Time { return base.Add(2 * time.Minute) }
	if ok, _ := p.Allow("a", "b", "M"); ok {
		t.Fatal("deny after ttl")
	}
	if p.DynamicCount() != 0 {
		t.Fatal("expired grants should be pruned")
	}
}

func TestDynamicSurvivesReplaceRules(t *testing.T) {
	p, err := Parse([]byte(`[]`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.GrantDynamic("keep", "a", "b", []string{"M"}, 0); err != nil {
		t.Fatal(err)
	}
	fresh, err := Parse([]byte(`
- caller: "x"
  target: "y"
  methods: ["Z"]
`))
	if err != nil {
		t.Fatal(err)
	}
	p.ReplaceRules(fresh)
	if ok, _ := p.Allow("a", "b", "M"); !ok {
		t.Fatal("dynamic grant should survive SIGHUP reload")
	}
	if ok, _ := p.Allow("x", "y", "Z"); !ok {
		t.Fatal("static rule from reload should apply")
	}
}

func TestRevokeDynamicMatch(t *testing.T) {
	p, err := Parse([]byte(`[]`))
	if err != nil {
		t.Fatal(err)
	}
	p.GrantDynamic("1", "a", "b", []string{"M"}, 0)
	p.GrantDynamic("2", "a", "c", []string{"M"}, 0)
	if n := p.RevokeDynamicMatch("a", "b"); n != 1 {
		t.Fatalf("revoke match count=%d", n)
	}
	if ok, _ := p.Allow("a", "c", "M"); !ok {
		t.Fatal("other grant should remain")
	}
}
