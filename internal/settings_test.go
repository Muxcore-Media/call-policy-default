package internal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSettingsPolicyFile(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "a.yaml")
	p2 := filepath.Join(dir, "b.yaml")
	if err := os.WriteFile(p1, []byte("rules:\n  - caller: \"*\"\n    target: \"*\"\n    methods: [\"*\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p2, []byte("rules:\n  - caller: a\n    target: b\n    methods: [\"*\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewModule(Config{FilePath: p1, GRPCAddr: "127.0.0.1:0"})
	if err := m.Init(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Stop(t.Context()) }()

	if err := m.UpdateSetting("policy_file", p2); err != nil {
		t.Fatal(err)
	}
	if got := m.Settings()[0].Value; got != p2 {
		t.Fatalf("path=%q", got)
	}
	if err := m.UpdateSetting("policy_file", ""); err == nil {
		t.Fatal("expected error")
	}
}
