package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func repoPolicyPaths(t *testing.T) (base, overlay string) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	base = filepath.Join(root, "policies.yaml")
	overlay = filepath.Join(root, "policies-dev.yaml")
	if _, err := os.Stat(base); err != nil {
		t.Fatalf("policies.yaml: %v", err)
	}
	if _, err := os.Stat(overlay); err != nil {
		t.Fatalf("policies-dev.yaml: %v", err)
	}
	return base, overlay
}

func TestShippedPoliciesFixture(t *testing.T) {
	base, overlay := repoPolicyPaths(t)

	prod, err := Load(base)
	if err != nil {
		t.Fatalf("Load prod: %v", err)
	}

	storageModules := []string{
		"media-scanner",
		"downloader-native-torrent",
		"indexer-torznab",
		"indexer-piratebay",
		"indexer-mux",
	}
	for _, caller := range storageModules {
		for _, method := range []string{"read", "write"} {
			ok, reason := prod.Allow(caller, "storage", method)
			if !ok {
				t.Errorf("prod: Allow(%q, storage, %q) denied: %s", caller, method, reason)
			}
		}
	}

	if ok, _ := prod.Allow("_public", "storage", "read"); ok {
		t.Fatal("prod must deny _public storage read")
	}
	if ok, _ := prod.Allow("unknown-module", "storage", "read"); ok {
		t.Fatal("prod must deny unknown caller")
	}
	if ok, _ := prod.Allow("media-scanner", "unknown-target", "read"); ok {
		t.Fatal("prod must deny unknown target")
	}
	if ok, _ := prod.Allow("media-scanner", "storage", "delete"); ok {
		t.Fatal("prod must deny unknown method")
	}

	withOverlay, err := LoadWithOverlay(base, overlay)
	if err != nil {
		t.Fatalf("LoadWithOverlay: %v", err)
	}
	if ok, _ := withOverlay.Allow("_public", "storage", "write"); !ok {
		t.Fatal("overlay must allow _public storage write")
	}
}

func TestLoadWithOverlay_MergesGroups(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.yaml")
	overlayPath := filepath.Join(dir, "overlay.yaml")
	if err := os.WriteFile(basePath, []byte(`
groups:
  media:
    - media-movies
rules:
  - caller_group: media
    target: "storage"
    methods: ["read"]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlayPath, []byte(`
groups:
  media:
    - media-tvshows
rules:
  - caller: "media-tvshows"
    target: "storage"
    methods: ["write"]
`), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := LoadWithOverlay(basePath, overlayPath)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := p.Allow("media-movies", "storage", "read"); !ok {
		t.Fatal("base group member should retain read from base rules")
	}
	if ok, _ := p.Allow("media-tvshows", "storage", "write"); !ok {
		t.Fatal("overlay rule should allow tvshows write")
	}
	if ok, _ := p.Allow("media-tvshows", "storage", "read"); !ok {
		t.Fatal("overlay group member should match merged media group for base read rule")
	}
}

func TestGrantors(t *testing.T) {
	p, err := Parse([]byte(`
grantors:
  - admin-ui
  - core
rules: []
`))
	if err != nil {
		t.Fatal(err)
	}
	if !p.GrantorAllowed("admin-ui") {
		t.Fatal("admin-ui should be allowed")
	}
	if p.GrantorAllowed("evil") {
		t.Fatal("unknown grantor should deny")
	}
	p.SetGrantors([]string{"request-media"})
	if !p.GrantorAllowed("request-media") {
		t.Fatal("SetGrantors should replace allowlist")
	}
	if p.GrantorAllowed("admin-ui") {
		t.Fatal("old grantor should not remain after SetGrantors")
	}
}
