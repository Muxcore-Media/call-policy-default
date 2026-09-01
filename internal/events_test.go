package internal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func testGrantModule(t *testing.T) *Module {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policies.yaml")
	if err := os.WriteFile(path, []byte("grantors:\n  - admin-ui\nrules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewModule(Config{FilePath: path, GRPCAddr: "127.0.0.1:0"})
	if err := m.Init(t.Context()); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestHandleGrantForTest_Valid(t *testing.T) {
	m := testGrantModule(t)
	payload, _ := json.Marshal(grantPayload{
		ID: "g1", Caller: "mod-a", Target: "mod-b", Methods: []string{"Call"},
	})
	if err := m.HandleGrantForTest("admin-ui", payload); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.policy.Allow("mod-a", "mod-b", "Call"); !ok {
		t.Fatal("expected dynamic grant to allow call")
	}
}

func TestHandleGrantForTest_MissingFields(t *testing.T) {
	m := testGrantModule(t)
	payload, _ := json.Marshal(grantPayload{Caller: "mod-a", Target: "mod-b"})
	if err := m.HandleGrantForTest("admin-ui", payload); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.policy.Allow("mod-a", "mod-b", "Call"); ok {
		t.Fatal("expected missing methods to reject grant")
	}
}

func TestHandleGrantForTest_UnknownGrantor(t *testing.T) {
	m := testGrantModule(t)
	payload, _ := json.Marshal(grantPayload{
		ID: "g1", Caller: "mod-a", Target: "mod-b", Methods: []string{"Call"},
	})
	if err := m.HandleGrantForTest("evil-module", payload); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.policy.Allow("mod-a", "mod-b", "Call"); ok {
		t.Fatal("expected grant from non-grantor to be ignored")
	}
}

func TestHandleRevokeForTest_ByID(t *testing.T) {
	m := testGrantModule(t)
	grant, _ := json.Marshal(grantPayload{
		ID: "g1", Caller: "mod-a", Target: "mod-b", Methods: []string{"Call"},
	})
	if err := m.HandleGrantForTest("admin-ui", grant); err != nil {
		t.Fatal(err)
	}
	revoke, _ := json.Marshal(revokePayload{ID: "g1"})
	if err := m.HandleRevokeForTest("admin-ui", revoke); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.policy.Allow("mod-a", "mod-b", "Call"); ok {
		t.Fatal("expected revoke-by-id to remove grant")
	}
}

func TestHandleRevokeForTest_ByCallerTarget(t *testing.T) {
	m := testGrantModule(t)
	grant, _ := json.Marshal(grantPayload{
		ID: "g1", Caller: "mod-a", Target: "mod-b", Methods: []string{"Call"},
	})
	if err := m.HandleGrantForTest("admin-ui", grant); err != nil {
		t.Fatal(err)
	}
	revoke, _ := json.Marshal(revokePayload{Caller: "mod-a", Target: "mod-b"})
	if err := m.HandleRevokeForTest("admin-ui", revoke); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.policy.Allow("mod-a", "mod-b", "Call"); ok {
		t.Fatal("expected revoke-by-match to remove grant")
	}
}

func TestHandleRevokeForTest_UnknownGrantor(t *testing.T) {
	m := testGrantModule(t)
	grant, _ := json.Marshal(grantPayload{
		ID: "g1", Caller: "mod-a", Target: "mod-b", Methods: []string{"Call"},
	})
	if err := m.HandleGrantForTest("admin-ui", grant); err != nil {
		t.Fatal(err)
	}
	revoke, _ := json.Marshal(revokePayload{ID: "g1"})
	if err := m.HandleRevokeForTest("evil-module", revoke); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.policy.Allow("mod-a", "mod-b", "Call"); !ok {
		t.Fatal("revoke from non-grantor must not remove grant")
	}
}
