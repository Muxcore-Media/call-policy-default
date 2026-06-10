package server

import (
	"context"
	"testing"

	"github.com/Muxcore-Media/call-policy-default/internal/policy"
	policyv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/policy/v1"
)

func newTestServer(t *testing.T, yamlData string) *PolicyServer {
	t.Helper()
	p, err := policy.Parse([]byte(yamlData))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return New(p)
}

func TestAllowCall_Allowed(t *testing.T) {
	srv := newTestServer(t, `
- caller: "mod-a"
  target: "mod-b"
  methods: ["Get"]
`)
	resp, err := srv.AllowCall(context.Background(), &policyv1.AllowCallRequest{
		CallerModuleId: "mod-a",
		TargetModuleId: "mod-b",
		Method:         "Get",
	})
	if err != nil {
		t.Fatalf("AllowCall: %v", err)
	}
	if !resp.Allowed {
		t.Fatal("expected call to be allowed")
	}
}

func TestAllowCall_Denied(t *testing.T) {
	srv := newTestServer(t, `
- caller: "mod-a"
  target: "mod-b"
  methods: ["Get"]
`)
	resp, err := srv.AllowCall(context.Background(), &policyv1.AllowCallRequest{
		CallerModuleId: "mod-a",
		TargetModuleId: "mod-b",
		Method:         "Delete",
	})
	if err != nil {
		t.Fatalf("AllowCall: %v", err)
	}
	if resp.Allowed {
		t.Fatal("expected call to be denied")
	}
	if resp.Reason == "" {
		t.Fatal("expected non-empty reason for denial")
	}
}

func TestAllowCall_EmptyFields(t *testing.T) {
	srv := newTestServer(t, `
- caller: "*"
  target: "*"
  methods: ["*"]
`)
	_, err := srv.AllowCall(context.Background(), &policyv1.AllowCallRequest{
		CallerModuleId: "",
		TargetModuleId: "b",
		Method:         "Get",
	})
	if err == nil {
		t.Fatal("expected error for empty caller_module_id")
	}
}

func TestAllowCall_WildcardCatchAll(t *testing.T) {
	srv := newTestServer(t, `
- caller: "*"
  target: "*"
  methods: ["*"]
`)
	resp, err := srv.AllowCall(context.Background(), &policyv1.AllowCallRequest{
		CallerModuleId: "anything",
		TargetModuleId: "anything",
		Method:         "anything",
	})
	if err != nil {
		t.Fatalf("AllowCall: %v", err)
	}
	if !resp.Allowed {
		t.Fatal("expected catch-all wildcard to allow anything")
	}
}

func TestAllowPublish_DefaultsDenied(t *testing.T) {
	srv := newTestServer(t, `
- caller: "*"
  target: "*"
  methods: ["*"]
`)
	resp, err := srv.AllowPublish(context.Background(), &policyv1.AllowPublishRequest{
		CallerModuleId: "any",
		EventType:      "test.event",
	})
	if err != nil {
		t.Fatalf("AllowPublish: %v", err)
	}
	if resp.Allowed {
		t.Fatal("expected call-policy-default to deny publish requests")
	}
}
