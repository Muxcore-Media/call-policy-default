package test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	policyv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/policy/v1"
)

func TestCallPolicyIntegration(t *testing.T) {
	bin := buildModule(t, "call-policy-default")
	policyFile := writePolicy(t)
	addr := ":19101"

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin,
		"--grpc-addr", addr,
		"--policy-file", policyFile,
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer cmd.Process.Kill()

	time.Sleep(500 * time.Millisecond)

	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := policyv1.NewPolicyServiceClient(conn)

	t.Run("allow_exact", func(t *testing.T) {
		resp, err := client.AllowCall(ctx, &policyv1.AllowCallRequest{
			CallerModuleId: "mod-a", TargetModuleId: "mod-b", Method: "Get",
		})
		if err != nil {
			t.Fatalf("AllowCall: %v", err)
		}
		if !resp.Allowed {
			t.Fatal("expected allowed")
		}
	})

	t.Run("deny_no_match", func(t *testing.T) {
		resp, err := client.AllowCall(ctx, &policyv1.AllowCallRequest{
			CallerModuleId: "mod-a", TargetModuleId: "mod-b", Method: "Delete",
		})
		if err != nil {
			t.Fatalf("AllowCall: %v", err)
		}
		if resp.Allowed {
			t.Fatal("expected denied")
		}
	})

	t.Run("wildcard_caller", func(t *testing.T) {
		resp, err := client.AllowCall(ctx, &policyv1.AllowCallRequest{
			CallerModuleId: "any", TargetModuleId: "mod-c", Method: "Status",
		})
		if err != nil {
			t.Fatalf("AllowCall: %v", err)
		}
		if !resp.Allowed {
			t.Fatal("expected allowed via wildcard")
		}
	})
}

func TestCallPolicyAllowAll(t *testing.T) {
	bin := buildModule(t, "call-policy-default")
	addr := ":19102"

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin,
		"--grpc-addr", addr,
		"--allow-all",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer cmd.Process.Kill()

	time.Sleep(500 * time.Millisecond)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := policyv1.NewPolicyServiceClient(conn)

	resp, err := client.AllowCall(ctx, &policyv1.AllowCallRequest{
		CallerModuleId: "anything", TargetModuleId: "anything", Method: "anything",
	})
	if err != nil {
		t.Fatalf("AllowCall: %v", err)
	}
	if !resp.Allowed {
		t.Fatal("expected --allow-all to permit everything")
	}
}

func buildModule(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/module")
	cmd.Dir = findRepoRoot(t)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return bin
}

func writePolicy(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policies.yaml")
	content := strings.TrimSpace(`
- caller: "mod-a"
  target: "mod-b"
  methods: ["Get", "Put"]
- caller: "*"
  target: "mod-c"
  methods: ["Status"]
`)
	os.WriteFile(p, []byte(content), 0644)
	return p
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		// Fallback: walk up from test dir
		dir, _ := os.Getwd()
		for dir != "/" {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir
			}
			dir = filepath.Dir(dir)
		}
		t.Fatal("cannot find repo root")
	}
	return strings.TrimSpace(string(out))
}

func init() {
	fmt.Fprintln(os.Stderr, "integration tests: building module binary (this may take a moment)...")
}
