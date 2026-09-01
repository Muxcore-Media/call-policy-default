package internal

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func testPolicyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policies.yaml")
	data := []byte("- caller: \"*\"\n  target: \"*\"\n  methods: [\"*\"]\n")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func TestModuleInfo(t *testing.T) {
	m := NewModule(Config{})
	info := m.Info()
	if info.ID == "" {
		t.Error("module ID must not be empty")
	}
	if info.Version == "" {
		t.Error("module version must not be empty")
	}
}

func TestModuleLifecycle(t *testing.T) {
	m := NewModule(Config{FilePath: testPolicyFile(t), GRPCAddr: "127.0.0.1:0"})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestModuleGRPCHealth(t *testing.T) {
	m := NewModule(Config{FilePath: testPolicyFile(t), GRPCAddr: "127.0.0.1:0"})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = m.Stop(ctx) }()

	if err := m.Health(ctx); err != nil {
		t.Fatalf("Health: %v", err)
	}

	conn, err := grpc.NewClient(m.lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	health := grpc_health_v1.NewHealthClient(conn)
	resp, err := health.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("expected SERVING, got %s", resp.GetStatus())
	}

	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := health.Watch(watchCtx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	first, err := stream.Recv()
	if err != nil {
		t.Fatalf("Watch Recv: %v", err)
	}
	if first.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("Watch expected SERVING, got %s", first.GetStatus())
	}
	cancel()
	if _, err := stream.Recv(); err == nil {
		t.Fatal("expected Watch stream to end after client cancel")
	}
}

func TestInitFailsMissingPolicy(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-policies.yaml")
	m := NewModule(Config{FilePath: missing, GRPCAddr: "127.0.0.1:0"})
	if err := m.Init(context.Background()); err == nil {
		t.Fatal("expected Init to fail when policy file is missing")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("expected missing policy file not to be created, stat err: %v", err)
	}
}

func TestInitFailsInvalidPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policies.yaml")
	if err := os.WriteFile(path, []byte("- caller: \"*\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m := NewModule(Config{FilePath: path, GRPCAddr: "127.0.0.1:0"})
	if err := m.Init(context.Background()); err == nil {
		t.Fatal("expected Init to fail when policy file is invalid")
	}
}
