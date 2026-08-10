package internal

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/Muxcore-Media/call-policy-default/internal/policy"
	"github.com/Muxcore-Media/call-policy-default/internal/server"
	"github.com/Muxcore-Media/core/pkg/contracts"
	"github.com/Muxcore-Media/core/sdk/go/client"
)

type Module struct {
	policy   *policy.Policy
	srv      *server.PolicyServer
	grpcSrv  *grpc.Server
	lis      net.Listener
	filePath string
	id       string
	grpcAddr string
	mc       *client.Client
}

type Config struct {
	ID       string
	GRPCAddr string
	FilePath string
}

func NewModule(cfg Config) *Module {
	if cfg.ID == "" {
		cfg.ID = "call-policy-default"
	}
	if cfg.GRPCAddr == "" {
		cfg.GRPCAddr = ":9101"
	}
	if cfg.FilePath == "" {
		cfg.FilePath = "policies.yaml"
	}
	if v := os.Getenv("CALL_POLICY_GRPC_ADDR"); v != "" {
		cfg.GRPCAddr = v
	}
	if v := os.Getenv("CALL_POLICY_FILE"); v != "" {
		cfg.FilePath = v
	}
	return &Module{
		id:       cfg.ID,
		grpcAddr: cfg.GRPCAddr,
		filePath: cfg.FilePath,
	}
}

func (m *Module) Info() contracts.ModuleInfo {
	return contracts.ModuleInfo{
		ID:           m.id,
		Name:         "Call Policy Default",
		Version:      "0.3.1",
		Roles:        []string{"security"},
		Description:  "Default inter-module call access control with static YAML and dynamic event-bus grants",
		Author:       "MuxCore",
		Capabilities: []string{contracts.CapabilityCallPolicy},
		Contracts: []contracts.ContractDeclaration{
			{Repo: "github.com/Muxcore-Media/core/pkg/contracts", Interface: "CallPolicyProvider", Version: "v0.4.0"},
		},
		MinCoreVersion: "0.4.0",
		HTTPAddr:       m.grpcAddr,
	}
}

func (m *Module) Init(ctx context.Context) error {
	var err error
	m.policy, err = policy.Load(m.filePath)
	if err != nil {
		return fmt.Errorf("load policy %q: %w", m.filePath, err)
	}
	m.srv = server.New(m.policy)
	m.lis, err = net.Listen("tcp", m.grpcAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", m.grpcAddr, err)
	}
	slog.Info("call-policy initialized", "file", m.filePath)
	return nil
}

func (m *Module) Start(ctx context.Context) error {
	m.grpcSrv = grpc.NewServer()
	m.srv.RegisterWithGRPC(m.grpcSrv)
	grpc_health_v1.RegisterHealthServer(m.grpcSrv, &healthServer{})

	go func() {
		slog.Info("call-policy gRPC started", "addr", m.grpcAddr)
		if err := m.grpcSrv.Serve(m.lis); err != nil {
			slog.Error("call-policy gRPC error", "error", err)
		}
	}()

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		for range sighupCh {
			slog.Info("SIGHUP: reloading policy")
			newP, err := policy.Load(m.filePath)
			if err != nil {
				slog.Error("policy reload failed", "error", err)
				continue
			}
			m.policy.ReplaceRules(newP)
			slog.Info("policy reloaded")
		}
	}()

	go m.subscribePolicyEvents()
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	if m.grpcSrv != nil {
		m.grpcSrv.GracefulStop()
	}
	slog.Info("call-policy stopped")
	return nil
}

func (m *Module) Health(ctx context.Context) error {
	return nil
}

type healthServer struct {
	grpc_health_v1.UnimplementedHealthServer
}

func (s *healthServer) Check(_ context.Context, _ *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}

func (s *healthServer) Watch(_ *grpc_health_v1.HealthCheckRequest, stream grpc_health_v1.Health_WatchServer) error {
	return stream.Send(&grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING})
}
