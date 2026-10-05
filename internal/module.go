package internal

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"

	manifest "github.com/Muxcore-Media/call-policy-default"
	"github.com/Muxcore-Media/call-policy-default/internal/grpctls"
	"github.com/Muxcore-Media/call-policy-default/internal/policy"
	"github.com/Muxcore-Media/call-policy-default/internal/server"
	"github.com/Muxcore-Media/core/pkg/contracts"
	"github.com/Muxcore-Media/core/sdk/go/client"
	modulesdk "github.com/Muxcore-Media/core/sdk/go/module"
)

type Module struct {
	policy   *policy.Policy
	srv      *server.PolicyServer
	grpcSrv  *grpc.Server
	lis      net.Listener
	cfgMu    sync.RWMutex
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
		cfg.GRPCAddr = "127.0.0.1:9101"
	}
	if cfg.FilePath == "" {
		cfg.FilePath = "policies.yaml"
	}
	if v := os.Getenv("CALL_POLICY_GRPC_ADDR"); v != "" {
		cfg.GRPCAddr = v
	}
	cfg.GRPCAddr = resolveGRPCAddr(cfg.GRPCAddr)
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
		Version:      modulesdk.ManifestVersion(manifest.ManifestJSON),
		Roles:        []string{"security"},
		Description:  "Default inter-module call access control with static YAML and dynamic event-bus grants",
		Author:       "MuxCore",
		Capabilities: []string{contracts.CapabilityCallPolicy, "settings"},
		Contracts: []contracts.ContractDeclaration{
			{Repo: "github.com/Muxcore-Media/core/pkg/contracts", Interface: "CallPolicyProvider", Version: "v0.4.0"},
		},
		MinCoreVersion: "0.4.0",
		HTTPAddr:       m.grpcAddr,
	}
}

func (m *Module) Init(ctx context.Context) error {
	var err error
	overlay := strings.TrimSpace(os.Getenv("CALL_POLICY_DEV_FILE"))
	m.policy, err = policy.LoadWithOverlay(m.filePath, overlay)
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
	var grpcOpts []grpc.ServerOption
	tlsCfg, err := grpctls.ServerConfig()
	if err != nil {
		return fmt.Errorf("gRPC TLS: %w", err)
	}
	if tlsCfg != nil {
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
		slog.Info("call-policy gRPC TLS enabled", "addr", m.grpcAddr)
	} else {
		slog.Warn("call-policy gRPC listening without TLS (dev only)",
			"addr", m.grpcAddr,
			"hint", "unset MUXCORE_INSECURE_DISABLE_TLS for production",
		)
	}
	m.grpcSrv = grpc.NewServer(grpcOpts...)
	m.srv.RegisterWithGRPC(m.grpcSrv)
	grpc_health_v1.RegisterHealthServer(m.grpcSrv, &healthServer{})
	modulesdk.RegisterSettings(m.grpcSrv, m.id, m)

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
			if err := m.ReloadPolicy(); err != nil {
				slog.Error("policy reload failed", "error", err)
			}
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

// resolveGRPCAddr prefers loopback when plaintext is explicitly enabled and the
// bind address would otherwise listen on all interfaces.
func resolveGRPCAddr(addr string) string {
	if !grpctls.InsecureAllowed() {
		return addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.HasPrefix(addr, ":") {
			return "127.0.0.1" + addr
		}
		return addr
	}
	if host == "" || host == "0.0.0.0" {
		return "127.0.0.1:" + port
	}
	return addr
}
