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
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/Muxcore-Media/call-policy-default/internal/policy"
	"github.com/Muxcore-Media/call-policy-default/internal/server"
	"github.com/Muxcore-Media/core/pkg/contracts"
	"github.com/Muxcore-Media/core/sdk/go/client"
	modulesdk "github.com/Muxcore-Media/core/sdk/go/module"
)

type Module struct {
	policy      *policy.Policy
	srv         *server.PolicyServer
	grpcSrv     *grpc.Server
	lis         net.Listener
	cfgMu       sync.RWMutex
	filePath    string
	overlayPath string
	id          string
	grpcAddr    string
	mc          *client.Client
	meshMu      sync.Mutex
	stopCancel  context.CancelFunc
	sighupCh    chan os.Signal
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
	overlay := strings.TrimSpace(os.Getenv("CALL_POLICY_DEV_FILE"))
	return &Module{
		id:          cfg.ID,
		grpcAddr:    cfg.GRPCAddr,
		filePath:    cfg.FilePath,
		overlayPath: overlay,
	}
}

func (m *Module) Info() contracts.ModuleInfo {
	return contracts.ModuleInfo{
		ID:           m.id,
		Name:         "Call Policy Default",
		Version:      "0.3.5",
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
	m.policy, err = policy.LoadWithOverlay(m.filePath, m.overlayPath)
	if err != nil {
		return fmt.Errorf("load policy %q: %w", m.filePath, err)
	}
	m.srv = server.New(m.policy)
	m.lis, err = net.Listen("tcp", m.grpcAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", m.grpcAddr, err)
	}
	slog.Info("call-policy initialized", "file", m.filePath, "overlay", m.overlayPath)
	return nil
}

func (m *Module) Start(ctx context.Context) error {
	stopCtx, cancel := context.WithCancel(context.Background())
	m.stopCancel = cancel

	m.grpcSrv = grpc.NewServer()
	m.srv.RegisterWithGRPC(m.grpcSrv)
	grpc_health_v1.RegisterHealthServer(m.grpcSrv, &healthServer{})
	modulesdk.RegisterSettings(m.grpcSrv, m.id, m)

	go func() {
		slog.Info("call-policy gRPC started", "addr", m.grpcAddr)
		if err := m.grpcSrv.Serve(m.lis); err != nil {
			slog.Error("call-policy gRPC error", "error", err)
		}
	}()

	m.sighupCh = make(chan os.Signal, 1)
	signal.Notify(m.sighupCh, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-stopCtx.Done():
				return
			case _, ok := <-m.sighupCh:
				if !ok {
					return
				}
				slog.Info("SIGHUP: reloading policy")
				if err := m.ReloadPolicy(); err != nil {
					slog.Error("policy reload failed", "error", err)
				}
			}
		}
	}()

	go m.subscribePolicyEvents(stopCtx)
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	if m.stopCancel != nil {
		m.stopCancel()
	}
	if m.sighupCh != nil {
		signal.Stop(m.sighupCh)
		close(m.sighupCh)
		m.sighupCh = nil
	}
	if m.grpcSrv != nil {
		m.grpcSrv.GracefulStop()
	}
	m.meshMu.Lock()
	if m.mc != nil {
		_ = m.mc.Close()
		m.mc = nil
	}
	m.meshMu.Unlock()
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
	if err := stream.Send(&grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}
