package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Muxcore-Media/call-policy-default/internal/policy"
	"github.com/Muxcore-Media/call-policy-default/internal/server"
	modulev1 "github.com/Muxcore-Media/core/proto/gen/muxcore/module/v1"
)

func main() {
	meshAddr := flag.String("muxcore-mesh-addr", "localhost:9090", "gRPC address of the MuxCore mesh")
	moduleID := flag.String("muxcore-module-id", "call-policy-default", "Module identifier")
	policyFile := flag.String("policy-file", "policies.yaml", "Path to policy YAML file")
	allowAll := flag.Bool("allow-all", false, "Permit all inter-module calls (development)")
	grpcAddr := flag.String("grpc-addr", ":9101", "Address for this module's gRPC policy server")
	healthAddr := flag.String("health-addr", ":9102", "Address for HTTP health endpoint")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	slog.Info("starting call-policy-default", "version", "0.1.0")

	// Load initial policy.
	p, err := loadPolicy(*policyFile, *allowAll)
	if err != nil {
		slog.Error("failed to load policy", "error", err)
		os.Exit(1)
	}
	slog.Info("policy loaded", "file", *policyFile, "allow_all", *allowAll)

	// Start our own gRPC server for core to query.
	lis, err := net.Listen("tcp", *grpcAddr)
	if err != nil {
		slog.Error("failed to listen", "addr", *grpcAddr, "error", err)
		os.Exit(1)
	}

	grpcSrv := grpc.NewServer()
	policySrv := server.New(p)
	policySrv.RegisterWithGRPC(grpcSrv)

	go func() {
		slog.Info("gRPC policy server listening", "addr", *grpcAddr)
		if err := grpcSrv.Serve(lis); err != nil {
			slog.Error("gRPC policy server error", "error", err)
		}
	}()
	// Start HTTP health server.
	healthLis, err := net.Listen("tcp", *healthAddr)
	if err != nil {
		slog.Warn("health listen failed", "addr", *healthAddr, "error", err)
	} else {
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"status":"ok"}`))
			})
			slog.Info("HTTP health endpoint listening", "addr", *healthAddr)
			http.Serve(healthLis, mux)
		}()
	}

	// Connect to core's mesh.
	conn, err := grpc.NewClient(*meshAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		slog.Warn("core not reachable, running standalone", "addr", *meshAddr, "error", err)
	}
	defer conn.Close()
	slog.Info("connected to core mesh", "addr", *meshAddr)

	// Register as a sidecar module.
	regClient := modulev1.NewModuleRegistrationClient(conn)

	resp, err := regClient.Register(context.Background(), &modulev1.RegisterRequest{
		ModuleId: *moduleID,
		ModuleInfo: &modulev1.ModuleInfo{
			Id:           *moduleID,
			Name:         "Call Policy Default",
			Version:      "0.1.0",
			Description:  "Default inter-module call access control with static allow-list policy",
			Author:       "MuxCore",
			Roles:        []string{"security"},
			Capabilities: []string{"call.policy"},
			HttpAddr:     *grpcAddr,
		},
	})
	if err != nil {
		slog.Warn("registration failed, running standalone", "error", err)
	}
	if err == nil {
		if !resp.Accepted {
			slog.Warn("registration rejected, running standalone", "reason", resp.Error)
		}
		slog.Info("module registered with core",
		"id", *moduleID,
		"mesh_addr", resp.MeshAddr,
		"node_id", resp.NodeId,
	)
	}

	// Watch for SIGHUP to reload policy.
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)

	go func() {
		for range sighupCh {
			slog.Info("SIGHUP received — reloading policy")
			newP, err := loadPolicy(*policyFile, *allowAll)
			if err != nil {
				slog.Error("policy reload failed", "error", err)
				continue
			}
			p.ReplaceRules(newP)
			slog.Info("policy reloaded")
		}
	}()

	// Wait for shutdown signal.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	<-ctx.Done()

	slog.Info("shutting down...")

	// Unregister from core.
	regClient.Unregister(context.Background(), &modulev1.UnregisterRequest{ModuleId: *moduleID})

	// Stop gRPC server.
	grpcSrv.GracefulStop()

	slog.Info("shutdown complete")
}

func loadPolicy(path string, allowAll bool) (*policy.Policy, error) {
	if allowAll {
		return policy.Parse([]byte("\n- caller: \"*\"\n  target: \"*\"\n  methods: [\"*\"]\n"))
	}
	return policy.Load(path)
}

func init() {
	// Override default flag output format.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: call-policy-default [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
}
